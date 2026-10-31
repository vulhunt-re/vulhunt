use fugue::core::storage::SegmentView;
use fugue::lifter::runtime::input::MAX_INSN_BYTES;
use fugue::lifter::runtime::language::Language;
use fugue::lifter::runtime::pcode::LiftingContext;
use fugue::specs::pattern::PatternMatchIter;
use fugue::specs::PatternSpecs;
use goblin::elf::Elf;
use petgraph::graph::NodeIndex;
use petgraph::stable_graph::EdgeReference;
use petgraph::visit::EdgeRef;
use regex::RegexSet;

use super::{
    AddressRangeSet, Arch, ContextBitRange, ContextUpdates, ErasedArch, FunctionThunkTemplate,
};
use crate::cfg::block::BlockInfoTable;
use crate::cfg::function::FunctionStarts;
use crate::cfg::{FlowKind, ICFG};
use crate::ir::{Address, Expr, Term, Var};
use crate::kb::function::Function;
use crate::kb::{uuid, Lazy, Uuid};
use crate::lifter::Lifter;
use crate::region::{MemoryReader, Region, SegmentCursor};

#[derive(Copy, Clone, Default)]
pub struct ARM;

pub const ARCH_ARM: Uuid = uuid("303CDBAE-6878-437F-B926-6661D1FAA53E");

pub const TMODE_CONTEXT: ContextBitRange = ContextBitRange::new(0, 0);
pub const LRSET_CONTEXT: ContextBitRange = ContextBitRange::new(1, 1);

const EF_ARM_BE8: u32 = 0x0080_0000;

static ARM_LE_PAT: Lazy<PatternSpecs> = Lazy::new(|| {
    PatternSpecs::parse(include_str!("patterns/arm/ARM-LE.yaml")).expect("valid pattern definition")
});

static ARM_MAPPING_PATTERNS: Lazy<RegexSet> =
    Lazy::new(|| RegexSet::new(["^\\$[adt]$", "^\\$[adt]\\."]).unwrap());

impl Arch for ARM {
    fn id(&self) -> Uuid {
        ARCH_ARM
    }

    fn is_nonsense_pattern(&self, bytes: &[u8]) -> bool {
        if bytes.len() == 4 {
            bytes == &[0x00u8, 0x00, 0x00, 0x00]
        } else if bytes.len() == 2 {
            bytes == &[0x00u8, 0x00]
        } else {
            false
        }
    }

    fn is_halt_intrinsic(&self, name: &'static str, _args: &[Term<Expr>]) -> bool {
        name == "halt"
    }

    fn gprs(&self, language: &'static Language) -> Vec<Var> {
        || -> Option<Vec<Var>> {
            Some(vec![
                Var::from_varnode(language, &language.register_by_name("r0")?),
                Var::from_varnode(language, &language.register_by_name("r1")?),
                Var::from_varnode(language, &language.register_by_name("r2")?),
                Var::from_varnode(language, &language.register_by_name("r3")?),
                Var::from_varnode(language, &language.register_by_name("r4")?),
                Var::from_varnode(language, &language.register_by_name("r5")?),
                Var::from_varnode(language, &language.register_by_name("r6")?),
                Var::from_varnode(language, &language.register_by_name("r7")?),
                Var::from_varnode(language, &language.register_by_name("r8")?),
                Var::from_varnode(language, &language.register_by_name("r9")?),
                Var::from_varnode(language, &language.register_by_name("r10")?),
                Var::from_varnode(language, &language.register_by_name("r11")?),
                Var::from_varnode(language, &language.register_by_name("r12")?),
                Var::from_varnode(language, &language.register_by_name("sp")?),
                Var::from_varnode(language, &language.register_by_name("lr")?),
                Var::from_varnode(language, &language.register_by_name("pc")?),
            ])
        }()
        .unwrap_or_default()
    }

    fn invalid_or_nonsense_ranges(
        &self,
        start: Address,
        segment: &Region,
        reader: &mut MemoryReader<'_>,
    ) -> AddressRangeSet {
        use yaxpeax_arch::*;
        use yaxpeax_arm::armv7::{ConditionCode, DecodeError, InstDecoder, Opcode, Operand};

        let size = segment.len();
        let view = reader.bytes_at(*segment.address(), size);
        let run = view
            .as_ref()
            .and_then(SegmentView::as_contiguous)
            .unwrap_or_default();
        let mut insn_bytes = [0u8; MAX_INSN_BYTES];

        let mut address = start;
        let mut offset = 0usize;
        let mut invalid_or_nonsense = AddressRangeSet::new_with(address, size);

        let decoder = InstDecoder::default();
        let decoder_thumb = InstDecoder::default_thumb();

        let try_decode_slice = |data: &[u8]| {
            let mut reader = yaxpeax_arch::U8Reader::new(data);

            if let Ok(insn) = decoder.decode(&mut reader) {
                Ok(insn)
            } else {
                let mut reader = yaxpeax_arch::U8Reader::new(data);
                decoder_thumb.decode(&mut reader)
            }
        };

        while offset < size {
            let bytes = match run.get(offset..) {
                Some(bytes) if bytes.len() >= MAX_INSN_BYTES => bytes,
                _ => {
                    let read = reader
                        .read_bytes(*segment.address() + offset, &mut insn_bytes)
                        .unwrap_or(0);
                    &insn_bytes[..read]
                }
            };

            match try_decode_slice(bytes) {
                Ok(insn) => {
                    match (insn.condition, insn.opcode) {
                        (ConditionCode::EQ, Opcode::AND) => {
                            let op1 = insn.operands[0];
                            let op2 = insn.operands[1];
                            let op3 = insn.operands[2];
                            if matches!(
                                (op1, op2, op3),
                                (Operand::Reg(r1), Operand::Reg(r2), Operand::Reg(r3)) if r1 == r2 && r2 == r3
                            ) {
                                invalid_or_nonsense
                                    .insert_with_length(address, insn.len().to_const() as _);
                            }
                        }
                        (_, Opcode::MOV) => {
                            let op1 = insn.operands[0];
                            let op2 = insn.operands[1];
                            if matches!(
                                (op1, op2),
                                (Operand::Reg(r1), Operand::Reg(r2)) if r1 == r2
                            ) {
                                invalid_or_nonsense
                                    .insert_with_length(address, insn.len().to_const() as _);
                            }
                        }
                        (ConditionCode::AL, Opcode::LSL) => {
                            let op1 = insn.operands[0];
                            let op2 = insn.operands[1];
                            let op3 = insn.operands[2];
                            if matches!(
                                (op1, op2, op3),
                                (Operand::Reg(r1), Operand::Reg(r2), Operand::Imm12(0) | Operand::Imm32(0)) if r1 == r2
                            ) {
                                invalid_or_nonsense
                                    .insert_with_length(address, insn.len().to_const() as _);
                            }
                        }
                        _ => (),
                    }

                    let size = insn.len().to_const() as usize;

                    address += size;
                    offset += size;
                }
                Err(e) => {
                    if !matches!(e, DecodeError::Incomplete) {
                        invalid_or_nonsense.insert(address);
                    }

                    address += 1usize;
                    offset += 1usize;
                }
            }
        }

        invalid_or_nonsense.compute_avoids(16);
        invalid_or_nonsense
    }

    fn is_tail_call(
        &self,
        edge: EdgeReference<'_, FlowKind>,
        icfg: &ICFG,
        blocks: &BlockInfoTable,
        functions: &FunctionStarts,
    ) -> Option<(NodeIndex, NodeIndex)> {
        // check if we jump to the start of another function
        let tgt_block_id = icfg[edge.target()];
        if matches!(blocks.get(tgt_block_id), Some(tgt_block) if functions.contains_key(&tgt_block.first_insn().address()))
        {
            return Some((edge.source(), edge.target()));
        }

        // instruction-level heuristics
        let src_block_id = icfg[edge.source()];
        let src_block = blocks.get(src_block_id)?;

        let num_insns_in_block = src_block.num_insns();
        let second_to_last_insn = src_block.get_insn(num_insns_in_block.checked_sub(2)?)?;

        // if we assign (with `pop`) to register 0x58 (`[L]ink[R]egister`) right before branch, mark as tailcall else return None
        second_to_last_insn.insn().operations().iter().find_map(|stmt| {
            matches!(stmt.value(), crate::ir::Stmt::Assign(dest, _src) if dest.is_register() && dest.offset() == 0x58)
                .then_some((edge.source(), edge.target()))
        })
    }

    fn external_thunk_template(&self, language: &'static Language) -> FunctionThunkTemplate {
        let thumb = language.variant().ends_with("T");

        // BX LR
        if thumb {
            let mut bytes = [0x70, 0x47];
            if language.insn_endian().is_big() {
                bytes.reverse();
            }
            FunctionThunkTemplate::new_with(bytes, ContextUpdates::single(TMODE_CONTEXT, 1))
        } else {
            let mut bytes = [0x1E, 0xFF, 0x2F, 0xE1];
            if language.insn_endian().is_big() {
                bytes.reverse();
            }
            FunctionThunkTemplate::new_with(bytes, ContextUpdates::single(TMODE_CONTEXT, 0))
        }
    }

    fn compute_function_properties(
        &self,
        func: &mut Function,
        lifter: &Lifter,
        ctxt: &LiftingContext,
        _icfg: &ICFG,
    ) {
        tracing::trace!("checking TMode at {}", func.address());

        let addr = lifter
            .language()
            .wrap_offset_in_default_space(func.address().offset());
        let tmode = ctxt.get_variable_by_bits(TMODE_CONTEXT, addr);

        tracing::trace!("TMode at {} = {}", func.address(), tmode);

        func.set_tmode(tmode != 0);
    }

    fn compute_function_start_context(&self, address: Address) -> (Address, ContextUpdates) {
        let naddress = Address::from(address.offset() & !1);
        let value = (address != naddress) as u32;

        (naddress, ContextUpdates::single(TMODE_CONTEXT, value))
    }

    fn compute_aligned_address(
        &self,
        address: Address,
        lifter: &Lifter,
        ctx: &LiftingContext,
    ) -> Option<(Address, usize)> {
        let addr_val = lifter
            .language()
            .wrap_offset_in_default_space(address.offset());
        let alignment = match ctx.get_variable_by_bits(TMODE_CONTEXT, addr_val) {
            1 => 2,
            _ => 4,
        };
        let mask = alignment - 1;
        let naddress = Address::from(address.offset() & !mask);

        (address != naddress).then_some((naddress, alignment as usize))
    }

    fn function_start_patterns<'a>(
        &self,
        lifter: &Lifter,
        cursor: SegmentCursor<'a, '_>,
    ) -> Option<PatternMatchIter<'a>> {
        if lifter.language().insn_endian().is_little() {
            Some(ARM_LE_PAT.matches_cursor(cursor))
        } else {
            None
        }
    }

    fn for_each_function_by_pattern<F>(
        &self,
        lifter: &Lifter,
        ctx: &mut LiftingContext,
        start: Address,
        cursor: SegmentCursor<'_, '_>,
        mut f: F,
    ) where
        Self: Sized,
        F: FnMut(Address),
    {
        let alignment = 4;
        let mut thumb_functions = 0usize;
        let mut arm_functions = 0usize;

        if let Some(matches) = <Self as Arch>::function_start_patterns(self, lifter, cursor) {
            for (range, context, _confidence) in matches {
                let addr = start + range.start;
                // discard if not aligned
                if addr.offset() % alignment != 0 {
                    continue;
                }

                let addr_and_space = lifter
                    .language()
                    .wrap_offset_in_default_space(addr.offset());

                for (name, value) in context.variables() {
                    if name != "TMode" {
                        tracing::trace!("setting {name} context at {addr} to {value}");

                        // XXX: do we need to set the whole region?
                        // ctx.set_variable_region(name, addr_and_space, None, value);
                        ctx.set_variable(name, addr_and_space, value);
                        continue;
                    }

                    if value == 1 {
                        thumb_functions += 1;
                    } else {
                        arm_functions += 1;
                    }

                    tracing::trace!("setting TMode context at {addr} to {value}");

                    // XXX: do we need to set the whole region?
                    // ctx.set_variable_region_by_bits(&TMODE_CONTEXT, addr_and_space, None, value);
                    ctx.set_variable_by_bits(TMODE_CONTEXT, addr_and_space, value);
                }

                f(addr);
            }
        }

        // if the majority of found patterns hint at thumb, globally assume thumb mode as default
        let tmode = thumb_functions > arm_functions * 2;
        tracing::trace!(
            "using TMode as default context = {}; {} Thumb and {} ARM functions",
            tmode,
            thumb_functions,
            arm_functions
        );

        /*
        ctx.set_variable_default_by_bits(&TMODE_CONTEXT, 1);
        ctx.set_variable_default_by_bits(&LRSET_CONTEXT, 0);
        */

        let addr = lifter
            .language()
            .wrap_offset_in_default_space(start.offset());

        ctx.set_variable_by_bits(TMODE_CONTEXT, addr, tmode as u32);
        ctx.set_variable_by_bits(LRSET_CONTEXT, addr, 0);
    }

    fn is_mapping_symbol(&self, symbol: &str) -> bool {
        ARM_MAPPING_PATTERNS.is_match_at(symbol, 0)
    }
}

impl ARM {
    pub fn new() -> Box<dyn ErasedArch> {
        Box::new(ARM)
    }

    pub fn check_variant(elf: &Elf, bytes: &[u8]) -> &'static str {
        let be8 = !elf.little_endian && elf.header.e_flags & EF_ARM_BE8 != 0;
        let v7 = if be8 { "v7LEInstruction" } else { "v7" };

        // parse .ARM.attributes
        let Some(arm_attributes_section) = elf.section_headers.iter().find(|&section| {
            elf.shdr_strtab
                .get_at(section.sh_name)
                .map(|name| name == ".ARM.attributes")
                .unwrap_or(false)
        }) else {
            return v7;
        };

        let offset = arm_attributes_section.sh_offset as usize;
        let size = arm_attributes_section.sh_size as usize;
        if size == 0 {
            tracing::debug!(
                "section data for .ARM.attributes seems corrputed (empty section); using v7"
            );
            return v7;
        }
        let Some(section_data) = bytes.get(offset..offset.saturating_add(size)) else {
            tracing::debug!("section data for .ARM.attributes seems corrupted; using v7");
            return v7;
        };

        let mut cpu_arch;
        let mut arm_isa_use = 0;
        let mut thumb_isa_use = 0;

        // skip section start `A`
        let mut index = 1;

        while index < section_data.len() - 1 {
            let tag = section_data[index];
            index += 1;
            match tag {
                6 => {
                    // Tag_CPU_arch
                    cpu_arch = section_data[index];
                    tracing::debug!("parsed CPU architecture from .ARM.attributes as {cpu_arch}");
                    index += 1;
                }
                8 => {
                    // Tag_ARM_ISA_use
                    arm_isa_use = section_data[index];
                    index += 1;
                }
                9 => {
                    // Tag_THUMB_ISA_use
                    thumb_isa_use = section_data[index];
                    index += 1;
                }
                _ => {
                    index += 1;
                }
            }
        }

        if thumb_isa_use > 0 && arm_isa_use == 0 {
            if be8 {
                "v8LEInstruction"
            } else {
                "v8T"
            }
        } else {
            v7
        }
    }
}

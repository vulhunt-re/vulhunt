use fugue::fspec::pattern::{PatternSet, PatternSetMatchIter};
use fugue::ir::disassembly::context::ContextDatabase;
use fugue::ir::{Address, Translator};
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
use crate::ir::{Expr, Term, Var};
use crate::kb::function::Function;
use crate::kb::{uuid, Lazy, Uuid};
use crate::lifter::{Lifter, TranslatorExt};
use crate::region::Region;

#[derive(Copy, Clone, Default)]
pub struct ARM;

pub const ARCH_ARM: Uuid = uuid("303CDBAE-6878-437F-B926-6661D1FAA53E");

pub const TMODE_CONTEXT: ContextBitRange = ContextBitRange::new(0, 0);
pub const LRSET_CONTEXT: ContextBitRange = ContextBitRange::new(1, 1);

static ARM_LE_PAT: Lazy<PatternSet> = Lazy::new(|| {
    PatternSet::from_str(include_str!("patterns/arm/ARM-LE.yaml"))
        .expect("valid pattern definition")
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

    fn gprs(&self, translator: &Translator) -> Vec<Var> {
        || -> Option<Vec<Var>> {
            Some(vec![
                translator.register_var("r0")?,
                translator.register_var("r1")?,
                translator.register_var("r2")?,
                translator.register_var("r3")?,
                translator.register_var("r4")?,
                translator.register_var("r5")?,
                translator.register_var("r6")?,
                translator.register_var("r7")?,
                translator.register_var("r8")?,
                translator.register_var("r9")?,
                translator.register_var("r10")?,
                translator.register_var("r11")?,
                translator.register_var("r12")?,
                translator.register_var("sp")?,
                translator.register_var("lr")?,
                translator.register_var("pc")?,
            ])
        }()
        .unwrap_or_default()
    }

    fn invalid_or_nonsense_ranges(&self, start: Address, bytes: &[u8]) -> AddressRangeSet {
        use yaxpeax_arch::*;
        use yaxpeax_arm::armv7::{ConditionCode, DecodeError, InstDecoder, Opcode, Operand};

        let mut address = start;
        let mut offset = 0usize;
        let mut invalid_or_nonsense = AddressRangeSet::new_with(address, bytes.len());

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

        while offset < bytes.len() {
            match try_decode_slice(&bytes[offset..]) {
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

    fn external_thunk_template(&self, translator: &Translator) -> FunctionThunkTemplate {
        let arch = translator.architecture();
        let endian = arch.endian();
        let thumb = arch.variant().ends_with("T");

        // BX LR
        if thumb {
            let mut bytes = [0x70, 0x47];
            if endian.is_big() {
                bytes.reverse();
            }
            FunctionThunkTemplate::new_with(bytes, ContextUpdates::single(TMODE_CONTEXT, 1))
        } else {
            let mut bytes = [0x1E, 0xFF, 0x2F, 0xE1];
            if endian.is_big() {
                bytes.reverse();
            }
            FunctionThunkTemplate::new_with(bytes, ContextUpdates::single(TMODE_CONTEXT, 0))
        }
    }

    fn compute_function_properties(
        &self,
        func: &mut Function,
        lifter: &Lifter,
        ctxt: &ContextDatabase,
        _icfg: &ICFG,
    ) {
        tracing::trace!("checking TMode at {}", func.address());

        let addr = lifter.translator().address(func.address().offset());
        let tmode = ctxt.get_variable_by_bits(&TMODE_CONTEXT, addr);

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
        ctx: &ContextDatabase,
    ) -> Option<(Address, usize)> {
        let addr_val = lifter.translator().address(address.into());
        let alignment = match ctx.get_variable_by_bits(&TMODE_CONTEXT, addr_val) {
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
        bytes: &'a [u8],
    ) -> Option<PatternSetMatchIter<'a>> {
        if lifter.endian().is_little() {
            Some(ARM_LE_PAT.matches(bytes))
        } else {
            None
        }
    }

    fn for_each_function_by_pattern<F>(
        &self,
        lifter: &Lifter,
        ctx: &mut ContextDatabase,
        segment: &Region,
        mut f: F,
    ) where
        Self: Sized,
        F: FnMut(Address),
    {
        let alignment = 4;
        let mut thumb_functions = 0usize;
        let mut arm_functions = 0usize;

        if let Some(matches) =
            <Self as Arch>::function_start_patterns(self, &lifter, segment.bytes())
        {
            for (range, context) in matches {
                let addr = *segment.address() + range.start;
                // discard if not aligned
                if addr.offset() % alignment != 0 {
                    continue;
                }

                let addr_and_space = lifter.translator().address(addr.offset());

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
                    ctx.set_variable_by_bits(&TMODE_CONTEXT, addr_and_space, value);
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

        let addr = lifter.address_value(*segment.address());

        ctx.set_variable_by_bits(&TMODE_CONTEXT, addr, tmode as u32);
        ctx.set_variable_by_bits(&LRSET_CONTEXT, addr, 0);
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
        // parse .ARM.attributes
        let Some(arm_attributes_section) = elf.section_headers.iter().find(|&section| {
            elf.shdr_strtab
                .get_at(section.sh_name)
                .map(|name| name == ".ARM.attributes")
                .unwrap_or(false)
        }) else {
            return "v7";
        };

        let offset = arm_attributes_section.sh_offset as usize;
        let size = arm_attributes_section.sh_size as usize;
        if size == 0 {
            tracing::debug!(
                "section data for .ARM.attributes seems corrputed (empty section); using v7"
            );
            return "v7";
        }
        let Some(section_data) = bytes.get(offset..offset.saturating_add(size)) else {
            tracing::debug!("section data for .ARM.attributes seems corrupted; using v7");
            return "v7";
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
            "v8T"
        } else {
            "v7"
        }
    }
}

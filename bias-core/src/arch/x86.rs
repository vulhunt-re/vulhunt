use fugue::core::storage::SegmentView;
use fugue::lifter::runtime::input::MAX_INSN_BYTES;
use fugue::lifter::runtime::language::Language;
use fugue::lifter::runtime::pcode::LiftingContext;
use fugue::specs::pattern::PatternMatchIter;
use fugue::specs::PatternSpecs;

use super::{AddressRangeSet, Arch, ErasedArch, Flag, FunctionThunkTemplate};
use crate::ir::{Address, Expr, Term, Var};
use crate::kb::{uuid, Lazy, Uuid};
use crate::lifter::Lifter;
use crate::region::{MemoryReader, Region, SegmentCursor};

#[derive(Copy, Clone, Default)]
#[repr(transparent)]
pub struct X86(Uuid);

pub const ARCH_X86: Uuid = uuid("41CCF45D-CF79-4C02-8BFB-230DC29FA926");
pub const ARCH_X86_64: Uuid = uuid("9CD0AB9F-1FEE-4F47-8352-BC234ED571F2");

static X86_64_PAT: Lazy<PatternSpecs> = Lazy::new(|| {
    PatternSpecs::parse(include_str!("patterns/x86/x86-64.yaml")).expect("valid pattern definition")
});

// NOTE: we should likely allow this stucture to be built based on different
// kinds of conventions, e.g., GCC convention will activate syscall detection

impl Arch for X86 {
    fn id(&self) -> Uuid {
        self.0
    }

    fn flags(&self, language: &'static Language) -> Vec<Flag> {
        || -> Option<Vec<Flag>> {
            Some(vec![
                Flag::c(Var::from_varnode(
                    language,
                    &language.register_by_name("CF")?,
                )),
                Flag::p(Var::from_varnode(
                    language,
                    &language.register_by_name("PF")?,
                )),
                Flag::a(Var::from_varnode(
                    language,
                    &language.register_by_name("AF")?,
                )),
                Flag::z(Var::from_varnode(
                    language,
                    &language.register_by_name("ZF")?,
                )),
                Flag::n(Var::from_varnode(
                    language,
                    &language.register_by_name("SF")?,
                )),
                Flag::new(Var::from_varnode(
                    language,
                    &language.register_by_name("DF")?,
                )),
                Flag::v(Var::from_varnode(
                    language,
                    &language.register_by_name("OF")?,
                )),
            ])
        }()
        .unwrap_or_default()
    }

    fn gprs(&self, language: &'static Language) -> Vec<Var> {
        || -> Option<Vec<Var>> {
            let is_64 = self.is_64();
            let mut pfx = vec![
                Var::from_varnode(
                    language,
                    &language.register_by_name(if is_64 { "RAX" } else { "EAX" })?,
                ),
                Var::from_varnode(
                    language,
                    &language.register_by_name(if is_64 { "RBX" } else { "EBX" })?,
                ),
                Var::from_varnode(
                    language,
                    &language.register_by_name(if is_64 { "RCX" } else { "ECX" })?,
                ),
                Var::from_varnode(
                    language,
                    &language.register_by_name(if is_64 { "RDX" } else { "EDX" })?,
                ),
                Var::from_varnode(
                    language,
                    &language.register_by_name(if is_64 { "RSI" } else { "ESI" })?,
                ),
                Var::from_varnode(
                    language,
                    &language.register_by_name(if is_64 { "RDI" } else { "EDI" })?,
                ),
                Var::from_varnode(
                    language,
                    &language.register_by_name(if is_64 { "RBP" } else { "EBP" })?,
                ),
                Var::from_varnode(
                    language,
                    &language.register_by_name(if is_64 { "RSP" } else { "ESP" })?,
                ),
            ];

            if is_64 {
                pfx.push(Var::from_varnode(
                    language,
                    &language.register_by_name("R8")?,
                ));
                pfx.push(Var::from_varnode(
                    language,
                    &language.register_by_name("R9")?,
                ));
                pfx.push(Var::from_varnode(
                    language,
                    &language.register_by_name("R10")?,
                ));
                pfx.push(Var::from_varnode(
                    language,
                    &language.register_by_name("R11")?,
                ));
                pfx.push(Var::from_varnode(
                    language,
                    &language.register_by_name("R12")?,
                ));
                pfx.push(Var::from_varnode(
                    language,
                    &language.register_by_name("R13")?,
                ));
                pfx.push(Var::from_varnode(
                    language,
                    &language.register_by_name("R14")?,
                ));
                pfx.push(Var::from_varnode(
                    language,
                    &language.register_by_name("R15")?,
                ));
            }

            Some(pfx)
        }()
        .unwrap_or_default()
    }

    fn frame_pointer(&self, language: &'static Language) -> Option<Var> {
        language
            .register_by_name(if self.is_64() { "RBP" } else { "EBP" })
            .map(|varnode| Var::from_varnode(language, &varnode))
    }

    fn is_nonsense_pattern(&self, bytes: &[u8]) -> bool {
        const NONSENSE: &[&[u8]] = &[&[0x00u8, 0x00u8], &[0x00u8], &[0xf0u8]];
        NONSENSE.contains(&bytes)
    }

    fn is_skip_intrinsic(&self, name: &'static str, _args: &[Term<Expr>]) -> bool {
        name == "int3"
    }

    fn is_trap_intrinsic(&self, name: &'static str, args: &[Term<Expr>]) -> bool {
        name == "int3"
            || (name == "swi"
                && args
                    .first()
                    .map(|expr| expr.is_bv(0x3u8))
                    .unwrap_or_default())
            || name == "invalidInstructionException"
    }

    fn is_halt_intrinsic(&self, name: &'static str, _args: &[Term<Expr>]) -> bool {
        name == "halt"
    }

    fn invalid_or_nonsense_ranges(
        &self,
        start: Address,
        segment: &Region,
        reader: &mut MemoryReader<'_>,
    ) -> AddressRangeSet {
        if self.is_64() {
            self.invalid_or_nonsense_ranges_64(start, segment, reader)
        } else {
            // 32-bit
            self.invalid_or_nonsense_ranges_32(start, segment, reader)
        }
    }

    fn external_thunk_template(&self, _language: &'static Language) -> FunctionThunkTemplate {
        // RET
        FunctionThunkTemplate::new([0xC3])
    }

    /*
    fn is_service_call(&self, name: &'static str, _args: &[Term<Expr>]) -> bool {
        name == "syscall" // || "int80, etc."
    }
    */

    fn function_start_patterns<'a>(
        &self,
        _lifter: &Lifter,
        cursor: SegmentCursor<'a, '_>,
    ) -> Option<PatternMatchIter<'a>> {
        if self.is_64() {
            Some(X86_64_PAT.matches_cursor(cursor))
        } else {
            None
        }
    }

    fn for_each_function_by_pattern<F>(
        &self,
        lifter: &Lifter,
        _ctx: &mut LiftingContext,
        start: Address,
        cursor: SegmentCursor<'_, '_>,
        mut f: F,
    ) where
        Self: Sized,
        F: FnMut(Address),
    {
        if let Some(matches) = <Self as Arch>::function_start_patterns(self, lifter, cursor) {
            for (range, _context, _confidence) in matches {
                let addr = start + range.start;
                f(addr);
            }
        }
    }
}

impl X86 {
    pub fn new(amd64: bool) -> Box<dyn ErasedArch> {
        Box::new(X86(if amd64 { ARCH_X86_64 } else { ARCH_X86 }))
    }

    pub fn is_64(&self) -> bool {
        self.0 == ARCH_X86_64
    }

    fn invalid_or_nonsense_ranges_32(
        &self,
        start: Address,
        segment: &Region,
        reader: &mut MemoryReader<'_>,
    ) -> AddressRangeSet {
        use yaxpeax_arch::*;
        use yaxpeax_x86::protected_mode::{register_class, InstDecoder, Opcode, Operand};

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

            if let Ok(inst) = decoder.decode_slice(bytes) {
                match inst.opcode() {
                    Opcode::ADD => {
                        let op1 = inst.operand(0);
                        let op2 = inst.operand(1);

                        if matches!(op1, Operand::MemDeref { base: r1 }
                                    if matches!(op2, Operand::Register { reg: r2 }
                                                if [
                                                    register_class::D,
                                                    register_class::W,
                                                ].contains(&r1.class())
                                                && r2.class() == register_class::B && r1.num() == r2.num()))
                        {
                            invalid_or_nonsense
                                .insert_with_length(address, inst.len().to_const() as _);
                        }
                    }
                    Opcode::INT => {
                        if matches!(inst.operand(0), Operand::ImmediateU8 { imm: 3 }) {
                            invalid_or_nonsense
                                .insert_with_length(address, inst.len().to_const() as _);
                        }
                    }
                    _ => (),
                }

                let size = inst.len().to_const() as usize;

                address += size;
                offset += size;
            } else {
                invalid_or_nonsense.insert(address);

                address += 1usize;
                offset += 1usize;
            }
        }

        invalid_or_nonsense.compute_avoids(16);
        invalid_or_nonsense
    }

    fn invalid_or_nonsense_ranges_64(
        &self,
        start: Address,
        segment: &Region,
        reader: &mut MemoryReader<'_>,
    ) -> AddressRangeSet {
        use yaxpeax_arch::*;
        use yaxpeax_x86::long_mode::{register_class, InstDecoder, Opcode, Operand};

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

            if let Ok(inst) = decoder.decode_slice(bytes) {
                match inst.opcode() {
                    Opcode::ADD => {
                        let op1 = inst.operand(0);
                        let op2 = inst.operand(1);

                        if matches!(op1, Operand::MemDeref { base: r1 }
                                    if matches!(op2, Operand::Register { reg: r2 }
                                                if [
                                                    register_class::Q,
                                                    register_class::D,
                                                    register_class::W,
                                                ].contains(&r1.class())
                                                && r2.class() == register_class::B && r1.num() == r2.num()))
                        {
                            invalid_or_nonsense
                                .insert_with_length(address, inst.len().to_const() as _);
                        }
                    }
                    Opcode::INT => {
                        if matches!(inst.operand(0), Operand::ImmediateU8 { imm: 3 }) {
                            invalid_or_nonsense
                                .insert_with_length(address, inst.len().to_const() as _);
                        }
                    }
                    _ => (),
                }

                let size = inst.len().to_const() as usize;

                address += size;
                offset += size;
            } else {
                invalid_or_nonsense.insert(address);

                address += 1usize;
                offset += 1usize;
            }
        }

        invalid_or_nonsense.compute_avoids(16);
        invalid_or_nonsense
    }
}

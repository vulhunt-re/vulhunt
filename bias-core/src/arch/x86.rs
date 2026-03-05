use fugue::fspec::pattern::{PatternSet, PatternSetMatchIter};
use fugue::ir::disassembly::ContextDatabase;
use fugue::ir::{Address, Translator};

use super::{AddressRangeSet, Arch, ErasedArch, Flag, FunctionThunkTemplate};
use crate::ir::{Expr, Term, Var};
use crate::kb::{uuid, Lazy, Uuid};
use crate::lifter::{Lifter, TranslatorExt};
use crate::region::Region;

#[derive(Copy, Clone, Default)]
#[repr(transparent)]
pub struct X86(Uuid);

pub const ARCH_X86: Uuid = uuid("41CCF45D-CF79-4C02-8BFB-230DC29FA926");
pub const ARCH_X86_64: Uuid = uuid("9CD0AB9F-1FEE-4F47-8352-BC234ED571F2");

static X86_64_PAT: Lazy<PatternSet> = Lazy::new(|| {
    PatternSet::from_str(include_str!("patterns/x86/x86-64.yaml"))
        .expect("valid pattern definition")
});

// NOTE: we should likely allow this stucture to be built based on different
// kinds of conventions, e.g., GCC convention will activate syscall detection

impl Arch for X86 {
    fn id(&self) -> Uuid {
        self.0
    }

    fn flags(&self, translator: &Translator) -> Vec<Flag> {
        || -> Option<Vec<Flag>> {
            Some(vec![
                Flag::c(translator.register_var("CF")?),
                Flag::p(translator.register_var("PF")?),
                Flag::a(translator.register_var("AF")?),
                Flag::z(translator.register_var("ZF")?),
                Flag::n(translator.register_var("SF")?),
                Flag::new(translator.register_var("DF")?),
                Flag::v(translator.register_var("OF")?),
            ])
        }()
        .unwrap_or_default()
    }

    fn gprs(&self, translator: &Translator) -> Vec<Var> {
        || -> Option<Vec<Var>> {
            let is_64 = self.is_64();
            let mut pfx = vec![
                translator.register_var(if is_64 { "RAX" } else { "EAX" })?,
                translator.register_var(if is_64 { "RBX" } else { "EBX" })?,
                translator.register_var(if is_64 { "RCX" } else { "ECX" })?,
                translator.register_var(if is_64 { "RDX" } else { "EDX" })?,
                translator.register_var(if is_64 { "RSI" } else { "ESI" })?,
                translator.register_var(if is_64 { "RDI" } else { "EDI" })?,
                translator.register_var(if is_64 { "RBP" } else { "EBP" })?,
                translator.register_var(if is_64 { "RSP" } else { "ESP" })?,
            ];

            if is_64 {
                pfx.push(translator.register_var("R8")?);
                pfx.push(translator.register_var("R9")?);
                pfx.push(translator.register_var("R10")?);
                pfx.push(translator.register_var("R11")?);
                pfx.push(translator.register_var("R12")?);
                pfx.push(translator.register_var("R13")?);
                pfx.push(translator.register_var("R14")?);
                pfx.push(translator.register_var("R15")?);
            }

            Some(pfx)
        }()
        .unwrap_or_default()
    }

    fn frame_pointer(&self, translator: &Translator) -> Option<Var> {
        translator.register_var(if self.is_64() { "RBP" } else { "EBP" })
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

    fn invalid_or_nonsense_ranges(&self, start: Address, bytes: &[u8]) -> AddressRangeSet {
        if self.is_64() {
            self.invalid_or_nonsense_ranges_64(start, bytes)
        } else {
            // 32-bit
            self.invalid_or_nonsense_ranges_32(start, bytes)
        }
    }

    fn external_thunk_template(&self, _translator: &Translator) -> FunctionThunkTemplate {
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
        bytes: &'a [u8],
    ) -> Option<PatternSetMatchIter<'a>> {
        if self.is_64() {
            Some(X86_64_PAT.matches(bytes))
        } else {
            None
        }
    }

    fn for_each_function_by_pattern<F>(
        &self,
        lifter: &Lifter,
        _ctx: &mut ContextDatabase,
        segment: &Region,
        mut f: F,
    ) where
        Self: Sized,
        F: FnMut(Address),
    {
        if let Some(matches) =
            <Self as Arch>::function_start_patterns(self, &lifter, segment.bytes())
        {
            for (range, _context) in matches {
                let addr = *segment.address() + range.start;
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

    fn invalid_or_nonsense_ranges_32(&self, start: Address, bytes: &[u8]) -> AddressRangeSet {
        use yaxpeax_arch::*;
        use yaxpeax_x86::protected_mode::{register_class, InstDecoder, Opcode, Operand};

        let mut address = start;
        let mut offset = 0usize;
        let mut invalid_or_nonsense = AddressRangeSet::new_with(address, bytes.len());

        let decoder = InstDecoder::default();

        while offset < bytes.len() {
            if let Ok(inst) = decoder.decode_slice(&bytes[offset..]) {
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

    fn invalid_or_nonsense_ranges_64(&self, start: Address, bytes: &[u8]) -> AddressRangeSet {
        use yaxpeax_arch::*;
        use yaxpeax_x86::long_mode::{register_class, InstDecoder, Opcode, Operand};

        let mut address = start;
        let mut offset = 0usize;
        let mut invalid_or_nonsense = AddressRangeSet::new_with(address, bytes.len());

        let decoder = InstDecoder::default();

        while offset < bytes.len() {
            if let Ok(inst) = decoder.decode_slice(&bytes[offset..]) {
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

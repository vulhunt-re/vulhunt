use fugue::lifter::runtime::language::Language;
use fugue::lifter::runtime::pcode::LiftingContext;
use fugue::specs::pattern::PatternMatchIter;
use fugue::specs::PatternSpecs;

use super::{register_var, AddressRangeSet, Arch, ErasedArch, Flag, FunctionThunkTemplate};
use crate::ir::{Address, Expr, Term, Var};
use crate::kb::{uuid, Lazy, Uuid};
use crate::lifter::Lifter;

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
                Flag::c(register_var(language, "CF")?),
                Flag::p(register_var(language, "PF")?),
                Flag::a(register_var(language, "AF")?),
                Flag::z(register_var(language, "ZF")?),
                Flag::n(register_var(language, "SF")?),
                Flag::new(register_var(language, "DF")?),
                Flag::v(register_var(language, "OF")?),
            ])
        }()
        .unwrap_or_default()
    }

    fn gprs(&self, language: &'static Language) -> Vec<Var> {
        || -> Option<Vec<Var>> {
            let is_64 = self.is_64();
            let mut pfx = vec![
                register_var(language, if is_64 { "RAX" } else { "EAX" })?,
                register_var(language, if is_64 { "RBX" } else { "EBX" })?,
                register_var(language, if is_64 { "RCX" } else { "ECX" })?,
                register_var(language, if is_64 { "RDX" } else { "EDX" })?,
                register_var(language, if is_64 { "RSI" } else { "ESI" })?,
                register_var(language, if is_64 { "RDI" } else { "EDI" })?,
                register_var(language, if is_64 { "RBP" } else { "EBP" })?,
                register_var(language, if is_64 { "RSP" } else { "ESP" })?,
            ];

            if is_64 {
                pfx.push(register_var(language, "R8")?);
                pfx.push(register_var(language, "R9")?);
                pfx.push(register_var(language, "R10")?);
                pfx.push(register_var(language, "R11")?);
                pfx.push(register_var(language, "R12")?);
                pfx.push(register_var(language, "R13")?);
                pfx.push(register_var(language, "R14")?);
                pfx.push(register_var(language, "R15")?);
            }

            Some(pfx)
        }()
        .unwrap_or_default()
    }

    fn frame_pointer(&self, language: &'static Language) -> Option<Var> {
        register_var(language, if self.is_64() { "RBP" } else { "EBP" })
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
        bytes: &'a [u8],
    ) -> Option<PatternMatchIter<'a>> {
        if self.is_64() {
            Some(X86_64_PAT.matches(bytes))
        } else {
            None
        }
    }

    fn for_each_function_by_pattern<F>(
        &self,
        lifter: &Lifter,
        _ctx: &mut LiftingContext,
        start: Address,
        bytes: &[u8],
        mut f: F,
    ) where
        Self: Sized,
        F: FnMut(Address),
    {
        if let Some(matches) = <Self as Arch>::function_start_patterns(self, lifter, bytes) {
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

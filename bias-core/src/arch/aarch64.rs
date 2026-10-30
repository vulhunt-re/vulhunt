use fugue::lifter::runtime::language::Language;

use super::{register_var, Arch, ErasedArch, FunctionThunkTemplate};
use crate::arch::AddressRangeSet;
use crate::ir::{Address, Expr, Term, Var};
use crate::kb::{uuid, Uuid};

#[derive(Copy, Clone, Default)]
pub struct AARCH64;

pub const ARCH_AARCH64: Uuid = uuid("72F6D5A0-6470-447D-AE29-5E6C1DCEE6B2");

impl Arch for AARCH64 {
    fn id(&self) -> Uuid {
        ARCH_AARCH64
    }

    fn is_nonsense_pattern(&self, bytes: &[u8]) -> bool {
        bytes == &[0x00u8, 0x00u8, 0x00u8, 0x00u8]
    }

    fn is_halt_intrinsic(&self, name: &'static str, _args: &[Term<Expr>]) -> bool {
        name == "halt"
    }

    fn external_thunk_template(&self, _language: &'static Language) -> FunctionThunkTemplate {
        FunctionThunkTemplate::new([0xC0, 0x03, 0x5F, 0xD6]) // RET
    }

    fn gprs(&self, language: &'static Language) -> Vec<Var> {
        || -> Option<Vec<Var>> {
            Some(vec![
                register_var(language, "x0")?,
                register_var(language, "x1")?,
                register_var(language, "x2")?,
                register_var(language, "x3")?,
                register_var(language, "x4")?,
                register_var(language, "x5")?,
                register_var(language, "x6")?,
                register_var(language, "x7")?,
                register_var(language, "x8")?,
                register_var(language, "x9")?,
                register_var(language, "x10")?,
                register_var(language, "x11")?,
                register_var(language, "x12")?,
                register_var(language, "x13")?,
                register_var(language, "x14")?,
                register_var(language, "x15")?,
                register_var(language, "x16")?,
                register_var(language, "x17")?,
                register_var(language, "x18")?,
                register_var(language, "x19")?,
                register_var(language, "x20")?,
                register_var(language, "x21")?,
                register_var(language, "x22")?,
                register_var(language, "x23")?,
                register_var(language, "x24")?,
                register_var(language, "x25")?,
                register_var(language, "x26")?,
                register_var(language, "x27")?,
                register_var(language, "x28")?,
                register_var(language, "x29")?,
                register_var(language, "x30")?,
            ])
        }()
        .unwrap_or_default()
    }

    fn invalid_or_nonsense_ranges(&self, start: Address, bytes: &[u8]) -> AddressRangeSet {
        use yaxpeax_arch::*;
        use yaxpeax_arm::armv8::a64::{DecodeError, InstDecoder, Opcode, Operand};

        let mut address = start;
        let mut offset = 0usize;
        let mut invalid_or_nonsense = AddressRangeSet::new_with(address, bytes.len());

        let decoder = InstDecoder::default();

        let try_decode_slice = |data: &[u8]| {
            let mut reader = yaxpeax_arch::U8Reader::new(data);
            decoder.decode(&mut reader)
        };

        while offset < bytes.len() {
            match try_decode_slice(&bytes[offset..]) {
                Ok(insn) => {
                    match insn.opcode {
                        Opcode::UDF => {
                            if matches!(insn.operands[0], Operand::Imm16(0)) {
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
                    if !matches!(e, DecodeError::IncompleteDecoder) {
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
}

impl AARCH64 {
    pub fn new() -> Box<dyn ErasedArch> {
        Box::new(AARCH64)
    }
}

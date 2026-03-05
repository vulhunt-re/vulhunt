use fugue::ir::{Address, Translator};

use super::{Arch, ErasedArch, FunctionThunkTemplate};
use crate::arch::AddressRangeSet;
use crate::ir::{Expr, Term, Var};
use crate::kb::{uuid, Uuid};
use crate::lifter::TranslatorExt;

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

    fn external_thunk_template(&self, _translator: &Translator) -> FunctionThunkTemplate {
        FunctionThunkTemplate::new([0xC0, 0x03, 0x5F, 0xD6]) // RET
    }

    fn gprs(&self, translator: &Translator) -> Vec<Var> {
        || -> Option<Vec<Var>> {
            Some(vec![
                translator.register_var("x0")?,
                translator.register_var("x1")?,
                translator.register_var("x2")?,
                translator.register_var("x3")?,
                translator.register_var("x4")?,
                translator.register_var("x5")?,
                translator.register_var("x6")?,
                translator.register_var("x7")?,
                translator.register_var("x8")?,
                translator.register_var("x9")?,
                translator.register_var("x10")?,
                translator.register_var("x11")?,
                translator.register_var("x12")?,
                translator.register_var("x13")?,
                translator.register_var("x14")?,
                translator.register_var("x15")?,
                translator.register_var("x16")?,
                translator.register_var("x17")?,
                translator.register_var("x18")?,
                translator.register_var("x19")?,
                translator.register_var("x20")?,
                translator.register_var("x21")?,
                translator.register_var("x22")?,
                translator.register_var("x23")?,
                translator.register_var("x24")?,
                translator.register_var("x25")?,
                translator.register_var("x26")?,
                translator.register_var("x27")?,
                translator.register_var("x28")?,
                translator.register_var("x29")?,
                translator.register_var("x30")?,
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

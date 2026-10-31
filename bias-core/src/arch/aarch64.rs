use fugue::core::storage::SegmentView;
use fugue::lifter::runtime::input::MAX_INSN_BYTES;
use fugue::lifter::runtime::language::Language;

use super::{Arch, ErasedArch, FunctionThunkTemplate};
use crate::arch::AddressRangeSet;
use crate::ir::{Address, Expr, Term, Var};
use crate::kb::{uuid, Uuid};
use crate::region::{MemoryReader, Region};

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
                Var::from_varnode(language, &language.register_by_name("x0")?),
                Var::from_varnode(language, &language.register_by_name("x1")?),
                Var::from_varnode(language, &language.register_by_name("x2")?),
                Var::from_varnode(language, &language.register_by_name("x3")?),
                Var::from_varnode(language, &language.register_by_name("x4")?),
                Var::from_varnode(language, &language.register_by_name("x5")?),
                Var::from_varnode(language, &language.register_by_name("x6")?),
                Var::from_varnode(language, &language.register_by_name("x7")?),
                Var::from_varnode(language, &language.register_by_name("x8")?),
                Var::from_varnode(language, &language.register_by_name("x9")?),
                Var::from_varnode(language, &language.register_by_name("x10")?),
                Var::from_varnode(language, &language.register_by_name("x11")?),
                Var::from_varnode(language, &language.register_by_name("x12")?),
                Var::from_varnode(language, &language.register_by_name("x13")?),
                Var::from_varnode(language, &language.register_by_name("x14")?),
                Var::from_varnode(language, &language.register_by_name("x15")?),
                Var::from_varnode(language, &language.register_by_name("x16")?),
                Var::from_varnode(language, &language.register_by_name("x17")?),
                Var::from_varnode(language, &language.register_by_name("x18")?),
                Var::from_varnode(language, &language.register_by_name("x19")?),
                Var::from_varnode(language, &language.register_by_name("x20")?),
                Var::from_varnode(language, &language.register_by_name("x21")?),
                Var::from_varnode(language, &language.register_by_name("x22")?),
                Var::from_varnode(language, &language.register_by_name("x23")?),
                Var::from_varnode(language, &language.register_by_name("x24")?),
                Var::from_varnode(language, &language.register_by_name("x25")?),
                Var::from_varnode(language, &language.register_by_name("x26")?),
                Var::from_varnode(language, &language.register_by_name("x27")?),
                Var::from_varnode(language, &language.register_by_name("x28")?),
                Var::from_varnode(language, &language.register_by_name("x29")?),
                Var::from_varnode(language, &language.register_by_name("x30")?),
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
        use yaxpeax_arm::armv8::a64::{DecodeError, InstDecoder, Opcode, Operand};

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

        let try_decode_slice = |data: &[u8]| {
            let mut reader = yaxpeax_arch::U8Reader::new(data);
            decoder.decode(&mut reader)
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

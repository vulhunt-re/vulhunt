use bias_core::prelude::{ArchitectureDef, Endian};
use crate::util::BytesOrMapping;

use goblin::elf::header::{EM_386, EM_AARCH64, EM_ARM, EM_BPF, EM_X86_64, EM_XTENSA};
use goblin::pe::header::{
    COFF_MACHINE_ARM, COFF_MACHINE_ARM64, COFF_MACHINE_X86, COFF_MACHINE_X86_64,
};

pub fn input_architecture<'a>(input: impl Into<BytesOrMapping<'a>>) -> Option<ArchitectureDef> {
    let input = input.into();

    match goblin::Object::parse(input.as_ref()) {
        Ok(goblin::Object::Elf(elf)) => {
            let endian = if elf.header.endianness().ok()?.is_little() {
                Endian::Little
            } else {
                Endian::Big
            };

            Some(match elf.header.e_machine {
                EM_AARCH64 => ArchitectureDef::new("AARCH64", endian, 64, "v8A"),
                EM_ARM => ArchitectureDef::new("ARM", endian, 32, "v7"),
                EM_BPF => ArchitectureDef::new("eBPF", endian, 64, "default"),
                EM_X86_64 => ArchitectureDef::new("x86", endian, 64, "default"),
                EM_386 => ArchitectureDef::new("x86", endian, 32, "default"),
                EM_XTENSA => ArchitectureDef::new("Xtensa", endian, 32, "default"),
                _ => return None,
            })
        }
        Ok(goblin::Object::PE(pe)) => Some(match pe.header.coff_header.machine {
            COFF_MACHINE_ARM64 => ArchitectureDef::new("AARCH64", Endian::Little, 64, "v8A"),
            COFF_MACHINE_ARM => ArchitectureDef::new("ARM", Endian::Little, 32, "v7"),
            COFF_MACHINE_X86_64 => ArchitectureDef::new("x86", Endian::Little, 64, "default"),
            COFF_MACHINE_X86 => ArchitectureDef::new("x86", Endian::Little, 32, "default"),
            _ => return None,
        }),
        Ok(goblin::Object::TE(te)) => Some(match te.header.machine {
            COFF_MACHINE_ARM64 => ArchitectureDef::new("AARCH64", Endian::Little, 64, "v8A"),
            COFF_MACHINE_ARM => ArchitectureDef::new("ARM", Endian::Little, 32, "v7"),
            COFF_MACHINE_X86_64 => ArchitectureDef::new("x86", Endian::Little, 64, "default"),
            COFF_MACHINE_X86 => ArchitectureDef::new("x86", Endian::Little, 32, "default"),
            _ => return None,
        }),
        _ => None,
    }
}

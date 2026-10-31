use fugue::lifter::runtime::language::Language;

use super::{Arch, ErasedArch, FunctionThunkTemplate};
use crate::ir::Var;
use crate::kb::{uuid, Uuid};

#[derive(Copy, Clone, Default)]
pub struct XTENSA;

pub const ARCH_XTENSA: Uuid = uuid("0224FD9A-D378-4CF7-8D78-E95C1E90359E");

impl Arch for XTENSA {
    fn id(&self) -> Uuid {
        ARCH_XTENSA
    }

    fn gprs(&self, language: &'static Language) -> Vec<Var> {
        || -> Option<Vec<Var>> {
            Some(vec![
                Var::from_varnode(language, &language.register_by_name("a0")?),
                Var::from_varnode(language, &language.register_by_name("a1")?),
                Var::from_varnode(language, &language.register_by_name("a2")?),
                Var::from_varnode(language, &language.register_by_name("a3")?),
                Var::from_varnode(language, &language.register_by_name("a4")?),
                Var::from_varnode(language, &language.register_by_name("a5")?),
                Var::from_varnode(language, &language.register_by_name("a6")?),
                Var::from_varnode(language, &language.register_by_name("a7")?),
                Var::from_varnode(language, &language.register_by_name("a8")?),
                Var::from_varnode(language, &language.register_by_name("a9")?),
                Var::from_varnode(language, &language.register_by_name("a10")?),
                Var::from_varnode(language, &language.register_by_name("a11")?),
                Var::from_varnode(language, &language.register_by_name("a12")?),
                Var::from_varnode(language, &language.register_by_name("a13")?),
                Var::from_varnode(language, &language.register_by_name("a14")?),
                Var::from_varnode(language, &language.register_by_name("a15")?),
            ])
        }()
        .unwrap_or_default()
    }

    fn external_thunk_template(&self, language: &'static Language) -> FunctionThunkTemplate {
        let bytes = if language.insn_endian().is_big() {
            [0x02, 0x00, 0x00]
        } else {
            [0x80, 0x00, 0x00]
        };
        FunctionThunkTemplate::new(bytes)
    }
}

impl XTENSA {
    pub fn new() -> Box<dyn ErasedArch> {
        Box::new(XTENSA)
    }
}

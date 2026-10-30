use fugue::lifter::runtime::language::Language;

use super::{register_var, Arch, ErasedArch, FunctionThunkTemplate};
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
                register_var(language, "a0")?,
                register_var(language, "a1")?,
                register_var(language, "a2")?,
                register_var(language, "a3")?,
                register_var(language, "a4")?,
                register_var(language, "a5")?,
                register_var(language, "a6")?,
                register_var(language, "a7")?,
                register_var(language, "a8")?,
                register_var(language, "a9")?,
                register_var(language, "a10")?,
                register_var(language, "a11")?,
                register_var(language, "a12")?,
                register_var(language, "a13")?,
                register_var(language, "a14")?,
                register_var(language, "a15")?,
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

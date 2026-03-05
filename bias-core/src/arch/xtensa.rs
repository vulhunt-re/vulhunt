use fugue::ir::Translator;

use super::{Arch, ErasedArch, FunctionThunkTemplate};
use crate::ir::Var;
use crate::kb::{uuid, Uuid};
use crate::lifter::TranslatorExt;

#[derive(Copy, Clone, Default)]
pub struct XTENSA;

pub const ARCH_XTENSA: Uuid = uuid("0224FD9A-D378-4CF7-8D78-E95C1E90359E");

impl Arch for XTENSA {
    fn id(&self) -> Uuid {
        ARCH_XTENSA
    }

    fn gprs(&self, translator: &Translator) -> Vec<Var> {
        || -> Option<Vec<Var>> {
            Some(vec![
                translator.register_var("a0")?,
                translator.register_var("a1")?,
                translator.register_var("a2")?,
                translator.register_var("a3")?,
                translator.register_var("a4")?,
                translator.register_var("a5")?,
                translator.register_var("a6")?,
                translator.register_var("a7")?,
                translator.register_var("a8")?,
                translator.register_var("a9")?,
                translator.register_var("a10")?,
                translator.register_var("a11")?,
                translator.register_var("a12")?,
                translator.register_var("a13")?,
                translator.register_var("a14")?,
                translator.register_var("a15")?,
            ])
        }()
        .unwrap_or_default()
    }

    fn external_thunk_template(&self, translator: &Translator) -> FunctionThunkTemplate {
        let bytes = if translator.architecture().is_big() {
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

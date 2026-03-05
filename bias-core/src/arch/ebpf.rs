use fugue::ir::Translator;

use super::{Arch, ErasedArch, FunctionThunkTemplate};
use crate::ir::{Expr, Term};
use crate::kb::{uuid, Uuid};

#[derive(Copy, Clone, Default)]
pub struct EBPF;

pub const ARCH_EBPF: Uuid = uuid("EF2FE7BD-3AAA-4179-A11F-872F28F0044C");

impl Arch for EBPF {
    fn id(&self) -> Uuid {
        ARCH_EBPF
    }

    fn is_service_call(&self, name: &'static str, _args: &[Term<Expr>]) -> bool {
        name == "bpf_syscall"
    }

    fn external_thunk_template(&self, _translator: &Translator) -> FunctionThunkTemplate {
        FunctionThunkTemplate::new([0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    }
}

impl EBPF {
    pub fn new() -> Box<dyn ErasedArch> {
        Box::new(EBPF)
    }
}

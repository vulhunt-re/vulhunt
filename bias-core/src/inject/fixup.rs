use std::fmt;
use std::sync::Arc;

use fugue::sleigh::semantics::{IRBuilder, IRBuilderError};
use ouroboros::self_referencing;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use thiserror::Error;

use crate::ir::insn::IntraInsnCFG;
use crate::ir::{Address, Insn, Stmt, Term};
use crate::kb::Ustr;
use crate::lifter::Lifter;

#[self_referencing]
struct InjectionFixupImpl {
    insn: Insn,
    #[borrows(insn)]
    #[covariant]
    iicfg: IntraInsnCFG<'this>,
}

impl fmt::Debug for InjectionFixupImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InjectionFixupImpl")
            .field("insn", self.borrow_insn() as &dyn fmt::Debug)
            .finish_non_exhaustive()
    }
}

impl<'de> Deserialize<'de> for InjectionFixupImpl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let insn = Insn::deserialize(deserializer)?;
        Ok(Self::new(insn, |insn| {
            let (_, iicfg) = insn.local_cfg();
            iicfg
        }))
    }
}

impl Serialize for InjectionFixupImpl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.borrow_insn().serialize(serializer)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InjectionFixup {
    fixup: Arc<InjectionFixupImpl>,
    name: Ustr,
    shift: i64,
}

#[derive(Debug, Error)]
pub enum InjectionFixupError {
    #[error(transparent)]
    Build(#[from] IRBuilderError),
}

impl InjectionFixup {
    pub fn new(
        lifter: &Lifter,
        name: impl Into<Ustr>,
        input: impl AsRef<str>,
        shift: i64,
    ) -> Result<Self, InjectionFixupError> {
        let language = lifter.language();

        let pcode = IRBuilder::new(language).translate(&mut language.builder(), input)?;

        let operations =
            Stmt::from_pcode(language, lifter.float_kinds(), Address::from(0u32), &pcode)
                .collect::<SmallVec<_>>();

        let insn = Insn::from_parts(0u32, operations);

        Ok(Self {
            name: name.into(),
            fixup: Arc::new(InjectionFixupImpl::new(insn, |insn| {
                let (_, iicfg) = insn.local_cfg();
                iicfg
            })),
            shift,
        })
    }

    pub fn name(&self) -> Ustr {
        self.name
    }

    pub fn operations(&self) -> &[Term<Stmt>] {
        self.fixup.borrow_insn().operations()
    }

    pub fn iicfg(&self) -> &IntraInsnCFG<'_> {
        self.fixup.borrow_iicfg()
    }

    pub fn shift(&self) -> i64 {
        self.shift
    }
}

use std::collections::BTreeMap;

use ahash::AHashMap;
use serde::{Deserialize, Serialize};

use crate::ir::{Address, BitSize, BitVec, Var};
use crate::kb::function::FunctionId;

pub mod externs;
pub use externs::ExternalFunction;

pub mod fixup;
pub use fixup::{InjectionFixup, InjectionFixupError};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct InjectionManager {
    values: AHashMap<InjectionOperand, BitVec>,
    function_values: BTreeMap<FunctionId, AHashMap<InjectionOperand, BitVec>>,
    stubs: BTreeMap<FunctionId, InjectionStub>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub enum InjectionOperand {
    Global(Address),
    Register(Var),
}

impl From<Address> for InjectionOperand {
    fn from(value: Address) -> Self {
        Self::Global(value)
    }
}

impl From<Var> for InjectionOperand {
    fn from(var: Var) -> Self {
        assert!(var.is_register());
        Self::Register(var)
    }
}

impl InjectionOperand {
    pub fn global(&self) -> Option<Address> {
        match self {
            Self::Global(addr) => Some(*addr),
            _ => None,
        }
    }

    pub fn register(&self) -> Option<Var> {
        match self {
            Self::Register(var) => Some(*var),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum InjectionStub {
    Extern(ExternalFunction),
    Fixup(InjectionFixup),
    Redirect(Address),
}

impl From<ExternalFunction> for InjectionStub {
    fn from(value: ExternalFunction) -> Self {
        Self::Extern(value)
    }
}

impl From<InjectionFixup> for InjectionStub {
    fn from(value: InjectionFixup) -> Self {
        Self::Fixup(value)
    }
}

impl From<Address> for InjectionStub {
    fn from(value: Address) -> Self {
        Self::Redirect(value)
    }
}

impl InjectionStub {
    pub fn external(&self) -> Option<&ExternalFunction> {
        match self {
            Self::Extern(f) => Some(f),
            _ => None,
        }
    }

    pub fn fixup(&self) -> Option<&InjectionFixup> {
        match self {
            Self::Fixup(fixup) => Some(fixup),
            _ => None,
        }
    }

    pub fn redirect(&self) -> Option<Address> {
        match self {
            Self::Redirect(addr) => Some(*addr),
            _ => None,
        }
    }
}

impl InjectionManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_function_stub(&mut self, fid: FunctionId, stub: impl Into<InjectionStub>) {
        self.stubs.insert(fid, stub.into());
    }

    pub fn get_function_stub(&self, fid: FunctionId) -> Option<&InjectionStub> {
        self.stubs.get(&fid)
    }

    pub fn fixups(&self) -> impl Iterator<Item = (FunctionId, &InjectionFixup)> {
        self.stubs
            .iter()
            .filter_map(|(fid, stub)| Some((*fid, stub.fixup()?)))
    }

    fn fix_value(opnd: &InjectionOperand, val: impl Into<BitVec>) -> BitVec {
        if let InjectionOperand::Register(var) = opnd {
            assert!(var.is_register());
            let mut val = val.into();
            let nbits = var.nbits();
            if nbits != val.nbits() {
                val.cast_assign(nbits as usize);
            }
            val
        } else {
            val.into()
        }
    }

    pub fn set_global_value(
        &mut self,
        operand: impl Into<InjectionOperand>,
        value: impl Into<BitVec>,
    ) {
        let operand = operand.into();
        let value = Self::fix_value(&operand, value);

        self.values.insert(operand, value);
    }

    pub fn set_function_value(
        &mut self,
        fid: FunctionId,
        operand: impl Into<InjectionOperand>,
        value: impl Into<BitVec>,
    ) {
        let operand = operand.into();
        let value = Self::fix_value(&operand, value);

        self.function_values
            .entry(fid)
            .or_default()
            .insert(operand, value);
    }

    pub fn global_values(&self) -> impl ExactSizeIterator<Item = (&InjectionOperand, &BitVec)> {
        self.values.iter()
    }

    pub fn function_values(
        &self,
        fid: FunctionId,
    ) -> impl Iterator<Item = (&InjectionOperand, &BitVec)> {
        self.function_values.get(&fid).into_iter().flatten()
    }

    pub fn has_stubs(&self) -> bool {
        !self.stubs.is_empty()
    }

    pub fn has_overrides(&self) -> bool {
        !self.values.is_empty() && !self.function_values.is_empty()
    }
}

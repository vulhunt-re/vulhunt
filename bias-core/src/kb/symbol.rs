use fugue::ir::Address;
use ustr::Ustr;

use crate::kb::function::{Function, FunctionId};
use crate::kb::function_summary::{FunctionSummary, FunctionSummaryId};
use crate::kb::id::Identifiable;

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum SymbolRef {
    External(FunctionSummaryId),
    Function(FunctionId),
    Variable(Address),
}

impl From<FunctionId> for SymbolRef {
    fn from(f: FunctionId) -> Self {
        Self::Function(f)
    }
}

impl From<&'_ Function> for SymbolRef {
    fn from(f: &'_ Function) -> Self {
        Self::Function(f.id())
    }
}

impl From<FunctionSummaryId> for SymbolRef {
    fn from(f: FunctionSummaryId) -> Self {
        Self::External(f)
    }
}

impl From<&'_ FunctionSummary> for SymbolRef {
    fn from(f: &'_ FunctionSummary) -> Self {
        Self::External(f.id())
    }
}

impl From<Address> for SymbolRef {
    fn from(addr: Address) -> Self {
        Self::Variable(addr)
    }
}

impl SymbolRef {
    pub fn external(id: FunctionSummaryId) -> Self {
        Self::External(id)
    }

    pub fn function(id: FunctionId) -> Self {
        Self::Function(id)
    }

    pub fn variable(address: Address) -> Self {
        Self::Variable(address)
    }

    pub fn is_external(&self) -> bool {
        matches!(self, Self::External(_))
    }

    pub fn get_external(&self) -> Option<FunctionSummaryId> {
        if let Self::External(id) = self {
            Some(*id)
        } else {
            None
        }
    }

    pub fn is_function(&self) -> bool {
        matches!(self, Self::Function(_))
    }

    pub fn get_function(&self) -> Option<FunctionId> {
        if let Self::Function(id) = self {
            Some(*id)
        } else {
            None
        }
    }

    pub fn is_variable(&self) -> bool {
        matches!(self, Self::Variable(_))
    }

    pub fn get_variable(&self) -> Option<Address> {
        if let Self::Variable(addr) = self {
            Some(*addr)
        } else {
            None
        }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Symbol {
    symbol: Ustr,
    referent: SymbolRef,
}

impl Symbol {
    pub fn new<S>(symbol: S, referent: SymbolRef) -> Self
    where
        S: Into<Ustr>,
    {
        Self {
            symbol: symbol.into(),
            referent,
        }
    }

    pub fn external<S>(symbol: S, external: FunctionSummaryId) -> Self
    where
        S: Into<Ustr>,
    {
        Self::new(symbol, SymbolRef::External(external))
    }

    pub fn function<S>(symbol: S, function: FunctionId) -> Self
    where
        S: Into<Ustr>,
    {
        Self::new(symbol, SymbolRef::Function(function))
    }

    pub fn variable<S>(symbol: S, address: Address) -> Self
    where
        S: Into<Ustr>,
    {
        Self::new(symbol, SymbolRef::Variable(address))
    }

    pub fn referent(&self) -> &SymbolRef {
        &self.referent
    }

    pub fn symbol(&self) -> Ustr {
        self.symbol
    }
}

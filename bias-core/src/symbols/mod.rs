use thiserror::Error;
use ustr::{Ustr, UstrMap};

use crate::kb::function::FunctionId;
use crate::kb::symbol::{Symbol, SymbolRef};
use crate::kb::{uuid, Uuid};
use crate::project::analysis::AnalysisError;
use crate::Project;

pub mod pdb;

#[derive(Debug, Default, Clone, serde::Deserialize, serde::Serialize)]
pub struct SymbolTable {
    symbol_to_ref: UstrMap<SymbolRef>,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert<N, R>(&mut self, name: N, info: R)
    where
        N: Into<Ustr>,
        R: Into<SymbolRef>,
    {
        self.symbol_to_ref.insert(name.into(), info.into());
    }

    pub fn insert_fresh_with_prefix<N, R>(&mut self, base_name: N, info: R) -> Ustr
    where
        N: AsRef<str>,
        R: Into<SymbolRef>,
    {
        let base_name = base_name.as_ref();
        let info = info.into();

        match self.lookup(base_name) {
            None => {
                // just insert it
                let base_name = Ustr::from(base_name);
                self.symbol_to_ref.insert(base_name, info.into());
                return base_name;
            }
            Some(curr) => {
                if info == *curr.referent() {
                    // it's the same...
                    return base_name.into();
                }
            }
        }

        let mut i = 0u32;
        let mut proposed = Ustr::from(&format!("{base_name}{i}"));
        while self.contains(&proposed) {
            i += 1;
            proposed = Ustr::from(&format!("{base_name}{i}"));
        }

        self.symbol_to_ref.insert(proposed, info.into());

        proposed
    }

    pub fn insert_fresh_with_prefix_or_rebind<N, R>(&mut self, base_name: N, info: R) -> Ustr
    where
        N: AsRef<str>,
        R: Into<SymbolRef>,
    {
        let base_name = base_name.as_ref();
        let info = info.into();

        if let Some((imp_sym, sym)) = base_name.strip_prefix("imp.").and_then(|imp_name| {
            self.lookup(imp_name)
                .and_then(|imp_sym| self.lookup(base_name).map(|sym| (imp_sym, sym)))
        }) {
            if imp_sym.referent() == sym.referent() {
                // rebind
                let name = Ustr::from(base_name);
                self.symbol_to_ref.insert(name, info);
                return name;
            }
        }

        self.insert_fresh_with_prefix(base_name, info)
    }

    pub fn contains<S>(&self, name: S) -> bool
    where
        S: AsRef<str>,
    {
        let name = name.as_ref();
        if let Some(name) = ustr::existing_ustr(name) {
            self.symbol_to_ref.contains_key(&name)
        } else {
            false
        }
    }

    pub fn lookup<S>(&self, name: S) -> Option<Symbol>
    where
        S: AsRef<str>,
    {
        let name = name.as_ref();
        if let Some(name) = ustr::existing_ustr(name) {
            self.symbol_to_ref
                .get(&name)
                .map(|referent| Symbol::new(name, *referent))
        } else {
            None
        }
    }

    pub fn lookup_function<S>(&self, name: S) -> Option<FunctionId>
    where
        S: AsRef<str>,
    {
        self.lookup(name)
            .and_then(|sym| sym.referent().get_function())
    }

    pub fn rebind(
        &mut self,
        old_name: impl Into<Option<Ustr>>,
        new_name: impl Into<Ustr>,
        new_ref: impl Into<SymbolRef>,
    ) {
        let old_name = old_name.into();
        let new_name = new_name.into();
        let new_ref = new_ref.into();

        if let Some(old_name) = old_name {
            self.symbol_to_ref.remove(&old_name);
        }

        self.symbol_to_ref.insert(new_name, new_ref);
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = (Ustr, &SymbolRef)> {
        self.symbol_to_ref.iter().map(|(&k, v)| (k, v))
    }
}

#[derive(Debug, Error)]
pub enum SymboliseError {
    #[error("could not apply symbols to project: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

pub const SYMBOLISATION_ANALYSIS: Uuid = uuid("BD830EE6-E3E0-4E76-970E-F6012D0B6766");

impl SymboliseError {
    pub fn other<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Other(Box::new(e))
    }
}

impl From<SymboliseError> for AnalysisError {
    fn from(e: SymboliseError) -> Self {
        AnalysisError::Analysis(SYMBOLISATION_ANALYSIS, Box::new(e))
    }
}

pub trait Symbolise {
    fn apply_symbols(&self, target: &mut Project) -> Result<(), SymboliseError>;
}

use std::ops::Deref;

use bias_core::analyses::blocks::CodeBlockBounds;
use bias_core::ir::Address;
use bias_core::kb::AHashMap;
use bias_core::prelude::{Function, Identifiable as _};
use bias_core::Project;

use bias_compat_fwhunt::code::Code;
use bias_compat_fwhunt::{bmatch, MatchContext, MatchesRule as _};

use bias::platform::common::flirt::FunctionSymbolMapping;

use itertools::Itertools as _;
use regex::Regex;
use serde::Deserialize;
use thiserror::Error;
use ustr::Ustr;

use crate::lua::api::AddressValue;

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize)]
pub enum FuzzyMatchKind {
    #[serde(rename = "bytes")]
    Bytes,
    #[default]
    #[serde(rename = "symbol", alias = "name")]
    Symbol,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FuzzyMatch {
    matching: String,
    #[serde(default)]
    kind: FuzzyMatchKind,
}

impl FuzzyMatch {
    pub fn targets<'a>(
        &self,
        project: &'a Project,
        symbols: impl Into<Option<&'a FunctionSymbolMapping>>,
    ) -> Result<Vec<&'a Function>, FunctionQueryError> {
        match self.kind {
            FuzzyMatchKind::Bytes => Self::targets_by_bytes(&self.matching, project),
            FuzzyMatchKind::Symbol => Self::targets_by_symbol(&self.matching, project, symbols),
        }
    }

    fn targets_by_bytes<'a>(
        pattern: &str,
        project: &'a Project,
    ) -> Result<Vec<&'a Function>, FunctionQueryError> {
        let searcher = Code::from_pattern(pattern)?;
        let pattern_length = searcher.pattern().len();

        if pattern_length == 0 {
            return Err(FunctionQueryError::PatternLength);
        }

        let mut context = MatchContext::new();
        let checkpoint = context.begin(&searcher);
        let result = searcher.matches_rule(&mut context, project);
        context.commit(checkpoint);

        if result {
            let bounds = project.get_analysis::<CodeBlockBounds>();

            return Ok(context
                .explain()
                .filter_map(|(addr, _)| {
                    // NOTE: this matches any function overlapping, so we check the bounds
                    let last_addr = addr + searcher.pattern().len() - 1usize;

                    let fid1 = bounds
                        .get(addr)
                        .map(|(_, &bid)| project.code_blocks()[bid].function())?;

                    let fid2 = bounds
                        .get(last_addr)
                        .map(|(_, &bid)| project.code_blocks()[bid].function())?;

                    if fid1 == fid2 {
                        Some(&project.functions()[fid1])
                    } else {
                        None
                    }
                })
                .collect());
        }

        Ok(Vec::new())
    }

    fn targets_by_symbol<'a>(
        regex: &str,
        project: &'a Project,
        symbols: impl Into<Option<&'a FunctionSymbolMapping>>,
    ) -> Result<Vec<&'a Function>, FunctionQueryError> {
        let regex = Regex::new(regex)?;
        let symbols = symbols.into();

        let mut map = AHashMap::from_iter(
            project
                .functions()
                .values()
                .filter(|f| f.name().is_some_and(|name| regex.is_match(name.as_str())))
                .map(|f| (f.id(), f)),
        );

        if let Some(symbols) = symbols {
            map.extend(symbols.symbol_mapping().iter().filter_map(|(name, &fid)| {
                regex
                    .is_match(name.as_str())
                    .then_some((fid, &project.functions()[fid]))
            }));
        }

        Ok(map.into_values().collect::<Vec<_>>())
    }
}

#[derive(Debug, Error)]
pub enum FunctionQueryError {
    #[error("cannot create pattern: {0}")]
    Pattern(#[from] bmatch::Error),
    #[error("pattern length must be > 1")]
    PatternLength,
    #[error("cannot build regex: {0}")]
    Regex(#[from] regex::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize)]
#[serde(deny_unknown_fields)]
#[repr(transparent)]
pub struct NamedTarget {
    named: String,
}

impl From<String> for NamedTarget {
    fn from(named: String) -> Self {
        Self { named }
    }
}

impl Deref for NamedTarget {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.named
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize)]
#[serde(deny_unknown_fields)]
#[repr(transparent)]
pub struct AddressTarget {
    #[serde(with = "::serde_with::As::<::serde_with::FromInto::<AddressValue>>")]
    address: Address,
}

impl From<Address> for AddressTarget {
    fn from(address: Address) -> Self {
        Self { address }
    }
}

impl Deref for AddressTarget {
    type Target = Address;

    fn deref(&self) -> &Self::Target {
        &self.address
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize)]
#[serde(untagged)]
pub enum FunctionQueryTarget {
    Address(AddressTarget),
    Symbol(NamedTarget),
    Fuzzy(FuzzyMatch),
}

impl TryFrom<FunctionQuery> for FunctionQueryTarget {
    type Error = &'static str;

    fn try_from(query: FunctionQuery) -> Result<Self, Self::Error> {
        match query {
            FunctionQuery::Address(addr) => Ok(FunctionQueryTarget::Address(addr.into())),
            FunctionQuery::Symbol(name) => Ok(FunctionQueryTarget::Symbol(name.into())),
            FunctionQuery::Fuzzy(fuzzy) => Ok(FunctionQueryTarget::Fuzzy(fuzzy)),
            FunctionQuery::WithOptions(_) => Err("options not allowed"),
        }
    }
}

impl FunctionQueryTarget {
    pub fn targets<'a>(
        &self,
        project: &'a Project,
        symbols: impl Into<Option<&'a FunctionSymbolMapping>>,
    ) -> Result<Vec<&'a Function>, FunctionQueryError> {
        self.targets_with(project, symbols, false)
    }

    pub fn targets_with<'a>(
        &self,
        project: &'a Project,
        symbols: impl Into<Option<&'a FunctionSymbolMapping>>,
        imp: bool,
    ) -> Result<Vec<&'a Function>, FunctionQueryError> {
        Ok(match &self {
            Self::Address(addr) => Self::target_by_address(**addr, project)
                .map(|t| vec![t])
                .unwrap_or_default(),
            Self::Symbol(name) => {
                if imp {
                    Self::targets_by_symbol(name, project, symbols)
                } else {
                    Self::target_by_symbol(name, project, symbols)
                        .map(|t| vec![t])
                        .unwrap_or_default()
                }
            }
            Self::Fuzzy(fuzzy) => Self::targets_by_fuzzy(fuzzy, project, symbols)?,
        })
    }

    pub fn target_by_address(addr: Address, project: &Project) -> Option<&Function> {
        project.function_at(addr)
    }

    pub fn target_by_symbol<'a>(
        name: &str,
        project: &'a Project,
        symbols: impl Into<Option<&'a FunctionSymbolMapping>>,
    ) -> Option<&'a Function> {
        let Some(name) = Ustr::from_existing(&name) else {
            return None;
        };

        let symbols = symbols.into();

        project.function_named(name).or_else(|| {
            symbols
                .and_then(|s| s.symbol_mapping().get(&name))
                .copied()
                .map(|fid| &project.functions()[fid])
        })
    }

    pub fn targets_by_symbol<'a>(
        name: &str,
        project: &'a Project,
        symbols: impl Into<Option<&'a FunctionSymbolMapping>>,
    ) -> Vec<&'a Function> {
        let symbols = symbols.into();

        let named_function = |to: &str| -> Option<&Function> {
            ustr::existing_ustr(to).and_then(|to| {
                // First check the symbol table, then the FLIRT mapping; it's not clear
                // what we should do in the case where we have a name for the function in
                // `project`, but a different name from FLIRT... I suspect we should only
                // apply FLIRT to unnamed functions (default behaviour).
                //
                project.function_named(to).or_else(|| {
                    symbols
                        .and_then(|s| s.symbol_mapping().get(&to))
                        .copied()
                        .map(|fid| &project.functions()[fid])
                })
            })
        };

        let exact = named_function(name);
        let alternate = if let Some(stripped) = name.strip_prefix("imp.") {
            named_function(stripped)
        } else {
            named_function(compact_str::format_compact!("imp.{name}").as_str())
        };

        [exact, alternate]
            .into_iter()
            .filter_map(|f| f)
            .unique_by(|f| f.id())
            .collect::<Vec<_>>()
    }

    fn targets_by_fuzzy<'a>(
        fuzzy: &FuzzyMatch,
        project: &'a Project,
        symbols: impl Into<Option<&'a FunctionSymbolMapping>>,
    ) -> Result<Vec<&'a Function>, FunctionQueryError> {
        fuzzy.targets(project, symbols)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize)]
pub struct FunctionQueryOpts {
    #[serde(flatten)]
    query: FunctionQueryTarget,
    #[serde(default)]
    all: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize)]
#[serde(untagged)]
pub enum FunctionQuery {
    #[serde(with = "::serde_with::As::<::serde_with::FromInto::<AddressValue>>")]
    Address(Address),
    Symbol(String),
    Fuzzy(FuzzyMatch),
    WithOptions(FunctionQueryOpts),
}

impl FunctionQuery {
    pub fn into_parts(self) -> (FunctionQueryTarget, bool) {
        match self {
            Self::Address(addr) => (FunctionQueryTarget::Address(addr.into()), false),
            Self::Symbol(s) => (FunctionQueryTarget::Symbol(s.into()), false),
            Self::Fuzzy(fm) => (FunctionQueryTarget::Fuzzy(fm), false),
            Self::WithOptions(opts) => (opts.query, opts.all),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize)]
pub struct FunctionQueryCallOpts {
    #[serde(flatten)]
    pub(crate) to: FunctionQueryTarget,
    #[serde(default)]
    pub(crate) jumps_as_calls: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize)]
#[serde(untagged)]
pub enum CallsToQuery {
    #[serde(with = "::serde_with::As::<::serde_with::FromInto::<AddressValue>>")]
    Address(Address),
    Symbol(String),
    Fuzzy(FuzzyMatch),
    WithOptions(FunctionQueryCallOpts),
}

impl CallsToQuery {
    pub fn targets<'a>(
        &self,
        project: &'a Project,
        symbols: impl Into<Option<&'a FunctionSymbolMapping>>,
    ) -> Result<(Vec<&'a Function>, bool), FunctionQueryError> {
        self.targets_with(project, symbols, false)
    }

    pub fn targets_with<'a>(
        &self,
        project: &'a Project,
        symbols: impl Into<Option<&'a FunctionSymbolMapping>>,
        imp: bool,
    ) -> Result<(Vec<&'a Function>, bool), FunctionQueryError> {
        Ok(match &self {
            Self::Address(addr) => {
                let target = FunctionQueryTarget::target_by_address(*addr, project)
                    .map(|f| vec![f])
                    .unwrap_or_default();

                (target, false)
            }
            Self::Symbol(name) => {
                let targets = if imp {
                    FunctionQueryTarget::targets_by_symbol(name, project, symbols)
                } else {
                    FunctionQueryTarget::target_by_symbol(name, project, symbols)
                        .map(|f| vec![f])
                        .unwrap_or_default()
                };

                (targets, false)
            }
            Self::Fuzzy(fuzzy) => (fuzzy.targets(project, symbols)?, false),
            Self::WithOptions(FunctionQueryCallOpts { to, jumps_as_calls }) => {
                let targets = if imp {
                    to.targets_with(project, symbols, true)?
                } else {
                    to.targets(project, symbols)?
                };

                (targets, *jumps_as_calls)
            }
        })
    }
}

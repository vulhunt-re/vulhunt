use std::collections::{BTreeSet, HashMap, HashSet};

use regex::Regex;
pub use tree_sitter::Tree;
pub use weggli::result::{CaptureResult, QueryResult};
use weggli::RegexMap;

use crate::analyses::stack::StackAccess;
use crate::decompiler::annotation::DecompilerAnnotationDB;
use crate::decompiler::ffi::HighVarWithType;
pub use crate::decompiler::ffi::{JumpTableInfo, LoadTableInfo};
use crate::decompiler::types::{DataTypeRef, SpaceKind};
use crate::decompiler::DecompilerError;
use crate::prelude::*;

#[derive(Debug, Clone)]
pub struct DecompilerAst {
    tree: Tree,
    annotations: DecompilerAnnotationDB,
    tables: Vec<JumpTableInfo>,
    parameters: Vec<String>,
    variables: BTreeSet<HighVarInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HighVarInfo {
    name: String,
    addr: u64,
    space: SpaceKind,
    offset: u64,
    size: u32,
    type_: Option<Term<Type>>,
}

impl HighVarInfo {
    pub(crate) fn new(var: HighVarWithType, tdb: &TypeDB, bits: u32) -> HighVarInfo {
        Self {
            name: var.name,
            addr: var.addr,
            space: var.space,
            offset: var.offset,
            size: var.size,
            type_: DataTypeRef::new(var.type_)
                .map(|t| t.to_type(tdb, bits).ok())
                .flatten(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct HighVarRef<'a>(&'a HighVarInfo);

impl<'a> HighVarRef<'a> {
    pub fn name(&self) -> &str {
        &self.0.name
    }

    pub fn reference_address(&self) -> Address {
        self.0.addr.into()
    }

    pub fn is_temporary(&self) -> bool {
        self.0.space == SpaceKind::Unique
    }

    pub fn is_stack(&self) -> bool {
        self.0.space == SpaceKind::Stack
    }

    pub fn is_global(&self) -> bool {
        self.0.space == SpaceKind::Global
    }

    pub fn is_register(&self) -> bool {
        self.0.space == SpaceKind::Register
    }

    pub fn stack_variable(&self) -> Option<StackAccess> {
        if self.is_stack() {
            Some(StackAccess::new(self.offset(), self.nbytes()))
        } else {
            None
        }
    }

    pub fn variable(&self, lifter: &Lifter) -> Option<Var> {
        match self.0.space {
            SpaceKind::Register => {
                if lifter
                    .translator()
                    .registers()
                    .get(self.0.offset, self.0.size as _)
                    .is_some()
                {
                    Some(Var::new0(
                        lifter.register_space(),
                        self.0.offset,
                        self.nbits(),
                    ))
                } else {
                    None
                }
            }
            SpaceKind::Unique => Some(Var::new0(
                lifter.temporary_space(),
                self.0.offset,
                self.nbits(),
            )),
            _ => None,
        }
    }

    pub fn offset(&self) -> i64 {
        self.0.offset as i64
    }

    pub fn type_(&self) -> Option<&Term<Type>> {
        self.0.type_.as_ref()
    }

    pub fn nbytes(&self) -> usize {
        self.0.size as _
    }
}

impl<'a> BitSize for HighVarRef<'a> {
    fn nbits(&self) -> u32 {
        self.0.size * 8
    }
}

impl<'a> ToAddress for HighVarRef<'a> {
    fn to_address(&self) -> Option<Address> {
        if self.is_global() {
            Some(self.0.offset.into())
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct JumpTable<'a>(&'a JumpTableInfo);

impl<'a> JumpTable<'a> {
    pub fn branch(&self) -> Address {
        self.0.branch.into()
    }

    pub fn entries<'b>(&'b self) -> impl ExactSizeIterator<Item = Address> + 'b {
        self.0.targets.iter().copied().map(Address::from)
    }
}

impl DecompilerAst {
    pub(crate) fn new(
        annotations: DecompilerAnnotationDB,
        tables: Vec<JumpTableInfo>,
        parameters: Vec<String>,
        variables: Vec<HighVarInfo>,
    ) -> Result<Self, DecompilerError> {
        Ok(Self {
            tree: weggli::parse(annotations.source(), false).map_err(DecompilerError::ParseAst)?,
            annotations,
            tables,
            parameters,
            variables: variables.into_iter().collect(),
        })
    }

    pub fn annotations(&self) -> &DecompilerAnnotationDB {
        &self.annotations
    }

    pub fn tree(&self) -> &Tree {
        &self.tree
    }

    pub fn source(&self) -> &str {
        self.annotations.source()
    }

    pub fn jump_tables<'b>(&'b self) -> impl ExactSizeIterator<Item = JumpTable<'b>> + 'b {
        self.tables.iter().map(JumpTable)
    }

    pub fn parameters<'b>(&'b self) -> impl ExactSizeIterator<Item = &'b str> + 'b {
        self.parameters.iter().map(|v| v.as_ref())
    }

    pub fn variables<'b>(&'b self) -> impl ExactSizeIterator<Item = HighVarRef<'b>> {
        self.variables.iter().map(HighVarRef)
    }

    pub fn query(&self, query: impl AsRef<str>) -> Result<Vec<QueryResult>, DecompilerError> {
        self.query_with(query, None, None)
    }

    pub fn query_with(
        &self,
        query: impl AsRef<str>,
        unique: impl Into<Option<bool>>,
        regexes: impl Into<Option<Vec<String>>>,
    ) -> Result<Vec<QueryResult>, DecompilerError> {
        let unique = unique.into().unwrap_or_default();
        let regexes = regexes.into().map(|r| process_regexes(&r)).transpose()?;

        let query = query.as_ref();
        let parsed_query = weggli::parse(query, false).map_err(DecompilerError::QueryAst)?;

        let mut query_context = parsed_query.walk();
        let query_tree =
            weggli::builder::build_query_tree(query, &mut query_context, false, regexes)
                .map_err(DecompilerError::QueryAst)?;

        let matches = query_tree.matches(self.tree.root_node(), self.source());

        let results = if unique {
            // Taken from https://github.com/weggli-rs/weggli/blob/bb45066004d281268b5408655df4978b7d921acd/src/main.rs#L352
            let check_unique = |m: &QueryResult| {
                let mut seen = HashSet::new();
                m.vars
                    .keys()
                    .map(|k| m.value(k, self.source()).unwrap())
                    .all(|x| seen.insert(x))
            };

            matches.into_iter().filter(check_unique).collect()
        } else {
            matches
        };

        Ok(results)
    }
}

// Taken from https://github.com/weggli-rs/weggli/blob/bb45066004d281268b5408655df4978b7d921acd/src/main.rs#L210
fn process_regexes(regexes: &[String]) -> Result<RegexMap, DecompilerError> {
    let mut result = HashMap::new();

    for r in regexes {
        let mut s = r.splitn(2, '=');
        let var = s
            .next()
            .ok_or_else(|| DecompilerError::RegexArg(r.clone()))?;
        let raw_regex = s
            .next()
            .ok_or_else(|| DecompilerError::RegexArg(r.clone()))?;

        let mut normalised_var = if var.starts_with('$') {
            var.to_owned()
        } else {
            format!("${var}")
        };
        let negative = normalised_var.ends_with('!');

        if negative {
            normalised_var.pop(); // remove !
        }

        let regex = Regex::new(raw_regex).map_err(DecompilerError::InvalidRegex)?;
        result.insert(normalised_var, (negative, regex));
    }
    Ok(RegexMap::new(result))
}

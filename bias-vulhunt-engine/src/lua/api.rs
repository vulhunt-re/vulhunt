use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::fmt::Display;
use std::mem;
use std::ops::{Deref, RangeInclusive};
use std::sync::Arc;
use std::time::Duration;

use bias_core::analyses::blocks::CodeBlockBounds;
use bias_core::analyses::symbolic::typed::{AliasOrigin, NamedValue};
use bias_core::ir::insn::InsnText;
use bias_core::prelude::graph::algo::has_path_connecting;
use bias_core::prelude::*;

use bias_core::decompiler::{Decompiler, DecompilerAst, DecompilerConfig};

use bias_compat_fwhunt::code::{Code, CodeLocation};
use bias_compat_fwhunt::{MatchContext, MatchesRule};

use bias_compat_patfind::Pattern;

use bias::pipeline::types::Severity;
use bias::platform::common::flirt::FunctionSymbolMapping;
use bias::platform::common::types::FunctionTypeMapping;
use bias::platform::PlatformAttributes;
use bias::reporting::code::{CodeReport, CodeReportBuilder};

use bias::util::tags::BlobTag;

use itertools::Itertools as _;

use mlua::{
    Error, FromLua, IntoLua, Lua, LuaSerdeExt, MetaMethod, Table, UserData, UserDataFields,
    UserDataMethods, Value, Variadic,
};

use range_set_blaze::RangeSetBlaze;
use regex::Regex;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::analysis::{FindingData, FindingKind, Provenance, VariantData, CVSS, CWE, MBC};
use crate::engine::Engine;
use crate::lua::types::bv::BitVec as LuaBitVec;
use crate::lua::types::ir::IRTerm;
use crate::lua::CallsToQuery;

use super::ctypes::{CDeclarationExtractor, CPrototypeExtractor};
use super::project::{DynamicDecompilerContext, PlatformApi};
use super::source::extract::Extractor;
use super::CheckerError;

pub(crate) const PRELUDE: &'static [u8] = include_bytes!("prelude.lua");
pub(crate) const FUNCTIONAL: &'static [u8] = include_bytes!("fun.lua");

pub type CheckSeverity = Severity;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CheckResult {
    name: String,
    description: String,
    severity: CheckSeverity,
    #[serde(default)]
    evidence: Option<CheckEvidence>,
    #[serde(default)]
    advisory: Option<String>, // URL to advisory
    #[serde(default)]
    patch: Option<String>, // URL to patch
    #[serde(default)]
    source: Option<String>, // URL to source file or repository
    #[serde(default)]
    cvss: Option<CVSS>, // CVSS score
    #[serde(default)]
    cwes: Vec<CWE>, // List of applicable CWEs
    #[serde(default)]
    mbcs: Vec<MBC>, // List of applicable MBC identifiers
    #[serde(default)]
    identifiers: Vec<String>, // List of additional identifiers (BRLY-, GHSA-, ...)
    #[serde(default)]
    provenance: Option<Provenance>, // Provenance information if this is an embedded component
    #[serde(default)]
    variants: BTreeMap<String, VariantData>, // List of variants of this finding
    #[serde(default)]
    references: BTreeMap<String, String>, // Additional references (title, url) pairs
    #[serde(default)]
    notes: BTreeMap<String, String>, // Notes related to this finding
    #[serde(default)]
    kind: FindingKind,
    #[serde(skip)]
    matching_rule: usize,
}

impl CheckResult {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn severity(&self) -> CheckSeverity {
        self.severity
    }

    pub fn evidence(&self) -> Option<&CheckEvidence> {
        self.evidence.as_ref()
    }

    pub fn rule(&self) -> usize {
        self.matching_rule
    }

    pub fn with_rule(mut self, id: usize) -> Self {
        self.set_rule(id);
        self
    }

    pub fn set_rule(&mut self, id: usize) {
        self.matching_rule = id;
    }

    pub fn into_parts(self) -> (String, CheckSeverity, Option<CheckEvidence>, FindingData) {
        (
            self.name,
            self.severity,
            self.evidence,
            FindingData {
                description: self.description,
                advisory: self.advisory,
                patch: self.patch,
                source: self.source,
                cvss: self.cvss,
                cwes: self.cwes,
                mbcs: self.mbcs,
                identifiers: self.identifiers,
                provenance: self.provenance,
                variants: self.variants,
                references: self.references,
                notes: self.notes,
                kind: self.kind,
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, FromLua, Deserialize, Serialize)]
#[repr(transparent)]
pub struct AddressValue {
    #[serde(with = "::serde_with::As::<::serde_with::DisplayFromStr>")]
    value: u64,
}

impl AddressValue {
    pub fn new_ser(lua: &Lua, value: impl Into<u64>) -> Result<Value, Error> {
        let av = AddressValue {
            value: value.into(),
        };
        lua.create_ser_userdata(av).map(Value::UserData)
    }

    pub fn register(lua: &Lua) -> Result<(), Error> {
        lua.globals()
            .set("AddressValue", lua.create_proxy::<Self>()?)?;
        Ok(())
    }

    pub fn value(&self) -> u64 {
        self.value
    }
}

impl From<Address> for AddressValue {
    fn from(value: Address) -> Self {
        Self {
            value: value.offset(),
        }
    }
}

impl From<AddressValue> for Address {
    fn from(value: AddressValue) -> Self {
        Address::from(value.value)
    }
}

impl UserData for AddressValue {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("to_bitvec", |_lua, this, bits: u32| {
            Ok(LuaBitVec::from_u64(this.value, bits))
        });

        methods.add_meta_method(MetaMethod::Eq, |_lua, this, other: AddressValue| {
            Ok(this.value == other.value)
        });
        methods.add_meta_method(MetaMethod::Le, |_lua, this, other: AddressValue| {
            Ok(this.value <= other.value)
        });
        methods.add_meta_method(MetaMethod::Lt, |_lua, this, other: AddressValue| {
            Ok(this.value < other.value)
        });

        methods.add_meta_method(MetaMethod::Add, |_lua, this, other: u64| {
            Ok(AddressValue {
                value: this.value + other,
            })
        });
        methods.add_meta_method(MetaMethod::Sub, |_lua, this, other: u64| {
            Ok(AddressValue {
                value: this.value - other,
            })
        });

        methods.add_meta_method(MetaMethod::ToString, |_lua, this, ()| {
            Ok(Address::from(this.value).to_string())
        });

        methods.add_function("from_integer", |_lua, value: u64| {
            Ok(AddressValue { value })
        });

        methods.add_function("from_string", |_lua, s: String| {
            let s = s
                .strip_prefix("0x")
                .unwrap_or(s.strip_prefix("0X").unwrap_or(&s));

            let value = u64::from_str_radix(s, 16).map_err(|e| {
                Error::RuntimeError(format!("failed to parse AddressValue from string: {e}"))
            })?;

            Ok(AddressValue { value })
        });

        methods.add_function("from_bitvec", |_lua, bv: LuaBitVec| {
            let value = bv.to_u64().ok_or_else(|| {
                Error::RuntimeError(format!(
                    "BitVec value `{:#x}` does not fit into an address",
                    *bv,
                ))
            })?;
            Ok(AddressValue { value })
        });

        methods.add_function("new", |lua, value: Value| match value {
            Value::Integer(i) if i >= 0 => {
                lua.create_ser_userdata(AddressValue { value: i as u64 })
            }
            Value::String(s) => {
                let s = s.to_str()?;
                let s = s
                    .strip_prefix("0x")
                    .unwrap_or(s.strip_prefix("0X").unwrap_or(&s));

                let value = u64::from_str_radix(s, 16).map_err(|e| {
                    Error::RuntimeError(format!("failed to parse AddressValue from string: {e}"))
                })?;

                lua.create_ser_userdata(AddressValue { value })
            }
            Value::UserData(ud) => {
                if let Ok(av) = ud.borrow::<AddressValue>() {
                    return lua.create_ser_userdata(av.clone());
                }

                if let Ok(bv) = ud.borrow::<LuaBitVec>() {
                    let value = bv.to_u64().ok_or_else(|| {
                        Error::RuntimeError(format!(
                            "BitVec value `{:#x}` does not fit into an address",
                            **bv,
                        ))
                    })?;

                    return lua.create_ser_userdata(AddressValue { value });
                }

                Err(Error::RuntimeError(
                    "invalid user data type for AddressValue.new".into(),
                ))
            }
            _ => Err(Error::RuntimeError(
                "invalid argument to AddressValue.new".into(),
            )),
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CheckEvidence {
    #[serde(default)]
    functions: BTreeMap<CheckEvidenceLocation, Vec<CheckCodeAnnotation>>,
    #[serde(default)]
    references: BTreeMap<CheckEvidenceLocation, CheckDataEvidence>,
}

impl CheckEvidence {
    fn function_index(annotation: &CheckCodeAnnotation) -> Option<usize> {
        if let CheckCodeAnnotation::Prototype { index, .. } = annotation {
            Some(*index)
        } else {
            None
        }
    }

    pub fn functions(
        &self,
    ) -> impl ExactSizeIterator<Item = (&CheckEvidenceLocation, &Vec<CheckCodeAnnotation>)> {
        let mut entries = self.functions.iter().collect::<Vec<_>>();
        entries.sort_by_key(|(_, annotations)| {
            annotations
                .iter()
                .find_map(Self::function_index)
                .unwrap_or(usize::MAX)
        });

        entries.into_iter()
    }
}

type CheckEvidenceBuilderKey<'a> = (Option<&'a str>, BlobTag);

pub struct CheckEvidenceBuilders<'a, P>
where
    P: for<'evidence> PlatformApi<'evidence>,
{
    builders: BTreeMap<CheckEvidenceBuilderKey<'a>, CheckEvidenceBuilder<'a>>,
    project: &'a Project,
    decompiler_config: &'a DecompilerConfig,
    attributes: PlatformAttributes<'a>,
    engine: &'a Engine<'a, P>,
}

impl<'a, P> CheckEvidenceBuilders<'a, P>
where
    P: for<'evidence> PlatformApi<'evidence>,
{
    pub fn new(
        project: &'a Project,
        decompiler_config: &'a DecompilerConfig,
        attributes: PlatformAttributes<'a>,
        engine: &'a Engine<'a, P>,
    ) -> Self {
        Self {
            builders: BTreeMap::new(),
            decompiler_config,
            project,
            attributes,
            engine,
        }
    }

    pub fn get_for(&mut self, id: usize) -> Result<&mut CheckEvidenceBuilder<'a>, CheckerError> {
        let checker = self.engine.checker_for(id).ok_or_else(|| {
            CheckerError::decompiler_with("attempt to build decompiler for invalid check result")
        })?;

        let sig_tag = checker
            .signature_arch_tags()
            .get(self.project.lifter().translator().architecture())
            .copied()
            .unwrap_or_default();

        let key = (checker.types(), sig_tag);

        match self.builders.entry(key) {
            Entry::Occupied(eb) => Ok(eb.into_mut()),
            Entry::Vacant(eb) => {
                let sm = self.engine.symbols_for(id);
                let tm = self.engine.types_for(id);

                tracing::trace!(
                    "building new evidence builder for rule {id}; {} types in database",
                    tm.map(|t| t.types().len())
                        .unwrap_or_else(|| self.project.type_db().len()),
                );

                let neb = CheckEvidenceBuilder::new_with::<P>(
                    self.project,
                    self.decompiler_config.to_owned(),
                    &self.attributes,
                    sm,
                    tm,
                )?;
                Ok(eb.insert(neb))
            }
        }
    }
}

pub struct CheckEvidenceBuilder<'a> {
    decompiler: Decompiler<'a>,
    context: DynamicDecompilerContext,
    project: &'a Project,
    symbols: Option<&'a FunctionSymbolMapping>,
    typedb: &'a TypeDB,
    functions: AHashMap<FunctionId, DecompilerAst>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckDecompilationAnnotation {
    message: String,
    ranges: RangeSetBlaze<usize>,
}

impl CheckDecompilationAnnotation {
    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn ranges<'a>(&'a self) -> impl ExactSizeIterator<Item = RangeInclusive<usize>> + 'a {
        self.ranges.ranges()
    }

    pub fn maximal_range(&self) -> Option<RangeInclusive<usize>> {
        let mut it = self.ranges();
        let mut candidate = it.next()?.to_owned();

        for r in it {
            let start = *candidate.start().min(r.start());
            let end = *candidate.end().max(r.end());

            candidate = start..=end;
        }

        Some(candidate)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckDecompilation {
    source: String,
    annotations: Vec<CheckDecompilationAnnotation>,
}

impl CheckDecompilation {
    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn annotations(&self) -> impl ExactSizeIterator<Item = &CheckDecompilationAnnotation> {
        self.annotations.iter()
    }

    pub fn to_report_builder(&self, name: impl Into<String>) -> CodeReportBuilder {
        CodeReportBuilder::new(&self.source)
            .with_issue(name)
            .with_annotations(self.annotations().filter_map(|annot| {
                let range = annot.maximal_range()?;
                Some((range, annot.message()))
            }))
    }

    pub fn to_report(&self, name: impl Into<String>, description: impl Into<String>) -> CodeReport {
        self.to_report_builder(name).into_report(description)
    }
}

impl<'a> CheckEvidenceBuilder<'a> {
    pub fn new<P>(
        project: &'a Project,
        attributes: &PlatformAttributes<'a>,
    ) -> Result<Self, CheckerError>
    where
        P: for<'evidence> PlatformApi<'evidence>,
    {
        Self::new_with::<P>(project, DecompilerConfig::default(), attributes, None, None)
    }

    pub fn new_with<P>(
        project: &'a Project,
        decompiler_config: DecompilerConfig,
        attributes: &PlatformAttributes<'a>,
        symbol_mapping: impl Into<Option<&'a FunctionSymbolMapping>>,
        type_mapping: impl Into<Option<&'a FunctionTypeMapping>>,
    ) -> Result<Self, CheckerError>
    where
        P: for<'evidence> PlatformApi<'evidence>,
    {
        let symbols = symbol_mapping.into();
        let type_mapping = type_mapping.into();

        let (decompiler, context) = P::decompiler(
            project,
            decompiler_config,
            attributes,
            symbols,
            type_mapping,
        )?;
        let typedb = type_mapping.map(|t| t.types()).unwrap_or(project.type_db());

        Ok(Self {
            decompiler,
            context,
            project,
            symbols,
            typedb,
            functions: Default::default(),
        })
    }

    pub fn resolve_function(&self, evidence: &CheckEvidenceLocation) -> Option<&'a Function> {
        match evidence {
            CheckEvidenceLocation::Address(addr) => self.project.function_at(*addr),
            CheckEvidenceLocation::Symbol(sym) => {
                let sym = Ustr::from_existing(sym)?;
                let fid = if let Some(syms) = self.symbols {
                    syms.symbol_mapping().get(&sym).copied()?
                } else {
                    self.project
                        .symbols()
                        .lookup(sym)
                        .and_then(|sym| sym.referent().get_function())?
                };
                self.project.functions().get(fid)
            }
        }
    }

    pub fn decompile_with(
        &mut self,
        evidence: &CheckEvidenceLocation,
        annotations: &[CheckCodeAnnotation],
        timeout: impl Into<Option<Duration>>,
    ) -> Result<CheckDecompilation, CheckerError> {
        use std::collections::hash_map::Entry;

        let Some(fcn) = self.resolve_function(evidence) else {
            return Err(CheckerError::decompiler_with(format!(
                "function {evidence} could not be decompiled"
            )))?;
        };

        let mut fresh = false;
        let mut extractor = Extractor::new_with(CPrototypeExtractor::new_with(
            self.typedb,
            self.project.lifter().address_bits(),
        ))
        .map_err(CheckerError::decompiler)?;
        let mut variable_extractor = Extractor::new_with(CDeclarationExtractor::new_with(
            self.typedb,
            self.project.lifter().address_bits(),
        ))
        .map_err(CheckerError::decompiler)?;

        let mut annotated = AHashSet::new();
        for (prototype, location) in annotations.iter().filter_map(|proto| {
            if let CheckCodeAnnotation::Prototype {
                prototype,
                location,
                ..
            } = proto
            {
                Some((prototype, location))
            } else {
                None
            }
        }) {
            let addr = location.unwrap_or(fcn.address());

            if !annotated.insert(addr) {
                tracing::warn!("function at {addr} is already annotated");
                continue;
            }

            let extracted = extractor
                .extract_first(prototype.as_ref())
                .map_err(CheckerError::decompiler)?;

            // NOTE: we reject an invalid prototype, but warn on a prototype that is missing types.
            //
            if let Some(extracted) = extracted {
                let ftype = extracted.data().prototype();
                let fname = if let Some(name) = extracted.data().name() {
                    Cow::Borrowed(name.as_str())
                } else if let Some(name) = fcn.name() {
                    Cow::Borrowed(name.as_str())
                } else {
                    Cow::Owned(format!("sub_{addr}"))
                };

                self.decompiler
                    .try_add_function_symbol_with(
                        fname,
                        addr,
                        ftype,
                        ftype.is_variadic_function(),
                        true,
                    )
                    .ok();

                fresh = true;
            } else {
                tracing::warn!("function prototype `{prototype}` is invalid; the required type database may not be loaded");
            }
        }

        for annotation in annotations.iter() {
            let CheckCodeAnnotation::Variable {
                location,
                position,
                index: 0,
                declaration,
            } = annotation
            else {
                continue;
            };

            match *position {
                VariablePosition::Output => {
                    let Some(extracted) = variable_extractor
                        .extract_first(declaration.as_ref())
                        .map_err(CheckerError::decompiler)?
                    else {
                        tracing::warn!("function variable declaration `{declaration}` is invalid; the required type database may not be loaded");
                        continue;
                    };

                    if let Some(name) = extracted.data().name() {
                        self.context.set_assignment_symbol(*location, name.as_str());

                        fresh = true;
                    }
                }
                VariablePosition::Global => {
                    let extracted = variable_extractor
                        .extract_first(declaration.as_ref())
                        .map_err(CheckerError::decompiler)?;

                    if let Some(extracted) = extracted {
                        let gtype = extracted.data().type_();
                        let gname = if let Some(name) = extracted.data().name() {
                            Cow::Borrowed(name.as_str())
                        } else {
                            Cow::Owned(format!("g_{location}"))
                        };

                        self.decompiler.add_global(gname, *location, gtype).ok();

                        fresh = true;
                    } else {
                        tracing::warn!("global variable declaration `{declaration}` is invalid; the required type database may not be loaded");
                    }
                }
                _ => {}
            }
        }

        let decompilation = if fresh {
            Cow::Owned(
                self.decompiler
                    .try_decompile_ast(fcn, timeout)
                    .map_err(CheckerError::decompiler)?,
            )
        } else {
            Cow::Borrowed(match self.functions.entry(fcn.id()) {
                Entry::Vacant(entry) => {
                    // try to label strings + important globals for this function....
                    /*
                    let aliases = TypedAliases::analyse_function(self.project, fcn);

                    for (_, blk) in aliases.blocks() {
                        //
                    }
                    */
                    let output = self
                        .decompiler
                        .try_decompile_ast(fcn, timeout)
                        .map_err(CheckerError::decompiler)?;
                    entry.insert(output)
                }
                Entry::Occupied(entry) => &*entry.into_mut(),
            })
        };

        let source = decompilation.source().to_owned();
        let annodb = decompilation.annotations();

        let annotations =
            annotations
                .iter()
                .filter_map(|annotation| match annotation {
                    CheckCodeAnnotation::At { location, message } => {
                        annodb.address_to_position().get(location).map_or_else(
                            // If we can't find the address in the listing, likely the decompiler
                            // output is bad. Therefore, we annotate the entire function.
                            || {
                                Some(CheckDecompilationAnnotation {
                                    message: message.to_owned(),
                                    ranges: RangeSetBlaze::from_iter(
                                        annodb
                                            .position_to_address()
                                            .range()
                                            .map(|range| range.start..=(range.end - 1)),
                                    ),
                                })
                            },
                            |positions| {
                                // Handle the successful case
                                Some(CheckDecompilationAnnotation {
                                    message: message.to_owned(),
                                    ranges: RangeSetBlaze::from_iter(
                                        positions.iter().map(|range| range.start..=(range.end - 1)),
                                    ),
                                })
                            },
                        )
                    }
                    CheckCodeAnnotation::Range { from, to, message } => {
                        // If any of the addresses within the range can't be found in the listing, likely the decompiler
                        // output is bad. Therefore, we annotate the entire function.
                        let result =
                            (from.offset()..=to.offset()).fold(Vec::new(), |mut acc, addr| {
                                match annodb.address_to_position().get(&Address::from(addr)) {
                                    Some(positions) => {
                                        acc.extend(
                                            positions
                                                .iter()
                                                .map(|range| range.start..=(range.end - 1)),
                                        );
                                        acc
                                    }
                                    None => acc,
                                }
                            });

                        Some(if !result.is_empty() {
                            CheckDecompilationAnnotation {
                                message: message.to_owned(),
                                ranges: RangeSetBlaze::from_iter(result),
                            }
                        } else {
                            CheckDecompilationAnnotation {
                                message: message.to_owned(),
                                ranges: RangeSetBlaze::from_iter(
                                    annodb
                                        .position_to_address()
                                        .range()
                                        .map(|range| range.start..=(range.end - 1)),
                                ),
                            }
                        })
                    }
                    CheckCodeAnnotation::Operand { .. } => {
                        // For now we skip it
                        None
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();

        Ok(CheckDecompilation {
            source,
            annotations,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, PartialOrd, Ord)]
#[serde(untagged)]
pub enum CheckEvidenceLocation {
    Address(
        #[serde(
            with = "::serde_with::As::<::serde_with::FromInto::<AddressValue>>",
            // serialize_with = "::serde_with::As::<DisplayFromStr>"
        )]
        Address,
    ),
    Symbol(String),
}

impl Display for CheckEvidenceLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Address(addr) => addr.fmt(f),
            Self::Symbol(symbol) => symbol.fmt(f),
        }
    }
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind")]
pub enum CheckCodeAnnotation {
    #[serde(rename = "at")]
    At {
        #[serde(with = "::serde_with::As::<::serde_with::FromInto::<AddressValue>>")]
        location: Address,
        message: String,
    },
    #[serde(rename = "range")]
    Range {
        #[serde(with = "::serde_with::As::<::serde_with::FromInto::<AddressValue>>")]
        from: Address,
        #[serde(with = "::serde_with::As::<::serde_with::FromInto::<AddressValue>>")]
        to: Address,
        message: String,
    },
    #[serde(rename = "operand")]
    Operand {
        #[serde(with = "::serde_with::As::<::serde_with::FromInto::<AddressValue>>")]
        location: Address,
        annotation: Option<String>,
        origin: Option<OperandOrigin>,
        message: String,
    },
    #[serde(rename = "prototype")]
    Prototype {
        prototype: String,
        #[serde_as(as = "Option<::serde_with::FromInto::<AddressValue>>")]
        location: Option<Address>,
        index: usize,
    },
    #[serde(rename = "variable")]
    Variable {
        #[serde(with = "::serde_with::As::<::serde_with::FromInto::<AddressValue>>")]
        location: Address,
        position: VariablePosition,
        index: usize,
        declaration: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum VariablePosition {
    #[serde(rename = "global")]
    Global,
    #[serde(rename = "input")]
    Input,
    #[serde(rename = "output")]
    Output,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CheckDataEvidence {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    display: Option<String>,
    #[serde(default)]
    annotations: Vec<CheckDataAnnotation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind")]
pub enum CheckDataAnnotation {
    #[serde(rename = "at")]
    At {
        #[serde(with = "::serde_with::As::<::serde_with::FromInto::<AddressValue>>")]
        location: Address,
        message: String,
    },
    #[serde(rename = "range")]
    Range {
        #[serde(with = "::serde_with::As::<::serde_with::FromInto::<AddressValue>>")]
        from: Address,
        #[serde(with = "::serde_with::As::<::serde_with::FromInto::<AddressValue>>")]
        to: Address,
        message: String,
    },
}

#[derive(Clone)]
pub struct CallSiteContext<'a> {
    project: &'a Project,
    function: &'a Function,
    block: &'a CodeBlock,
    symbols: &'a FunctionSymbolMapping,
    types: &'a TypeDB,
    aliases: &'a TypedBlockAliases,
    proto: DefaultPrototype,
    stack_pointer: Var,
    stack_buffers: Vec<(i64, Vec<u8>)>,
}

impl<'a> CallSiteContext<'a> {
    pub fn new(
        project: &'a Project,
        function: &'a Function,
        block: &'a CodeBlock,
        context: &'a TypedBlockAliases,
        symbols: &'a FunctionSymbolMapping,
        types: &'a TypeDB,
    ) -> Self {
        CallSiteContext {
            project,
            function,
            block,
            symbols,
            types,
            proto: project.lifter().default_prototype(),
            stack_pointer: project.lifter().stack_pointer(),
            stack_buffers: CallSiteContext::stack_buffers(project.lifter(), context),
            aliases: context,
        }
    }

    pub fn inputs(&self) -> Vec<OperandInfo<'_>> {
        (0..16)
            .into_iter()
            .map(|i| OperandInfo::new(self.project, self.function, i, true, self))
            .collect()
    }

    pub fn output(&self) -> OperandInfo<'_> {
        OperandInfo::new(self.project, self.function, 0, false, self)
    }

    fn address_bits(&self) -> u32 {
        self.project.lifter().address_bits()
    }

    fn address_bytes(&self) -> usize {
        self.project.lifter().address_bytes()
    }

    fn stack_buffers(lifter: &Lifter, context: &TypedBlockAliases) -> Vec<(i64, Vec<u8>)> {
        let mut regions = Vec::<(i64, Vec<u8>)>::new();
        let stack_variables = context.outgoing_stack();
        let is_be = lifter.endian().is_big();

        for (off, val) in stack_variables.iter().filter_map(|(off, vt)| {
            if let Some(val) = vt.v.value() {
                Some((off, val))
            } else {
                None
            }
        }) {
            if let Some((last_off, last_buf)) = regions.last_mut() {
                let last_len = last_buf.len();
                if *last_off + last_len as i64 == *off {
                    last_buf.extend(std::iter::repeat(0u8).take(val.bits() / 8));
                    if is_be {
                        val.to_be_bytes(&mut last_buf[last_len..]);
                    } else {
                        val.to_le_bytes(&mut last_buf[last_len..]);
                    }

                    continue;
                }
            }

            let mut buf = vec![0u8; val.bits() / 8];
            if is_be {
                val.to_be_bytes(&mut buf);
            } else {
                val.to_le_bytes(&mut buf);
            }
            regions.push((*off, buf));
        }

        regions
    }

    #[inline]
    fn input_operand(&self, index: usize) -> Option<&TypedAliasValue> {
        match self.proto.input_operand(index)? {
            Operand::Register(r) => self.aliases.outgoing().get(&r),
            Operand::Stack(d, _) => {
                let shift = self
                    .aliases
                    .outgoing()
                    .get(&self.stack_pointer)
                    .and_then(|vt| vt.v.stack_delta())?;
                let delta = d
                    .wrapping_add(shift)
                    .wrapping_sub(self.proto.extra_pop() as i64);

                self.aliases.outgoing_stack().get(&delta)
            }
            _ => None,
        }
    }

    #[inline]
    fn output_operand(&self, index: usize) -> Option<&TypedAliasValue> {
        match self.proto.output_operand(index)? {
            Operand::Register(r) => self.aliases.outgoing().get(&r),
            Operand::Stack(d, _) => {
                let shift = self
                    .aliases
                    .outgoing()
                    .get(&self.stack_pointer)
                    .and_then(|vt| vt.v.stack_delta())?;
                let delta = d
                    .wrapping_add(shift)
                    .wrapping_sub(self.proto.extra_pop() as i64);

                self.aliases.outgoing_stack().get(&delta)
            }
            _ => None,
        }
    }

    #[inline]
    fn pre_call_input_operand(&self, index: usize) -> Option<&TypedAliasValue> {
        let aliases = self.aliases.pre_call_state()?;
        match self.proto.input_operand(index)? {
            Operand::Register(r) => aliases.registers().get(&r),
            Operand::Stack(d, _) => {
                let shift = aliases
                    .registers()
                    .get(&self.stack_pointer)
                    .and_then(|vt| vt.v.stack_delta())?;
                let delta = d
                    .wrapping_add(shift)
                    .wrapping_sub(self.proto.extra_pop() as i64);

                aliases.stack_variables().get(&delta)
            }
            _ => None,
        }
    }

    #[inline]
    fn pre_call_output_operand(&self, index: usize) -> Option<&TypedAliasValue> {
        let aliases = self.aliases.pre_call_state()?;
        match self.proto.output_operand(index)? {
            Operand::Register(r) => aliases.registers().get(&r),
            Operand::Stack(d, _) => {
                let shift = aliases
                    .registers()
                    .get(&self.stack_pointer)
                    .and_then(|vt| vt.v.stack_delta())?;
                let delta = d
                    .wrapping_add(shift)
                    .wrapping_sub(self.proto.extra_pop() as i64);

                aliases.stack_variables().get(&delta)
            }
            _ => None,
        }
    }

    fn const_cstr(&self, from: &AliasValue) -> Option<String> {
        self.with_bytes(from, |bytes| StringData::Ascii.decode(bytes).ok())
            .flatten()
    }

    fn with_bytes<U, F>(&self, from: &AliasValue, mut f: F) -> Option<U>
    where
        F: FnMut(&[u8]) -> U,
    {
        match from {
            /*
            AliasValue::G(base, offset) if offset.is_zero() => {
                let Some(base) = base.value().to_address() else {
                    return None;
                };

                let bytes = self.project.memory().view_bytes_from(base).ok()?;
                Some(f(bytes))
            }
            */
            AliasValue::G(base, offset) => {
                // NOTE: on ARM we see patterns like (*base) + offset to get buffers
                //       so we handle those cases here.
                //
                let Some(base) = base.value().to_address() else {
                    return None;
                };

                let Ok(base_val) = self.project.memory().view_bytes(base, self.address_bytes())
                else {
                    return None;
                };

                let value = offset.unsigned_cast(self.address_bits() as _)
                    + if self.project.lifter().endian().is_big() {
                        BitVec::from_be_bytes(base_val)
                    } else {
                        BitVec::from_le_bytes(base_val)
                    };

                let Some(addr) = value.to_address() else {
                    return None;
                };

                let bytes = self.project.memory().view_bytes_from(addr).ok()?;
                Some(f(bytes))
            }
            AliasValue::V(bv) => {
                if let Some(addr) = bv.to_address() {
                    let bytes = self.project.memory().view_bytes_from(addr).ok()?;
                    Some(f(bytes))
                } else {
                    None
                }
            }
            AliasValue::S(d) => {
                if let Some(d) = d.signed_cast(64).to_i64() {
                    let i = self
                        .stack_buffers
                        .binary_search_by(|(s, b)| {
                            if d < *s {
                                Ordering::Less
                            } else if ((d - s) as usize) < b.len() {
                                Ordering::Equal
                            } else {
                                Ordering::Greater
                            }
                        })
                        .ok()?;

                    let (start, bytes) = &self.stack_buffers[i];
                    let offset = (d - start) as usize;

                    Some(f(&bytes[offset..]))
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

impl<'a> UserData for &CallSiteContext<'a> {
    fn add_fields<F: UserDataFields<Self>>(fields: &mut F) {
        fields.add_field_method_get("address", |lua, this| {
            lua.create_ser_userdata(AddressValue::from(this.function.address()))
        });
        fields.add_field_method_get("call_address", |lua, this| {
            lua.create_ser_userdata(AddressValue::from(this.block.last_address()))
        });

        fields.add_field_method_get("name", |_lua, this| {
            Ok(this
                .symbols
                .function_mapping()
                .get(&this.function.id())
                .copied()
                .or_else(|| this.function.name())
                .map(|v| v.as_str()))
        });

        fields.add_field_method_get("address_bits", |_lua, this| Ok(this.address_bits()));
        fields.add_field_method_get("address_bytes", |_lua, this| Ok(this.address_bytes()));
    }
}

#[derive(Clone)]
pub struct FunctionContext<'a> {
    f: &'a Function,
    name: Option<Ustr>,
    project: &'a Project,
    symbols: Option<&'a FunctionSymbolMapping>,
}

impl<'a> FunctionContext<'a> {
    pub fn new(f: &'a Function, project: &'a Project) -> Self {
        Self::new_with(f, project, None)
    }

    pub fn new_with(
        f: &'a Function,
        project: &'a Project,
        symbols: impl Into<Option<&'a FunctionSymbolMapping>>,
    ) -> Self {
        let symbols = symbols.into();
        let name = symbols
            .and_then(|syms| syms.function_mapping().get(&f.id()).copied())
            .or_else(|| f.name());

        Self {
            f,
            name,
            project,
            symbols: symbols.into(),
        }
    }

    pub fn has_call_with(&self, f: impl Fn(&'a Function) -> bool, with_jumps: bool) -> bool {
        for block in self.f.blocks_with(self.project.code_blocks()) {
            let node = block.node();
            if self
                .project
                .icfg()
                .edges_directed(node, Direction::Outgoing)
                .any(|e| {
                    (e.weight().is_call() || (with_jumps && e.weight().is_branch())) && {
                        let fcn = &self.project.functions()[self.project.code_blocks()
                            [self.project.icfg()[e.target()]]
                        .function()];
                        f(fcn)
                    }
                })
            {
                return true;
            }
        }
        false
    }

    pub fn has_call_to(&self, addr: impl Into<Address>, with_jumps: bool) -> bool {
        let addr = addr.into();
        self.has_call_with(|f| f.address() == addr, with_jumps)
    }

    pub fn has_reference_to(&self, addr: impl Into<Address>) -> bool {
        let target = addr.into();

        let xref_db = self.project.get_analysis::<XRefDB>();
        self.f.blocks().iter().any(|(block_id, _)| {
            xref_db
                .xrefs_from(*block_id)
                .any(|xref| xref.target() == target)
        })
    }

    pub fn calls_with(
        &self,
        f: impl Fn(&'a Function) -> bool,
        with_jumps: bool,
    ) -> BTreeMap<Address, Address> {
        let mut calls = BTreeMap::new();
        for block in self.f.blocks_with(self.project.code_blocks()) {
            let node = block.node();
            let addr = block.last_address();
            calls.extend(
                self.project
                    .icfg()
                    .edges_directed(node, Direction::Outgoing)
                    .filter_map(|e| {
                        if e.weight().is_call() || (with_jumps && e.weight().is_branch()) {
                            let fcn = &self.project.functions()[self.project.code_blocks()
                                [self.project.icfg()[e.target()]]
                            .function()];
                            if f(fcn) {
                                Some((addr, fcn.address()))
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }),
            );
        }
        calls
    }

    pub fn calls_to(
        &self,
        addr: impl Into<Address>,
        with_jumps: bool,
    ) -> BTreeMap<Address, Address> {
        let addr = addr.into();
        self.calls_with(|f| f.address() == addr, with_jumps)
    }

    pub fn bytes(&self) -> impl Iterator<Item = (Address, &[u8])> {
        self.f
            .chunks(self.project.code_blocks())
            .into_iter()
            .filter_map(|iv| {
                let start = iv.start;
                let last = iv.end;
                let count = usize::from(last - start);

                let region = self.project.memory().find_region(start)?;
                region
                    .view_bytes(start, count)
                    .ok()
                    .map(|bytes| (start, bytes))
            })
    }

    pub fn total_bytes(&self) -> usize {
        self.bytes().map(|(_, bytes)| bytes.len()).sum()
    }

    pub fn is_reachable(&self, a1: impl Into<Address>, a2: impl Into<Address>) -> bool {
        let bounds = self.project.get_analysis::<CodeBlockBounds>();

        let Some(b1) = bounds
            .get(a1)
            .map(|(_, bid)| &self.project.code_blocks()[*bid])
        else {
            return false;
        };

        let Some(b2) = bounds
            .get(a2)
            .map(|(_, bid)| &self.project.code_blocks()[*bid])
        else {
            return false;
        };

        if self.f.id() != b1.function() || self.f.id() != b2.function() {
            return false;
        }

        let icfg = self.project.icfg();
        let g = self.f.cfg(icfg, self.project.code_blocks());

        has_path_connecting(&g, b1.node(), b2.node(), Default::default())
    }

    pub fn dominates(&self, a1: impl Into<Address>, a2: impl Into<Address>) -> bool {
        let bounds = self.project.get_analysis::<CodeBlockBounds>();

        let Some(b1) = bounds
            .get(a1)
            .map(|(_, bid)| &self.project.code_blocks()[*bid])
        else {
            return false;
        };

        let Some(b2) = bounds
            .get(a2)
            .map(|(_, bid)| &self.project.code_blocks()[*bid])
        else {
            return false;
        };

        if self.f.id() != b1.function() || self.f.id() != b2.function() {
            return false;
        }

        let icfg = self.project.icfg();
        let g = self.f.cfg(icfg, self.project.code_blocks());

        let doms = g.dominators();

        doms.dominates(b1.id(), b2.id())
    }

    pub fn precedes(&self, a1: impl Into<Address>, a2: impl Into<Address>) -> bool {
        let a1 = a1.into();
        let a2 = a2.into();

        self.is_reachable(a1, a2) && !self.dominates(a2, a1)
    }
}

impl<'a> UserData for FunctionContext<'a> {
    fn add_fields<F: UserDataFields<Self>>(fields: &mut F) {
        fields.add_field_method_get("address", |lua, this| {
            lua.create_ser_userdata(AddressValue::from(this.f.address()))
        });
        fields.add_field_method_get("name", |_lua, this| Ok(this.name.map(|v| v.as_str())));
        fields.add_field_method_get("total_bytes", |_lua, this| Ok(this.total_bytes()));
    }

    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("calls", |lua, this, arg: Value| {
            let query = lua.from_value::<CallsToQuery>(arg)?;

            let (to, jumps_as_calls) = query
                .targets_with(this.project, this.symbols, true)
                .map_err(Error::external)?;

            let targets = to
                .iter()
                .map(|f| this.calls_to(f.address(), jumps_as_calls))
                .reduce(|mut acc, item| {
                    acc.extend(item);
                    acc
                })
                .unwrap_or_default();

            let seq = targets
                .into_keys()
                .map(|addr| lua.create_ser_userdata(AddressValue::from(addr)))
                .collect::<Result<Vec<_>, _>>()?;
            lua.create_sequence_from(seq)
        });

        methods.add_method("has_call", |lua, this, arg: Value| {
            let query = lua.from_value::<CallsToQuery>(arg)?;

            let (to, jumps_as_calls) = query
                .targets_with(this.project, this.symbols, true)
                .map_err(Error::external)?;

            Ok(to
                .iter()
                .any(|target| this.has_call_to(target.address(), jumps_as_calls)))
        });

        methods.add_method("has_reference", |_lua, this, addr: AddressValue| {
            Ok(this.has_reference_to(addr))
        });

        methods.add_method("named", |_lua, this, arg: String| {
            Ok(matches!(this.name, Some(name) if name == arg))
        });

        methods.add_method("find", |lua, this, pat: PatternMatcher| {
            this.bytes()
                .find_map(|(addr, bytes)| {
                    pat.find_iter(bytes)
                        .next()
                        .map(|off| lua.create_ser_userdata(AddressValue::from(addr + off.start())))
                })
                .transpose()
        });

        methods.add_method("matches", |_lua, this, pat: PatternMatcher| {
            Ok(this
                .bytes()
                .any(|(_, bytes)| pat.find_iter(bytes).next().is_some()))
        });

        methods.add_method("blocks", |_lua, this, ()| {
            Ok(this
                .f
                .blocks_with(this.project.code_blocks())
                .into_iter()
                .map(|blk| IRTerm::new(blk.to_owned()))
                .collect::<Vec<_>>())
        });

        methods.add_method("prototype", |_lua, this, ()| {
            Ok(this
                .project
                .type_db()
                .get_code_type_at(this.f.address())
                .map(IRTerm::new))
        });

        methods.add_method(
            "is_reachable",
            |_lua, this, (addr1, addr2): (AddressValue, AddressValue)| {
                Ok(this.is_reachable(addr1, addr2))
            },
        );

        methods.add_method(
            "dominates",
            |_lua, this, (addr1, addr2): (AddressValue, AddressValue)| {
                Ok(this.dominates(addr1, addr2))
            },
        );

        methods.add_method(
            "precedes",
            |_lua, this, (addr1, addr2): (AddressValue, AddressValue)| {
                Ok(this.precedes(addr1, addr2))
            },
        );
    }
}

#[derive(Clone)]
pub struct Instruction {
    text: InsnText,
}

impl Instruction {
    pub fn new(insn: InsnText) -> Self {
        Self { text: insn }
    }
}

impl UserData for Instruction {
    fn add_fields<F: UserDataFields<Self>>(fields: &mut F) {
        fields.add_field_method_get("address", |lua, this| {
            lua.create_ser_userdata(AddressValue::from(this.text.address()))
        });

        fields.add_field_method_get("size", |_lua, this| Ok(this.text.length()));

        fields.add_field_method_get("mnemonic", |_lua, this| Ok(this.text.mnemonic().to_owned()));

        fields.add_field_method_get("operands", |lua, this| {
            let mut tokens = Vec::new();

            for opnd in this.text.tokens() {
                match opnd {
                    InsnToken::Address(v) => {
                        let t = lua.create_table()?;
                        t.set(
                            "address",
                            lua.create_ser_userdata(AddressValue::from(*v))?
                                .into_lua(lua)?,
                        )?;
                        tokens.push(t);
                    }
                    InsnToken::Register(v) => {
                        let t = lua.create_table()?;
                        t.set("register", v.to_owned().into_lua(lua)?)?;
                        tokens.push(t);
                    }
                    InsnToken::Value(v) => {
                        let t = lua.create_table()?;
                        t.set("value", (*v).into_lua(lua)?)?;
                        t.set(
                            "address",
                            lua.create_ser_userdata(AddressValue::from(Address::from(*v as u64)))?
                                .into_lua(lua)?,
                        )?;
                        tokens.push(t);
                    }
                    _ => (),
                }
            }

            lua.create_sequence_from(tokens)
        });
    }
}

#[derive(Clone)]
pub struct OperandInfo<'a> {
    name: Option<Ustr>,
    index: usize,
    input: bool,
    state: &'a CallSiteContext<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, FromLua)]
pub struct OperandOrigin {
    named: Option<NamedValue>,
    origin: AliasOrigin,
}

impl UserData for OperandOrigin {
    fn add_fields<F: UserDataFields<Self>>(fields: &mut F) {
        fields.add_field_method_get("source_address", |lua, this| {
            this.named
                .as_ref()
                .map(|named| lua.create_ser_userdata(AddressValue::from(named.source().address())))
                .transpose()
        });
        fields.add_field_method_get("source_position", |_lua, this| {
            Ok(this.named.as_ref().map(|named| named.source().position()))
        });

        fields.add_field_method_get("definition_address", |lua, this| {
            lua.create_ser_userdata(AddressValue::from(this.origin.location().address()))
        });
        fields.add_field_method_get("definition_position", |_lua, this| {
            Ok(this.origin.location().position())
        });

        fields.add_field_method_get("index", |_lua, this| Ok(this.origin.index()));
    }

    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_meta_method("__eq", |_lua, this, other: OperandOrigin| {
            Ok(matches!((this.named, other.named), (Some(o1), Some(o2)) if o1.source() == o2.source()))
        });
        methods.add_meta_method("__tostring", |_lua, this, ()| Ok(this.origin.to_string()));
    }
}

impl<'a> OperandInfo<'a> {
    pub fn new(
        _project: &'a Project,
        f: &'a Function,
        index: usize,
        input: bool,
        state: &'a CallSiteContext<'a>,
    ) -> Self {
        let name = state.types.get_code_type_at(f.address()).and_then(|ft| {
            if input {
                ft.function_args()
                    .and_then(|args| args.get(index))
                    .and_then(|arg| arg.name())
            } else {
                None
            }
        });
        Self {
            name,
            index,
            input,
            state,
        }
    }

    pub fn operand(&self) -> Option<&TypedAliasValue> {
        if self.input {
            self.state.input_operand(self.index)
        } else {
            self.state.output_operand(self.index)
        }
    }

    pub fn pre_call_operand(&self) -> Option<&TypedAliasValue> {
        if self.input {
            self.state.pre_call_input_operand(self.index)
        } else {
            self.state.pre_call_output_operand(self.index)
        }
    }

    pub fn to_table(&self, lua: &Lua) -> Result<Table, Error> {
        let table = lua.create_table()?;
        let operand = self.operand();
        let pre_call_operand = self.pre_call_operand();

        table.set("name", self.name.map(|name| name.as_str()))?;
        table.set("index", self.index)?;

        let pre_call_annotation = pre_call_operand
            .and_then(|opnd| opnd.v.symbol())
            .map(|sym| sym.name().as_str())
            .into_lua(&lua)?;

        let post_call_annotation = operand
            .and_then(|opnd| opnd.v.symbol())
            .map(|sym| sym.name().as_str())
            .into_lua(&lua)?;

        table.set("pre_call_annotation", pre_call_annotation.clone())?;
        table.set("post_call_annotation", post_call_annotation)?;
        table.set("annotation", pre_call_annotation)?;

        let pre_call_origin = pre_call_operand
            .map(|opnd| {
                lua.create_ser_userdata(OperandOrigin {
                    named: opnd.v.symbol().cloned(),
                    origin: opnd.o.clone(),
                })
            })
            .transpose()?
            .into_lua(&lua)?;

        let post_call_origin = operand
            .map(|opnd| {
                lua.create_ser_userdata(OperandOrigin {
                    named: opnd.v.symbol().cloned(),
                    origin: opnd.o.clone(),
                })
            })
            .transpose()?
            .into_lua(&lua)?;

        let pre_call_string = pre_call_operand
            .and_then(|opnd| self.state.const_cstr(&opnd.v))
            .into_lua(lua)?;

        let post_call_string = operand
            .and_then(|opnd| self.state.const_cstr(&opnd.v))
            .into_lua(lua)?;

        let is_unk_pre_call = pre_call_operand.map(|opnd| opnd.v.is_unk()).unwrap_or(true);

        let is_unk_pre_callf = lua
            .create_function(move |lua: &Lua, _this: Value| -> Result<Value, Error> {
                is_unk_pre_call.into_lua(lua)
            })?
            .into_lua(lua)?;

        let is_unk_post_call = operand.map(|opnd| opnd.v.is_unk()).unwrap_or(true);

        let is_unk_post_callf = lua
            .create_function(move |lua: &Lua, _this: Value| -> Result<Value, Error> {
                is_unk_post_call.into_lua(lua)
            })?
            .into_lua(lua)?;

        let is_const_pre_call = pre_call_operand
            .map(|opnd| opnd.v.is_val())
            .unwrap_or(false);

        let is_const_pre_callf = lua
            .create_function(move |lua: &Lua, _this: Value| -> Result<Value, Error> {
                is_const_pre_call.into_lua(lua)
            })?
            .into_lua(lua)?;

        let is_const_post_call = operand.map(|opnd| opnd.v.is_val()).unwrap_or(false);

        let is_const_post_callf = lua
            .create_function(move |lua: &Lua, _this: Value| -> Result<Value, Error> {
                is_const_post_call.into_lua(lua)
            })?
            .into_lua(lua)?;

        let pre_call_constf = pre_call_operand
            .and_then(|opnd| opnd.v.value().map(|val| LuaBitVec::from(val.to_owned())))
            .into_lua(lua)?;

        let post_call_constf = operand
            .and_then(|opnd| opnd.v.value().map(|val| LuaBitVec::from(val.to_owned())))
            .into_lua(lua)?;

        let pre_call_bytes = pre_call_operand.and_then(|opnd| {
            self.state
                .with_bytes(&opnd.v, |bytes| bytes[..bytes.len().min(256)].to_vec())
        });

        let pre_call_bytesf = lua
            .create_function(move |_, limit: Option<usize>| {
                if let Some(bytes) = pre_call_bytes.as_ref() {
                    let limit = limit.unwrap_or(256).min(bytes.len());

                    Ok(bytes.get(..limit).map(|bytes| bytes.to_vec()))
                } else {
                    Ok(None)
                }
            })?
            .into_lua(lua)?;

        let post_call_bytes = operand.and_then(|opnd| {
            self.state
                .with_bytes(&opnd.v, |bytes| bytes[..bytes.len().min(256)].to_vec())
        });

        let post_call_bytesf = lua
            .create_function(move |_, limit: Option<usize>| {
                if let Some(bytes) = post_call_bytes.as_ref() {
                    let limit = limit.unwrap_or(256).min(bytes.len());

                    Ok(bytes.get(..limit).map(|bytes| bytes.to_vec()))
                } else {
                    Ok(None)
                }
            })?
            .into_lua(lua)?;

        table.set("pre_call_origin", pre_call_origin.clone())?;
        table.set("post_call_origin", post_call_origin)?;
        table.set("origin", pre_call_origin)?;

        table.set("pre_call_string", pre_call_string.clone())?;
        table.set("post_call_string", post_call_string)?;
        table.set("string", pre_call_string)?;

        table.set("is_unk_pre_call", is_unk_pre_callf.clone())?;
        table.set("is_unk_post_call", is_unk_post_callf)?;
        table.set("is_unk", is_unk_pre_callf)?;

        table.set("is_const_pre_call", is_const_pre_callf.clone())?;
        table.set("is_const_post_call", is_const_post_callf)?;
        table.set("is_const", is_const_pre_callf)?;

        table.set("pre_call_bytes", pre_call_bytesf.clone())?;
        table.set("post_call_bytes", post_call_bytesf)?;
        table.set("bytes", pre_call_bytesf)?;

        table.set("pre_call_constant", pre_call_constf.clone())?;
        table.set("post_call_constant", post_call_constf)?;
        table.set("constant", pre_call_constf)?;

        Ok(table)
    }
}

impl<'a> UserData for OperandInfo<'a> {
    fn add_fields<F: UserDataFields<Self>>(fields: &mut F) {
        fields.add_field_method_get("name", |_lua, this| Ok(this.name.map(|name| name.as_str())));
        fields.add_field_method_get("index", |_lua, this| Ok(this.index));

        fields.add_field_method_get("pre_call_annotation", |_lua, this| {
            Ok(this
                .pre_call_operand()
                .and_then(|opnd| opnd.v.symbol())
                .map(|sym| sym.name().as_str()))
        });

        fields.add_field_method_get("post_call_annotation", |_lua, this| {
            Ok(this
                .operand()
                .and_then(|opnd| opnd.v.symbol())
                .map(|sym| sym.name().as_str()))
        });

        fields.add_field_method_get("annotation", |_lua, this| {
            Ok(this
                .pre_call_operand()
                .and_then(|opnd| opnd.v.symbol())
                .map(|sym| sym.name().as_str()))
        });

        fields.add_field_method_get("pre_call_origin", |lua, this| {
            this.pre_call_operand()
                .map(|opnd| {
                    lua.create_ser_userdata(OperandOrigin {
                        named: opnd.v.symbol().cloned(),
                        origin: opnd.o.clone(),
                    })
                })
                .transpose()
        });

        fields.add_field_method_get("post_call_origin", |lua, this| {
            this.operand()
                .map(|opnd| {
                    lua.create_ser_userdata(OperandOrigin {
                        named: opnd.v.symbol().cloned(),
                        origin: opnd.o.clone(),
                    })
                })
                .transpose()
        });

        fields.add_field_method_get("origin", |lua, this| {
            this.pre_call_operand()
                .map(|opnd| {
                    lua.create_ser_userdata(OperandOrigin {
                        named: opnd.v.symbol().cloned(),
                        origin: opnd.o.clone(),
                    })
                })
                .transpose()
        });

        fields.add_field_method_get("pre_call_string", |_lua, this| {
            Ok(this
                .pre_call_operand()
                .and_then(|operand| this.state.const_cstr(&operand.v)))
        });

        fields.add_field_method_get("post_call_string", |_lua, this| {
            Ok(this
                .operand()
                .and_then(|operand| this.state.const_cstr(&operand.v)))
        });

        fields.add_field_method_get("string", |_lua, this| {
            Ok(this
                .pre_call_operand()
                .and_then(|operand| this.state.const_cstr(&operand.v)))
        });

        fields.add_field_method_get("pre_call_constant", |_lua, this| {
            Ok(this
                .pre_call_operand()
                .and_then(|operand| operand.v.value().map(|val| LuaBitVec::from(val.to_owned()))))
        });

        fields.add_field_method_get("post_call_constant", |_lua, this| {
            Ok(this
                .operand()
                .and_then(|operand| operand.v.value().map(|val| LuaBitVec::from(val.to_owned()))))
        });

        fields.add_field_method_get("constant", |_lua, this| {
            Ok(this
                .pre_call_operand()
                .and_then(|operand| operand.v.value().map(|val| LuaBitVec::from(val.to_owned()))))
        })
    }

    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("is_const_pre_call", |_lua, this, _args: ()| {
            Ok(this
                .pre_call_operand()
                .map(|opnd| opnd.v.is_val())
                .unwrap_or(false))
        });

        methods.add_method("is_const_post_call", |_lua, this, _args: ()| {
            Ok(this.operand().map(|opnd| opnd.v.is_val()).unwrap_or(false))
        });

        methods.add_method("is_const", |_lua, this, _args: ()| {
            Ok(this
                .pre_call_operand()
                .map(|opnd| opnd.v.is_val())
                .unwrap_or(false))
        });

        methods.add_method("is_unk_pre_call", |_lua, this, _args: ()| {
            Ok(this
                .pre_call_operand()
                .map(|opnd| opnd.v.is_unk())
                .unwrap_or(true))
        });

        methods.add_method("is_unk_post_call", |_lua, this, _args: ()| {
            Ok(this.operand().map(|opnd| opnd.v.is_unk()).unwrap_or(true))
        });

        methods.add_method("is_unk", |_lua, this, _args: ()| {
            Ok(this
                .pre_call_operand()
                .map(|opnd| opnd.v.is_unk())
                .unwrap_or(true))
        });

        methods.add_method("pre_call_bytes", |_lua, this, args: (Option<usize>,)| {
            let limit = args.0.unwrap_or(256).min(256); // OK?
            let Some(operand) = this.pre_call_operand() else {
                return Ok(None);
            };

            Ok(this
                .state
                .with_bytes(&operand.v, |bytes| bytes[..bytes.len().min(limit)].to_vec()))
        });

        methods.add_method("post_call_bytes", |_lua, this, args: (Option<usize>,)| {
            let limit = args.0.unwrap_or(256).min(256);
            let Some(operand) = this.operand() else {
                return Ok(None);
            };

            Ok(this
                .state
                .with_bytes(&operand.v, |bytes| bytes[..bytes.len().min(limit)].to_vec()))
        });

        methods.add_method("bytes", |_lua, this, args: (Option<usize>,)| {
            let limit = args.0.unwrap_or(256).min(256);
            let Some(operand) = this.pre_call_operand() else {
                return Ok(None);
            };

            Ok(this
                .state
                .with_bytes(&operand.v, |bytes| bytes[..bytes.len().min(limit)].to_vec()))
        })
    }
}

#[derive(Clone)]
#[repr(transparent)]
pub struct PatternMatcher {
    pattern: Arc<Pattern>,
}

impl Deref for PatternMatcher {
    type Target = Pattern;

    fn deref(&self) -> &Self::Target {
        &*self.pattern
    }
}

impl PatternMatcher {
    pub(crate) fn register<'lua>(lua: &'lua Lua) -> Result<(), Error> {
        lua.globals()
            .set("PatternMatcher", lua.create_proxy::<Self>()?)?;
        Ok(())
    }
}

impl UserData for PatternMatcher {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_function("new", |_lua, pat: String| {
            Ok(PatternMatcher {
                pattern: Arc::new(pat.parse::<Pattern>().map_err(Error::external)?),
            })
        });
    }
}

impl FromLua for PatternMatcher {
    fn from_lua(value: Value, _lua: &Lua) -> Result<Self, Error> {
        let ty = value.type_name();
        value
            .as_userdata()
            .and_then(|d| d.borrow::<Self>().map(|v| v.to_owned()).ok())
            .ok_or_else(|| Error::FromLuaConversionError {
                from: ty,
                to: "PatternMatcher".to_owned(),
                message: None,
            })
    }
}

#[derive(Debug, Clone, Default, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
pub enum DecompilerQueryEngine {
    #[serde(rename = "syntax", alias = "weggli", alias = "default")]
    #[default]
    Weggli,
    #[serde(rename = "ast-grep")]
    AstGrep,
    #[serde(rename = "semgrep")]
    Semgrep,
}

#[derive(Clone)]
pub struct DecompiledFunction<'a> {
    source: FunctionContext<'a>,
    decompilation: Arc<DecompilerAst>,
}

impl<'a> DecompiledFunction<'a> {
    pub fn new(source: FunctionContext<'a>, decompilation: DecompilerAst) -> Self {
        Self {
            source,
            decompilation: Arc::new(decompilation),
        }
    }

    fn weggli_query(&self, query: impl AsRef<str>) -> Result<SyntaxMatchResult<'static>, Error> {
        self.weggli_query_with(query, false, false, None)
    }

    fn weggli_query_with(
        &self,
        query: impl AsRef<str>,
        raw: bool,
        unique: bool,
        regexes: impl Into<Option<Vec<String>>>,
    ) -> Result<SyntaxMatchResult<'static>, Error> {
        let query = if raw {
            Cow::Borrowed(query.as_ref())
        } else {
            Cow::Owned(format!("{{{}}}", query.as_ref()))
        };

        self.decompilation
            .query_with(query, unique, regexes)
            .map(|results| SyntaxMatchResult {
                source: unsafe { mem::transmute(self.clone()) },
                results: results
                    .iter()
                    .map(|instance| SyntaxQueryResult {
                        matches: instance
                            .captures
                            .iter()
                            .skip(1)
                            .filter_map(|capture| {
                                let range = &capture.range;
                                let real_range = range.start..range.end - 1;
                                if real_range.is_empty() {
                                    return None;
                                }
                                self.decompilation
                                    .annotations()
                                    .position_to_address()
                                    .iter(real_range)
                                    .next()
                                    .map(|(_, &v)| v.into())
                            })
                            .dedup()
                            .collect(),
                        variables: instance
                            .vars
                            .keys()
                            .map(|var| {
                                (
                                    var.to_owned(),
                                    instance
                                        .value(var, self.decompilation.source())
                                        .map(ToOwned::to_owned),
                                )
                            })
                            .collect(),
                    })
                    .collect(),
            })
            .map_err(Error::external)
    }
}

impl<'a> FromLua for DecompiledFunction<'a> {
    fn from_lua(value: Value, _lua: &Lua) -> mlua::Result<Self> {
        let ty = value.type_name();
        value
            .as_userdata()
            .and_then(|d| {
                d.borrow::<DecompiledFunction<'_>>()
                    .map(|v| v.to_owned())
                    .ok()
            })
            .ok_or_else(|| Error::FromLuaConversionError {
                from: ty,
                to: "DecompiledFunction".to_owned(),
                message: None,
            })
    }
}

impl<'a> UserData for DecompiledFunction<'a> {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_meta_method("__eq", |_lua, this, other: DecompiledFunction<'_>| {
            Ok(this.source.f.address() == other.source.f.address())
        });

        methods.add_meta_method("__tostring", |_lua, this, ()| {
            Ok(this.decompilation.source().to_owned())
        });

        methods.add_method("query", |lua, this, query: Value| {
            // case 1: value is a string; use syntax engine
            if let Some(query) = query.as_string().and_then(|s| s.to_str().ok()) {
                return this.weggli_query(query);
            }

            // case 2: value is a table; get engine and query
            let Some(table) = query.as_table() else {
                return Err(Error::runtime("expected query string or specification"));
            };

            let Ok(engine) = table.get::<Option<Value>>("engine") else {
                return Err(Error::runtime("invalid option: engine should be a string"));
            };

            let engine = if let Some(v) = engine {
                lua.from_value::<DecompilerQueryEngine>(v)?
            } else {
                DecompilerQueryEngine::default()
            };

            match engine {
                DecompilerQueryEngine::Weggli => {
                    let Ok(query) = table.get::<String>("query") else {
                        return Err(Error::runtime("query string missing for syntax engine"));
                    };

                    let Ok(raw) = table.get::<Option<bool>>("raw") else {
                        return Err(Error::runtime(
                            "invalid option for syntax engine: raw should be a boolean",
                        ));
                    };

                    let Ok(unique) = table.get::<Option<bool>>("unique") else {
                        return Err(Error::runtime(
                            "invalid option for syntax engine: unique should be a boolean",
                        ));
                    };

                    let Ok(regexes) = table.get::<Option<Vec<String>>>("regexes") else {
                        return Err(Error::runtime(
                            "invalid option for syntax engine: regexes should be a table of strings",
                        ));
                    };

                    return this.weggli_query_with(
                        query,
                        raw.unwrap_or_default(),
                        unique.unwrap_or_default(),
                        regexes,
                    );
                }
                DecompilerQueryEngine::AstGrep | DecompilerQueryEngine::Semgrep => {
                    Err(Error::runtime("unsupported query engine"))
                }
            }
        });
    }
}

pub struct SyntaxMatchResult<'a> {
    source: DecompiledFunction<'a>,
    results: Vec<SyntaxQueryResult>,
}

#[derive(Debug)]
struct SyntaxQueryResult {
    matches: Vec<Address>,
    variables: BTreeMap<String, Option<String>>,
}

impl<'a> UserData for SyntaxMatchResult<'a> {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("dump", |lua, this, _: ()| {
            lua.create_sequence_from(this.results.iter().map(|qr| format!("{qr:#?}")))
        });

        methods.add_method("dump_ranges", |lua, this, _: ()| {
            lua.create_sequence_from(
                this.source
                    .decompilation
                    .annotations()
                    .position_to_address()
                    .iter(..)
                    .map(|(iv, v)| {
                        format!(
                            "{}..{}: {v} / {:?}",
                            iv.start,
                            iv.end - 1,
                            this.source
                                .decompilation
                                .source()
                                .get(iv.start..(iv.end - 1))
                        )
                    }),
            )
        });

        methods.add_method("binding_of_match", |_lua, this, var: Value| {
            if let Some(var) = var.as_string().and_then(|s| s.to_str().ok()) {
                return Ok(this.results.get(0).and_then(|instance| {
                    instance.variables.get(&*var).and_then(|v| v.as_ref().map(ToOwned::to_owned))
                }));
            }

            let Some(table) = var.as_table() else {
                return Err(Error::runtime(
                    "expected variable or variable and result index",
                ));
            };

            let Ok(var) = table.get::<String>("var") else {
                return Err(Error::runtime("expected string for variable"));
            };

            let Ok(result) = table.get::<usize>("result") else {
                return Err(Error::runtime("expected integer for result index"));
            };

            let Some(result) = result.checked_sub(1) else {
                return Ok(None);
            };

            Ok(this.results.get(result).and_then(|instance| {
                instance
                    .variables
                    .get(&var)
                    .map(ToOwned::to_owned)
                    .flatten()
            }))
        });

        methods.add_method("address_of_match", |lua, this, index: Value| {
            if let Some(index) = index.as_usize() {
                let Some(index) = index.checked_sub(1) else {
                    return Ok(None);
                };

                return this
                    .results
                    .get(0)
                    .and_then(|instance| {
                        let addr = instance
                            .matches
                            .get(index)
                            .copied()
                            .map(AddressValue::from)?;
                        Some(lua.create_ser_userdata(addr))
                    })
                    .transpose();
            }

            let Some(table) = index.as_table() else {
                return Err(Error::runtime("expected index or match and result indices"));
            };

            let Ok(match_) = table.get::<usize>("match") else {
                return Err(Error::runtime("expected integer for match index"));
            };

            let Some(match_) = match_.checked_sub(1) else {
                return Ok(None);
            };

            let Ok(result) = table.get::<usize>("result") else {
                return Err(Error::runtime("expected integer for result index"));
            };

            let Some(result) = result.checked_sub(1) else {
                return Ok(None);
            };

            this.results
                .get(result)
                .and_then(|instance| {
                    let addr = instance
                        .matches
                        .get(match_)
                        .copied()
                        .map(AddressValue::from)?;
                    Some(lua.create_ser_userdata(addr))
                })
                .transpose()
        });
    }
}

pub struct FindCodeResult {
    function_address: Address,
    start_address: Address,
    end_address: Address,
    insns: Vec<Instruction>,
}

impl FindCodeResult {
    pub fn find(project: &Project, pattern: impl AsRef<str>) -> Result<Option<Self>, Error> {
        Self::find_with(project, pattern, None)
    }

    pub fn find_with(
        project: &Project,
        pattern: impl AsRef<str>,
        location: impl Into<Option<CodeLocation>>,
    ) -> Result<Option<Self>, Error> {
        let finder = if let Some(location) = location.into() {
            Code::from_pattern_with(pattern, location)
        } else {
            Code::from_pattern(pattern)
        }
        .map_err(Error::external)?;

        let mut context = MatchContext::new();
        let checkpoint = context.begin(&finder);
        let result = finder.matches_rule(&mut context, project);
        context.commit(checkpoint);

        if result {
            context
                .explain()
                .next()
                .map(|(addr, _)| {
                    let bounds = project.get_analysis::<CodeBlockBounds>();
                    let faddr = bounds
                        .get(addr)
                        .and_then(|(_, &bid)| {
                            let fid = project.code_blocks().get(bid)?.function();
                            project.functions().get(fid).map(|f| f.address())
                        })
                        .ok_or_else(|| Error::external("code outside any function"))?;

                    let bytes = finder.pattern().len();

                    let mut disas = Disassembler::new(project.lifter());
                    let mut insns = Vec::new();

                    let mut curr = addr;
                    let last = addr + bytes;

                    while curr < last {
                        let text = disas
                            .disassemble_at(curr, project.memory())
                            .map_err(|_| Error::external("invalid instruction"))?;

                        let size = text.len();

                        insns.push(Instruction::new(text));
                        curr += size;
                    }

                    Ok(Self {
                        function_address: faddr,
                        start_address: curr,
                        end_address: last,
                        insns,
                    })
                })
                .transpose()
        } else {
            Ok(None)
        }
    }
}

impl UserData for FindCodeResult {
    fn add_fields<F: UserDataFields<Self>>(fields: &mut F) {
        fields.add_field_method_get("function_address", |lua, this| {
            lua.create_ser_userdata(AddressValue::from(this.function_address))
        });

        fields.add_field_method_get("start_address", |lua, this| {
            lua.create_ser_userdata(AddressValue::from(this.start_address))
        });

        fields.add_field_method_get("end_address", |lua, this| {
            lua.create_ser_userdata(AddressValue::from(this.end_address))
        });

        fields.add_field_method_get("insns", |_lua, this| Ok(this.insns.clone()));
    }
}

#[derive(Clone)]
#[repr(transparent)]
pub struct RegexMatcher {
    regex: Regex,
}

impl RegexMatcher {
    pub fn new(re: impl AsRef<str>) -> Result<Self, regex::Error> {
        let regex = Regex::new(re.as_ref())?;

        Ok(Self { regex })
    }

    pub fn is_match(&self, text: impl AsRef<str>) -> bool {
        self.regex.is_match(text.as_ref())
    }

    pub fn is_match_at(&self, text: impl AsRef<str>, start: usize) -> bool {
        self.regex.is_match_at(text.as_ref(), start)
    }
}

impl RegexMatcher {
    pub fn register(lua: &Lua) -> Result<(), Error> {
        lua.globals()
            .set("RegexMatcher", lua.create_proxy::<Self>()?)?;
        Ok(())
    }
}

impl UserData for RegexMatcher {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_function("new", |_lua, regex: String| {
            RegexMatcher::new(regex).map_err(Error::external)
        });

        methods.add_method(
            "is_match",
            |_lua, this, value: (String, Variadic<usize>)| {
                let text = value.0;

                if let Some(start) = value.1.first() {
                    let Some(start) = start.checked_sub(1) else {
                        return Ok(false);
                    };

                    Ok(this.is_match_at(text, start))
                } else {
                    Ok(this.is_match(text))
                }
            },
        );
    }
}

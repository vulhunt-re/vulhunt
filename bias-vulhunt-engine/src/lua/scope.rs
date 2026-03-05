use std::borrow::{Borrow, Cow};
use std::collections::BTreeMap;
use std::fmt::Display;
use std::str::FromStr;

use bias_core::analyses::symbolic::typed::{AliasOrigin, ContextualTypeResolver, NamedValue};
use bias_core::prelude::*;

use bias_compat_fwhunt::bmatch::BMatcher;

use bias::component::LoadedBinaryComponent;
use bias::platform::common::flirt::FunctionSymbolMapping;

use memchr::memmem;
use mlua::Lua;
use serde::Deserialize;

use super::project::PlatformTypeResolver;
use super::FunctionContext;

use crate::lua::{CallsToQuery, FunctionQuery, FunctionQueryTarget};
use crate::CheckerError;

const SCOPE_CONDITIONS_API: &'static [u8] = include_bytes!("scope-conditions.lua");

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize)]
#[serde(untagged)]
pub enum CheckScopeValue {
    Bool(bool),
    Integer(i64),
    String(String),
    Array(Vec<CheckScopeValue>),
    Object(BTreeMap<String, CheckScopeValue>),
}

impl CheckScopeValue {
    pub fn at(&self, index: usize) -> Option<&CheckScopeValue> {
        let Self::Array(ref m) = self else {
            return None;
        };
        m.get(index)
    }

    pub fn get(&self, key: impl Borrow<str>) -> Option<&CheckScopeValue> {
        let Self::Object(ref m) = self else {
            return None;
        };
        m.get(key.borrow())
    }

    pub fn as_map(&self) -> Option<&BTreeMap<String, Self>> {
        let Self::Object(ref v) = self else {
            return None;
        };
        Some(v)
    }

    pub fn as_slice(&self) -> Option<&[Self]> {
        let Self::Array(ref v) = self else {
            return None;
        };
        Some(v)
    }

    pub fn as_str(&self) -> Option<&str> {
        let Self::String(ref s) = self else {
            return None;
        };
        Some(s)
    }

    pub fn as_i64(&self) -> Option<i64> {
        let Self::Integer(v) = self else { return None };
        Some(*v)
    }

    pub fn as_bool(&self) -> Option<bool> {
        let Self::Bool(v) = self else { return None };
        Some(*v)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize)]
#[serde(tag = "anchor", content = "args")]
pub enum CheckValidatorLocation {
    #[default]
    #[serde(rename = "anywhere")]
    Anywhere,
    #[serde(rename = "at")]
    At(usize),
    #[serde(rename = "from")]
    From(usize),
    // TODO: matches relative to other check
    // After(Box<CheckValidatorContains>),
    // Before(Box<CheckValidatorContains>),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize)]
pub enum CheckValidatorContainsKind {
    #[default]
    #[serde(rename = "bytes", alias = "raw")]
    Bytes,
    #[serde(rename = "ascii")]
    Ascii,
    #[serde(rename = "utf-8", alias = "utf8")]
    Utf8,
    #[serde(rename = "utf16-le", alias = "utf16le", alias = "utf16")]
    Utf16Le,
    #[serde(rename = "utf16-be", alias = "utf16be")]
    Utf16Be,
    #[serde(rename = "regex")]
    Regex,
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize)]
pub struct CheckValidatorContains {
    pattern: String,
    #[serde(default, rename = "where")]
    location: CheckValidatorLocation,
    // TODO: we may wish to add more options here, e.g. case sensitivity, encoding, etc.
    #[serde(default)]
    kind: CheckValidatorContainsKind,
}

impl CheckValidatorContains {
    fn validate_bytes(&self, bytes: &[u8], anchored: bool) -> Result<bool, CheckerError> {
        use CheckValidatorContainsKind::*;

        match self.kind {
            Bytes => {
                let pat = BMatcher::from_str(&self.pattern)?;
                let found = if anchored {
                    pat.matches_prefix(bytes)
                } else {
                    pat.matches(bytes)
                };
                Ok(found)
            }
            Regex => {
                let re = regex::bytes::Regex::new(&self.pattern)
                    .map_err(CheckerError::malformed_condition)?;
                let found = if anchored {
                    re.is_match_at(bytes, 0)
                } else {
                    re.is_match(bytes)
                };
                Ok(found)
            }
            _ => {
                let encoded = match self.kind {
                    Ascii => StringData::Ascii
                        .encode(&*self.pattern)
                        .map_err(CheckerError::malformed_condition)?,
                    Utf8 => self.pattern.as_bytes().to_vec(),
                    Utf16Le => StringData::Utf16Le
                        .encode(&*self.pattern)
                        .map_err(CheckerError::malformed_condition)?,
                    Utf16Be => StringData::Utf16Be
                        .encode(&*self.pattern)
                        .map_err(CheckerError::malformed_condition)?,
                    _ => unreachable!(),
                };

                let found = if anchored {
                    bytes.starts_with(&encoded)
                } else {
                    memmem::find(bytes, &encoded).is_some()
                };

                Ok(found)
            }
        }
    }

    pub fn validate(&self, binary: &LoadedBinaryComponent) -> Result<bool, CheckerError> {
        let bytes = binary.bytes();
        let bytes_ref = bytes.as_ref();

        match self.location {
            CheckValidatorLocation::Anywhere => self.validate_bytes(bytes_ref, false),
            CheckValidatorLocation::At(offset) => {
                let Some(view) = bytes_ref.get(offset..) else {
                    return Ok(false);
                };
                self.validate_bytes(view, true)
            }
            CheckValidatorLocation::From(offset) => {
                let Some(view) = bytes_ref.get(offset..) else {
                    return Ok(false);
                };
                self.validate_bytes(view, false)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize)]
#[serde(tag = "op", content = "args")]
pub enum CheckValidator {
    // logical operators
    #[serde(rename = "all")]
    And(Vec<CheckValidator>),
    #[serde(rename = "any")]
    Or(Vec<CheckValidator>),
    #[serde(rename = "not")]
    Not(Box<CheckValidator>),
    // validators
    #[serde(rename = "contains")]
    Contains(CheckValidatorContains),
}

impl CheckValidator {
    pub fn validate(&self, binary: &LoadedBinaryComponent) -> Result<bool, CheckerError> {
        match self {
            Self::And(clauses) => {
                for clause in clauses {
                    if !clause.validate(binary)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Self::Or(clauses) => {
                for clause in clauses {
                    if clause.validate(binary)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Self::Not(clause) => Ok(!clause.validate(binary)?),
            Self::Contains(contains) => contains.validate(binary),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize)]
pub struct CheckScopeProjectData {
    #[serde(default)]
    name: Option<CheckScopeValue>,
    #[serde(default)]
    name_with_prefix: Option<CheckScopeValue>,
    #[serde(default)]
    platform: Option<BTreeMap<String, CheckScopeValue>>,
    #[serde(default)]
    validate: Option<CheckValidator>,
}

impl CheckScopeProjectData {
    pub fn name(&self) -> Option<&CheckScopeValue> {
        self.name.as_ref()
    }

    pub fn name_with_prefix(&self) -> Option<&CheckScopeValue> {
        self.name_with_prefix.as_ref()
    }

    pub fn get(&self, key: impl Borrow<str>) -> Option<&CheckScopeValue> {
        self.platform
            .as_ref()
            .and_then(|platform| platform.get(key.borrow()))
    }

    pub fn validate(&self, binary: &LoadedBinaryComponent) -> Result<bool, CheckerError> {
        let Some(validator) = &self.validate else {
            return Ok(true);
        };

        validator.validate(binary)
    }
}

#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureRange {
    project: String,
    from: Option<String>,
    to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureVersion {
    project: String,
    version: String,
}

impl SignatureRange {
    pub fn new(
        project: impl Into<String>,
        from: impl Into<Option<String>>,
        to: impl Into<Option<String>>,
    ) -> Self {
        Self {
            project: project.into(),
            from: from.into(),
            to: to.into(),
        }
    }

    pub fn project(&self) -> &str {
        &self.project
    }

    pub fn from(&self) -> Option<&str> {
        self.from.as_deref()
    }

    pub fn to(&self) -> Option<&str> {
        self.to.as_deref()
    }
}

impl SignatureVersion {
    pub fn new(project: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            project: project.into(),
            version: version.into(),
        }
    }

    pub fn project(&self) -> &str {
        &self.project
    }

    pub fn version(&self) -> &str {
        &self.version
    }
}

#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Deserialize)]
#[serde(untagged)]
pub enum SignatureEntry {
    Range(SignatureRange),
    Version(SignatureVersion),
    File(String),
}

impl Display for SignatureEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Range(r) => write!(
                f,
                "{}@{}..{}",
                r.project(),
                r.from().unwrap_or("*"),
                r.to().unwrap_or("*")
            ),
            Self::Version(v) => write!(f, "{}@{}", v.project(), v.version()),
            Self::File(path) => write!(f, "file:{path}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize)]
#[serde(tag = "kind")]
pub enum CheckScope {
    #[serde(rename = "calls")]
    Calls(Calls),
    #[serde(rename = "functions")]
    FunctionWith(FunctionWith),
    #[serde(rename = "project")]
    ProjectWith(ProjectWith),
}

impl CheckScope {
    #[inline]
    pub fn with(&self) -> &CheckScopeFunction {
        match self {
            Self::Calls(Calls { with, .. })
            | Self::FunctionWith(FunctionWith { with, .. })
            | Self::ProjectWith(ProjectWith { with, .. }) => with,
        }
    }
}

pub type CheckScopeFunction = String;

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct FunctionWith {
    target: Option<FunctionQueryTarget>,
    with: CheckScopeFunction,
}

impl<'de> serde::Deserialize<'de> for FunctionWith {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct FunctionWithT {
            #[serde(default)]
            named: Option<String>,
            #[serde(default)]
            target: Option<FunctionQuery>,
            with: CheckScopeFunction,
        }

        let fields = FunctionWithT::deserialize(deserializer)?;

        let target = match (fields.named, fields.target) {
            (Some(_), Some(_)) => {
                return Err(serde::de::Error::custom(
                    "cannot specify both 'named' and 'target'",
                ));
            }
            (None, None) => None,
            (Some(name), None) => Some(FunctionQueryTarget::Symbol(name.into())),
            (None, Some(q)) => {
                Some(FunctionQueryTarget::try_from(q).map_err(serde::de::Error::custom)?)
            }
        };

        Ok(FunctionWith {
            target,
            with: fields.with,
        })
    }
}

impl FunctionWith {
    #[inline]
    pub fn target(&self) -> Option<&FunctionQueryTarget> {
        self.target.as_ref()
    }

    #[inline]
    pub fn with(&self) -> &CheckScopeFunction {
        &self.with
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize)]
pub struct ProjectWith {
    #[serde(default, rename = "where")]
    data: CheckScopeProjectData,
    with: CheckScopeFunction,
}

impl ProjectWith {
    #[inline]
    pub fn data(&self) -> &CheckScopeProjectData {
        &self.data
    }

    #[inline]
    pub fn with(&self) -> &CheckScopeFunction {
        &self.with
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize)]
pub struct Calls {
    to: CallsToQuery,
    #[serde(rename = "where")]
    where_: Option<String>, // this will be a Lua expression
    using: CheckScopeCallsAnnotations,
    with: CheckScopeFunction,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize)]
pub struct CheckScopeCallsAnnotations {
    #[serde(default)]
    callees: BTreeMap<String, CheckScopeCalleeAnnotations>,
    #[serde(default)]
    parameters: Vec<CheckScopeVarAnnotation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize)]
pub struct CheckScopeCalleeAnnotations {
    #[serde(default)]
    output: Option<CheckScopeVarAnnotation>,
    #[serde(default)]
    inputs: Vec<CheckScopeVarAnnotation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize)]
#[serde(untagged)]
pub enum CheckScopeVarAnnotation {
    Sanitiser {
        sanitiser: bool,
    },
    Named {
        #[serde(default)]
        name: Option<String>,
    },
}

impl Calls {
    #[inline]
    pub fn to(&self) -> &CallsToQuery {
        &self.to
    }

    #[inline]
    pub fn annotations(&self) -> &CheckScopeCallsAnnotations {
        &self.using
    }

    #[inline]
    pub fn with(&self) -> &CheckScopeFunction {
        &self.with
    }

    pub fn eval_where<'a>(&self, fcontext: FunctionContext<'a>) -> Result<bool, CheckerError> {
        let Some(source) = &self.where_ else {
            return Ok(true);
        };

        let context = Lua::new();

        // context.sandbox(true).map_err(CheckerError::Load)?;

        let result = context
            .scope(|scope| {
                // Load function context
                let f = scope.create_userdata(fcontext)?;
                context.globals().set("__current_function", f)?;

                // Load the available API
                context
                    .load(&*SCOPE_CONDITIONS_API)
                    .set_name("bias_core::scope")
                    .exec()?;

                // Eval. the clause
                let result = context.load(source).eval::<bool>()?;

                Ok(result)
            })
            .map_err(CheckerError::Run)?;

        Ok(result)
    }
}

impl CheckScopeCallsAnnotations {
    pub fn get(&self, name: impl AsRef<str>) -> Option<&CheckScopeCalleeAnnotations> {
        self.callees.get(name.as_ref())
    }

    pub fn parameters(&self) -> impl ExactSizeIterator<Item = &CheckScopeVarAnnotation> {
        self.parameters.iter()
    }
}

impl CheckScopeCalleeAnnotations {
    pub fn inputs(&self) -> impl ExactSizeIterator<Item = &CheckScopeVarAnnotation> {
        self.inputs.iter()
    }

    pub fn output(&self) -> Option<&CheckScopeVarAnnotation> {
        self.output.as_ref()
    }
}

impl CheckScopeVarAnnotation {
    pub fn is_named(&self) -> bool {
        matches!(self, Self::Named { .. })
    }

    pub fn is_sanitiser(&self) -> bool {
        matches!(self, Self::Sanitiser { .. })
    }

    pub fn name(&self) -> Option<&str> {
        let Self::Named { name } = self else {
            return None;
        };
        name.as_deref()
    }

    pub fn should_sanitise(&self) -> bool {
        let Self::Sanitiser { sanitiser } = self else {
            return false;
        };
        *sanitiser
    }

    pub fn named_value(&self, at: impl Into<Location>) -> Option<NamedValue> {
        self.name().map(|name| NamedValue::new(name, at.into()))
    }
}

pub struct AnnotatingPlatformTypeResolver<'a> {
    resolver: PlatformTypeResolver<'a>,
    project: &'a Project,
    annotations: Cow<'a, CheckScopeCallsAnnotations>,
    symbols: Option<&'a FunctionSymbolMapping>,
    types: Option<&'a TypeDB>,
}

impl<'a> AnnotatingPlatformTypeResolver<'a> {
    pub fn new(
        resolver: PlatformTypeResolver<'a>,
        project: &'a Project,
        annotations: Cow<'a, CheckScopeCallsAnnotations>,
    ) -> Self {
        Self::new_with(resolver, project, annotations, None, None)
    }

    pub fn new_with(
        resolver: PlatformTypeResolver<'a>,
        project: &'a Project,
        annotations: Cow<'a, CheckScopeCallsAnnotations>,
        symbols: impl Into<Option<&'a FunctionSymbolMapping>>,
        types: impl Into<Option<&'a TypeDB>>,
    ) -> Self {
        Self {
            resolver,
            project,
            annotations,
            symbols: symbols.into(),
            types: types.into(),
        }
    }

    pub fn with_symbols(&mut self, symbols: impl Into<Option<&'a FunctionSymbolMapping>>) {
        self.symbols = symbols.into();
    }

    pub fn with_types(&mut self, types: impl Into<Option<&'a TypeDB>>) {
        self.types = types.into();
    }
}

impl<'a> ContextualTypeResolver<'a> for AnnotatingPlatformTypeResolver<'a> {
    fn resolve_entry_type(&self, context: &mut AliasTypingContext<'a>, function: &'a Function) {
        self.resolver.resolve_entry_type(context, function);

        // NOTE: resolve_entry_type will set appropriate origin information iff the function
        // already has some type information; if not, we will account for this now.

        if self.annotations.parameters.is_empty() {
            return;
        }

        let proto = context.lifter.default_prototype();
        for (i, parameter) in self.annotations.parameters().enumerate() {
            let Some(input) = parameter.named_value(function.address()) else {
                continue;
            };

            // NOTE: working via input_operand here will not work, since it accounts for the
            // current stack pointer properties at a call-site whereas we want to apply it via the
            // raw SP without shifts to the delta.

            match proto.input_operand(i) {
                Some(Operand::Register(reg)) => {
                    context
                        .registers
                        .entry(reg)
                        .and_modify(|vto| {
                            vto.v = AliasValue::sym(input);
                        })
                        .or_insert_with(|| {
                            TypedAliasValue::new(
                                AliasValue::sym(input),
                                AliasType::Top,
                                AliasOrigin::new_before_for(function.address(), &reg, i + 1),
                            )
                        });
                }
                Some(Operand::Stack(delta, _)) => {
                    context
                        .stack_variables
                        .entry(delta)
                        .and_modify(|vto| {
                            vto.v = AliasValue::sym(input);
                        })
                        .or_insert_with(|| {
                            TypedAliasValue::new(
                                AliasValue::sym(input),
                                AliasType::Top,
                                AliasOrigin::new_before_for(function.address(), delta, i + 1),
                            )
                        });
                }
                _ => (),
            }
        }
    }

    fn resolve_intrinsic_with(
        &self,
        context: &mut AliasTypingContext<'a>,
        name: Ustr,
        arguments: Vec<TypedAliasValue>,
        bits: Option<u32>,
    ) -> Option<TypedAliasValue> {
        self.resolver
            .resolve_intrinsic_with(context, name, arguments, bits)
    }

    fn resolve_type_with(
        &self,
        context: &mut AliasTypingContext<'a>,
        target: Option<Address>,
        t: &Term<Type>,
    ) -> Option<ResolvedType> {
        context.sync_pre_call_state();

        let Some(call) = target
            .and_then(|faddr| self.project.function_at(faddr))
            .and_then(|f| {
                self.symbols
                    .and_then(|syms| syms.function_mapping().get(&f.id()).copied())
                    .or_else(|| f.name())
            })
            .and_then(|name| self.annotations.get(name))
        else {
            return self.resolver.resolve_type_with(context, target, t);
        };

        for (index, input) in call.inputs().enumerate() {
            if let Some(named) = input.named_value(context.location) {
                context.update_named_with_input(named, index);
            }
        }

        for (index, input) in call.inputs().enumerate() {
            let Some(operand) = context.input_operand(index) else {
                continue;
            };

            let v = if let Some(named) = input.named_value(context.location) {
                AliasValue::sym(named)
            } else if input.should_sanitise() {
                // if named => clobber
                if operand.v.is_sym() || operand.v.is_sym_ptr() {
                    AliasValue::Top
                } else {
                    operand.v.clone()
                }
            } else {
                continue;
            };

            let t = operand.t.clone();
            let o = operand.o.clone();

            context.update_aliases_by_origin(v, t, o, true);
        }

        if let Some(named) = call
            .output()
            .and_then(|output| output.named_value(context.location))
        {
            let t = context
                .output_operand(0)
                .cloned()
                .map(|v| v.t)
                .unwrap_or(AliasType::Top);

            let operand = TypedAliasValue {
                v: AliasValue::sym(named),
                t,
                o: AliasOrigin::new(context.location),
            };

            context.update_output(0, operand);
            // This must be called after update_output to ensure the output
            // operand is initialised. Otherwise, this function will fail
            // because context.output_operand(0) will be None
            context.update_named_with_output(named, 0);
        }

        self.resolver
            .resolve_type_with(context, target, t)
            .map(ResolvedType::into_preserve)
    }

    fn types(&self) -> Option<&'a TypeDB> {
        self.types
    }
}

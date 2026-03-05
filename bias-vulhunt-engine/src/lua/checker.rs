use std::collections::BTreeMap;
use std::path::Path;
use std::{fs, io};

pub use bias_compat_fwhunt::meta::RuleArch as CheckerArch;
use bias_core::prelude::ArchitectureDef;

use bias::platform::common::flirt::FLIRTSymbolManagerError;
use bias::platform::common::types::TypeManagerError;

use bias::util::tags::BlobTag;
use bias::util::version::VersionParseError;

use bitflags::bitflags;
use mlua::{Lua, LuaSerdeExt, ObjectLike, Table, Value};
use thiserror::Error;

use crate::lua::query::FunctionQueryError;
use crate::lua::types::ir::IRTerm;
use crate::VulHuntModuleDir;

use super::api::{
    AddressValue, CallSiteContext, CheckResult, FunctionContext, PatternMatcher, RegexMatcher,
    FUNCTIONAL, PRELUDE,
};
use super::modules::register_module_loader;
use super::parse_and_preprocess;
use super::project::{PlatformApi, ProjectHandle};
use super::scope::{CheckScope, CheckScopeProjectData, SignatureEntry};
use super::types::BitVec as LuaBitVec;

#[derive(Debug, Error)]
pub enum CheckerError {
    #[error(transparent)]
    Decompiler(anyhow::Error),
    #[error("cannot load checker: {0}")]
    Io(#[from] io::Error),
    #[error("cannot parse and load checker: {0}")]
    Load(mlua::Error),
    #[error("malformed rule: {0}")]
    Malformed(anyhow::Error),
    #[error("malformed condition: {0}")]
    MalformedCondition(anyhow::Error),
    #[error("cannot register module loader: {0}")]
    ModuleLoader(mlua::Error),
    #[error("cannot parse pattern: {0}")]
    Pattern(#[from] bias_compat_fwhunt::bmatch::Error),
    #[error("cannot preprocess rule: {0:#?}")]
    Preprocess(Vec<full_moon::Error>),
    #[error("cannot run checker: {0}")]
    Run(mlua::Error),
    #[error("cannot load required signatures: {0}")]
    Signatures(#[from] FLIRTSymbolManagerError),
    #[error("cannot parse signature path, invalid signature arch: {0}")]
    SignatureArch(String),
    #[error("cannot parse signature path, invalid signature path: {0}")]
    SignaturePathFormat(String),
    #[error("cannot parse signature versions: {0}")]
    SignatureVersionFormat(VersionParseError),
    #[error("cannot load required type database: {0}")]
    Types(#[from] TypeManagerError),
    #[error("invalid query: {0}")]
    FunctionQuery(#[from] FunctionQueryError),
}

impl CheckerError {
    pub fn decompiler<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Decompiler(e.into())
    }

    pub fn decompiler_with(msg: impl Into<String>) -> Self {
        Self::Decompiler(anyhow::Error::msg(msg.into()))
    }

    pub fn malformed<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Malformed(e.into())
    }

    pub fn malformed_with(msg: impl Into<String>) -> Self {
        Self::Malformed(anyhow::Error::msg(msg.into()))
    }

    pub fn malformed_condition<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::MalformedCondition(e.into())
    }

    pub fn malformed_condition_with(msg: impl Into<String>) -> Self {
        Self::MalformedCondition(anyhow::Error::msg(msg.into()))
    }
}

#[derive(Clone)]
pub struct Checker {
    name: String,
    author: String,
    architecture: Vec<CheckerArch>,
    platform: String,
    conditions: CheckScopeProjectData,
    signatures: Vec<SignatureEntry>,
    signature_arch_tags: BTreeMap<ArchitectureDef, BlobTag>,
    types: Option<String>,
    scopes: Vec<CheckScope>,
    extensions: CheckerExtensions,
    code: Vec<u8>,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct CheckerExtensions: u8 {
        const DECOMPILER = 0b0000_0001;
    }
}

impl CheckerExtensions {
    pub fn requires_decompiler(&self) -> bool {
        self.contains(CheckerExtensions::DECOMPILER)
    }
}

#[repr(transparent)]
pub struct CheckerContext(Lua);

impl Checker {
    pub fn from_file(
        path: impl AsRef<Path>,
        module_dir: impl Into<VulHuntModuleDir>,
    ) -> Result<Self, CheckerError> {
        let path = path.as_ref();
        let module_dir = module_dir.into();
        Self::from_str_with(
            path.to_string_lossy(),
            fs::read_to_string(path)?,
            &module_dir,
        )
    }

    fn new_vm(name: &str, code: &[u8], module_dir: Option<&Path>) -> Result<Lua, CheckerError> {
        let context = unsafe { Lua::unsafe_new() };

        // Load the Rust FFI ctors
        AddressValue::register(&context).map_err(CheckerError::Load)?;
        PatternMatcher::register(&context).map_err(CheckerError::Load)?;
        RegexMatcher::register(&context).map_err(CheckerError::Load)?;
        LuaBitVec::register(&context).map_err(CheckerError::Load)?;
        IRTerm::register(&context).map_err(CheckerError::Load)?;

        // Load the prelude
        context
            .load(&*PRELUDE)
            .set_name("bias_core::prelude")
            .exec()
            .map_err(CheckerError::Load)?;

        // Load the prelude
        {
            let fun = context
                .load(&*FUNCTIONAL)
                .set_name("lua::functional")
                .call::<Table>(())
                .map_err(CheckerError::Load)?;

            fun.call::<()>(()).map_err(CheckerError::Load)?;
        }

        // Register the module loader
        register_module_loader(&context, module_dir).map_err(CheckerError::ModuleLoader)?;

        // Load the checker
        let chunk = context.load(code);

        chunk.set_name(name).exec().map_err(CheckerError::Load)?;

        Ok(context)
    }

    pub fn from_str(
        name: impl AsRef<str>,
        script: impl AsRef<str>,
        module_dir: impl Into<VulHuntModuleDir>,
    ) -> Result<Self, CheckerError> {
        Self::from_str_with(name, script, &module_dir.into())
    }

    fn from_str_with(
        name: impl AsRef<str>,
        script: impl AsRef<str>,
        module_dir: &VulHuntModuleDir,
    ) -> Result<Self, CheckerError> {
        let script = parse_and_preprocess(script)?;
        let code = script.as_bytes().to_vec();
        let context = Self::new_vm(name.as_ref(), code.as_ref(), module_dir.as_deref())?;

        let globals = context.globals();

        let Some(name) = globals
            .get::<Option<String>>("name")
            .map_err(CheckerError::Load)?
        else {
            return Err(CheckerError::malformed_with("missing `name`"));
        };

        let Some(author) = globals
            .get::<Option<String>>("author")
            .map_err(CheckerError::Load)?
        else {
            return Err(CheckerError::malformed_with("missing `author`"));
        };

        let Some(platform) = globals
            .get::<Option<String>>("platform")
            .map_err(CheckerError::Load)?
        else {
            return Err(CheckerError::malformed_with("missing `platform`"));
        };

        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum ArchOrArchList {
            Arch(CheckerArch),
            ArchList(Vec<CheckerArch>),
        }

        let Some(architecture) = globals
            .get::<Value>("architecture")
            .and_then(|value| context.from_value::<Option<ArchOrArchList>>(value))
            .map_err(CheckerError::Load)?
        else {
            return Err(CheckerError::malformed_with("missing `architecture`"));
        };

        let architecture = match architecture {
            ArchOrArchList::Arch(architecture) => vec![architecture],
            ArchOrArchList::ArchList(architecture) => {
                if architecture.is_empty() {
                    return Err(CheckerError::malformed_with("no `architecture` specified"));
                } else {
                    architecture
                }
            }
        };

        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum SigOrSigList {
            Sig(SignatureEntry),
            SigList(Vec<SignatureEntry>),
        }

        let signatures = globals
            .get::<Value>("signatures")
            .and_then(|value| context.from_value::<Option<SigOrSigList>>(value))
            .map_err(CheckerError::Load)?
            .unwrap_or_else(|| SigOrSigList::SigList(Vec::with_capacity(0)));

        let mut signatures = match signatures {
            SigOrSigList::Sig(sig) => {
                vec![sig]
            }
            SigOrSigList::SigList(sigs) => sigs,
        };

        // NOTE: this is to ensure we apply signatures deterministically
        signatures.sort();

        let types = globals
            .get::<Value>("types")
            .and_then(|value| context.from_value::<Option<String>>(value))
            .map_err(CheckerError::Load)?;

        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Extensions {
            Ext(String),
            ExtList(Vec<String>),
        }

        let extensions = globals
            .get::<Value>("extensions")
            .and_then(|value| context.from_value::<Option<Extensions>>(value))
            .map_err(CheckerError::Load)?
            .unwrap_or_else(|| Extensions::ExtList(Vec::with_capacity(0)));

        let extensions = match extensions {
            Extensions::Ext(mut ext) => {
                ext.make_ascii_uppercase();
                bitflags::parser::from_str_strict::<CheckerExtensions>(&ext).map_err(|_| {
                    CheckerError::malformed_with(format!("unsupported language extension `{ext}`"))
                })?
            }
            Extensions::ExtList(exts) => exts.into_iter().try_fold(
                CheckerExtensions::empty(),
                |acc, mut ext| -> Result<CheckerExtensions, CheckerError> {
                    ext.make_ascii_uppercase();
                    let ext = bitflags::parser::from_str_strict::<CheckerExtensions>(&ext)
                        .map_err(|_| {
                            CheckerError::malformed_with(format!(
                                "unsupported language extension `{ext}`"
                            ))
                        })?;
                    Ok(ext | acc)
                },
            )?,
        };

        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum ScopeOrScopeList {
            Scope(CheckScope),
            ScopeList(Vec<CheckScope>),
        }

        let Some(scopes) = globals
            .get::<Value>("scopes")
            .and_then(|value| context.from_value::<Option<ScopeOrScopeList>>(value))
            .map_err(CheckerError::Load)?
        else {
            return Err(CheckerError::malformed_with("missing `scopes`"));
        };

        let scopes = match scopes {
            ScopeOrScopeList::Scope(scope) => vec![scope],
            ScopeOrScopeList::ScopeList(scopes) => {
                if scopes.is_empty() {
                    return Err(CheckerError::malformed_with("no `scopes` specified"));
                } else {
                    scopes
                }
            }
        };

        let conditions = globals
            .get::<Value>("conditions")
            .and_then(|value| context.from_value::<Option<CheckScopeProjectData>>(value))
            .map_err(CheckerError::Load)?;

        drop(globals);

        Ok(Self {
            name,
            author,
            platform,
            architecture,
            conditions: conditions.unwrap_or_default(),
            signatures,
            signature_arch_tags: BTreeMap::new(),
            scopes,
            code,
            extensions,
            types,
        })
    }

    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[inline]
    pub fn author(&self) -> &str {
        &self.author
    }

    #[inline]
    pub fn architecture(&self) -> &[CheckerArch] {
        &self.architecture
    }

    #[inline]
    pub fn platform(&self) -> &str {
        &self.platform
    }

    #[inline]
    pub fn signatures(&self) -> &[SignatureEntry] {
        &self.signatures
    }

    #[inline]
    pub(crate) fn signature_arch_tags_mut(&mut self) -> &mut BTreeMap<ArchitectureDef, BlobTag> {
        &mut self.signature_arch_tags
    }

    #[inline]
    pub fn signature_arch_tags(&self) -> &BTreeMap<ArchitectureDef, BlobTag> {
        &self.signature_arch_tags
    }

    #[inline]
    pub fn types(&self) -> Option<&str> {
        self.types.as_deref()
    }

    #[inline]
    pub fn extensions(&self) -> CheckerExtensions {
        self.extensions
    }

    #[inline]
    pub fn scopes(&self) -> &[CheckScope] {
        &self.scopes
    }

    #[inline]
    pub fn conditions(&self) -> &CheckScopeProjectData {
        &self.conditions
    }

    #[inline]
    pub fn context(
        &self,
        module_dir: impl Into<VulHuntModuleDir>,
    ) -> Result<CheckerContext, CheckerError> {
        Self::new_vm(&self.name, &self.code, module_dir.into().as_deref()).map(CheckerContext)
    }
}

impl CheckerContext {
    #[inline]
    pub fn calls<'a, 'd, 'c, P>(
        &self,
        handler: &str,
        project: ProjectHandle<'a, 'd, P>,
        context: CallSiteContext<'c>,
    ) -> Result<Option<CheckResult>, CheckerError>
    where
        P: PlatformApi<'a>,
        'a: 'd,
    {
        self.0
            .scope(|scope| {
                let inputs = self.0.create_sequence_from(
                    context
                        .inputs()
                        .into_iter()
                        .map(|input| scope.create_userdata(input))
                        .collect::<Result<Vec<_>, _>>()?,
                )?;
                let output = scope.create_userdata(context.output())?;
                let context = scope.create_userdata(&context)?;

                let fctx = self.0.create_table()?;

                fctx.set("caller", context)?;
                fctx.set("inputs", inputs)?;
                fctx.set("output", output)?;

                let project = scope.create_userdata(project)?;
                let handlers = self.0.globals().get::<Table>("__scope_handlers")?;

                handlers
                    .call_function::<Value>(handler, (project, fctx))
                    .and_then(|value| self.0.from_value::<Option<CheckResult>>(value))
            })
            .map_err(CheckerError::Run)
    }

    #[inline]
    pub fn function_with<'a, 'd, P>(
        &self,
        handler: &str,
        project: ProjectHandle<'a, 'd, P>,
        context: FunctionContext<'a>,
    ) -> Result<Option<CheckResult>, CheckerError>
    where
        P: PlatformApi<'a>,
        'a: 'd,
    {
        self.0
            .scope(|scope| {
                let context = scope.create_userdata(context)?;
                let project = scope.create_userdata(project)?;
                let handlers = self.0.globals().get::<Table>("__scope_handlers")?;

                let result = handlers
                    .call_function::<Value>(handler, (project, context))
                    .and_then(|value| self.0.from_value::<Option<CheckResult>>(value));

                if let Err(err) = result.as_ref() {
                    tracing::trace!("checker failed: {err}");
                }

                result
            })
            .map_err(CheckerError::Run)
    }

    pub fn project_with<'a, 'd, P>(
        &self,
        handler: &str,
        project: ProjectHandle<'a, 'd, P>,
    ) -> Result<Option<CheckResult>, CheckerError>
    where
        P: PlatformApi<'a>,
        'a: 'd,
    {
        self.0
            .scope(|scope| {
                let project = scope.create_userdata(project)?;
                let handlers = self.0.globals().get::<Table>("__scope_handlers")?;

                handlers
                    .call_function::<Value>(handler, project)
                    .and_then(|value| self.0.from_value::<Option<CheckResult>>(value))
            })
            .map_err(CheckerError::Run)
    }
}

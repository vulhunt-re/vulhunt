use std::any::Any;
use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};

use bias::component::{ComponentLoader, LoadedBinaryComponent};
use bias::platform::PlatformProvider;
use bias::platform::common::data::{PlatformDataProvider, PlatformDataProviderBuilder};
use bias::platform::common::flirt::{
    FLIRTSymbolManager, FLIRTSymbolManagerError, FunctionSymbolMapping,
};
use bias::platform::common::types::{FunctionTypeMapping, TypeManagerError};
use bias::platform::common::{PlatformAttributeMap, SourceFilePath, TypeManager};

use bias::platform::efi::analysis::EFIModuleAnalysis;
use bias::platform::efi::{EFIModule, EFIStandalone};
use bias::platform::posix::PosixBinary;
use bias::platform::posix::analysis::PosixBinaryAnalysis;
use bias::types::Uuid;

use bias_core::decompiler::{DecompilerConfig, DecompilerState};
use bias_core::prelude::*;

#[cfg(feature = "bndb")]
use bias_loader_bndb::BNDBData;

use bias_vulhunt_engine::lua::api::AddressValue;
use bias_vulhunt_engine::lua::project::PlatformApi;
use bias_vulhunt_engine::lua::{ProjectHandle, new_vm};
use bias_vulhunt_engine::{CheckerError, SignatureEntry, flirt_arch_lib_lookup};

use mlua::LuaSerdeExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::tools::{VulHuntSignatureLoadResult, VulHuntTypeLoadResult};

const SUPPORTED_PLATFORMS: &[&str] = &[EFIStandalone::NAME, EFIModule::NAME, PosixBinary::NAME];

macro_rules! project_platform {
    ($slf:ident : $T:ident => $block:stmt) => {
        match $slf.component.platform() {
            EFIStandalone::NAME | EFIModule::NAME => {
                #[allow(unused_imports)]
                use bias::platform::efi::EFIModule as $T;
                $block
            }
            PosixBinary::NAME => {
                #[allow(unused_imports)]
                use bias::platform::posix::PosixBinary as $T;
                $block
            }
            _ => unreachable!(),
        }
    };
}

#[derive(Debug, Error)]
#[error("{path}: {kind}")]
pub struct VulHuntProjectError {
    kind: VulHuntProjectErrorKind,
    path: PathBuf,
}

#[derive(Debug, Error)]
pub enum VulHuntProjectErrorKind {
    #[error("could not initialise analyses: {0}")]
    AnalysisInit(anyhow::Error),
    #[error("could not initialise decompiler: {0}")]
    DecompilerInit(CheckerError),
    #[error("could not load project: {0}")]
    Loader(anyhow::Error),
    #[error("could not initialise Lua virtual machine: {0}")]
    LuaInit(mlua::Error),
    #[error("module directory does not exist or is not a directory: {0}")]
    ModuleDirUnavailable(PathBuf),
    #[error("platform data directory does not exist or is not a directory: {0}")]
    PlatformDataDirUnavailable(PathBuf),
    #[error("error during query execution: {0}")]
    Query(anyhow::Error),
    #[error("unable to read or parse input file")]
    ReadOrParse,
    #[error("unknown function: {0}")]
    UnknownFunction(String),
    #[error("invalid function symbol: {0}")]
    InvalidFunctionSymbol(String),
    #[error("duplicate function symbol: {0}")]
    DuplicateFunctionSymbol(String),
    #[error("could not resolve signature `{0}`: {1}")]
    SignatureResolution(SignatureEntry, CheckerError),
    #[error("could not load signatures: {0}")]
    SignatureLoad(FLIRTSymbolManagerError),
    #[error("could not initialise symbol manager: {0}")]
    SymbolManagerInit(#[from] FLIRTSymbolManagerError),
    #[error("could not load type library `{0}`: {1}")]
    TypeLibraryLoad(String, TypeManagerError),
    #[error("could not initialise type manager: {0}")]
    TypeManagerInit(#[from] TypeManagerError),
    #[error("unsupported file type or platform")]
    Unsupported,
}

impl VulHuntProjectError {
    fn new(kind: VulHuntProjectErrorKind, path: impl AsRef<Path>) -> Self {
        Self {
            kind,
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn kind(&self) -> &VulHuntProjectErrorKind {
        &self.kind
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn analysis_init(
        path: impl AsRef<Path>,
        error: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::new(VulHuntProjectErrorKind::AnalysisInit(error.into()), path)
    }

    fn decompiler_init(path: impl AsRef<Path>, error: impl Into<CheckerError>) -> Self {
        Self::new(VulHuntProjectErrorKind::DecompilerInit(error.into()), path)
    }

    fn loader(
        path: impl AsRef<Path>,
        error: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::new(VulHuntProjectErrorKind::Loader(error.into()), path)
    }

    fn lua_init(path: impl AsRef<Path>, error: mlua::Error) -> Self {
        Self::new(VulHuntProjectErrorKind::LuaInit(error), path)
    }

    fn module_dir_unavailable(path: impl AsRef<Path>, dir: impl AsRef<Path>) -> Self {
        Self::new(
            VulHuntProjectErrorKind::ModuleDirUnavailable(dir.as_ref().to_path_buf()),
            path,
        )
    }

    fn platform_data_dir_unavailable(path: impl AsRef<Path>, dir: impl AsRef<Path>) -> Self {
        Self::new(
            VulHuntProjectErrorKind::PlatformDataDirUnavailable(dir.as_ref().to_path_buf()),
            path,
        )
    }

    fn read_or_parse(path: impl AsRef<Path>) -> Self {
        Self::new(VulHuntProjectErrorKind::ReadOrParse, path)
    }

    fn query(
        path: impl AsRef<Path>,
        error: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::new(VulHuntProjectErrorKind::Query(error.into()), path)
    }

    fn signature_resolution(
        path: impl AsRef<Path>,
        spec: SignatureEntry,
        error: CheckerError,
    ) -> Self {
        Self::new(
            VulHuntProjectErrorKind::SignatureResolution(spec.into(), error),
            path,
        )
    }

    fn signature_load(path: impl AsRef<Path>, error: FLIRTSymbolManagerError) -> Self {
        Self::new(VulHuntProjectErrorKind::SignatureLoad(error), path)
    }

    fn symbol_manager_init(path: impl AsRef<Path>, error: FLIRTSymbolManagerError) -> Self {
        Self::new(VulHuntProjectErrorKind::SymbolManagerInit(error), path)
    }

    pub fn type_library_load(
        path: impl AsRef<Path>,
        library: impl Into<String>,
        error: TypeManagerError,
    ) -> Self {
        Self::new(
            VulHuntProjectErrorKind::TypeLibraryLoad(library.into(), error),
            path,
        )
    }

    fn type_manager_init(path: impl AsRef<Path>, error: TypeManagerError) -> Self {
        Self::new(VulHuntProjectErrorKind::TypeManagerInit(error), path)
    }

    fn unsupported(path: impl AsRef<Path>) -> Self {
        Self::new(VulHuntProjectErrorKind::Unsupported, path)
    }

    fn unknown_function(path: impl AsRef<Path>, symbol: impl Into<String>) -> Self {
        Self::new(
            VulHuntProjectErrorKind::UnknownFunction(symbol.into()),
            path,
        )
    }

    fn invalid_function_symbol(path: impl AsRef<Path>, symbol: impl Into<String>) -> Self {
        Self::new(
            VulHuntProjectErrorKind::InvalidFunctionSymbol(symbol.into()),
            path,
        )
    }

    fn duplicate_function_symbol(path: impl AsRef<Path>, symbol: impl Into<String>) -> Self {
        Self::new(
            VulHuntProjectErrorKind::DuplicateFunctionSymbol(symbol.into()),
            path,
        )
    }
}

struct ProjectData {
    project: Project,
    decompiler_config: DecompilerConfig,
    data_provider: PlatformDataProvider,
}

impl ProjectData {
    fn new(
        data: &PlatformDataProviderBuilder,
        lifter: Lifter,
        path: impl AsRef<Path>,
        component: &mut LoadedBinaryComponent,
    ) -> Result<Self, VulHuntProjectError> {
        let path = path.as_ref();

        match component.platform() {
            EFIStandalone::NAME | EFIModule::NAME => {
                let analyses = EFIModuleAnalysis::new(data)
                    .map_err(|e| VulHuntProjectError::analysis_init(path, e))?;

                let mut project = if let Some(guided) = component.project_loader() {
                    guided
                        .load_project(component, lifter, analyses.configuration())
                        .map_err(|e| VulHuntProjectError::loader(path, e))?
                } else {
                    Project::new_with(component, lifter, analyses.configuration())
                };

                analyses
                    .register_analyses(component, &mut project)
                    .map_err(|e| VulHuntProjectError::analysis_init(path, e))?;
                project
                    .analyse()
                    .map_err(|e| VulHuntProjectError::analysis_init(path, e))?;

                if let Err(e) = analyses.apply_symbols(component, &mut project) {
                    tracing::warn!("could not apply symbols: {e}");
                }

                Ok(Self {
                    project,
                    decompiler_config: analyses.decompiler_configuration().to_owned(),
                    data_provider: analyses.platform_data_provider().to_owned(),
                })
            }
            PosixBinary::NAME => {
                let analyses = PosixBinaryAnalysis::new(data)
                    .map_err(|e| VulHuntProjectError::analysis_init(path, e))?;

                let mut project = if let Some(guided) = component.project_loader() {
                    guided
                        .load_project(component, lifter, analyses.configuration())
                        .map_err(|e| VulHuntProjectError::loader(path, e))?
                } else {
                    Project::new_with(component, lifter, analyses.configuration())
                };

                analyses
                    .register_analyses(component, &mut project)
                    .map_err(|e| VulHuntProjectError::analysis_init(path, e))?;
                project
                    .analyse()
                    .map_err(|e| VulHuntProjectError::analysis_init(path, e))?;

                if let Err(e) = analyses.apply_symbols(component, &mut project) {
                    tracing::warn!("could not apply symbols: {e}");
                }

                Ok(Self {
                    project,
                    decompiler_config: DecompilerConfig::default(),
                    data_provider: analyses.platform_data_provider().to_owned(),
                })
            }
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Deserialize, Serialize)]
pub enum VulHuntLoader {
    #[default]
    #[serde(rename = "component")]
    Component,
    #[cfg(feature = "bndb")]
    #[serde(rename = "bndb")]
    BNDB,
}

pub struct VulHuntProject {
    component: LoadedBinaryComponent<'static>,
    project: Project,
    decompiler: Option<DecompilerState>,
    decompiler_config: DecompilerConfig,
    #[allow(unused)]
    type_manager: TypeManager,
    type_mapping: FunctionTypeMapping,
    #[allow(unused)]
    symbol_manager: FLIRTSymbolManager,
    symbol_mapping: FunctionSymbolMapping,
    #[allow(unused)]
    data_provider: PlatformDataProvider,
    notes: BTreeMap<FunctionId, String>,
    module_dir: Option<PathBuf>,
    // currently this is to allow us to handle custom drop, etc.
    #[allow(unused)]
    loader_data: Option<Box<dyn Any + Send + Sync>>,
}

impl VulHuntProject {
    pub fn new(
        data: &PlatformDataProviderBuilder,
        loader: &ComponentLoader,
        path: impl AsRef<Path>,
        attrs: impl Into<Option<PlatformAttributeMap>>,
    ) -> Result<Self, VulHuntProjectError> {
        let path = path.as_ref();

        if !path.is_file() {
            return Err(VulHuntProjectError::read_or_parse(path));
        }

        let attrs = attrs.into().unwrap_or_default();
        let module_dir = attrs.get_attr::<PathBuf>("modules");
        let loader_override = attrs.get_attr::<VulHuntLoader>("loader");

        let platform_dir_path = data.root_dir();

        if !platform_dir_path.is_dir() {
            return Err(VulHuntProjectError::platform_data_dir_unavailable(
                path,
                platform_dir_path,
            ));
        }

        let (loaded, loader_data) = match loader_override {
            None | Some(VulHuntLoader::Component) => {
                let loaded = loader
                    .load_file_with_attrs(Uuid::now_v7(), path, attrs)
                    .map_err(|e| VulHuntProjectError::loader(path, e))?;
                (loaded, None)
            }
            #[cfg(feature = "bndb")]
            Some(VulHuntLoader::BNDB) => {
                let data = BNDBData::from_file_with(path, attrs)
                    .map_err(|e| VulHuntProjectError::loader(path, e))?;
                let loaded = data
                    .load_as_owned(loader)
                    .map_err(|e| VulHuntProjectError::loader(path, e))?;
                (loaded, Some(Box::new(data) as Box<dyn Any + Send + Sync>))
            }
            #[allow(unreachable_patterns)]
            _ => return Err(VulHuntProjectError::unsupported(path)),
        };

        let (lifter, mut component) = loaded
            .into_binary_parts()
            .ok_or_else(|| VulHuntProjectError::unsupported(path))?;

        if !SUPPORTED_PLATFORMS.contains(&component.platform()) {
            return Err(VulHuntProjectError::unsupported(path));
        }

        let ProjectData {
            project,
            decompiler_config,
            data_provider,
        } = ProjectData::new(data, lifter, path, &mut component)?;

        let type_manager = TypeManager::new(data_provider.clone())
            .map_err(|e| VulHuntProjectError::type_manager_init(path, e))?;
        let symbol_manager = FLIRTSymbolManager::new(data_provider.clone())
            .map_err(|e| VulHuntProjectError::symbol_manager_init(path, e))?;

        let type_mapping = FunctionTypeMapping::from_project(&project);
        let symbol_mapping = FunctionSymbolMapping::from_project(&project);

        let explicit_module_dir =
            module_dir.or_else(|| env::var("BIAS_VULHUNT_MODULES").ok().map(PathBuf::from));

        let module_dir = if let Some(dir) = explicit_module_dir {
            if !dir.is_dir() {
                return Err(VulHuntProjectError::module_dir_unavailable(path, &dir));
            }
            Some(dir)
        } else {
            None
        };

        Ok(Self {
            component,
            project,
            decompiler: None,
            decompiler_config,
            type_manager,
            type_mapping,
            symbol_manager,
            symbol_mapping,
            notes: BTreeMap::new(),
            data_provider,
            module_dir,
            loader_data,
        })
    }

    fn init_decompiler(&mut self) -> Result<(), VulHuntProjectError> {
        if self.decompiler.is_some() {
            return Ok(());
        }

        let attributes = self.component.container();
        let config = self.decompiler_config.clone();

        let (decompiler, _context) = project_platform!(self : P => {
            P::decompiler(
                &self.project,
                config,
                &attributes,
                Some(&self.symbol_mapping),
                Some(&self.type_mapping),
            )
        })
        .map_err(|e| {
            let path = attributes.get_attr::<SourceFilePath>().expect("present");
            VulHuntProjectError::decompiler_init(path, e)
        })?;

        self.decompiler = Some(decompiler.into_state());

        Ok(())
    }

    pub fn update_function_name(
        &mut self,
        old_name: impl AsRef<str>, // may be address, symbol, etc.
        name: impl AsRef<str>,
    ) -> Result<(), VulHuntProjectError> {
        let old_name = old_name.as_ref();
        let name = name.as_ref();

        let attributes = self.component.container();
        let path = attributes.get_attr::<SourceFilePath>().expect("present");

        let Some((old_name, fid)) = self.resolve_function_by_symbol(old_name) else {
            return Err(VulHuntProjectError::unknown_function(path, old_name));
        };

        if name.is_empty() {
            return Err(VulHuntProjectError::invalid_function_symbol(path, name));
        }

        if old_name.is_some_and(|old_name| old_name == name) {
            return Ok(());
        }

        if let Some(known) = Ustr::from_existing(name)
            && self.symbol_mapping.symbol_mapping().contains_key(&known)
        {
            return Err(VulHuntProjectError::duplicate_function_symbol(path, name));
        }

        let f = self.project.functions_mut().get_mut(fid).expect("present");
        let proj_name = f.name();

        f.update_name(name);

        self.symbol_mapping
            .rebind(old_name.or(proj_name), name, fid);

        // if not equal, then we are dealing with a situation where we've got FLIRT overrides or
        // we're working with an address, but they're not applied to the underlying Project, but
        // the Project has a name applied. In this case, we need to rebind the symbol in the
        // Project as well to ensure it's consistent available for queries.
        if proj_name != old_name {
            self.project
                .symbols_mut()
                .rebind(proj_name, name, SymbolRef::function(fid));
        }

        Ok(())
    }

    pub fn function_notes(&self, f: impl AsRef<str>) -> Option<&str> {
        let (_, fid) = self.resolve_function_by_symbol(f)?;
        self.notes.get(&fid).map(AsRef::as_ref)
    }

    pub fn set_function_notes(
        &mut self,
        f: impl AsRef<str>,
        notes: impl Into<String>,
    ) -> Result<(), VulHuntProjectError> {
        let attributes = self.component.container();
        let path = attributes.get_attr::<SourceFilePath>().expect("present");

        let f = f.as_ref();
        let (_, fid) = self
            .resolve_function_by_symbol(f)
            .ok_or_else(|| VulHuntProjectError::unknown_function(path, f))?;

        self.notes.insert(fid, notes.into());

        Ok(())
    }

    fn resolve_function_by_symbol(
        &self,
        symbol: impl AsRef<str>, // may be address, symbol, etc.
    ) -> Option<(Option<Ustr>, FunctionId)> {
        let symbol = symbol.as_ref();
        Ustr::from_existing(symbol)
            .and_then(|s| {
                self.symbol_mapping
                    .symbol_mapping()
                    .get(&s)
                    .copied()
                    .map(|fid| (Some(s), fid))
            })
            .or_else(|| {
                // ugly...
                let name = symbol.strip_prefix("sub_").or_else(|| {
                    symbol
                        .strip_prefix("0x")
                        .or_else(|| symbol.strip_prefix("0X"))
                })?;
                self.project
                    .functions()
                    .get_point(&u64::from_str_radix(name, 16).ok()?.into())
                    .map(|f| {
                        let fid = f.id();
                        let name = self
                            .symbol_mapping
                            .function_mapping()
                            .get(&fid)
                            .copied()
                            .or(f.name());
                        (name, fid)
                    })
            })
    }

    pub fn query(&mut self, query: impl AsRef<str>) -> Result<Value, VulHuntProjectError> {
        // ensure the decompiler is initialised before we run any queries
        self.init_decompiler()?;

        let attributes = self.component.container();
        let decompiler_state = self.decompiler.as_mut().unwrap();

        decompiler_state.apply_with_types(&self.project, self.type_mapping.types(), |decompiler| {
            project_platform!(self : P => {
                let vm = new_vm(self.module_dir.as_deref()).map_err(|e| {
                    let path = attributes.get_attr::<SourceFilePath>().expect("present");
                    VulHuntProjectError::lua_init(path, e)
                })?;

                let mut handle = ProjectHandle::<P>::new(
                    &self.project,
                    &self.symbol_mapping,
                    &self.type_mapping,
                );

                handle.set_decompiler(decompiler);

                vm.scope(|scope| {
                    let project = scope.create_userdata(handle)?;

                    vm.globals().set("project", project)?;

                    let chunk = vm.load(query.as_ref());
                    let result = chunk.set_name("<query>").eval::<mlua::Value>()?;

                    if let Some(ud) = result.as_userdata() {
                        if ud.is::<AddressValue>() {
                            let addr = vm.from_value::<AddressValue>(result)?.value();
                            return Ok(Value::String(format!("{addr:#x}")));
                        }
                    }

                    vm.from_value(result)
                }).map_err(|e| {
                    let path = attributes.get_attr::<SourceFilePath>().expect("present");
                    VulHuntProjectError::query(path, e)
                })
            })
        })
    }

    pub fn load_signatures(
        &mut self,
        entries: impl IntoIterator<Item = SignatureEntry>,
    ) -> Result<VulHuntSignatureLoadResult, VulHuntProjectError> {
        let attributes = self.component.container();
        let path = attributes.get_attr::<SourceFilePath>().expect("present");
        let arch = self.project.lifter().translator().architecture();

        let mut signature_files = Vec::new();

        for entry in entries {
            let mut arch_map = flirt_arch_lib_lookup(&entry, &self.symbol_manager)
                .map_err(|e| VulHuntProjectError::signature_resolution(&path, entry, e))?;

            if let Some(files) = arch_map.remove(arch) {
                signature_files.extend(files.into_iter());
            }
        }

        if signature_files.is_empty() {
            return Ok(VulHuntSignatureLoadResult::new(Vec::new(), 0));
        }

        let new_symbols = self
            .symbol_manager
            .function_symbol_mapping(signature_files.iter(), &self.project)
            .map_err(|e| VulHuntProjectError::signature_load(&path, e))?;

        let matched_functions = new_symbols.function_mapping().len();

        new_symbols.update_type_mapping(&mut self.type_mapping);

        self.symbol_mapping = new_symbols;
        self.decompiler = None;

        Ok(VulHuntSignatureLoadResult::new(
            signature_files,
            matched_functions,
        ))
    }

    pub fn load_types(
        &mut self,
        prefix: impl AsRef<str>,
    ) -> Result<VulHuntTypeLoadResult, VulHuntProjectError> {
        let attributes = self.component.container();
        let path = attributes.get_attr::<SourceFilePath>().expect("present");
        let prefix = prefix.as_ref();

        let type_db = self
            .type_manager
            .get(prefix)
            .map_err(|e| VulHuntProjectError::type_library_load(&path, prefix, e))?;

        let imported_types = type_db.len();

        self.type_mapping.import_types(&type_db);
        self.type_mapping.update(&self.project);

        let matched_functions = self.type_mapping.mapping().len();

        self.decompiler = None;

        Ok(VulHuntTypeLoadResult::new(
            prefix,
            imported_types,
            matched_functions,
        ))
    }
}

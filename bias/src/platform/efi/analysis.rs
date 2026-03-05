use bias_core::analyses::blocks::CodeBlockBounds;
use bias_core::analyses::dataflow::reaching_constants::ReachingConsts;
use bias_core::analyses::functions::{MaybeNonReturning, PropagatedMaybeNonReturning};
use bias_core::analyses::strings::StringsXRefDB;
use bias_core::arch::aarch64::ARCH_AARCH64;
use bias_core::prelude::efi::*;
use bias_core::prelude::*;

use bias_core::decompiler::DecompilerConfig;

use crate::types::property::METADATA_SYMBOLS_PDB;
use crate::types::Property;

use crate::platform::common::data::{
    PlatformDataProvider, PlatformDataProviderBuilder, PlatformDataProviderBuilderError,
    PlatformDataProviderError,
};
use crate::platform::common::fspec::{FunctionSpecDB, FunctionSpecDBError};
use crate::platform::common::PlatformDataDirectoryAttribute;

use super::*;

pub struct EFIModuleAnalysis {
    config: ProjectConfig<'static>,
    fspecs: FunctionSpecDB,
    guiddb: GuidDB,
    typedb: TypeInfoDB,
    platform_data_provider: PlatformDataProvider,
    decompiler_config: DecompilerConfig,
}

#[derive(Debug, Error)]
pub enum EFIModuleAnalysisError {
    #[error("component kind attribute missing")]
    ComponentKindMissing,
    #[error("cannot build platform data provider: {0}")]
    PlatformData(#[from] PlatformDataProviderBuilderError),
    #[error("cannot resolve path via platform data provider: {0}")]
    ResolvePath(#[from] PlatformDataProviderError),
    #[error("cannot load function specifications: {0}")]
    FunctionSpecDB(#[from] FunctionSpecDBError),
    #[error("cannot load GUID database: {0}")]
    GuidDB(#[from] bias_core::efi::guids::Error),
    #[error("cannot load type database: {0}")]
    TypeDB(#[from] bias_core::cio::TypeError),
}

#[derive(Debug, Default, serde::Serialize)]
struct EFISymbols {
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    guid: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    age: Option<u32>,
    used: bool,
}

impl EFISymbols {
    pub fn apply_symbols(
        component: &mut LoadedBinaryComponent,
        _project: &mut Project,
    ) -> Result<Self, PipelineError> {
        let mut meta = Self::default();

        let LoadedBinaryComponentData::EFI(efi) = component.binary() else {
            return Ok(meta);
        };

        let Some(sig) = efi.efi().pdb_signature() else {
            return Ok(meta);
        };

        meta.guid = Some(sig);

        let Some(age) = efi.efi().pdb_age() else {
            return Ok(meta);
        };

        meta.age = Some(age);

        let Some(path) = efi.efi().pdb_path() else {
            return Ok(meta);
        };

        meta.path = Some(path);

        Ok(meta)
    }
}

impl EFIModuleAnalysis {
    pub fn new(
        platform_data_builder: &PlatformDataProviderBuilder,
    ) -> Result<Self, EFIModuleAnalysisError> {
        let platform_data_provider = platform_data_builder.build("uefi")?;

        let guids = platform_data_provider.resolve("/auxiliary/guids.json")?;
        tracing::trace!("loading guid database from {}", guids.display());

        let guiddb = GuidDB::from_file(guids)?;

        let types = platform_data_provider.resolve("/types/edk.h")?;
        tracing::trace!("loading type database from {}", types.display());

        let typedb = TypeInfoDB::from_file(types)?;

        let fspecs = Path::new("/fspecs");
        tracing::trace!("loading function specifications from {}", fspecs.display());

        let fspecs =
            FunctionSpecDB::from_platform_data_with(&platform_data_provider, fspecs, true)?;

        let config = ProjectConfig {
            use_function_specifications: fspecs.specifications().to_vec().into(),
            platform: Some("uefi"),
            ..Default::default()
        };

        Ok(Self {
            config,
            fspecs,
            guiddb,
            typedb,
            platform_data_provider,
            decompiler_config: DecompilerConfig::without_read_only_regions(),
        })
    }

    pub fn configuration(&self) -> &ProjectConfig<'_> {
        &self.config
    }

    pub fn decompiler_configuration(&self) -> &DecompilerConfig {
        &self.decompiler_config
    }

    pub fn specifications(&self) -> &FunctionSpecDB {
        &self.fspecs
    }

    pub fn platform_directory(&self) -> &Path {
        self.platform_data_provider.platform_root_dir()
    }

    pub fn platform_data_provider(&self) -> &PlatformDataProvider {
        &self.platform_data_provider
    }

    pub fn apply_symbols(
        &self,
        component: &mut LoadedBinaryComponent,
        project: &mut Project,
    ) -> Result<Option<Property>, PipelineError> {
        EFISymbols::apply_symbols(component, project).map(|meta| {
            Some(Property::new_metadata(
                component.id(),
                METADATA_SYMBOLS_PDB,
                serde_json::json!({
                    "symbols": {
                        "pdb": meta
                    }
                }),
            ))
        })
    }

    pub fn register_analyses(
        &self,
        component: &mut LoadedBinaryComponent,
        project: &mut Project,
    ) -> Result<(), PipelineError> {
        component.register_platform_attribute(PlatformDataDirectoryAttribute::from(
            self.platform_data_provider.platform_root_dir(),
        ));

        let container = component.container();

        let kind = container
            .get_attr::<EFIComponentKind>()
            .ok_or(EFIModuleAnalysisError::ComponentKindMissing)
            .map_err(PipelineError::analysis)?;

        if project.type_db().is_empty() {
            project.type_db_mut().import_types(&self.typedb);
        }

        if !project.injections().has_stubs() {
            project.register_fixups()?;
        }

        let maybe_non_returning = MaybeNonReturning::new();
        project.analyses_mut().register(maybe_non_returning)?;

        let propagated_non_returning = PropagatedMaybeNonReturning::new();
        project.analyses_mut().register(propagated_non_returning)?;

        let globals_analyser = GlobalsAnalyser::new();
        project.analyses_mut().register(globals_analyser)?;

        let module_info = ModuleInfo::new(component, **kind).map_err(PipelineError::source)?;
        project.analyses_mut().register(module_info)?;

        let block_bounds = CodeBlockBounds::new();
        project.analyses_mut().register(block_bounds)?;

        let services_analyser = ServicesAnalyser::new_with(**kind == EFIModuleType::PeiModule);
        project.analyses_mut().register(services_analyser)?;

        project.analyses_mut().register(self.guiddb.analyser())?;

        let smi_analyser = SmiHandlerAnalyser::new();
        project.analyses_mut().register(smi_analyser)?;

        let strings_analyser = StringsXRefDB::new();
        project.analyses_mut().register(strings_analyser)?;

        if project.lifter().arch().id() == ARCH_AARCH64 {
            project.analyses_mut().register(XRefDB::folded())?;
            project.analyses_mut().register(ReachingConsts::new())?;
        } else {
            project.analyses_mut().register(XRefDB::folded())?;
        };

        Ok(())
    }
}

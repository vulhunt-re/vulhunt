use bias_core::analyses::blocks::CodeBlockBounds;
use bias_core::analyses::dataflow::reaching_constants::ReachingConsts;
use bias_core::analyses::strings::StringsXRefDB;
use bias_core::analyses::types::TypesForImports;
use bias_core::arch::aarch64::ARCH_AARCH64;
use bias_core::posix::non_returning::PropagatedPosixNonReturningExternals;
use bias_core::prelude::*;

use crate::types::property::METADATA_SYMBOLS_ELF;
use crate::types::Property;

use thiserror::Error;

use crate::component::LoadedBinaryComponent;
use crate::pipeline::PipelineError;
use crate::platform::common::data::{
    PlatformDataProvider, PlatformDataProviderBuilder, PlatformDataProviderBuilderError,
    PlatformDataProviderError,
};
use crate::platform::common::fspec::{FunctionSpecDB, FunctionSpecDBError};
use crate::platform::common::PlatformDataDirectoryAttribute;

use super::*;

pub struct PosixBinaryAnalysis {
    typedb: TypeInfoDB,
    fspecs: FunctionSpecDB,
    config: ProjectConfig<'static>,
    platform_data_provider: PlatformDataProvider,
}

#[derive(Debug, Error)]
pub enum PosixBinaryAnalysisError {
    #[error("cannot build platform data provider: {0}")]
    PlatformData(#[from] PlatformDataProviderBuilderError),
    #[error("cannot resolve path via platform data provider: {0}")]
    ResolvePath(#[from] PlatformDataProviderError),
    #[error("cannot load function specifications: {0}")]
    FunctionSpecDB(#[from] FunctionSpecDBError),
    #[error("cannot load type database: {0}")]
    TypeDB(#[from] bias_core::cio::TypeError),
}

impl PosixBinaryAnalysis {
    pub fn new(
        platform_data_builder: &PlatformDataProviderBuilder,
    ) -> Result<Self, PosixBinaryAnalysisError> {
        let platform_data_provider = platform_data_builder.build("posix")?;

        let types = platform_data_provider.resolve("/types/libc.h")?;
        tracing::trace!("loading type database from {}", types.display());
        let typedb = TypeInfoDB::from_file(types)?;

        let fspecs = Path::new("/fspecs");
        tracing::trace!("loading function specifications from {}", fspecs.display());
        let fspecs =
            FunctionSpecDB::from_platform_data_with(&platform_data_provider, fspecs, true)?;

        let config = ProjectConfig {
            use_function_specifications: fspecs.specifications().to_vec().into(),
            platform: Some("posix"),
            ..Default::default()
        };

        Ok(Self {
            typedb,
            fspecs,
            config,
            platform_data_provider,
        })
    }

    pub fn configuration(&self) -> &ProjectConfig<'_> {
        &self.config
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
        Ok(Some(Property::new_metadata(
            component.id(),
            METADATA_SYMBOLS_ELF,
            serde_json::json!({
                "symbols": {
                    "elf": {
                        "used": project.load_symbols(component).is_ok(),
                    }
                }
            }),
        )))
    }

    pub fn register_analyses(
        &self,
        component: &mut LoadedBinaryComponent,
        project: &mut Project,
    ) -> Result<(), PipelineError> {
        component.register_platform_attribute(PlatformDataDirectoryAttribute::from(
            self.platform_data_provider.platform_root_dir(),
        ));

        if project.type_db().is_empty() {
            project.type_db_mut().import_types(&self.typedb);
        }

        if !project.injections().has_stubs() {
            project.register_fixups()?;
        }

        let propagated_non_returning = PropagatedPosixNonReturningExternals::new();
        project.analyses_mut().register(propagated_non_returning)?;

        let types_for_imports = TypesForImports::new();
        project.analyses_mut().register(types_for_imports)?;

        let block_bounds = CodeBlockBounds::new();
        project.analyses_mut().register(block_bounds)?;

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

use std::path::Path;
use std::sync::Arc;

use bias::loader::platform::{BA2CompatibleSource, PlatformLoader};
use bias::loader::BA2LoaderConfig;
use bias::pipeline::PipelineError;

#[cfg(feature = "bndb")]
use bias_loader_bndb::BNDBSource;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum VulHuntLoader {
    #[value(alias("default"))]
    BA2,
    Component,
    UEFI,
    #[cfg(feature = "bndb")]
    BNDB,
}

impl Default for VulHuntLoader {
    fn default() -> Self {
        Self::Component
    }
}

impl VulHuntLoader {
    pub fn has_attributes(&self) -> bool {
        match self {
            Self::Component => true,
            #[cfg(feature = "bndb")]
            Self::BNDB => true,
            _ => false,
        }
    }

    pub fn source_with(
        self,
        input: impl AsRef<Path>,
        config: BA2LoaderConfig,
    ) -> Result<Arc<dyn BA2CompatibleSource>, PipelineError> {
        match self {
            Self::BA2 => PlatformLoader::BA2.source_with(input, config),
            Self::Component => PlatformLoader::Component.source_with(input, config),
            Self::UEFI => PlatformLoader::UEFI.source_with(input, config),
            #[cfg(feature = "bndb")]
            Self::BNDB => {
                use bias::loader::BA2PackageLoader;
                BNDBSource::from_file_and_config(input, config)
                    .map(|s| Arc::new(s) as Arc<dyn BA2CompatibleSource>)
            }
        }
    }
}

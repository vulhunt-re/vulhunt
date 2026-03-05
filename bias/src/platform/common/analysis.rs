use bias_core::analyses::blocks::CodeBlockBounds;
use bias_core::analyses::dataflow::reaching_constants::ReachingConsts;
use bias_core::analyses::strings::StringsXRefDB;
use bias_core::arch::aarch64::ARCH_AARCH64;
use bias_core::prelude::*;

use ustr::UstrMap;

use crate::component::LoadedBinaryComponent;
use crate::pipeline::types::Property;
use crate::pipeline::PipelineError;
use crate::platform::common::data::PlatformDataProviderBuilder;
use crate::platform::efi::analysis::EFIModuleAnalysis;
use crate::platform::efi::EFIModule;
use crate::platform::efi::EFIStandalone;
use crate::platform::posix::analysis::PosixBinaryAnalysis;
use crate::platform::posix::PosixBinary;
use crate::platform::windows::WindowsBinary;
use crate::platform::PlatformProvider;

pub struct DefaultPlatformAnalyses {
    analyses: UstrMap<Box<dyn DefaultPlatformAnalysis>>,
}

impl DefaultPlatformAnalyses {
    pub fn new(platform_data_builder: &PlatformDataProviderBuilder) -> Result<Self, PipelineError> {
        Ok(Self {
            analyses: {
                let mut m = UstrMap::<Box<dyn DefaultPlatformAnalysis>>::default();

                m.insert(
                    EFIModule::NAME.into(),
                    Box::new(
                        EFIModuleAnalysis::new(platform_data_builder)
                            .map_err(PipelineError::analysis)?,
                    ),
                );

                m.insert(
                    EFIStandalone::NAME.into(),
                    Box::new(
                        EFIModuleAnalysis::new(platform_data_builder)
                            .map_err(PipelineError::analysis)?,
                    ),
                );

                m.insert(
                    PosixBinary::NAME.into(),
                    Box::new(
                        PosixBinaryAnalysis::new(platform_data_builder)
                            .map_err(PipelineError::analysis)?,
                    ),
                );

                m.insert(WindowsBinary::NAME.into(), Box::new(CommonAnalysisDefaults));

                m
            },
        })
    }

    pub fn apply_symbols(
        &self,
        component: &mut LoadedBinaryComponent,
        project: &mut Project,
    ) -> Result<Option<Property>, PipelineError> {
        let Some(platform) = Ustr::from_existing(component.platform()) else {
            return Ok(None);
        };

        let Some(analysis) = self.analyses.get(&platform) else {
            return Ok(None);
        };

        analysis.apply_symbols(component, project)
    }

    pub fn register_analyses(
        &self,
        component: &mut LoadedBinaryComponent,
        project: &mut Project,
    ) -> Result<(), PipelineError> {
        let Some(platform) = Ustr::from_existing(component.platform()) else {
            return Ok(());
        };

        let Some(analysis) = self.analyses.get(&platform) else {
            return Ok(());
        };

        analysis.register_analyses(component, project)
    }
}

trait DefaultPlatformAnalysis {
    fn apply_symbols(
        &self,
        component: &mut LoadedBinaryComponent,
        project: &mut Project,
    ) -> Result<Option<Property>, PipelineError>;

    fn register_analyses(
        &self,
        component: &mut LoadedBinaryComponent,
        project: &mut Project,
    ) -> Result<(), PipelineError>;
}

struct CommonAnalysisDefaults;

impl DefaultPlatformAnalysis for CommonAnalysisDefaults {
    fn apply_symbols(
        &self,
        _component: &mut LoadedBinaryComponent,
        _project: &mut Project,
    ) -> Result<Option<Property>, PipelineError> {
        Ok(None)
    }

    fn register_analyses(
        &self,
        _component: &mut LoadedBinaryComponent,
        project: &mut Project,
    ) -> Result<(), PipelineError> {
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

impl DefaultPlatformAnalysis for EFIModuleAnalysis {
    fn apply_symbols(
        &self,
        component: &mut LoadedBinaryComponent,
        project: &mut Project,
    ) -> Result<Option<Property>, PipelineError> {
        EFIModuleAnalysis::apply_symbols(self, component, project)
    }

    fn register_analyses(
        &self,
        component: &mut LoadedBinaryComponent,
        project: &mut Project,
    ) -> Result<(), PipelineError> {
        EFIModuleAnalysis::register_analyses(self, component, project)
    }
}

impl DefaultPlatformAnalysis for PosixBinaryAnalysis {
    fn apply_symbols(
        &self,
        component: &mut LoadedBinaryComponent,
        project: &mut Project,
    ) -> Result<Option<Property>, PipelineError> {
        PosixBinaryAnalysis::apply_symbols(self, component, project)
    }

    fn register_analyses(
        &self,
        component: &mut LoadedBinaryComponent,
        project: &mut Project,
    ) -> Result<(), PipelineError> {
        PosixBinaryAnalysis::register_analyses(self, component, project)
    }
}

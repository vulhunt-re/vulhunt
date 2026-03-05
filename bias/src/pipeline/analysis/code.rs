use std::borrow::Cow;

use bias_core::lifter::Lifter;
use bias_core::{Project, ProjectConfig};

use bias_core::decompiler::DecompilerConfig;

use crate::component::LoadedBinaryComponent;
use crate::pipeline::analysis::{AnalysisGroup, PrefilterWith};
use crate::pipeline::property::{ComponentsAndProperties, Properties};
use crate::pipeline::PipelineError;
use crate::platform::PlatformAttributes;

pub trait AnalysisGroupAnalyserForCode: Send + Sync + 'static {
    #[allow(unused)]
    fn analyse_and_prefilter(
        &self,
        component: &mut LoadedBinaryComponent,
        lifter: &Lifter,
    ) -> Result<PrefilterWith<Properties>, PipelineError> {
        Ok(PrefilterWith::continue_analysis())
    }

    /// This method allows us to analyse the component prior to it being loaded
    /// as a `Project`, and allows us to pre-filter it if necessary, as well as
    //  perform a lighter analysis that does not require the full project data.
    #[allow(unused)]
    fn analyse_and_prefilter_many(
        &self,
        component: &mut LoadedBinaryComponent,
        lifter: &Lifter,
    ) -> Result<PrefilterWith<ComponentsAndProperties>, PipelineError> {
        let filter_and_properties = self.analyse_and_prefilter(component, lifter)?;
        Ok(filter_and_properties.map(ComponentsAndProperties::from))
    }

    fn analyse_and_check(
        &self,
        component: &mut LoadedBinaryComponent,
        project: &mut Project,
    ) -> Result<Properties, PipelineError>;

    /// This method allows us to perform a full analysis of the component, so
    /// long as the pre-filtering step has allowed analysis to continue.
    fn analyse_and_check_many(
        &self,
        component: &mut LoadedBinaryComponent,
        project: &mut Project,
    ) -> Result<ComponentsAndProperties, PipelineError> {
        let properties = self.analyse_and_check(component, project)?;
        Ok(properties.into())
    }

    #[allow(unused)]
    fn configuration<'b>(
        &'b self,
        component: &LoadedBinaryComponent,
    ) -> Cow<'b, ProjectConfig<'b>> {
        Cow::Owned(ProjectConfig::default())
    }

    #[allow(unused)]
    fn decompiler_configuration(&self) -> Cow<'_, DecompilerConfig> {
        Cow::Owned(DecompilerConfig::default())
    }

    #[allow(unused)]
    fn should_analyse(&self, platform: &PlatformAttributes) -> bool {
        true
    }
}

pub struct AnalysisGroupForCode {
    analyser: Box<dyn AnalysisGroupAnalyserForCode>,
}

impl AnalysisGroupForCode {
    pub fn new(analyser: impl AnalysisGroupAnalyserForCode) -> Self {
        Self {
            analyser: Box::new(analyser),
        }
    }

    pub fn configuration<'b>(
        &'b self,
        component: &LoadedBinaryComponent,
    ) -> Cow<'b, ProjectConfig<'b>> {
        self.analyser.configuration(component)
    }

    pub fn decompiler_configuration(&self) -> Cow<'_, DecompilerConfig> {
        self.analyser.decompiler_configuration()
    }

    pub fn analyse_and_prefilter(
        &self,
        component: &mut LoadedBinaryComponent,
        lifter: &Lifter,
    ) -> Result<PrefilterWith<ComponentsAndProperties>, PipelineError> {
        self.analyser.analyse_and_prefilter_many(component, lifter)
    }

    pub fn analyse_and_check(
        &self,
        mut component: LoadedBinaryComponent,
        mut project: Project,
    ) -> Result<ComponentsAndProperties, PipelineError> {
        self.analyser
            .analyse_and_check_many(&mut component, &mut project)
    }
}

impl AnalysisGroup for AnalysisGroupForCode {
    fn should_analyse(&self, platform: &PlatformAttributes) -> bool {
        self.analyser.should_analyse(platform)
    }
}

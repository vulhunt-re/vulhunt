use crate::component::LoadedDataComponent;

use crate::pipeline::analysis::AnalysisGroup;
use crate::pipeline::property::{ComponentsAndProperties, Properties};
use crate::pipeline::PipelineError;
use crate::platform::PlatformAttributes;

pub trait AnalysisGroupAnalyserForData: Send + Sync + 'static {
    fn analyse_and_check(
        &self,
        component: &mut LoadedDataComponent,
    ) -> Result<Properties, PipelineError>;

    fn analyse_and_check_many(
        &self,
        component: &mut LoadedDataComponent,
    ) -> Result<ComponentsAndProperties, PipelineError> {
        let properties = self.analyse_and_check(component)?;
        Ok(properties.into())
    }

    #[allow(unused)]
    fn should_analyse(&self, platform: &PlatformAttributes) -> bool {
        true
    }
}

pub struct AnalysisGroupForData {
    analyser: Box<dyn AnalysisGroupAnalyserForData>,
}

impl AnalysisGroupForData {
    pub fn new(analyser: impl AnalysisGroupAnalyserForData) -> Self {
        Self {
            analyser: Box::new(analyser),
        }
    }

    pub fn analyse_and_check(
        &self,
        mut component: LoadedDataComponent,
    ) -> Result<ComponentsAndProperties, PipelineError> {
        self.analyser.analyse_and_check_many(&mut component)
    }
}

impl AnalysisGroup for AnalysisGroupForData {
    fn should_analyse(&self, platform: &PlatformAttributes) -> bool {
        self.analyser.should_analyse(platform)
    }
}

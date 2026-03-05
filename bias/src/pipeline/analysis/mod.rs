use bias_core::Project;

use crate::component::{LoadedBinaryComponent, LoadedDataComponent};
use crate::platform::PlatformAttributes;

use super::{ComponentsAndProperties, PipelineError, Properties};

pub mod code;
pub mod data;

pub use self::code::{AnalysisGroupAnalyserForCode, AnalysisGroupForCode};
pub use self::data::{AnalysisGroupAnalyserForData, AnalysisGroupForData};

pub struct PrefilterWith<T> {
    should_filter: bool,
    result: T,
}

impl<T> PrefilterWith<T> {
    pub fn new(result: T) -> Self {
        Self {
            should_filter: false,
            result,
        }
    }

    pub fn set_filter(&mut self, should_filter: bool) {
        self.should_filter = should_filter;
    }

    pub fn with_filter(mut self, should_filter: bool) -> Self {
        self.set_filter(should_filter);
        self
    }

    pub fn continue_analysis() -> Self
    where
        T: Default,
    {
        Self {
            should_filter: false,
            result: T::default(),
        }
    }

    pub fn continue_analysis_with(result: T) -> Self {
        Self {
            should_filter: false,
            result,
        }
    }

    pub fn and_continue_analysis(self) -> Self {
        PrefilterWith {
            should_filter: false,
            result: self.result,
        }
    }

    pub fn skip_analysis() -> Self
    where
        T: Default,
    {
        Self {
            should_filter: true,
            result: T::default(),
        }
    }

    pub fn skip_analysis_with(result: T) -> Self {
        Self {
            should_filter: true,
            result,
        }
    }

    pub fn and_skip_analysis(self) -> Self {
        PrefilterWith {
            should_filter: true,
            result: self.result,
        }
    }

    pub fn should_filter(&self) -> bool {
        self.should_filter
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> PrefilterWith<U> {
        PrefilterWith {
            should_filter: self.should_filter,
            result: f(self.result),
        }
    }
}

impl From<Properties> for PrefilterWith<Properties> {
    fn from(properties: Properties) -> Self {
        PrefilterWith::new(properties)
    }
}

impl From<ComponentsAndProperties> for PrefilterWith<ComponentsAndProperties> {
    fn from(components_and_properties: ComponentsAndProperties) -> Self {
        PrefilterWith::new(components_and_properties)
    }
}

impl PrefilterWith<ComponentsAndProperties> {
    pub fn into_components_and_properties(self) -> ComponentsAndProperties {
        self.result
    }
}

pub trait AnalysisGroup: Send + Sync + 'static {
    #[allow(unused)]
    fn should_analyse(&self, platform: &PlatformAttributes) -> bool {
        true
    }
}

pub struct NoOpAnalysisGroup;

impl AnalysisGroupAnalyserForData for NoOpAnalysisGroup {
    fn analyse_and_check(
        &self,
        _component: &mut LoadedDataComponent,
    ) -> Result<Properties, PipelineError> {
        Ok(Properties::default())
    }
}

impl AnalysisGroupAnalyserForCode for NoOpAnalysisGroup {
    fn analyse_and_check(
        &self,
        _component: &mut LoadedBinaryComponent,
        _project: &mut Project,
    ) -> Result<Properties, PipelineError> {
        Ok(Properties::default())
    }
}

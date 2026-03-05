use crate::component::Component;
use crate::package::Package;
use crate::pipeline::property::Property;
use crate::pipeline::sink::{ClonableSink, Sink};
use crate::pipeline::source::{ClonableSource, PackageDependencyGraph};
use crate::pipeline::{Pipeline, PipelineError};

use indicatif::{ProgressBar, ProgressStyle};
use uuid::Uuid;

#[derive(Clone)]
pub struct ProgressMonitorSink<T> {
    inner: T,
    progress: ProgressBar,
}

#[async_trait::async_trait]
impl<T: Sink> Sink for ProgressMonitorSink<T> {
    async fn push_package(
        &self,
        package: Package,
        dependencies: PackageDependencyGraph,
    ) -> Result<(), PipelineError> {
        self.progress.inc(1);
        self.progress.set_message(format!(
            "analysing package {}",
            package.id().as_hyphenated()
        ));
        self.inner.push_package(package, dependencies).await
    }

    async fn push_component(&self, pid: Uuid, component: Component) -> Result<(), PipelineError> {
        self.progress.inc(1);
        self.progress.set_message(format!(
            "analysing component {}",
            component.id().as_hyphenated()
        ));
        self.inner.push_component(pid, component).await
    }

    async fn push_component_property(
        &self,
        pid: Uuid,
        cid: Uuid,
        property: Property,
    ) -> Result<(), PipelineError> {
        self.progress
            .set_message(format!("analysing component {} 💥", cid.as_hyphenated()));
        self.inner.push_component_property(pid, cid, property).await
    }

    async fn push_package_property(
        &self,
        pid: Uuid,
        property: Property,
    ) -> Result<(), PipelineError> {
        self.progress
            .set_message(format!("analysing package {} 💥", pid.as_hyphenated()));
        self.inner.push_package_property(pid, property).await
    }

    async fn push_package_status(&self, pid: Uuid, components: usize) -> Result<(), PipelineError> {
        self.inner.push_package_status(pid, components).await
    }

    async fn push_component_status(
        &self,
        pid: Uuid,
        cid: Uuid,
        err: Option<PipelineError>,
    ) -> Result<(), PipelineError> {
        self.inner.push_component_status(pid, cid, err).await
    }
}

impl<T: Sink> ProgressMonitorSink<T> {
    fn new(inner: T) -> Self {
        let spinner =
            ProgressStyle::with_template("{elapsed_precise:.bold.dim} {spinner} {wide_msg}")
                .unwrap()
                .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ");

        Self {
            inner,
            progress: ProgressBar::new(u64::MAX)
                .with_style(spinner)
                .with_message("analysing..."),
        }
    }

    fn start(&self) {
        self.progress.tick();
    }

    fn finish(&self) {
        if !self.progress.is_finished() {
            self.progress.finish_and_clear();
        }
    }

    pub async fn run_pipeline<S>(
        source: S,
        sink: T,
        pipeline: &Pipeline,
    ) -> Result<(), PipelineError>
    where
        S: ClonableSource,
        T: ClonableSink + Clone,
    {
        let progress = Self::new(sink);
        progress.start();
        let result = pipeline.run(source, progress.clone()).await;
        progress.finish();
        result
    }
}

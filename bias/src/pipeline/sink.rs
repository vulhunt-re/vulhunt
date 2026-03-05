use std::ops::Deref;
use std::sync::Arc;

use async_trait::async_trait;
use dyn_clone::DynClone;
use uuid::Uuid;

use crate::component::Component;
use crate::package::Package;

use super::property::Property;
use super::source::PackageDependencyGraph;
use super::PipelineError;

#[async_trait]
pub trait Sink: Send + Sync {
    async fn push_package(
        &self,
        package: Package,
        dependencies: PackageDependencyGraph,
    ) -> Result<(), PipelineError>;

    // pid -> component
    async fn push_component(&self, pid: Uuid, component: Component) -> Result<(), PipelineError>;

    // (pid, cid) -> property
    async fn push_component_property(
        &self,
        pid: Uuid,
        cid: Uuid,
        property: Property,
    ) -> Result<(), PipelineError>;

    async fn push_package_property(
        &self,
        pid: Uuid,
        property: Property,
    ) -> Result<(), PipelineError>;

    #[allow(unused)]
    async fn push_package_status(&self, pid: Uuid, components: usize) -> Result<(), PipelineError> {
        Ok(())
    }

    #[allow(unused)]
    async fn push_component_status(
        &self,
        pid: Uuid,
        cid: Uuid,
        err: Option<PipelineError>,
    ) -> Result<(), PipelineError> {
        Ok(())
    }
}

pub trait ClonableSink: Sink + DynClone + 'static {}

dyn_clone::clone_trait_object!(ClonableSink);

impl<T> ClonableSink for T where T: Sink + Clone + 'static {}

#[async_trait]
impl<T> Sink for Arc<T>
where
    T: Sink + ?Sized,
{
    async fn push_package(
        &self,
        package: Package,
        dependencies: PackageDependencyGraph,
    ) -> Result<(), PipelineError> {
        self.deref().push_package(package, dependencies).await
    }

    async fn push_component(&self, pid: Uuid, component: Component) -> Result<(), PipelineError> {
        self.deref().push_component(pid, component).await
    }

    async fn push_component_property(
        &self,
        pid: Uuid,
        cid: Uuid,
        property: Property,
    ) -> Result<(), PipelineError> {
        self.deref()
            .push_component_property(pid, cid, property)
            .await
    }

    async fn push_package_property(
        &self,
        pid: Uuid,
        property: Property,
    ) -> Result<(), PipelineError> {
        self.deref().push_package_property(pid, property).await
    }

    async fn push_package_status(&self, pid: Uuid, components: usize) -> Result<(), PipelineError> {
        self.deref().push_package_status(pid, components).await
    }

    async fn push_component_status(
        &self,
        pid: Uuid,
        cid: Uuid,
        err: Option<PipelineError>,
    ) -> Result<(), PipelineError> {
        self.deref().push_component_status(pid, cid, err).await
    }
}

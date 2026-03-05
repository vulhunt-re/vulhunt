use std::borrow::Cow;
use std::collections::BTreeMap;

use bias_core::kb::Uuid;

use crate::component::{Component, ComponentIdentity};
use crate::pipeline::source::{
    AnalysisGroupFilter, PackageComponentItem, PackageComponentItemQueue, PackageDependencyGraph,
    PackageItem, PackageItemQueue, Source,
};
use crate::pipeline::{PipelineAnalysisGroups, PipelineError};
use crate::platform::Platform;
use crate::util::BytesOrMapping;

pub use crate::types::package::*;

#[derive(Debug, Clone)]
pub struct PackageData<'a> {
    pub(crate) package: Package,
    pub(crate) dependencies: Cow<'a, PackageDependencyGraph>,
}

impl<'a> PackageData<'a> {
    pub fn new(package: Package, dependencies: impl Into<Cow<'a, PackageDependencyGraph>>) -> Self {
        Self {
            package,
            dependencies: dependencies.into(),
        }
    }

    pub fn package(&self) -> &Package {
        &self.package
    }

    pub fn dependencies(&self) -> &PackageDependencyGraph {
        self.dependencies.as_ref()
    }

    pub fn into_owned(self) -> PackageData<'static> {
        PackageData {
            package: self.package,
            dependencies: Cow::Owned(self.dependencies.into_owned()),
        }
    }

    pub fn into_parts(self) -> (Package, Cow<'a, PackageDependencyGraph>) {
        (self.package, self.dependencies)
    }
}

pub struct PackageComponentData<'a> {
    pub(crate) id: Uuid,
    pub(crate) package: Option<Uuid>,
    pub(crate) component: Cow<'a, Component>,
    pub(crate) bytes: BytesOrMapping<'a>,
    pub(crate) platform: Cow<'a, Platform>,
}

impl<'a> PackageComponentData<'a> {
    pub fn new(
        id: Uuid,
        component: Component,
        bytes: impl Into<BytesOrMapping<'a>>,
        platform: Platform,
    ) -> Self {
        Self {
            id,
            package: None,
            component: Cow::Owned(component),
            bytes: bytes.into(),
            platform: Cow::Owned(platform),
        }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn global_id(&self) -> Option<ComponentIdentity> {
        self.component.global_component_id()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn package(&self) -> Option<Uuid> {
        self.package
    }

    pub fn set_package(&mut self, package: Uuid) {
        self.package = Some(package);
    }

    pub fn with_package(mut self, package: Uuid) -> Self {
        self.set_package(package);
        self
    }

    pub fn platform(&self) -> &Platform {
        &self.platform
    }

    pub fn into_data(self) -> Self {
        Self {
            id: self.id,
            package: self.package,
            component: self.component,
            bytes: self.bytes,
            platform: Cow::Owned(self.platform.into_owned().into_data()),
        }
    }

    pub fn into_owned(self) -> PackageComponentData<'static> {
        PackageComponentData {
            id: self.id,
            package: self.package,
            component: Cow::Owned(self.component.into_owned()),
            bytes: self.bytes.into_owned(),
            platform: Cow::Owned(self.platform.into_owned()),
        }
    }

    pub fn into_parts(self) -> (Uuid, BytesOrMapping<'a>, Cow<'a, Platform>) {
        (self.id, self.bytes, self.platform)
    }
}

pub struct PackageSource<'data> {
    package: Package,
    components: BTreeMap<Uuid, PackageComponentData<'data>>,
    dependencies: PackageDependencyGraph,
}

impl<'data> PackageSource<'data> {
    pub fn new(package: Package) -> Self {
        Self {
            package,
            components: BTreeMap::new(),
            dependencies: PackageDependencyGraph::new(),
        }
    }

    pub fn push(&mut self, component: PackageComponentData<'data>) {
        self.dependencies
            .add_entity_with(component.id(), component.platform());
        self.components.insert(component.id(), component);
    }
}

#[async_trait::async_trait]
impl<'data> Source for PackageSource<'data> {
    async fn fetch_component_if(
        &self,
        cid: PackageComponentItem,
        f: AnalysisGroupFilter<'_>,
    ) -> Result<Option<PackageComponentData>, PipelineError> {
        Ok(self.components.get(&cid.id()).and_then(|slf| {
            if f.should_analyse(slf.platform.as_ref()) {
                Some(
                    PackageComponentData::new(
                        slf.id,
                        slf.component.as_ref().to_owned(),
                        slf.bytes.as_ref(),
                        slf.platform.as_ref().to_owned(),
                    )
                    .with_package(self.package.id()),
                )
            } else {
                None
            }
        }))
    }

    async fn fetch_package<'a>(
        &'a self,
        pid: PackageItem,
    ) -> Result<Option<PackageData<'a>>, PipelineError> {
        if pid.id() != self.package.id() {
            return Ok(None);
        }

        Ok(Some(PackageData {
            package: self.package.clone(),
            dependencies: Cow::Borrowed(&self.dependencies),
        }))
    }

    async fn stream_packages(&self, queue: PackageItemQueue) -> Result<(), PipelineError> {
        queue
            .send_async(PackageItem::new(self.package.id()))
            .await
            .map_err(PipelineError::source)
    }

    async fn stream_package_components(
        &self,
        pid: PackageItem,
        analysis_groups: PipelineAnalysisGroups,
        queue: PackageComponentItemQueue,
    ) -> Result<(), PipelineError> {
        for (&uuid, meta) in self
            .dependencies
            .entities()
            .filter(|(_, meta)| analysis_groups.should_analyse(meta))
        {
            queue
                .send_async(PackageComponentItem::new(uuid, pid.clone(), meta))
                .await
                .map_err(PipelineError::source)?;
        }

        Ok(())
    }
}

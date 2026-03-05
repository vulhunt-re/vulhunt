use std::borrow::Cow;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;
use uuid::Uuid;

use crate::component::ComponentError;
use crate::loader::meta::{BA2ComponentMetadata, BA2ComponentMetadataSource};
use crate::loader::{BA2LoaderConfig, BA2PackageLoader};
use crate::package::{
    Package, PackageBuilder, PackageComponentData, PackageData, PackageError, PackageHashes,
};
use crate::pipeline::source::{
    AnalysisGroupFilter, PackageComponentItemQueue, PackageDependencyGraph, PackageItem,
    PackageItemQueue,
};
use crate::pipeline::{
    Component, PackageComponentItem, PipelineAnalysisGroups, PipelineError, Source,
};
use crate::platform::common::PlatformAttributeMap;
use crate::platform::{Platform, PlatformError};
use crate::util::BytesOrMapping;

#[derive(Debug, Error)]
pub enum ComponentSourceError {
    #[error("failed to load component from file: {0}: {1}")]
    Io(PathBuf, #[source] io::Error),
    #[error("failed to build component metadata: {0}")]
    Metadata(#[from] ComponentError),
    #[error("failed to build package metadata: {0}")]
    Package(#[from] PackageError),
    #[error(transparent)]
    Unsupported(#[from] PlatformError),
}

pub struct ComponentSource<'a> {
    package: Package,
    bytes: BytesOrMapping<'a>,
    metadata: BA2ComponentMetadata,
    platform: Platform,
    dependencies: PackageDependencyGraph,
}

impl<'a> ComponentSource<'a> {
    pub fn from_bytes(
        bytes: impl Into<BytesOrMapping<'a>>,
        path: impl AsRef<Path>,
    ) -> Result<Self, ComponentSourceError> {
        Self::from_bytes_with(bytes, path, None)
    }

    pub fn from_bytes_with(
        bytes: impl Into<BytesOrMapping<'a>>,
        path: impl AsRef<Path>,
        attrs: impl Into<Option<PlatformAttributeMap>>,
    ) -> Result<Self, ComponentSourceError> {
        let path = path.as_ref();
        let bytes = bytes.into();
        let attrs = attrs.into();
        let metadata = BA2ComponentMetadata::from_bytes_and_attrs_with(
            &*bytes,
            path.to_owned(),
            attrs.clone(),
        )?;

        let name = path
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_else(|| path.to_string_lossy());

        let package = PackageBuilder::new()
            .with_id(Uuid::now_v7())
            .with_name(name)
            .with_path(path.display().to_string())
            .with_hashes(PackageHashes::new(bytes.as_ref()))
            .build()?;

        let platform = metadata
            .platform()
            .expect("metadata platform should be valid");

        let mut dependencies = PackageDependencyGraph::new();
        dependencies.add_entity_with(metadata.id(), &platform);

        Ok(Self {
            package,
            bytes,
            metadata,
            platform,
            dependencies,
        })
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ComponentSourceError> {
        Self::from_file_with(path, None)
    }

    pub fn from_file_with(
        path: impl AsRef<Path>,
        attrs: impl Into<Option<PlatformAttributeMap>>,
    ) -> Result<Self, ComponentSourceError> {
        let path = path.as_ref();
        let attrs = attrs.into();
        let bytes = BytesOrMapping::from_file(path)
            .map_err(|e| ComponentSourceError::Io(path.to_owned(), e))?;

        Self::from_bytes_with(bytes, path, attrs)
    }

    fn package_id(&self) -> Uuid {
        self.package.id()
    }

    fn component_id(&self) -> Uuid {
        self.metadata.id()
    }
}

#[async_trait::async_trait]
impl<'a> Source for ComponentSource<'a> {
    async fn fetch_component_if(
        &self,
        cid: PackageComponentItem,
        f: AnalysisGroupFilter<'_>,
    ) -> Result<Option<PackageComponentData>, PipelineError> {
        let pid = cid.package().id();
        let cid = cid.id();

        let component = self
            .component_by_uuid(&pid, &cid)
            .map_err(PipelineError::source)?;

        Ok(component.filter(|p| f.should_analyse(p.platform())))
    }

    async fn fetch_package<'source>(
        &'source self,
        pid: PackageItem,
    ) -> Result<Option<PackageData<'source>>, PipelineError> {
        if pid.id() != self.package_id() {
            return Ok(None);
        }

        let package = PackageData::new(self.package.clone(), Cow::Borrowed(&self.dependencies));

        Ok(Some(package))
    }

    async fn stream_packages(&self, queue: PackageItemQueue) -> Result<(), PipelineError> {
        queue
            .send_async(PackageItem::new(self.package_id()))
            .await
            .map_err(PipelineError::source)
    }

    async fn stream_package_components(
        &self,
        pid: PackageItem,
        analysis_groups: PipelineAnalysisGroups,
        queue: PackageComponentItemQueue,
    ) -> Result<(), PipelineError> {
        if pid.id() != self.package_id() {
            return Ok(());
        }

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

impl<'a> BA2PackageLoader<'a> for ComponentSource<'a> {
    fn from_file_and_config(
        path: impl AsRef<Path>,
        config: impl Into<Option<BA2LoaderConfig>>,
    ) -> Result<Self, PipelineError> {
        let config = config.into();
        let (id, attrs) = config.map(|c| (c.package_identifier, c.attributes)).unzip();
        let attrs = attrs.map(PlatformAttributeMap::from);

        let mut slf = Self::from_file_with(path, attrs).map_err(PipelineError::source)?;

        if let Some(id) = id.flatten() {
            slf.package.set_id(id);
        }

        Ok(slf)
    }

    fn should_analyse(_path: impl AsRef<Path>) -> bool {
        true
    }

    fn package_by_uuid<'loader>(&'loader self, pid: &Uuid) -> Option<Cow<'loader, Package>> {
        if *pid != self.package_id() {
            return None;
        }
        Some(Cow::Borrowed(&self.package))
    }

    fn component_by_uuid<'loader>(
        &'loader self,
        pid: &Uuid,
        cid: &Uuid,
    ) -> Result<Option<PackageComponentData<'loader>>, PipelineError> {
        if *pid != self.package_id() || *cid != self.component_id() {
            return Ok(None);
        }

        let component = Component::try_from(&self.metadata)
            .map_err(PipelineError::source)?
            .with_package_id(self.package.id());

        Ok(Some(PackageComponentData::new(
            self.component_id(),
            component,
            &*self.bytes,
            self.platform.clone(),
        )))
    }

    fn components<'loader>(&'loader self, pid: &Uuid) -> impl Iterator<Item = Uuid> + 'loader {
        (*pid == self.package_id())
            .then(|| std::iter::once(self.component_id()))
            .into_iter()
            .flatten()
    }
}

impl<'a> BA2ComponentMetadataSource for ComponentSource<'a> {
    fn component_meta_by_uuid<'source>(
        &'source self,
        pid: &Uuid,
        cid: &Uuid,
    ) -> Result<Option<Cow<'source, BA2ComponentMetadata>>, PipelineError> {
        if *pid != self.package_id() || *cid != self.component_id() {
            return Ok(None);
        }

        Ok(Some(Cow::Borrowed(&self.metadata)))
    }
}

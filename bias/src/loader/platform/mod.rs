use std::borrow::Cow;
use std::ops::Deref;
use std::path::Path;
use std::sync::Arc;

use uuid::Uuid;

use crate::component::{ComponentLoader, LoadedComponent};
use crate::package::{Package, PackageComponentData, PackageData};
use crate::pipeline::source::{
    AnalysisGroupFilter, DataSource, PackageComponentItemQueue, PackageItem, PackageItemQueue,
    Source,
};
use crate::pipeline::{PackageComponentItem, PipelineAnalysisGroups, PipelineError};

use crate::loader::meta::{BA2ComponentMetadata, BA2ComponentMetadataSource};
use crate::loader::{BA2Loader, BA2LoaderConfig, BA2PackageLoader};
use crate::platform::Platform;
use crate::util::BytesOrMapping;

pub mod common;
pub mod component;
pub mod efi;

impl<T> BA2ComponentMetadataSource for DataSource<T>
where
    T: BA2ComponentMetadataSource + Source,
{
    fn component_meta_by_uuid<'a>(
        &'a self,
        pid: &Uuid,
        cid: &Uuid,
    ) -> Result<Option<Cow<'a, BA2ComponentMetadata>>, PipelineError> {
        AsRef::<T>::as_ref(self).component_meta_by_uuid(pid, cid)
    }
}

impl<'a, T> BA2PackageLoader<'a> for DataSource<T>
where
    T: BA2PackageLoader<'a> + BA2ComponentMetadataSource + Source,
{
    fn from_file_and_config(
        path: impl AsRef<Path>,
        config: impl Into<Option<BA2LoaderConfig>>,
    ) -> Result<Self, PipelineError> {
        let inner = T::from_file_and_config(path, config)?;
        Ok(DataSource::new(inner))
    }

    fn should_analyse(path: impl AsRef<Path>) -> bool {
        T::should_analyse(path)
    }

    fn package_by_uuid<'loader>(&'loader self, pid: &Uuid) -> Option<Cow<'loader, Package>> {
        T::package_by_uuid(self, pid)
    }

    fn component_by_uuid(
        &self,
        pid: &Uuid,
        cid: &Uuid,
    ) -> Result<Option<PackageComponentData>, PipelineError> {
        Ok(AsRef::<T>::as_ref(self)
            .component_by_uuid(pid, cid)?
            .map(|c| c.into_data()))
    }

    fn components<'loader>(&'loader self, pid: &Uuid) -> impl Iterator<Item = Uuid> + 'loader {
        AsRef::<T>::as_ref(self).components(pid)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum PlatformLoader {
    #[value(alias("default"))]
    BA2,
    Component,
    UEFI,
}

impl Default for PlatformLoader {
    fn default() -> Self {
        Self::BA2
    }
}

impl PlatformLoader {
    pub fn has_attributes(&self) -> bool {
        matches!(self, Self::Component)
    }
}

pub trait BA2CompatibleSource: BA2ComponentMetadataSource + Source {}

impl<T> BA2CompatibleSource for T where T: BA2ComponentMetadataSource + Source {}

#[async_trait::async_trait]
impl Source for Box<dyn BA2CompatibleSource> {
    async fn fetch_component_if<'a>(
        &'a self,
        cid: PackageComponentItem,
        filter: AnalysisGroupFilter<'_>,
    ) -> Result<Option<PackageComponentData<'a>>, PipelineError> {
        self.deref().fetch_component_if(cid, filter).await
    }

    async fn fetch_component<'a>(
        &'a self,
        cid: PackageComponentItem,
    ) -> Result<Option<PackageComponentData<'a>>, PipelineError> {
        self.deref().fetch_component(cid).await
    }

    async fn fetch_package<'a>(
        &'a self,
        pid: PackageItem,
    ) -> Result<Option<PackageData<'a>>, PipelineError> {
        self.deref().fetch_package(pid).await
    }

    async fn stream_packages(&self, queue: PackageItemQueue) -> Result<(), PipelineError> {
        self.deref().stream_packages(queue).await
    }

    async fn stream_package_components(
        &self,
        pid: PackageItem,
        analysis_groups: PipelineAnalysisGroups,
        queue: PackageComponentItemQueue,
    ) -> Result<(), PipelineError> {
        self.deref()
            .stream_package_components(pid, analysis_groups, queue)
            .await
    }

    fn load_component<'a>(
        &'a self,
        loader: &ComponentLoader<'_>,
        pid: Uuid,
        cid: Uuid,
        bytes: BytesOrMapping<'a>,
        platform: Platform,
    ) -> Result<LoadedComponent<'a>, PipelineError> {
        self.deref()
            .load_component(loader, pid, cid, bytes, platform)
    }
}

impl BA2ComponentMetadataSource for Box<dyn BA2CompatibleSource> {
    fn component_meta_by_uuid<'a>(
        &'a self,
        pid: &Uuid,
        cid: &Uuid,
    ) -> Result<Option<Cow<'a, BA2ComponentMetadata>>, PipelineError> {
        self.deref().component_meta_by_uuid(pid, cid)
    }
}

impl PlatformLoader {
    fn loader<T: BA2PackageLoader<'static> + BA2ComponentMetadataSource + 'static>(
        self,
        input: impl AsRef<Path>,
        config: BA2LoaderConfig,
    ) -> Result<Arc<dyn BA2CompatibleSource>, PipelineError> {
        let input = input.as_ref();
        if !input.is_file() {
            return Err(PipelineError::source(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Only file inputs are supported",
            )));
        }
        T::from_file_and_config(input, config).map(|v| Arc::new(v) as _)
    }

    pub fn source(
        self,
        input: impl AsRef<Path>,
    ) -> Result<Arc<dyn BA2CompatibleSource>, PipelineError> {
        self.source_with(input, BA2LoaderConfig::default())
    }

    pub fn source_with(
        self,
        input: impl AsRef<Path>,
        config: BA2LoaderConfig,
    ) -> Result<Arc<dyn BA2CompatibleSource>, PipelineError> {
        match self {
            Self::BA2 => self.loader::<BA2Loader>(input, config),
            Self::UEFI => self.loader::<efi::EFIFirmwareSource>(input, config),
            Self::Component => self.loader::<component::ComponentSource>(input, config),
        }
    }

    pub fn data_source(
        self,
        input: impl AsRef<Path>,
    ) -> Result<Arc<dyn BA2CompatibleSource>, PipelineError> {
        self.data_source_with(input, BA2LoaderConfig::default())
    }

    pub fn data_source_with(
        self,
        input: impl AsRef<Path>,
        config: BA2LoaderConfig,
    ) -> Result<Arc<dyn BA2CompatibleSource>, PipelineError> {
        match self {
            Self::BA2 => self.loader::<DataSource<BA2Loader>>(input, config),
            Self::UEFI => self.loader::<DataSource<efi::EFIFirmwareSource>>(input, config),
            Self::Component => self.loader::<DataSource<component::ComponentSource>>(input, config),
        }
    }
}

use std::borrow::Cow;
use std::path::Path;

use bias::component::{
    ComponentError, ComponentLoader, LoadedBinaryComponent, LoadedBinaryComponentData,
    LoadedComponent,
};
use bias::loader::meta::{
    BA2ComponentAttributes, BA2ComponentHashes, BA2ComponentMetadata, BA2ComponentMetadataBuilder,
    BA2ComponentMetadataSource,
};
use bias::loader::{BA2LoaderConfig, BA2PackageLoader};
use bias::package::{Package, PackageBuilder, PackageComponentData, PackageData, PackageHashes};
use bias::pipeline::source::{
    AnalysisGroupFilter, PackageComponentItemQueue, PackageDependencyGraph, PackageItem,
    PackageItemQueue,
};
use bias::pipeline::{
    Component, PackageComponentItem, PipelineAnalysisGroups, PipelineError, Source,
};
use bias::platform::Platform;
use bias::platform::common::{PlatformAttributeMap, SourceFilePathAttribute};
use bias::util::BytesOrMapping;
use bias_core::kb::Uuid;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::data_buffer::DataBuffer;
use binaryninja::headless::Session;
use binaryninja::rc::Ref;

use crate::error::BNDBSourceError;
use crate::loaded_binary::BNDBLoadedBinary;
use crate::platform::{build_lifter_for_platform, infer_platform};
use crate::util::view_bytes;

pub struct BNDBData {
    attributes: BA2ComponentAttributes,
    platform: Platform,
    view: Ref<BinaryView>,
    buffer: DataBuffer,
    #[allow(unused)]
    session: Session, // ensure we drop last
}

unsafe impl Send for BNDBData {}
unsafe impl Sync for BNDBData {}

impl BNDBData {
    pub fn from_file_with(
        path: impl AsRef<Path>,
        attrs: impl Into<Option<PlatformAttributeMap>>,
    ) -> Result<Self, BNDBSourceError> {
        let path = path.as_ref();
        let attrs = attrs.into();

        let session = Session::new().map_err(BNDBSourceError::Init)?;

        let view = session
            .load(path)
            .ok_or_else(|| BNDBSourceError::ViewLoad(path.to_owned()))?;

        let buffer = view_bytes(&view, path)?;
        let bytes = buffer.get_data();

        let (platform, component_attrs) = infer_platform(&view, bytes, path, attrs.as_ref())?;

        Ok(Self {
            attributes: component_attrs,
            platform,
            view,
            buffer,
            session,
        })
    }

    pub fn load<'a>(
        &'a self,
        loader: &ComponentLoader<'_>,
    ) -> Result<LoadedComponent<'a>, PipelineError> {
        self.load_with(Uuid::now_v7(), loader, self.platform.clone())
    }

    pub fn load_with<'a>(
        &'a self,
        id: Uuid,
        loader: &ComponentLoader<'_>,
        platform: Platform,
    ) -> Result<LoadedComponent<'a>, PipelineError> {
        let ldb = loader.languages();
        let lifter = build_lifter_for_platform(ldb, &platform)?;

        let (platform, attributes, loader) = platform.into_parts();

        if !loader.is_guided_binary() {
            return Err(PipelineError::source_with(
                "unsupported loader for BNDB components",
            ));
        }

        let view = self.view.clone();

        let mut loaded = LoadedBinaryComponent::new(
            id,
            BytesOrMapping::from_bytes(self.buffer.get_data()),
            platform,
            loader,
            attributes,
            Default::default(),
            |bytes| {
                let loaded = BNDBLoadedBinary::new(view, bytes, &lifter);
                LoadedBinaryComponentData::Other(Box::new(loaded))
            },
        );

        let original_path = self.view.file().filename();

        loaded.register_platform_attribute(SourceFilePathAttribute::from(
            original_path
                .strip_suffix(".bndb")
                .unwrap_or(&original_path),
        ));

        Ok(LoadedComponent::Binary(lifter, loaded))
    }

    pub fn load_as_owned(
        &self,
        loader: &ComponentLoader<'_>,
    ) -> Result<LoadedComponent<'static>, PipelineError> {
        self.load_as_owned_with(Uuid::now_v7(), loader, self.platform.clone())
    }

    pub fn load_as_owned_with(
        &self,
        id: Uuid,
        loader: &ComponentLoader<'_>,
        platform: Platform,
    ) -> Result<LoadedComponent<'static>, PipelineError> {
        let ldb = loader.languages();
        let lifter = build_lifter_for_platform(ldb, &platform)?;

        let (platform, attributes, loader) = platform.into_parts();

        if !loader.is_guided_binary() {
            return Err(PipelineError::source_with(
                "unsupported loader for BNDB components",
            ));
        }

        let view = self.view.clone();

        let mut loaded = LoadedBinaryComponent::new(
            id,
            BytesOrMapping::from_bytes(self.buffer.get_data().to_owned()),
            platform,
            loader,
            attributes,
            Default::default(),
            |bytes| {
                let loaded = BNDBLoadedBinary::new(view, bytes, &lifter);
                LoadedBinaryComponentData::Other(Box::new(loaded))
            },
        );

        let original_path = self.view.file().filename();

        loaded.register_platform_attribute(SourceFilePathAttribute::from(
            original_path
                .strip_suffix(".bndb")
                .unwrap_or(&original_path),
        ));

        Ok(LoadedComponent::Binary(lifter, loaded))
    }

    pub fn bytes(&self) -> &[u8] {
        self.buffer.get_data()
    }

    pub fn platform(&self) -> &Platform {
        &self.platform
    }

    pub fn view(&self) -> &BinaryView {
        &self.view
    }

    pub fn attributes(&self) -> &BA2ComponentAttributes {
        &self.attributes
    }
}

pub struct BNDBSource {
    package: Package,
    metadata: BA2ComponentMetadata,
    dependencies: PackageDependencyGraph,
    data: BNDBData,
}

impl BNDBSource {
    pub fn from_file_with(
        path: impl AsRef<Path>,
        attrs: impl Into<Option<PlatformAttributeMap>>,
    ) -> Result<Self, BNDBSourceError> {
        let path = path.as_ref();
        let attrs = attrs.into();

        let data = BNDBData::from_file_with(path, attrs)?;

        let original_path = data.view().file().filename();
        let original_name = Path::new(&original_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&original_path);

        let name = path
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_else(|| path.to_string_lossy());

        let hashes = BA2ComponentHashes::new(data.bytes());
        let package_hashes =
            PackageHashes::from_parts(*hashes.md5(), *hashes.sha1(), *hashes.sha256());

        let metadata = BA2ComponentMetadataBuilder::new(data.attributes().to_owned())
            .with_id(Uuid::now_v7())
            .with_name(original_name.strip_suffix(".bndb").unwrap_or(original_name))
            .with_path(
                original_path
                    .strip_suffix(".bndb")
                    .unwrap_or(&original_path),
            )
            .with_hashes(hashes)
            .build()
            .map_err(ComponentError::from)?;

        let package = PackageBuilder::new()
            .with_id(Uuid::now_v7())
            .with_name(name)
            .with_path(path.to_string_lossy())
            .with_hashes(package_hashes)
            .build()?;

        let mut dependencies = PackageDependencyGraph::new();
        dependencies.add_entity_with(metadata.id(), data.platform());

        Ok(Self {
            package,
            metadata,
            dependencies,
            data,
        })
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, BNDBSourceError> {
        Self::from_file_with(path, None)
    }

    pub(crate) fn package_id(&self) -> Uuid {
        self.package.id()
    }

    pub(crate) fn component_id(&self) -> Uuid {
        self.metadata.id()
    }
}

#[async_trait::async_trait]
impl Source for BNDBSource {
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

    fn load_component<'a>(
        &'a self,
        loader: &ComponentLoader<'_>,
        pid: Uuid,
        cid: Uuid,
        _bytes: BytesOrMapping<'a>,
        platform: Platform,
    ) -> Result<LoadedComponent<'a>, PipelineError> {
        if pid != self.package_id() || cid != self.component_id() {
            return Err(PipelineError::source_with("component not found"));
        }

        self.data.load_with(cid, loader, platform)
    }
}

impl BA2PackageLoader<'_> for BNDBSource {
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

    fn should_analyse(path: impl AsRef<Path>) -> bool {
        path.as_ref()
            .extension()
            .map(|ext| ext == "bndb")
            .unwrap_or(false)
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
            self.data.buffer.get_data(),
            self.data.platform.clone(),
        )))
    }

    fn components<'loader>(&'loader self, pid: &Uuid) -> impl Iterator<Item = Uuid> + 'loader {
        (*pid == self.package_id())
            .then(|| std::iter::once(self.component_id()))
            .into_iter()
            .flatten()
    }
}

impl BA2ComponentMetadataSource for BNDBSource {
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

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, copy, BufWriter, Cursor, Seek, Write};
use std::path::Path;

use crate::component::{ComponentBuilder, ComponentError, ComponentHashes};
use crate::pipeline::source::PackageDependencyKind;
use crate::pipeline::types::Property;
use crate::util::BytesOrMapping;

use thiserror::Error;
use uuid::Uuid;

use zip::write::SimpleFileOptions;
use zip::ZipWriter;

use crate::loader::meta::{
    BA2ComponentMetadata, BA2ComponentPlatformDetails, BA2Metadata, BA2MetadataError,
    EnvironmentKind,
};
use crate::loader::platform::common::PrimaryComponents;

/// Metadata output for BA2 archives (JSON format).
#[derive(Default)]
pub struct BA2MetadataOutput {
    components: Option<BufWriter<File>>,
    properties: Option<BufWriter<File>>,
}

impl BA2MetadataOutput {
    fn new(
        components: impl AsRef<Path>,
        properties: impl AsRef<Path>,
    ) -> Result<Self, BA2BuilderError> {
        let components = File::create(components)
            .map(BufWriter::new)
            .map_err(BA2BuilderError::MetaIo)?;

        let properties = File::create(properties)
            .map(BufWriter::new)
            .map_err(BA2BuilderError::MetaIo)?;

        Ok(Self {
            components: Some(components),
            properties: Some(properties),
        })
    }

    fn finalise(&mut self, meta: &BA2Metadata) -> Result<(), BA2BuilderError> {
        if let Some(components) = self.components.as_mut() {
            Self::write_components(meta, components)?;
        }

        if let Some(properties) = self.properties.as_mut() {
            Self::write_dependencies(meta, properties)?;
        }

        Ok(())
    }

    pub fn write_components(
        meta: &BA2Metadata,
        writer: &mut impl Write,
    ) -> Result<(), BA2BuilderError> {
        use crate::component::Component;

        for component in meta.components() {
            let mut builder = ComponentBuilder::new(component.attributes().kind())
                .with_id(component.id())
                .with_name(component.name())
                .with_path(component.path().to_string_lossy())
                .with_container_path(component.container_path())
                .with_virtual_path(component.virtual_path())
                .with_hashes(ComponentHashes::from_parts(
                    component.md5(),
                    component.sha1(),
                    component.sha256(),
                ))
                .with_attrs(BA2ComponentPlatformDetails::from(component.attributes()));

            if let Some(pid) = component.partition_id() {
                builder.set_partition_id(pid);
            }

            if let Some(pid) = component.primary_component_id() {
                builder.set_primary_component_id(pid);
            }

            if let Some(gid) = component.global_component_id() {
                builder.set_global_component_id(gid);
            }

            let component: Component = builder.build().map_err(BA2BuilderError::MetaComponent)?;
            serde_json::to_writer(&mut *writer, &component).map_err(BA2BuilderError::MetaSerialize)?;
            writer.write_all(b"\n").map_err(BA2BuilderError::MetaIo)?;
        }

        Ok(())
    }

    pub fn write_dependencies(
        meta: &BA2Metadata,
        writer: &mut impl Write,
    ) -> Result<(), BA2BuilderError> {
        for (source, target, dependency) in meta.dependencies() {
            let property = Property::new_component_ref(source, dependency.to_string(), target);
            serde_json::to_writer(&mut *writer, &property).map_err(BA2BuilderError::MetaSerialize)?;
            writer.write_all(b"\n").map_err(BA2BuilderError::MetaIo)?;
        }

        Ok(())
    }

    pub fn write_meta(
        meta: &BA2Metadata,
        components: impl AsRef<Path>,
        properties: impl AsRef<Path>,
    ) -> Result<(), BA2BuilderError> {
        let mut output = Self::new(components, properties)?;
        output.finalise(meta)
    }
}

pub struct BA2ComponentWriter<'a> {
    writer: Option<Box<dyn Write + 'a>>,
    primary_components: Option<&'a mut PrimaryComponents>,
    metadata: &'a mut BA2Metadata,
    component: Option<BA2ComponentMetadata>,
}

impl<'a> BA2ComponentWriter<'a> {
    fn new<W>(
        writer: Option<W>,
        primary_components: Option<&'a mut PrimaryComponents>,
        metadata: &'a mut BA2Metadata,
        component: BA2ComponentMetadata,
    ) -> Self
    where
        W: Write + 'a,
    {
        Self {
            writer: writer.map(|w| Box::new(w) as Box<dyn Write>),
            primary_components,
            metadata,
            component: Some(component),
        }
    }

    pub fn is_writable(&self) -> bool {
        self.writer.is_some()
    }

    pub fn finalise(self) -> Uuid {
        self.component.as_ref().expect("component present").id()
    }
}

impl<'a> Write for BA2ComponentWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let Some(writer) = self.writer.as_mut() else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "component `{}` not is writable",
                    self.component
                        .as_ref()
                        .expect("component present")
                        .id()
                        .hyphenated()
                ),
            ));
        };
        writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let Some(writer) = self.writer.as_mut() else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "component `{}` not is writable",
                    self.component
                        .as_ref()
                        .expect("component present")
                        .id()
                        .hyphenated()
                ),
            ));
        };
        writer.flush()
    }
}

impl<'a> Drop for BA2ComponentWriter<'a> {
    fn drop(&mut self) {
        if let Some(pcs) = self.primary_components.as_mut() {
            let component = self.component.as_mut().expect("component present");
            let gid = pcs.compute_identity(component);

            if let Some(pid) = component.primary_component_id() {
                // Ensure this primary component is registered
                pcs.insert_identity(component.kind(), gid, pid);
            }

            if self.metadata.version() >= 3 && component.global_component_id().is_none() {
                component.set_global_component_id(gid);
            }
        }

        self.metadata
            .add_component(self.component.take().expect("component present"));
    }
}

pub struct BA2Writer<W>
where
    W: Write + Seek,
{
    archive: ZipWriter<W>,
    metadata: BA2Metadata,
    metadata_output: BA2MetadataOutput,
    primary_components: Option<PrimaryComponents>,
    stored: BTreeSet<[u8; 32]>,
    sealed: bool,
}

pub type BA2Builder = BA2Writer<BufWriter<File>>;

#[derive(Debug, Error)]
pub enum BA2BuilderError {
    #[error("cannot write BA2 file: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Meta(#[from] BA2MetadataError),
    #[error("cannot construct component metadata for writing: {0}")]
    MetaComponent(ComponentError),
    #[error("cannot serialize BA2 metadata: {0}")]
    MetaSerialize(serde_json::Error),
    #[error("cannot write BA2 metadata file: {0}")]
    MetaIo(io::Error),
    #[error("cannot serialise meta.json: {0}")]
    Serialise(#[from] serde_json::Error),
    #[error("cannot construct BA2 container: {0}")]
    Zip(#[from] zip::result::ZipError),
}

impl<W> BA2Writer<W>
where
    W: Write + Seek,
{
    pub fn new(path: impl AsRef<Path>) -> Result<BA2Builder, BA2BuilderError> {
        Ok(BA2Builder::new_writer(BufWriter::new(File::create(path)?)))
    }

    pub fn new_v1(path: impl AsRef<Path>) -> Result<BA2Builder, BA2BuilderError> {
        Ok(BA2Builder::new_v1_writer(BufWriter::new(File::create(
            path,
        )?)))
    }

    pub fn new_v2(path: impl AsRef<Path>) -> Result<BA2Builder, BA2BuilderError> {
        Ok(BA2Builder::new_v2_writer(BufWriter::new(File::create(
            path,
        )?)))
    }

    pub fn new_v3(path: impl AsRef<Path>) -> Result<BA2Builder, BA2BuilderError> {
        Ok(BA2Builder::new_v3_writer(BufWriter::new(File::create(
            path,
        )?)))
    }

    pub fn new_v4(path: impl AsRef<Path>) -> Result<BA2Builder, BA2BuilderError> {
        Ok(BA2Builder::new_v4_writer(BufWriter::new(File::create(
            path,
        )?)))
    }

    pub fn new_with(
        path: impl AsRef<Path>,
        components: impl AsRef<Path>,
        properties: impl AsRef<Path>,
    ) -> Result<BA2Builder, BA2BuilderError> {
        Self::new(path)?.with_meta_output(components, properties)
    }

    pub fn new_v1_with(
        path: impl AsRef<Path>,
        components: impl AsRef<Path>,
        properties: impl AsRef<Path>,
    ) -> Result<BA2Builder, BA2BuilderError> {
        Self::new_v1(path)?.with_meta_output(components, properties)
    }

    pub fn new_v2_with(
        path: impl AsRef<Path>,
        components: impl AsRef<Path>,
        properties: impl AsRef<Path>,
    ) -> Result<BA2Builder, BA2BuilderError> {
        Self::new_v2(path)?.with_meta_output(components, properties)
    }

    pub fn new_v3_with(
        path: impl AsRef<Path>,
        components: impl AsRef<Path>,
        properties: impl AsRef<Path>,
    ) -> Result<BA2Builder, BA2BuilderError> {
        Self::new_v3(path)?.with_meta_output(components, properties)
    }

    pub fn new_v4_with(
        path: impl AsRef<Path>,
        components: impl AsRef<Path>,
        properties: impl AsRef<Path>,
    ) -> Result<BA2Builder, BA2BuilderError> {
        Self::new_v4(path)?.with_meta_output(components, properties)
    }

    pub fn new_writer(writer: W) -> Self {
        Self::new_v4_writer(writer)
    }

    pub fn new_v1_writer(writer: W) -> Self {
        Self {
            archive: ZipWriter::new(writer),
            metadata: BA2Metadata::new_v1(),
            metadata_output: BA2MetadataOutput::default(),
            primary_components: None,
            stored: BTreeSet::new(),
            sealed: false,
        }
    }

    pub fn new_v2_writer(writer: W) -> Self {
        Self {
            archive: ZipWriter::new(writer),
            metadata: BA2Metadata::new_v2(),
            metadata_output: BA2MetadataOutput::default(),
            primary_components: Some(PrimaryComponents::new()),
            stored: BTreeSet::new(),
            sealed: false,
        }
    }

    pub fn new_v3_writer(writer: W) -> Self {
        Self {
            archive: ZipWriter::new(writer),
            metadata: BA2Metadata::new_v3(),
            metadata_output: BA2MetadataOutput::default(),
            primary_components: Some(PrimaryComponents::new()),
            stored: BTreeSet::new(),
            sealed: false,
        }
    }

    pub fn new_v4_writer(writer: W) -> Self {
        Self {
            archive: ZipWriter::new(writer),
            metadata: BA2Metadata::new_v4(),
            metadata_output: BA2MetadataOutput::default(),
            primary_components: Some(PrimaryComponents::new()),
            stored: BTreeSet::new(),
            sealed: false,
        }
    }

    pub fn set_package_id(&mut self, id: impl Into<Uuid>) {
        self.metadata.set_id(id.into());
    }

    pub fn with_package_id(mut self, id: impl Into<Uuid>) -> Self {
        self.set_package_id(id);
        self
    }

    pub fn set_partition_id(&mut self, id: impl Into<u32>) -> Result<(), BA2BuilderError> {
        self.metadata
            .set_partition_id(id.into())
            .map_err(BA2BuilderError::Meta)
    }

    pub fn with_partition_id(mut self, id: impl Into<u32>) -> Result<Self, BA2BuilderError> {
        self.set_partition_id(id)?;
        Ok(self)
    }

    pub fn set_environment(&mut self, env: EnvironmentKind) -> Result<(), BA2BuilderError> {
        self.metadata
            .set_environment(env)
            .map_err(BA2BuilderError::Meta)
    }

    pub fn with_environment(mut self, env: EnvironmentKind) -> Result<Self, BA2BuilderError> {
        self.set_environment(env)?;
        Ok(self)
    }

    pub fn set_meta_output(
        &mut self,
        components: impl AsRef<Path>,
        properties: impl AsRef<Path>,
    ) -> Result<(), BA2BuilderError> {
        self.metadata_output = BA2MetadataOutput::new(components, properties)?;
        Ok(())
    }

    pub fn with_meta_output(
        mut self,
        components: impl AsRef<Path>,
        properties: impl AsRef<Path>,
    ) -> Result<Self, BA2BuilderError> {
        self.set_meta_output(components, properties)?;
        Ok(self)
    }

    pub fn set_components_output(
        &mut self,
        components: impl AsRef<Path>,
    ) -> Result<(), BA2BuilderError> {
        let components = File::create(components)
            .map(BufWriter::new)
            .map_err(BA2BuilderError::MetaIo)?;

        self.metadata_output.components = Some(components);
        Ok(())
    }

    pub fn with_components_output(
        mut self,
        components: impl AsRef<Path>,
    ) -> Result<Self, BA2BuilderError> {
        self.set_components_output(components)?;
        Ok(self)
    }

    pub fn set_properties_output(
        &mut self,
        properties: impl AsRef<Path>,
    ) -> Result<(), BA2BuilderError> {
        let properties = File::create(properties)
            .map(BufWriter::new)
            .map_err(BA2BuilderError::MetaIo)?;

        self.metadata_output.properties = Some(properties);
        Ok(())
    }

    pub fn with_properties_output(
        mut self,
        properties: impl AsRef<Path>,
    ) -> Result<Self, BA2BuilderError> {
        self.set_properties_output(properties)?;
        Ok(self)
    }

    pub fn meta(&mut self) -> &BA2Metadata {
        &self.metadata
    }

    pub fn meta_mut(&mut self) -> &mut BA2Metadata {
        &mut self.metadata
    }

    pub fn set_meta(&mut self, metadata: BA2Metadata) {
        self.metadata = metadata;
    }

    pub fn add_component_with<'a>(
        &mut self,
        meta: impl Into<BA2ComponentMetadata>,
        data: impl Into<BytesOrMapping<'a>>,
        compress: bool,
    ) -> Result<Uuid, BA2BuilderError> {
        let mut meta = meta.into();
        let id = meta.id();

        if let Some(path) = meta.container_path() {
            if self.stored.insert(meta.sha256()) {
                self.archive.start_file(
                    path,
                    SimpleFileOptions::default()
                        .large_file(true)
                        .compression_method(zip::CompressionMethod::Stored),
                )?;

                let uncompressed = data.into();
                let mut reader = Cursor::new(uncompressed.as_ref());

                if compress {
                    zstd::stream::copy_encode(reader, &mut self.archive, 0)?;
                } else {
                    copy(&mut reader, &mut self.archive)?;
                }
            }
        }

        if let Some(pcs) = self.primary_components.as_mut() {
            let gid = pcs.compute_identity(&meta);

            if let Some(pid) = meta.primary_component_id() {
                // Ensure this primary component is registered
                pcs.insert_identity(meta.kind(), gid, pid);
            }

            if self.meta().version() >= 3 && meta.global_component_id().is_none() {
                meta.set_global_component_id(gid);
            }
        }

        self.metadata.add_component(meta);

        Ok(id)
    }

    pub fn add_component<'a>(
        &mut self,
        meta: impl Into<BA2ComponentMetadata>,
        data: impl Into<BytesOrMapping<'a>>,
    ) -> Result<Uuid, BA2BuilderError> {
        self.add_component_with(meta, data, true)
    }

    pub fn add_component_metadata(
        &mut self,
        meta: impl Into<BA2ComponentMetadata>,
    ) -> Result<Uuid, BA2BuilderError> {
        let mut meta = meta.into();
        let id = meta.id();

        if !self.stored.contains(&meta.sha256()) {
            meta.set_meta();
        }

        if let Some(pcs) = self.primary_components.as_mut() {
            let gid = pcs.compute_identity(&meta);

            if let Some(pid) = meta.primary_component_id() {
                // Ensure this primary component is registered
                pcs.insert_identity(meta.kind(), gid, pid);
            }

            if self.meta().version() >= 3 && meta.global_component_id().is_none() {
                meta.set_global_component_id(gid);
                self.metadata.add_component(meta);
                return Ok(id);
            }
        }

        self.metadata.add_component(meta);

        Ok(id)
    }

    pub fn add_component_by_writer(
        &mut self,
        meta: impl Into<BA2ComponentMetadata>,
        compress: bool,
    ) -> Result<BA2ComponentWriter<'_>, BA2BuilderError> {
        let meta = meta.into();
        let mut writer = None::<Box<dyn Write>>;

        if let Some(path) = meta.container_path() {
            if self.stored.insert(meta.sha256()) {
                self.archive.start_file(
                    path,
                    SimpleFileOptions::default()
                        .large_file(true)
                        .compression_method(zip::CompressionMethod::Stored),
                )?;

                writer = Some(if compress {
                    let zwriter = zstd::Encoder::new(&mut self.archive, 0)?;
                    Box::new(zwriter) as Box<dyn Write>
                } else {
                    Box::new(&mut self.archive) as Box<dyn Write>
                });
            }
        }

        Ok(BA2ComponentWriter::new(
            writer,
            self.primary_components.as_mut(),
            &mut self.metadata,
            meta,
        ))
    }

    pub fn add_dependency(
        &mut self,
        source: impl Into<Uuid>,
        target: impl Into<Uuid>,
        kind: impl Into<PackageDependencyKind>,
    ) -> Result<(), BA2BuilderError> {
        self.metadata.add_dependency(source, target, kind)?;
        Ok(())
    }

    pub fn add_dependencies(
        &mut self,
        deps: impl IntoIterator<Item = (Uuid, Uuid, PackageDependencyKind)>,
    ) -> Result<(), BA2BuilderError> {
        for (source, target, kind) in deps {
            self.metadata.add_dependency(source, target, kind)?;
        }
        Ok(())
    }

    fn finalise(&mut self) -> Result<(), BA2BuilderError> {
        if self.sealed {
            return Ok(());
        }

        if let Some(pcs) = self.primary_components.as_mut() {
            for component in self.metadata.components_mut() {
                if component.primary_component_id().is_some() {
                    continue;
                }

                let pid = pcs.get_or_insert_with(component.id(), component, component.kind());
                if pid != component.id() {
                    component.set_primary_component_id(pid);
                }
            }
        }

        self.archive.start_file(
            "meta.json.zstd",
            SimpleFileOptions::default()
                .large_file(true)
                .compression_method(zip::CompressionMethod::Stored),
        )?;

        {
            let mut zwriter = zstd::Encoder::new(&mut self.archive, 0)?;
            serde_json::to_writer(&mut zwriter, &self.metadata)?;
            zwriter.finish()?;
        }

        self.sealed = true;
        self.metadata_output.finalise(&self.metadata)?;

        Ok(())
    }

    pub fn build(mut self) -> Result<W, BA2BuilderError> {
        self.finalise()?;
        self.archive.finish().map_err(BA2BuilderError::from)
    }
}

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::component::Component;
use crate::package::Package;
use crate::pipeline::property::Property;
use crate::pipeline::sink::Sink;
use crate::pipeline::source::PackageDependencyGraph;
use crate::pipeline::PipelineError;

use crate::loader::meta::BA2ComponentPlatformDetails;

use crossbeam::queue::SegQueue;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct ComponentResults<'a> {
    id: Uuid,

    name: String,
    kind: String,
    path: PathBuf,

    #[serde(serialize_with = "hex::serialize")]
    md5: [u8; 16],
    #[serde(serialize_with = "hex::serialize")]
    sha1: [u8; 20],
    #[serde(serialize_with = "hex::serialize")]
    sha256: [u8; 32],

    attributes: BA2ComponentPlatformDetails<'a>,
    properties: Vec<Property>,
}

impl<'a> ComponentResults<'a> {
    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn md5(&self) -> [u8; 16] {
        self.md5
    }

    pub fn sha1(&self) -> [u8; 20] {
        self.sha1
    }

    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    pub fn properties(&self) -> impl ExactSizeIterator<Item = &Property> {
        self.properties.iter()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Report {
    packages: Vec<Package>,
    components: Vec<Component>,
    properties: Vec<Property>,
}

impl Report {
    pub fn from_parts(
        packages: impl Into<Vec<Package>>,
        components: impl Into<Vec<Component>>,
        properties: impl Into<Vec<Property>>,
    ) -> Self {
        Self {
            packages: packages.into(),
            components: components.into(),
            properties: properties.into(),
        }
    }

    pub fn into_parts(self) -> (Vec<Package>, Vec<Component>, Vec<Property>) {
        (self.packages, self.components, self.properties)
    }

    pub fn packages(&self) -> impl ExactSizeIterator<Item = &Package> {
        self.packages.iter()
    }

    pub fn components(&self) -> impl ExactSizeIterator<Item = &Component> {
        self.components.iter()
    }

    pub fn properties(&self) -> impl ExactSizeIterator<Item = &Property> {
        self.properties.iter()
    }

    pub fn properties_to_json_file(&self, path: impl AsRef<Path>) -> Result<(), PipelineError> {
        self.properties_to_json_file_with(path, false)
    }

    pub fn properties_to_json_file_with(
        &self,
        path: impl AsRef<Path>,
        pretty: bool,
    ) -> Result<(), PipelineError> {
        let file = BufWriter::new(File::create(path).map_err(PipelineError::sink)?);
        self.properties_to_json_writer_with(file, pretty)
    }

    pub fn properties_to_json_writer(&self, writer: impl Write) -> Result<(), PipelineError> {
        self.properties_to_json_writer_with(writer, false)
    }

    pub fn properties_to_json_writer_with(
        &self,
        writer: impl Write,
        pretty: bool,
    ) -> Result<(), PipelineError> {
        if pretty {
            serde_json::to_writer_pretty(writer, &self.properties)
        } else {
            serde_json::to_writer(writer, &self.properties)
        }
        .map_err(PipelineError::sink)
    }
}

pub struct ReportSink {
    packages: SegQueue<Package>,
    components: SegQueue<Component>,
    properties: SegQueue<Property>,
}

impl ReportSink {
    pub fn new() -> Self {
        Self {
            packages: SegQueue::new(),
            components: SegQueue::new(),
            properties: SegQueue::new(),
        }
    }

    pub fn into_results(self) -> Result<Report, PipelineError> {
        Ok(Report {
            packages: self.packages.into_iter().collect(),
            components: self.components.into_iter().collect(),
            properties: self.properties.into_iter().collect(),
        })
    }

    pub fn into_file_as_json_with(
        self,
        path: impl AsRef<Path>,
        pretty: bool,
    ) -> Result<(), PipelineError> {
        let file = BufWriter::new(File::create(path).map_err(PipelineError::sink)?);
        self.into_writer_as_json_with(file, pretty)
    }

    pub fn into_file_as_json(self, path: impl AsRef<Path>) -> Result<(), PipelineError> {
        self.into_file_as_json_with(path, false)
    }

    pub fn into_writer_as_json_with(
        self,
        writer: impl Write,
        pretty: bool,
    ) -> Result<(), PipelineError> {
        let results = self.into_results()?;
        if pretty {
            serde_json::to_writer_pretty(writer, &results)
        } else {
            serde_json::to_writer(writer, &results)
        }
        .map_err(PipelineError::sink)
    }

    pub fn into_writer_as_json(self, writer: impl Write) -> Result<(), PipelineError> {
        self.into_writer_as_json_with(writer, false)
    }
}

#[async_trait::async_trait]
impl Sink for ReportSink {
    async fn push_package(
        &self,
        package: Package,
        _dependencies: PackageDependencyGraph,
    ) -> Result<(), PipelineError> {
        self.packages.push(package);
        Ok(())
    }

    async fn push_component(&self, _pid: Uuid, component: Component) -> Result<(), PipelineError> {
        self.components.push(component);
        Ok(())
    }

    async fn push_component_property(
        &self,
        _pid: Uuid,
        _cid: Uuid,
        property: Property,
    ) -> Result<(), PipelineError> {
        self.properties.push(property);
        Ok(())
    }

    async fn push_package_property(
        &self,
        _pid: Uuid,
        property: Property,
    ) -> Result<(), PipelineError> {
        self.properties.push(property);
        Ok(())
    }
}

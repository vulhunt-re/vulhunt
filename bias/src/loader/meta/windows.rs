use std::collections::BTreeSet;

use bias_core::prelude::ArchitectureDef;
use crate::platform::common::{BinaryLoaderMetadata, CompilerInformation, Compilers};

use serde::{Deserialize, Serialize};

use crate::loader::util::{arch_deserialiser, arch_serialiser};

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct WindowsPEAttributes {
    #[serde(default)]
    magic_string: String,
    #[serde(default)]
    extension: String,
    #[serde(
        default,
        deserialize_with = "arch_deserialiser",
        serialize_with = "arch_serialiser"
    )]
    architecture: Option<ArchitectureDef>,
    #[serde(default)]
    loader_metadata: Option<BinaryLoaderMetadata>,
    #[serde(default)]
    compiler_information: Compilers,
    #[serde(default)]
    links: BTreeSet<String>,
}

impl WindowsPEAttributes {
    pub fn new(magic_string: impl Into<String>, extension: impl Into<String>) -> Self {
        Self::new_with(magic_string, extension)
    }

    pub fn new_with(magic_string: impl Into<String>, extension: impl Into<String>) -> Self {
        Self {
            magic_string: magic_string.into(),
            extension: extension.into(),
            ..Default::default()
        }
    }

    pub fn magic_string(&self) -> &str {
        &self.magic_string
    }

    pub fn extension(&self) -> &str {
        &self.extension
    }

    pub fn architecture(&self) -> Option<&ArchitectureDef> {
        self.architecture.as_ref()
    }

    pub fn set_architecture(&mut self, architecture: impl Into<Option<ArchitectureDef>>) {
        self.architecture = architecture.into()
    }

    pub fn with_architecture(mut self, architecture: impl Into<Option<ArchitectureDef>>) -> Self {
        self.set_architecture(architecture);
        self
    }

    pub fn loader_metadata(&self) -> Option<&BinaryLoaderMetadata> {
        self.loader_metadata.as_ref()
    }

    pub fn set_loader_metadata(&mut self, meta: impl Into<Option<BinaryLoaderMetadata>>) {
        self.loader_metadata = meta.into();
    }

    pub fn with_loader_metadata(mut self, meta: impl Into<Option<BinaryLoaderMetadata>>) -> Self {
        self.set_loader_metadata(meta);
        self
    }

    pub fn compiler_information(&self) -> &Compilers {
        &self.compiler_information
    }

    pub fn set_compiler_information(
        &mut self,
        compiler_information: impl IntoIterator<Item = CompilerInformation>,
    ) {
        self.compiler_information = compiler_information.into_iter().collect();
    }

    pub fn add_compiler_information(
        &mut self,
        compiler_information: impl Into<CompilerInformation>,
    ) {
        self.compiler_information
            .insert(compiler_information.into());
    }

    pub fn with_compiler_information(
        mut self,
        compilers: impl IntoIterator<Item = CompilerInformation>,
    ) -> Self {
        self.set_compiler_information(compilers);
        self
    }

    pub fn links(&self) -> &BTreeSet<String> {
        &self.links
    }

    pub fn set_links(&mut self, links: impl IntoIterator<Item = String>) {
        self.links = links.into_iter().collect();
    }

    pub fn add_link(&mut self, link: impl Into<String>) {
        self.links.insert(link.into());
    }

    pub fn with_links(mut self, links: impl IntoIterator<Item = String>) -> Self {
        self.set_links(links);
        self
    }
}

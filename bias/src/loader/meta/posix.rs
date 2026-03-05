use std::collections::BTreeSet;

use bias_core::kb::Lazy;
use bias_core::prelude::ArchitectureDef;
use crate::platform::common::{
    BinaryLoaderMetadata, CompilerInformation, Compilers, Ecosystem, Ecosystems, PackageMetadata,
};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::loader::util::{arch_deserialiser, arch_serialiser};

pub static SONAME_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new("\\.so(?:\\.[0-9]+)*$").expect("valid regex"));

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct PosixELFAttributes {
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
    ecosystem: Option<String>,
    #[serde(default)]
    ecosystem_discriminant: Option<String>,
    #[serde(default)]
    ecosystem_candidates: Ecosystems,
    #[serde(default)]
    package: Option<PackageMetadata>,
    #[serde(default)]
    loader_metadata: Option<BinaryLoaderMetadata>,
    #[serde(default)]
    compiler_information: Compilers,
    #[serde(default)]
    dynamic_libraries: BTreeSet<String>,
    #[serde(default)]
    dynamic_library_search_paths: BTreeSet<String>,
    #[serde(default)]
    dynamic_linker: Option<String>,
    #[serde(default)]
    links: BTreeSet<String>,
}

impl PosixELFAttributes {
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

    pub fn ecosystem(&self) -> Option<&str> {
        self.ecosystem.as_deref()
    }

    pub fn set_ecosystem(&mut self, ecosystem: impl Into<Option<String>>) {
        self.ecosystem = ecosystem.into()
    }

    pub fn with_ecosystem(mut self, ecosystem: impl Into<Option<String>>) -> Self {
        self.set_ecosystem(ecosystem);
        self
    }

    pub fn ecosystem_discriminant(&self) -> Option<&str> {
        self.ecosystem_discriminant.as_deref()
    }

    pub fn set_ecosystem_discriminant(&mut self, ecosystem: impl Into<Option<String>>) {
        self.ecosystem_discriminant = ecosystem.into()
    }

    pub fn with_ecosystem_discriminant(mut self, ecosystem: impl Into<Option<String>>) -> Self {
        self.set_ecosystem_discriminant(ecosystem);
        self
    }

    pub fn ecosystem_candidates(&self) -> &Ecosystems {
        &self.ecosystem_candidates
    }

    pub fn set_ecosystem_candidates(
        &mut self,
        ecosystem_candidates: impl IntoIterator<Item = Ecosystem>,
    ) {
        self.ecosystem_candidates = ecosystem_candidates.into_iter().collect();
    }

    pub fn add_ecosystem_candidate(&mut self, ecosystem_candidate: impl Into<Ecosystem>) {
        self.ecosystem_candidates.insert(ecosystem_candidate.into());
    }

    pub fn with_ecosystem_candidates(
        mut self,
        ecosystem_candidate: impl IntoIterator<Item = Ecosystem>,
    ) -> Self {
        self.set_ecosystem_candidates(ecosystem_candidate);
        self
    }

    pub fn package(&self) -> Option<&PackageMetadata> {
        self.package.as_ref()
    }

    pub fn set_package(&mut self, package: impl Into<Option<PackageMetadata>>) {
        self.package = package.into()
    }

    pub fn with_package(mut self, package: impl Into<Option<PackageMetadata>>) -> Self {
        self.set_package(package);
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

    pub fn dynamic_libraries(&self) -> &BTreeSet<String> {
        &self.dynamic_libraries
    }

    pub fn add_dynamic_libraries(&mut self, libraries: impl IntoIterator<Item = String>) {
        self.dynamic_libraries = libraries.into_iter().collect();
    }

    pub fn add_dynamic_library(&mut self, library: impl Into<String>) {
        self.dynamic_libraries.insert(library.into());
    }

    pub fn with_dynamic_libraries(mut self, libraries: impl IntoIterator<Item = String>) -> Self {
        self.add_dynamic_libraries(libraries);
        self
    }

    pub fn clear_dynamic_libraries(&mut self) {
        self.dynamic_libraries.clear();
    }

    pub fn dynamic_library_search_paths(&self) -> &BTreeSet<String> {
        &self.dynamic_library_search_paths
    }

    pub fn add_dynamic_library_search_paths(&mut self, paths: impl IntoIterator<Item = String>) {
        self.dynamic_library_search_paths = paths.into_iter().collect();
    }

    pub fn add_dynamic_library_search_path(&mut self, path: impl Into<String>) {
        self.dynamic_library_search_paths.insert(path.into());
    }

    pub fn with_dynamic_library_search_paths(
        mut self,
        paths: impl IntoIterator<Item = String>,
    ) -> Self {
        self.add_dynamic_library_search_paths(paths);
        self
    }

    pub fn clear_dynamic_library_search_paths(&mut self) {
        self.dynamic_library_search_paths.clear();
    }

    pub fn dynamic_linker(&self) -> Option<&str> {
        self.dynamic_linker.as_deref()
    }

    pub fn set_dynamic_linker(&mut self, linker: impl Into<String>) {
        self.dynamic_linker = Some(linker.into());
    }

    pub fn with_dynamic_linker(mut self, linker: impl Into<String>) -> Self {
        self.set_dynamic_linker(linker);
        self
    }

    pub fn clear_dynamic_linker(&mut self) {
        self.dynamic_linker = None;
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PosixFirmwareImageAttributes {}

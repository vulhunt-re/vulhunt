use std::borrow::Cow;
use std::collections::BTreeSet;
use std::ops::Deref;
use std::path::{Path, PathBuf};

use bias_core::any::ProvidesStaticType;
use bias_core::kb::{uuid, Uuid};
use bias_core::loader::{LoaderAttribute, LoaderContainer};
use bias_core::prelude::*;

use crate::component::{ComponentLoaderError, LoadedBinaryComponentData};
use crate::util::BytesOrMapping;

pub mod analysis;

pub use super::common::{
    ComponentArch as PosixComponentArch,
    ComponentBinaryLoaderMetadata as PosixBinaryLoaderMetadata,
    ComponentCompilerInformation as PosixComponentCompilerInformation,
    ComponentDynamicLibraries as PosixComponentDynamicLibraries,
    ComponentDynamicLibrarySearchPaths as PosixComponentDynamicLibrarySearchPaths,
    ComponentDynamicLinker as PosixComponentDynamicLinker,
    ComponentEcosystem as PosixComponentEcosystem,
    ComponentEcosystemCandidates as PosixComponentEcosystemCandidates,
    ComponentEcosystemDiscriminant as PosixComponentEcosystemDiscriminant,
    ComponentLinkedPaths as PosixComponentLinkedPaths,
    ComponentPackageMetadata as PosixComponentPackageMetadata,
};

use super::common::{
    BinaryLoaderMetadata, Compilers, Ecosystems, PackageMetadata, PlatformAttributeMap,
};
use super::{
    PlatformAttributeProvider, PlatformBuilder, PlatformComponentBinaryData,
    PlatformComponentBinaryLoader, PlatformComponentLoader, PlatformProvider,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PosixBinary;

pub type PosixBinaryBuilder = PlatformBuilder<PosixBinary>;

impl PosixBinaryBuilder {
    pub fn from_attrs<'a, A>(attrs: A) -> PlatformBuilder<PosixBinary>
    where
        A: Into<Option<&'a PlatformAttributeMap>>,
    {
        let mut builder = Self::new();

        let Some(attrs) = attrs.into() else {
            return builder;
        };

        if let Some(package) = attrs.get_attr::<PackageMetadata>("package") {
            builder.push(PosixBinaryAttribute::package(package));
        }

        if let Some(ecosystem) = attrs.get_attr::<String>("ecosystem") {
            builder.push(PosixBinaryAttribute::ecosystem(ecosystem));
        }

        if let Some(discriminant) = attrs.get_attr::<String>("ecosystem_discriminant") {
            builder.push(PosixBinaryAttribute::ecosystem_discriminant(discriminant));
        }

        if let Some(candidates) = attrs.get_attr::<Ecosystems>("ecosystem_candidates") {
            builder.push(PosixBinaryAttribute::ecosystem_candidates(candidates));
        }

        let compilers = attrs
            .get_attr::<Compilers>("compiler_information")
            .unwrap_or_default();
        builder.push(PosixBinaryAttribute::compiler_information(compilers));

        if let Some(linker) = attrs.get_attr::<String>("dynamic_linker") {
            builder.push(PosixBinaryAttribute::dynamic_linker(linker));
        }

        if let Some(libraries) = attrs.get_attr::<BTreeSet<String>>("dynamic_libraries") {
            builder.push(PosixBinaryAttribute::dynamic_libraries(libraries));
        }

        if let Some(paths) = attrs.get_attr::<BTreeSet<String>>("dynamic_library_search_paths") {
            builder.push(PosixBinaryAttribute::dynamic_library_search_paths(paths));
        }

        let links = attrs
            .get_attr::<BTreeSet<String>>("links")
            .unwrap_or_default();
        builder.push(PosixBinaryAttribute::linked_paths(links));

        builder
    }
}

#[derive(Default)]
pub struct PosixBinaryLoader;

impl PosixBinaryLoader {
    pub const fn new() -> &'static Self {
        &PosixBinaryLoader
    }
}

impl PlatformComponentBinaryLoader for PosixBinaryLoader {
    fn load_bytes_with<'data, 'bytes>(
        &self,
        ldb: &LanguageDB,
        bytes: &'data BytesOrMapping<'bytes>,
        path: Option<PathBuf>,
    ) -> Result<PlatformComponentBinaryData<'data>, ComponentLoaderError> {
        let (lifter, loaded) = ELFLoader::new(Cow::Borrowed(ldb))
            .with_convention("gcc")
            .load_bytes_with(bytes.as_ref(), path)?;
        Ok(PlatformComponentBinaryData(
            lifter,
            LoadedBinaryComponentData::ELF(loaded),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PosixFirmwareImage;

pub type PosixFirmwareImageBuilder = PlatformBuilder<PosixFirmwareImage>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PosixArAttribute {
    Name(String),
    Path(PathBuf),
}

impl PosixArAttribute {
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }

    pub fn path(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PosixBinaryAttribute {
    Name(String),
    Path(PathBuf),
    Arch(ArchitectureDef),
    Ecosystem(String),
    EcosystemDiscriminant(String),
    EcosystemCandidates(Ecosystems),
    Package(PackageMetadata),
    LoaderMetadata(BinaryLoaderMetadata),
    CompilerInformation(Compilers),
    DynamicLinker(String),
    DynamicLibraries(BTreeSet<String>),
    DynamicLibrarySearchPaths(BTreeSet<String>),
    LinkedPaths(BTreeSet<String>),
}

impl PosixBinaryAttribute {
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }

    pub fn path(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }

    pub fn architecture(arch: impl Into<ArchitectureDef>) -> Self {
        Self::Arch(arch.into())
    }

    pub fn ecosystem(ecosystem: impl Into<String>) -> Self {
        Self::Ecosystem(ecosystem.into())
    }

    pub fn ecosystem_discriminant(discriminant: impl Into<String>) -> Self {
        Self::EcosystemDiscriminant(discriminant.into())
    }

    pub fn ecosystem_candidates(ecosystem_candidates: impl Into<Ecosystems>) -> Self {
        Self::EcosystemCandidates(ecosystem_candidates.into())
    }

    pub fn package(package: PackageMetadata) -> Self {
        Self::Package(package)
    }

    pub fn loader_metadata(meta: BinaryLoaderMetadata) -> Self {
        Self::LoaderMetadata(meta)
    }

    pub fn compiler_information(compilers: impl Into<Compilers>) -> Self {
        Self::CompilerInformation(compilers.into())
    }

    pub fn dynamic_linker(linker: impl Into<String>) -> Self {
        Self::DynamicLinker(linker.into())
    }

    pub fn dynamic_libraries(libraries: impl Into<BTreeSet<String>>) -> Self {
        Self::DynamicLibraries(libraries.into())
    }

    pub fn dynamic_library_search_paths(paths: impl Into<BTreeSet<String>>) -> Self {
        Self::DynamicLibrarySearchPaths(paths.into())
    }

    pub fn linked_paths(links: impl Into<BTreeSet<String>>) -> Self {
        Self::LinkedPaths(links.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PosixFirmwareAttribute {
    Name(String),
}

impl PosixFirmwareAttribute {
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }
}

#[derive(ProvidesStaticType)]
pub struct PosixComponentName<'a>(&'a str);
impl<'a> LoaderAttribute<'a> for PosixComponentName<'a> {
    const UUID: Uuid = uuid("669DE942-06B5-46D8-8F28-FAB35EEF306F");
}

impl<'a> AsRef<str> for PosixComponentName<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for PosixComponentName<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct PosixComponentPath<'a>(&'a Path);
impl<'a> LoaderAttribute<'a> for PosixComponentPath<'a> {
    const UUID: Uuid = uuid("B84BE0B0-239C-4D10-B83A-C051948A262F");
}

impl<'a> AsRef<Path> for PosixComponentPath<'a> {
    fn as_ref(&self) -> &Path {
        self.0
    }
}

impl<'a> Deref for PosixComponentPath<'a> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl PlatformAttributeProvider for PosixArAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::Name(name) => {
                container.set_attr(PosixComponentName(name));
            }
            Self::Path(path) => {
                container.set_attr(PosixComponentPath(path));
            }
        }
    }
}

impl PlatformProvider for PosixBinary {
    type Attribute = PosixBinaryAttribute;

    const NAME: &'static str = "posix-binary";
    const LOADER: PlatformComponentLoader =
        PlatformComponentLoader::binary(PosixBinaryLoader::new());
}

impl PlatformAttributeProvider for PosixBinaryAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::Name(name) => {
                container.set_attr(PosixComponentName(name));
            }
            Self::Path(path) => {
                container.set_attr(PosixComponentPath(path));
            }
            Self::Arch(arch) => {
                container.set_attr(PosixComponentArch(arch));
            }
            Self::Ecosystem(ecosystem) => {
                container.set_attr(PosixComponentEcosystem(ecosystem));
            }
            Self::EcosystemDiscriminant(discriminant) => {
                container.set_attr(PosixComponentEcosystemDiscriminant(discriminant));
            }
            Self::EcosystemCandidates(candidates) => {
                container.set_attr(PosixComponentEcosystemCandidates(candidates));
            }
            Self::Package(package) => {
                container.set_attr(PosixComponentPackageMetadata(package));
            }
            Self::LoaderMetadata(meta) => {
                container.set_attr(PosixBinaryLoaderMetadata(meta));
            }
            Self::CompilerInformation(compilers) => {
                container.set_attr(PosixComponentCompilerInformation(compilers));
            }
            Self::DynamicLinker(linker) => {
                container.set_attr(PosixComponentDynamicLinker::new(linker));
            }
            Self::DynamicLibraries(libraries) => {
                container.set_attr(PosixComponentDynamicLibraries::new(libraries));
            }
            Self::DynamicLibrarySearchPaths(paths) => {
                container.set_attr(PosixComponentDynamicLibrarySearchPaths::new(paths));
            }
            Self::LinkedPaths(links) => {
                container.set_attr(PosixComponentLinkedPaths::new(links));
            }
        }
    }
}

impl PlatformProvider for PosixFirmwareImage {
    type Attribute = PosixFirmwareAttribute;

    const NAME: &'static str = "posix-firmware";
    const LOADER: PlatformComponentLoader = PlatformComponentLoader::data();
}

impl PlatformAttributeProvider for PosixFirmwareAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::Name(name) => {
                container.set_attr(PosixComponentName(name));
            }
        }
    }
}

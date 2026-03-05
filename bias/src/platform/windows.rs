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

use super::common::{BinaryLoaderMetadata, Compilers, PlatformAttributeMap};
use super::{
    PlatformAttributeProvider, PlatformBuilder, PlatformComponentBinaryData,
    PlatformComponentBinaryLoader, PlatformComponentLoader, PlatformProvider,
};

pub use super::common::{
    ComponentArch as WindowsComponentArch,
    ComponentBinaryLoaderMetadata as WindowsBinaryLoaderMetadata,
    ComponentCompilerInformation as WindowsComponentCompilerInformation,
    ComponentLinkedPaths as WindowsComponentLinkedPaths,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WindowsBinary;

pub type WindowsBinaryBuilder = PlatformBuilder<WindowsBinary>;

impl WindowsBinaryBuilder {
    pub fn from_attrs<'a, A>(attrs: A) -> PlatformBuilder<WindowsBinary>
    where
        A: Into<Option<&'a PlatformAttributeMap>>,
    {
        let mut builder = Self::new();

        let Some(attrs) = attrs.into() else {
            return builder;
        };

        let compilers = attrs
            .get_attr::<Compilers>("compiler_information")
            .unwrap_or_default();
        builder.push(WindowsBinaryAttribute::compiler_information(compilers));

        let links = attrs
            .get_attr::<BTreeSet<String>>("links")
            .unwrap_or_default();
        builder.push(WindowsBinaryAttribute::linked_paths(links));

        builder
    }
}

pub struct WindowsBinaryLoader;

impl WindowsBinaryLoader {
    pub const fn new() -> &'static Self {
        &WindowsBinaryLoader
    }
}

impl PlatformComponentBinaryLoader for WindowsBinaryLoader {
    fn load_bytes_with<'data, 'bytes>(
        &self,
        ldb: &LanguageDB,
        bytes: &'data BytesOrMapping<'bytes>,
        path: Option<PathBuf>,
    ) -> Result<PlatformComponentBinaryData<'data>, ComponentLoaderError> {
        let (lifter, loaded) = PELoader::new(Cow::Borrowed(ldb))
            .with_convention("windows")
            .load_bytes_with(bytes.as_ref(), path)?;
        Ok(PlatformComponentBinaryData(
            lifter,
            LoadedBinaryComponentData::PE(loaded),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WindowsBinaryAttribute {
    Name(String),
    Path(PathBuf),
    Arch(ArchitectureDef),
    LoaderMetadata(BinaryLoaderMetadata),
    CompilerInformation(Compilers),
    LinkedPaths(BTreeSet<String>),
}

impl WindowsBinaryAttribute {
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }

    pub fn path(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }

    pub fn architecture(arch: impl Into<ArchitectureDef>) -> Self {
        Self::Arch(arch.into())
    }

    pub fn loader_metadata(meta: BinaryLoaderMetadata) -> Self {
        Self::LoaderMetadata(meta)
    }

    pub fn compiler_information(compilers: impl Into<Compilers>) -> Self {
        Self::CompilerInformation(compilers.into())
    }

    pub fn linked_paths(links: impl Into<BTreeSet<String>>) -> Self {
        Self::LinkedPaths(links.into())
    }
}

#[derive(ProvidesStaticType)]
pub struct WindowsComponentName<'a>(&'a str);
impl<'a> LoaderAttribute<'a> for WindowsComponentName<'a> {
    const UUID: Uuid = uuid("669DE942-06B5-46D8-8F28-FAB35EEF306F");
}

impl<'a> AsRef<str> for WindowsComponentName<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for WindowsComponentName<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct WindowsComponentPath<'a>(&'a Path);
impl<'a> LoaderAttribute<'a> for WindowsComponentPath<'a> {
    const UUID: Uuid = uuid("33AA829D-1C26-4E89-A8DC-CA1E1E139AB1");
}

impl<'a> AsRef<Path> for WindowsComponentPath<'a> {
    fn as_ref(&self) -> &Path {
        self.0
    }
}

impl<'a> Deref for WindowsComponentPath<'a> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl PlatformProvider for WindowsBinary {
    type Attribute = WindowsBinaryAttribute;

    const NAME: &'static str = "windows-binary";
    const LOADER: PlatformComponentLoader =
        PlatformComponentLoader::binary(WindowsBinaryLoader::new());
}

impl PlatformAttributeProvider for WindowsBinaryAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::Name(name) => {
                container.set_attr(WindowsComponentName(name));
            }
            Self::Path(path) => {
                container.set_attr(WindowsComponentPath(path));
            }
            Self::Arch(arch) => {
                container.set_attr(WindowsComponentArch(arch));
            }
            Self::LoaderMetadata(meta) => {
                container.set_attr(WindowsBinaryLoaderMetadata(meta));
            }
            Self::CompilerInformation(compilers) => {
                container.set_attr(WindowsComponentCompilerInformation(compilers));
            }
            Self::LinkedPaths(links) => {
                container.set_attr(WindowsComponentLinkedPaths::new(links));
            }
        }
    }
}

use std::ops::Deref;
use std::path::{Path, PathBuf};

use bias_core::any::ProvidesStaticType;
use bias_core::kb::{uuid, Uuid};
use bias_core::loader::{LoaderAttribute, LoaderContainer};

use super::{
    PlatformAttributeProvider, PlatformBuilder, PlatformComponentLoader, PlatformProvider,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JavaArchive;

pub type JavaArchiveBuilder = PlatformBuilder<JavaArchive>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JavaArchiveAttribute {
    Name(String),
    Path(PathBuf),
}

impl JavaArchiveAttribute {
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }

    pub fn path(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }
}

#[derive(ProvidesStaticType)]
pub struct JavaArchiveName<'a>(&'a str);
impl<'a> LoaderAttribute<'a> for JavaArchiveName<'a> {
    const UUID: Uuid = uuid("89A796E3-AFE8-4D31-B1E2-48196F54C6E8");
}

impl<'a> AsRef<str> for JavaArchiveName<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for JavaArchiveName<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct JavaArchivePath<'a>(&'a Path);
impl<'a> LoaderAttribute<'a> for JavaArchivePath<'a> {
    const UUID: Uuid = uuid("B1DB0812-888E-444B-9BB1-6B81D38DFA75");
}

impl<'a> AsRef<Path> for JavaArchivePath<'a> {
    fn as_ref(&self) -> &Path {
        self.0
    }
}

impl<'a> Deref for JavaArchivePath<'a> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl PlatformProvider for JavaArchive {
    type Attribute = JavaArchiveAttribute;

    const NAME: &'static str = "java.archive";
    const LOADER: PlatformComponentLoader = PlatformComponentLoader::data();
}

impl PlatformAttributeProvider for JavaArchiveAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::Name(name) => {
                container.set_attr(JavaArchiveName(name));
            }
            Self::Path(path) => {
                container.set_attr(JavaArchivePath(path));
            }
        }
    }
}

use std::marker::PhantomData;
use std::ops::Deref;
use std::path::{Path, PathBuf};

use bias_core::any::ProvidesStaticType;
use bias_core::kb::{uuid, Uuid};
use bias_core::loader::{LoaderAttribute, LoaderContainer};

use super::{
    PlatformAttributeProvider, PlatformBuilder, PlatformComponentLoader, PlatformProvider,
};

#[derive(Clone)]
#[repr(transparent)]
pub struct Link<T>
where
    T: LinkKind,
{
    kind: PhantomData<fn() -> T>,
}

pub trait LinkKind {
    const NAME: &'static str;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LinkAttribute {
    Name(String),
    Path(PathBuf),
}

impl LinkAttribute {
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }

    pub fn path(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }
}

#[derive(ProvidesStaticType)]
pub struct LinkComponentName<'a>(&'a str);
impl<'a> LoaderAttribute<'a> for LinkComponentName<'a> {
    const UUID: Uuid = uuid("6062F729-8A64-433F-91EE-57871A4B6462");
}

impl<'a> AsRef<str> for LinkComponentName<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for LinkComponentName<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct LinkComponentPath<'a>(&'a Path);
impl<'a> LoaderAttribute<'a> for LinkComponentPath<'a> {
    const UUID: Uuid = uuid("FE382A07-5D10-44B7-80EF-BBF18B051873");
}

impl<'a> AsRef<Path> for LinkComponentPath<'a> {
    fn as_ref(&self) -> &Path {
        self.0
    }
}

impl<'a> Deref for LinkComponentPath<'a> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<T> PlatformProvider for Link<T>
where
    T: LinkKind,
{
    type Attribute = LinkAttribute;

    const NAME: &'static str = T::NAME;
    const LOADER: PlatformComponentLoader = PlatformComponentLoader::data();
}

impl PlatformAttributeProvider for LinkAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::Name(name) => {
                container.set_attr(LinkComponentName(name));
            }
            Self::Path(path) => {
                container.set_attr(LinkComponentPath(path));
            }
        }
    }
}

pub type LinkBuilder<T> = PlatformBuilder<Link<T>>;

#[derive(Debug, Copy, Clone)]
pub struct HardLink;

impl LinkKind for HardLink {
    const NAME: &'static str = "link.hard";
}

pub type HardLinkBuilder = LinkBuilder<HardLink>;

#[derive(Debug, Copy, Clone)]
pub struct SoftLink;

impl LinkKind for SoftLink {
    const NAME: &'static str = "link.soft";
}

pub type SoftLinkBuilder = LinkBuilder<SoftLink>;

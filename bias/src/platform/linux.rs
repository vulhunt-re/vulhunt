use std::ops::Deref;
use std::path::{Path, PathBuf};

use bias_core::any::ProvidesStaticType;
use bias_core::kb::{uuid, Uuid};
use bias_core::loader::{LoaderAttribute, LoaderContainer};

use super::{
    PlatformAttributeProvider, PlatformBuilder, PlatformComponentLoader, PlatformProvider,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinuxKernel;

pub type LinuxKernelBuilder = PlatformBuilder<LinuxKernel>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LinuxKernelAttribute {
    Name(String),
    Path(PathBuf),
}

impl LinuxKernelAttribute {
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }

    pub fn path(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }
}

#[derive(ProvidesStaticType)]
pub struct LinuxKernelName<'a>(&'a str);
impl<'a> LoaderAttribute<'a> for LinuxKernelName<'a> {
    const UUID: Uuid = uuid("C9A3FE5C-9E75-422F-B843-5674975C5C7F");
}

impl<'a> AsRef<str> for LinuxKernelName<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for LinuxKernelName<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct LinuxKernelPath<'a>(&'a Path);
impl<'a> LoaderAttribute<'a> for LinuxKernelPath<'a> {
    const UUID: Uuid = uuid("12421BAD-24B1-4529-9EBF-AEDB82B34C57");
}

impl<'a> AsRef<Path> for LinuxKernelPath<'a> {
    fn as_ref(&self) -> &Path {
        self.0
    }
}

impl<'a> Deref for LinuxKernelPath<'a> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl PlatformProvider for LinuxKernel {
    type Attribute = LinuxKernelAttribute;

    const NAME: &'static str = "linux.kernel";
    const LOADER: PlatformComponentLoader = PlatformComponentLoader::data();
}

impl PlatformAttributeProvider for LinuxKernelAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::Name(name) => {
                container.set_attr(LinuxKernelName(name));
            }
            Self::Path(path) => {
                container.set_attr(LinuxKernelPath(path));
            }
        }
    }
}

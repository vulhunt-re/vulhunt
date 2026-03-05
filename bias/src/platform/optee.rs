use std::ops::Deref;
use std::path::{Path, PathBuf};

use bias_core::any::ProvidesStaticType;
use bias_core::kb::{uuid, Uuid};
use bias_core::loader::{LoaderAttribute, LoaderContainer};

use super::{
    PlatformAttributeProvider, PlatformBuilder, PlatformComponentLoader, PlatformProvider,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OPTEEKernel;

pub type OPTEEKernelBuilder = PlatformBuilder<OPTEEKernel>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OPTEEKernelAttribute {
    Name(String),
    Path(PathBuf),
}

impl OPTEEKernelAttribute {
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }

    pub fn path(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }
}

#[derive(ProvidesStaticType)]
pub struct OPTEEKernelName<'a>(&'a str);
impl<'a> LoaderAttribute<'a> for OPTEEKernelName<'a> {
    const UUID: Uuid = uuid("C085512F-EF93-4B01-B3A4-953AA596CED5");
}

impl<'a> AsRef<str> for OPTEEKernelName<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for OPTEEKernelName<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct OPTEEKernelPath<'a>(&'a Path);
impl<'a> LoaderAttribute<'a> for OPTEEKernelPath<'a> {
    const UUID: Uuid = uuid("20F16E35-5B4F-4475-89F4-2A7671DE84A5");
}

impl<'a> AsRef<Path> for OPTEEKernelPath<'a> {
    fn as_ref(&self) -> &Path {
        self.0
    }
}

impl<'a> Deref for OPTEEKernelPath<'a> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl PlatformProvider for OPTEEKernel {
    type Attribute = OPTEEKernelAttribute;

    const NAME: &'static str = "optee.kernel";
    const LOADER: PlatformComponentLoader = PlatformComponentLoader::data();
}

impl PlatformAttributeProvider for OPTEEKernelAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::Name(name) => {
                container.set_attr(OPTEEKernelName(name));
            }
            Self::Path(path) => {
                container.set_attr(OPTEEKernelPath(path));
            }
        }
    }
}

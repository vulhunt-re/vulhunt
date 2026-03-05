use std::ops::Deref;
use std::path::{Path, PathBuf};

use bias_core::any::ProvidesStaticType;
use bias_core::kb::{uuid, Uuid};
use bias_core::loader::{LoaderAttribute, LoaderContainer};

use super::{
    PlatformAttributeProvider, PlatformBuilder, PlatformComponentLoader, PlatformProvider,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AndroidPackage;

pub type AndroidPackageBuilder = PlatformBuilder<AndroidPackage>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AndroidPackageAttribute {
    Name(String),
    Path(PathBuf),
}

impl AndroidPackageAttribute {
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }

    pub fn path(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }
}

#[derive(ProvidesStaticType)]
pub struct AndroidPackageName<'a>(&'a str);
impl<'a> LoaderAttribute<'a> for AndroidPackageName<'a> {
    const UUID: Uuid = uuid("33B3D653-BF71-449B-94D0-F5871BE061C7");
}

impl<'a> AsRef<str> for AndroidPackageName<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for AndroidPackageName<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct AndroidPackagePath<'a>(&'a Path);
impl<'a> LoaderAttribute<'a> for AndroidPackagePath<'a> {
    const UUID: Uuid = uuid("EC199757-BFEC-4EB0-9956-C074061727D7");
}

impl<'a> AsRef<Path> for AndroidPackagePath<'a> {
    fn as_ref(&self) -> &Path {
        self.0
    }
}

impl<'a> Deref for AndroidPackagePath<'a> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl PlatformProvider for AndroidPackage {
    type Attribute = AndroidPackageAttribute;

    const NAME: &'static str = "android.package";
    const LOADER: PlatformComponentLoader = PlatformComponentLoader::data();
}

impl PlatformAttributeProvider for AndroidPackageAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::Name(name) => {
                container.set_attr(AndroidPackageName(name));
            }
            Self::Path(path) => {
                container.set_attr(AndroidPackagePath(path));
            }
        }
    }
}

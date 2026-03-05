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
pub struct Secret<T>
where
    T: SecretKind,
{
    kind: PhantomData<fn() -> T>,
}

pub trait SecretKind {
    const NAME: &'static str;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretAttribute {
    Name(String),
    Path(PathBuf),
}

impl SecretAttribute {
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }

    pub fn path(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }
}

#[derive(ProvidesStaticType)]
pub struct SecretComponentName<'a>(&'a str);
impl<'a> LoaderAttribute<'a> for SecretComponentName<'a> {
    const UUID: Uuid = uuid("AF4DB062-44BF-4611-980B-77A932AA825A");
}

impl<'a> AsRef<str> for SecretComponentName<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for SecretComponentName<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct SecretComponentPath<'a>(&'a Path);
impl<'a> LoaderAttribute<'a> for SecretComponentPath<'a> {
    const UUID: Uuid = uuid("AC758972-F5FA-4CCB-9515-A874F7D05946");
}

impl<'a> AsRef<Path> for SecretComponentPath<'a> {
    fn as_ref(&self) -> &Path {
        self.0
    }
}

impl<'a> Deref for SecretComponentPath<'a> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<T> PlatformProvider for Secret<T>
where
    T: SecretKind,
{
    type Attribute = SecretAttribute;

    const NAME: &'static str = T::NAME;
    const LOADER: PlatformComponentLoader = PlatformComponentLoader::data();
}

impl PlatformAttributeProvider for SecretAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::Name(name) => {
                container.set_attr(SecretComponentName(name));
            }
            Self::Path(path) => {
                container.set_attr(SecretComponentPath(path));
            }
        }
    }
}

pub type SecretBuilder<T> = PlatformBuilder<Secret<T>>;

#[derive(Debug, Copy, Clone)]
pub struct Generic;

impl SecretKind for Generic {
    const NAME: &'static str = "secret.generic";
}
pub type GenericSecretBuilder = SecretBuilder<Generic>;

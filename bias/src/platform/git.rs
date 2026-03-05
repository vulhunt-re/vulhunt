use std::ops::Deref;
use std::path::{Path, PathBuf};

use bias_core::any::ProvidesStaticType;
use bias_core::kb::{uuid, Uuid};
use bias_core::loader::{LoaderAttribute, LoaderContainer};

use super::{
    PlatformAttributeProvider, PlatformBuilder, PlatformComponentLoader, PlatformProvider,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GitDiff;

pub type GitDiffBuilder = PlatformBuilder<GitDiff>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GitDiffAttribute {
    Name(String),
    Path(PathBuf),
}

impl GitDiffAttribute {
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }

    pub fn path(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }
}

#[derive(ProvidesStaticType)]
pub struct GitDiffComponentName<'a>(&'a str);
impl<'a> LoaderAttribute<'a> for GitDiffComponentName<'a> {
    const UUID: Uuid = uuid("3C156680-EDC1-4345-B853-2128E001992A");
}

impl<'a> AsRef<str> for GitDiffComponentName<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for GitDiffComponentName<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct GitDiffComponentPath<'a>(&'a Path);
impl<'a> LoaderAttribute<'a> for GitDiffComponentPath<'a> {
    const UUID: Uuid = uuid("F687FBB6-2DAD-415D-A8C9-A2D7605BB1BE");
}

impl<'a> AsRef<Path> for GitDiffComponentPath<'a> {
    fn as_ref(&self) -> &Path {
        self.0
    }
}

impl<'a> Deref for GitDiffComponentPath<'a> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl PlatformProvider for GitDiff {
    type Attribute = GitDiffAttribute;

    const NAME: &'static str = "git.diff";
    const LOADER: PlatformComponentLoader = PlatformComponentLoader::data();
}

impl PlatformAttributeProvider for GitDiffAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::Name(name) => {
                container.set_attr(GitDiffComponentName(name));
            }
            Self::Path(path) => {
                container.set_attr(GitDiffComponentPath(path));
            }
        }
    }
}

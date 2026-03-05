use std::marker::PhantomData;
use std::ops::Deref;
use std::path::{Path, PathBuf};

use bias_core::any::ProvidesStaticType;
use bias_core::kb::{uuid, Uuid};
use bias_core::loader::{LoaderAttribute, LoaderContainer};

use super::source::{Java, Lua, Python};
use super::{
    PlatformAttributeProvider, PlatformBuilder, PlatformComponentLoader, PlatformProvider,
};

#[derive(Clone)]
#[repr(transparent)]
pub struct Bytecode<T>
where
    T: BytecodeKind,
{
    kind: PhantomData<fn() -> T>,
}

pub trait BytecodeKind {
    const NAME: &'static str;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BytecodeAttribute {
    Name(String),
    Path(PathBuf),
}

impl BytecodeAttribute {
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }

    pub fn path(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }
}

#[derive(ProvidesStaticType)]
pub struct BytecodeComponentName<'a>(&'a str);
impl<'a> LoaderAttribute<'a> for BytecodeComponentName<'a> {
    const UUID: Uuid = uuid("50005312-D949-470E-A55B-BFF371347E21");
}

impl<'a> AsRef<str> for BytecodeComponentName<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for BytecodeComponentName<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct BytecodeComponentPath<'a>(&'a Path);
impl<'a> LoaderAttribute<'a> for BytecodeComponentPath<'a> {
    const UUID: Uuid = uuid("D1FEB18F-E98C-4D5C-95EE-8B878127B1FF");
}

impl<'a> AsRef<Path> for BytecodeComponentPath<'a> {
    fn as_ref(&self) -> &Path {
        self.0
    }
}

impl<'a> Deref for BytecodeComponentPath<'a> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<T> PlatformProvider for Bytecode<T>
where
    T: BytecodeKind,
{
    type Attribute = BytecodeAttribute;

    const NAME: &'static str = T::NAME;
    const LOADER: PlatformComponentLoader = PlatformComponentLoader::data();
}

impl PlatformAttributeProvider for BytecodeAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::Name(name) => {
                container.set_attr(BytecodeComponentName(name));
            }
            Self::Path(path) => {
                container.set_attr(BytecodeComponentPath(path));
            }
        }
    }
}

pub type BytecodeBuilder<T> = PlatformBuilder<Bytecode<T>>;

impl BytecodeKind for Java {
    const NAME: &'static str = "bytecode.java";
}

pub type JavaBuilder = BytecodeBuilder<Java>;

impl BytecodeKind for Python {
    const NAME: &'static str = "bytecode.python";
}

pub type PythonBuilder = BytecodeBuilder<Python>;

pub type LuaBuilder = BytecodeBuilder<Lua>;

impl BytecodeKind for Lua {
    const NAME: &'static str = "bytecode.lua";
}

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
pub struct SourceCode<T>
where
    T: SourceCodeLanguage,
{
    language: PhantomData<fn() -> T>,
}

pub trait SourceCodeLanguage {
    const NAME: &'static str;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceCodeAttribute {
    Name(String),
    Path(PathBuf),
}

impl SourceCodeAttribute {
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }

    pub fn path(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }
}

#[derive(ProvidesStaticType)]
pub struct SourceCodeComponentName<'a>(&'a str);
impl<'a> LoaderAttribute<'a> for SourceCodeComponentName<'a> {
    const UUID: Uuid = uuid("C77F0137-9F2F-4F9C-B248-83287161E3AA");
}

impl<'a> AsRef<str> for SourceCodeComponentName<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for SourceCodeComponentName<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct SourceCodeComponentPath<'a>(&'a Path);
impl<'a> LoaderAttribute<'a> for SourceCodeComponentPath<'a> {
    const UUID: Uuid = uuid("C87CDA4D-240F-41B2-9608-04D73AEC3A70");
}

impl<'a> AsRef<Path> for SourceCodeComponentPath<'a> {
    fn as_ref(&self) -> &Path {
        self.0
    }
}

impl<'a> Deref for SourceCodeComponentPath<'a> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<T> PlatformProvider for SourceCode<T>
where
    T: SourceCodeLanguage,
{
    type Attribute = SourceCodeAttribute;

    const NAME: &'static str = T::NAME;
    const LOADER: PlatformComponentLoader = PlatformComponentLoader::data();
}

impl PlatformAttributeProvider for SourceCodeAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::Name(name) => {
                container.set_attr(SourceCodeComponentName(name));
            }
            Self::Path(path) => {
                container.set_attr(SourceCodeComponentPath(path));
            }
        }
    }
}

pub type SourceCodeBuilder<T> = PlatformBuilder<SourceCode<T>>;

#[derive(Debug, Copy, Clone)]
pub struct C;

impl SourceCodeLanguage for C {
    const NAME: &'static str = "source.c";
}

pub type CBuilder = SourceCodeBuilder<C>;

#[derive(Debug, Copy, Clone)]
pub struct CLikeHeader;

impl SourceCodeLanguage for CLikeHeader {
    const NAME: &'static str = "source.h";
}

pub type CLikeHeaderBuilder = SourceCodeBuilder<CLikeHeader>;

#[derive(Debug, Copy, Clone)]
pub struct CPlusPlus;

impl SourceCodeLanguage for CPlusPlus {
    const NAME: &'static str = "source.c++";
}

pub type CPlusPlusBuilder = SourceCodeBuilder<CPlusPlus>;

#[derive(Debug, Copy, Clone)]
pub struct Html;

impl SourceCodeLanguage for Html {
    const NAME: &'static str = "source.html";
}

pub type HtmlBuilder = SourceCodeBuilder<Html>;

#[derive(Debug, Copy, Clone)]
pub struct Java;

impl SourceCodeLanguage for Java {
    const NAME: &'static str = "source.java";
}

pub type JavaBuilder = SourceCodeBuilder<Java>;

#[derive(Debug, Copy, Clone)]
pub struct JavaScript;

impl SourceCodeLanguage for JavaScript {
    const NAME: &'static str = "source.javascript";
}

pub type JavaScriptBuilder = SourceCodeBuilder<JavaScript>;

#[derive(Debug, Copy, Clone)]
pub struct Json;

impl SourceCodeLanguage for Json {
    const NAME: &'static str = "source.json";
}

pub type JsonBuilder = SourceCodeBuilder<Json>;

#[derive(Debug, Copy, Clone)]
pub struct Julia;

impl SourceCodeLanguage for Julia {
    const NAME: &'static str = "source.julia";
}

pub type JuliaBuilder = SourceCodeBuilder<Julia>;

#[derive(Debug, Copy, Clone)]
pub struct Lisp;

impl SourceCodeLanguage for Lisp {
    const NAME: &'static str = "source.lisp";
}

pub type LispBuilder = SourceCodeBuilder<Lisp>;

#[derive(Debug, Copy, Clone)]
pub struct Lua;

impl SourceCodeLanguage for Lua {
    const NAME: &'static str = "source.lua";
}

pub type LuaBuilder = SourceCodeBuilder<Lua>;

#[derive(Debug, Copy, Clone)]
pub struct Ocaml;

impl SourceCodeLanguage for Ocaml {
    const NAME: &'static str = "source.ocaml";
}

pub type OcamlBuilder = SourceCodeBuilder<Ocaml>;

#[derive(Debug, Copy, Clone)]
pub struct Perl;

impl SourceCodeLanguage for Perl {
    const NAME: &'static str = "source.perl";
}

pub type PerlBuilder = SourceCodeBuilder<Perl>;

#[derive(Debug, Copy, Clone)]
pub struct Php;

impl SourceCodeLanguage for Php {
    const NAME: &'static str = "source.php";
}

pub type PhpBuilder = SourceCodeBuilder<Php>;

#[derive(Debug, Copy, Clone)]
pub struct Plaintext;

impl SourceCodeLanguage for Plaintext {
    const NAME: &'static str = "source.plaintext";
}

pub type PlaintextBuilder = SourceCodeBuilder<Plaintext>;

#[derive(Debug, Copy, Clone)]
pub struct PosixLikeShellScript;

impl SourceCodeLanguage for PosixLikeShellScript {
    const NAME: &'static str = "source.posix.sh";
}

pub type PosixLikeShellScriptBuilder = SourceCodeBuilder<PosixLikeShellScript>;

#[derive(Debug, Copy, Clone)]
pub struct Python;

impl SourceCodeLanguage for Python {
    const NAME: &'static str = "source.python";
}

pub type PythonBuilder = SourceCodeBuilder<Python>;

#[derive(Debug, Copy, Clone)]
pub struct Rlang;

impl SourceCodeLanguage for Rlang {
    const NAME: &'static str = "source.rlang";
}

pub type RlangBuilder = SourceCodeBuilder<Rlang>;

#[derive(Debug, Copy, Clone)]
pub struct Ruby;

impl SourceCodeLanguage for Ruby {
    const NAME: &'static str = "source.ruby";
}

pub type RubyBuilder = SourceCodeBuilder<Ruby>;

#[derive(Debug, Copy, Clone)]
pub struct Xml;

impl SourceCodeLanguage for Xml {
    const NAME: &'static str = "source.xml";
}

pub type XmlBuilder = SourceCodeBuilder<Xml>;

#[derive(Debug, Copy, Clone)]
pub struct Yaml;

impl SourceCodeLanguage for Yaml {
    const NAME: &'static str = "source.yaml";
}

pub type YamlBuilder = SourceCodeBuilder<Yaml>;

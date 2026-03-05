use std::fmt::{Debug, Display};
use std::marker::PhantomData;
use std::path::PathBuf;

use bias_core::any::AnyLifetime;
use bias_core::loader::LoaderContainer;
use bias_core::prelude::*;
use dyn_clone::*;
use thiserror::Error;

pub mod android;
pub mod bytecode;
pub mod common;
pub mod crypto;
pub mod docker;
pub mod efi;
pub mod git;
pub mod java;
pub mod link;
pub mod linux;
pub mod optee;
pub mod posix;
pub mod python;
pub mod secrets;
pub mod source;
pub mod windows;

use common::{BinaryLoaderMetadata, ComponentArch, PlatformAttributeMap};
use efi::{EFIModule, EFIModuleAttribute};
use posix::{PosixBinary, PosixBinaryAttribute};
use windows::{WindowsBinary, WindowsBinaryAttribute};

use crate::component::{ComponentLoaderError, LoadedBinaryComponent, LoadedBinaryComponentData};
use crate::util::BytesOrMapping;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("could not construct project from component: {0}")]
    Project(#[from] anyhow::Error),
    #[error("could not identify platform from component bytes")]
    UnknownFormat,
    #[error("component of type not supported")]
    UnsupportedFormat,
}

impl PlatformError {
    pub fn project<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Project(err.into())
    }

    pub fn project_with<M>(msg: M) -> Self
    where
        M: Debug + Display + Send + Sync + 'static,
    {
        Self::Project(anyhow::Error::msg(msg))
    }
}

#[derive(Clone)]
pub struct Platform {
    pub(crate) platform: &'static str,
    pub(crate) attributes: Box<[Box<dyn PlatformAttributeProvider>]>,
    pub(crate) loader: PlatformComponentLoader,
}

impl Platform {
    pub fn new<T: PlatformProvider>() -> Self {
        Self {
            platform: T::NAME,
            attributes: Vec::with_capacity(0).into_boxed_slice(),
            loader: T::LOADER,
        }
    }

    pub fn new_with<T: PlatformProvider>(loader: PlatformComponentLoader) -> Self {
        Self {
            platform: T::NAME,
            attributes: Vec::with_capacity(0).into_boxed_slice(),
            loader,
        }
    }

    pub fn is<T: PlatformProvider>(&self) -> bool {
        T::NAME == self.platform
    }

    pub fn name(&self) -> &'static str {
        self.platform
    }

    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, PlatformError> {
        Self::from_bytes_with(bytes, None)
    }

    pub fn from_bytes_with(
        bytes: impl AsRef<[u8]>,
        path: impl Into<Option<PathBuf>>,
    ) -> Result<Self, PlatformError> {
        Self::from_bytes_and_attrs_with(bytes, path, None)
    }

    pub fn from_bytes_and_attrs(
        bytes: impl AsRef<[u8]>,
        attrs: impl Into<Option<PlatformAttributeMap>>,
    ) -> Result<Self, PlatformError> {
        Self::from_bytes_and_attrs_with(bytes, None, attrs)
    }

    pub fn from_bytes_and_attrs_with(
        bytes: impl AsRef<[u8]>,
        path: impl Into<Option<PathBuf>>,
        attrs: impl Into<Option<PlatformAttributeMap>>,
    ) -> Result<Self, PlatformError> {
        let bytes = bytes.as_ref();
        if bytes.len() < 16 {
            return Err(PlatformError::UnknownFormat);
        }

        let attrs = attrs.into().unwrap_or_default();

        let fpath = path
            .into()
            .or_else(|| attrs.get_attr::<PathBuf>("path"))
            .unwrap_or_default();

        let fname = fpath
            .file_name()
            .map(|fname| fname.to_string_lossy().into_owned())
            .unwrap_or_default();

        let object = goblin::Object::parse(bytes).map_err(|_| PlatformError::UnknownFormat)?;
        let Some(architecture) = ComponentArch::from_object(&object) else {
            return Err(PlatformError::UnsupportedFormat);
        };
        let loader_meta = BinaryLoaderMetadata::from_object(&object, bytes.len());

        let efi_kind = EFIModule::object_kind_with(&object, &attrs);
        let is_efi = efi_kind.is_some();

        match object {
            goblin::Object::PE(_) if is_efi => {
                let mut builder =
                    PlatformBuilder::<EFIModule>::from_attrs(efi_kind.unwrap(), &attrs);

                builder.push(EFIModuleAttribute::name(fname));
                builder.push(EFIModuleAttribute::architecture(architecture));
                builder.push(EFIModuleAttribute::loader_metadata(loader_meta));

                Ok(builder.build())
            }
            goblin::Object::PE(_) => Ok(PlatformBuilder::<WindowsBinary>::from_iter([
                WindowsBinaryAttribute::name(fname),
                WindowsBinaryAttribute::path(fpath),
                WindowsBinaryAttribute::architecture(architecture),
                WindowsBinaryAttribute::loader_metadata(loader_meta),
            ])
            .build()),
            goblin::Object::Elf(_) => {
                let mut builder = PlatformBuilder::<PosixBinary>::from_attrs(&attrs);

                builder.push(PosixBinaryAttribute::name(fname));
                builder.push(PosixBinaryAttribute::path(fpath));
                builder.push(PosixBinaryAttribute::architecture(architecture));
                builder.push(PosixBinaryAttribute::loader_metadata(loader_meta));

                Ok(builder.build())
            }
            goblin::Object::TE(_) if is_efi => {
                let mut builder =
                    PlatformBuilder::<EFIModule>::from_attrs(efi_kind.unwrap(), &attrs);

                builder.push(EFIModuleAttribute::name(fname));
                builder.push(EFIModuleAttribute::architecture(architecture));
                builder.push(EFIModuleAttribute::loader_metadata(loader_meta));

                Ok(builder.build())
            }
            _ => Err(PlatformError::UnsupportedFormat),
        }
    }

    pub fn attributes(&self) -> PlatformAttributes<'_> {
        let mut attrs = PlatformAttributes::new(&[][..]);
        for attr in self.attributes.iter() {
            attr.apply_attribute(&mut attrs);
        }
        attrs
    }

    pub fn is_binary(&self) -> bool {
        self.loader.is_binary()
    }

    pub fn is_data(&self) -> bool {
        self.loader.is_data()
    }

    pub fn into_data(self) -> Self {
        Self {
            platform: self.platform,
            attributes: self.attributes,
            loader: PlatformComponentLoader::data(),
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        &'static str,
        Box<[Box<dyn PlatformAttributeProvider>]>,
        PlatformComponentLoader,
    ) {
        (self.platform, self.attributes, self.loader)
    }
}

pub struct PlatformBuilder<T>
where
    T: PlatformProvider,
{
    attributes: Vec<Box<dyn PlatformAttributeProvider>>,
    _marker: PhantomData<T>,
}

impl<T> PlatformBuilder<T>
where
    T: PlatformProvider,
{
    pub fn new() -> Self {
        Self {
            attributes: Vec::with_capacity(0),
            _marker: PhantomData,
        }
    }

    pub fn push(&mut self, attr: impl Into<T::Attribute>) {
        self.attributes.push(Box::new(attr.into()));
    }

    pub fn build(self) -> Platform {
        Platform {
            platform: T::NAME,
            attributes: self.attributes.into_boxed_slice(),
            loader: T::LOADER,
        }
    }

    pub fn build_with(self, loader: PlatformComponentLoader) -> Platform {
        Platform {
            platform: T::NAME,
            attributes: self.attributes.into_boxed_slice(),
            loader,
        }
    }
}

impl<V> FromIterator<V::Attribute> for PlatformBuilder<V>
where
    V: PlatformProvider,
{
    fn from_iter<I: IntoIterator<Item = V::Attribute>>(iter: I) -> Self {
        Self {
            attributes: iter
                .into_iter()
                .map(|attr| Box::new(attr) as Box<dyn PlatformAttributeProvider>)
                .collect(),
            _marker: PhantomData,
        }
    }
}

pub trait PlatformProvider {
    type Attribute: PlatformAttributeProvider + 'static;

    const NAME: &'static str;
    const LOADER: PlatformComponentLoader;
}

#[derive(Clone)]
#[repr(transparent)]
pub struct AsData<T>
where
    T: PlatformProvider,
{
    provider: PhantomData<fn() -> T>,
}

impl<T> PlatformProvider for AsData<T>
where
    T: PlatformProvider,
{
    type Attribute = T::Attribute;

    const NAME: &'static str = T::NAME;
    const LOADER: PlatformComponentLoader = PlatformComponentLoader::data();
}

#[derive(Clone, Copy)]
pub enum PlatformComponentLoader {
    Data,
    Binary(&'static dyn PlatformComponentBinaryLoader),
    GuidedBinary(&'static dyn PlatformComponentGuidedBinaryLoader),
}

impl PlatformComponentLoader {
    pub const fn data() -> Self {
        Self::Data
    }

    pub const fn binary(t: &'static dyn PlatformComponentBinaryLoader) -> Self {
        Self::Binary(t)
    }

    pub const fn guided_binary(t: &'static dyn PlatformComponentGuidedBinaryLoader) -> Self {
        Self::GuidedBinary(t)
    }

    pub fn is_binary(&self) -> bool {
        matches!(self, Self::Binary(_) | Self::GuidedBinary(_))
    }

    pub fn is_guided_binary(&self) -> bool {
        matches!(self, Self::GuidedBinary(_))
    }

    pub fn is_data(&self) -> bool {
        matches!(self, Self::Data)
    }
}

pub struct PlatformComponentBinaryData<'data>(pub Lifter, pub LoadedBinaryComponentData<'data>);

pub trait PlatformComponentBinaryLoader: Send + Sync + 'static {
    #[allow(unused)]
    fn load_bytes<'data, 'bytes>(
        &self,
        ldb: &LanguageDB,
        bytes: &'data BytesOrMapping<'bytes>,
    ) -> Result<PlatformComponentBinaryData<'data>, ComponentLoaderError> {
        self.load_bytes_with(ldb, bytes, None)
    }

    #[allow(unused)]
    fn load_bytes_with<'data, 'bytes>(
        &self,
        ldb: &LanguageDB,
        bytes: &'data BytesOrMapping<'bytes>,
        path: Option<PathBuf>,
    ) -> Result<PlatformComponentBinaryData<'data>, ComponentLoaderError> {
        Err(ComponentLoaderError::Unsupported)
    }
}

pub trait PlatformComponentGuidedBinaryLoader: PlatformComponentBinaryLoader {
    #[allow(unused)]
    fn load_project(
        &self,
        binary: &LoadedBinaryComponent<'_>,
        lifter: Lifter,
        config: &ProjectConfig,
    ) -> Result<Project, PlatformError> {
        Ok(Project::new_with(binary, lifter, config))
    }
}

pub trait PlatformAttributeProvider: DynClone + Send + Sync + 'static {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>);
}

clone_trait_object!(PlatformAttributeProvider);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NullaryPlatformAttribute;

impl PlatformAttributeProvider for NullaryPlatformAttribute {
    fn apply_attribute<'a>(&'a self, _container: &mut LoaderContainer<'a>) {}
}

pub trait PlatformAttribute: Clone + Send + Sync + 'static {
    type T<'a>: LoaderAttribute<'a>;

    fn as_attr<'a>(&'a self) -> Self::T<'a>;
}

pub trait DynamicPlatformAttribute: DynClone + Send + Sync + 'static {
    fn id(&self) -> Uuid;
    fn as_boxed_attr<'a>(&'a self) -> Box<dyn AnyLifetime<'a> + 'a>;
}
clone_trait_object!(DynamicPlatformAttribute);

impl<T> DynamicPlatformAttribute for T
where
    T: PlatformAttribute,
{
    fn id(&self) -> Uuid {
        <<T as PlatformAttribute>::T<'_>>::UUID
    }

    fn as_boxed_attr<'a>(&'a self) -> Box<dyn AnyLifetime<'a> + 'a> {
        Box::new(self.as_attr())
    }
}

pub type PlatformAttributes<'a> = LoaderContainer<'a>;

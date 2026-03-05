use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::{Debug, Display};
use std::path::Path;

use bias_core::loader::{
    LoadedBinary, LoaderBlock, LoaderBytes, LoaderContainer, LoaderFunction, LoaderImport,
    LoaderRegion,
};
use bias_core::prelude::*;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::pipeline::PipelineError;
use crate::platform::common::{PlatformAttributeMap, SourceFilePathAttribute};
use crate::platform::{
    DynamicPlatformAttribute, Platform, PlatformAttributeProvider, PlatformComponentBinaryData,
    PlatformComponentGuidedBinaryLoader, PlatformComponentLoader, PlatformError,
};
use crate::util::BytesOrMapping;

pub use crate::types::component::*;

#[derive(Clone, Deserialize, Serialize)]
pub struct ComponentWith<T> {
    pub component: Component,
    pub data: T,
}

impl<T> ComponentWith<T> {
    pub fn new(component: Component, data: T) -> Self {
        Self { component, data }
    }

    pub fn component(&self) -> &Component {
        &self.component
    }

    pub fn data(&self) -> &T {
        &self.data
    }

    pub fn into_parts(self) -> (Component, T) {
        (self.component, self.data)
    }
}

impl<T> ComponentWith<T>
where
    T: DeserializeOwned + Serialize,
{
    pub fn to_bytes(&self) -> Result<Vec<u8>, PipelineError> {
        rmp_serde::to_vec(self).map_err(PipelineError::io)
    }

    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, PipelineError> {
        rmp_serde::from_slice(bytes.as_ref()).map_err(PipelineError::io)
    }
}

#[derive(Debug, Error)]
pub enum ComponentLoaderError {
    #[error(transparent)]
    EFILoader(#[from] bias_core::loader::efi::Error),
    #[error(transparent)]
    ELFLoader(#[from] bias_core::loader::elf::Error),
    #[error(transparent)]
    PELoader(#[from] bias_core::loader::pe::Error),
    #[error(transparent)]
    TELoader(#[from] bias_core::loader::te::Error),
    #[error(transparent)]
    LanguageDB(#[from] bias_core::fugue::ir::error::Error),
    #[error(transparent)]
    LoaderIO(#[from] std::io::Error),
    #[error(transparent)]
    Platform(#[from] PlatformError),
    #[error(transparent)]
    Custom(anyhow::Error),
    #[error("unsupported component kind")]
    Unsupported,
}

impl ComponentLoaderError {
    pub fn custom<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Custom(anyhow::Error::new(error))
    }

    pub fn custom_with<M>(msg: M) -> Self
    where
        M: Debug + Display + Send + Sync + 'static,
    {
        Self::Custom(anyhow::Error::msg(msg))
    }
}

pub struct ComponentLoader<'a> {
    ldb: Cow<'a, LanguageDB>,
}

pub enum LoadedComponent<'a> {
    Binary(Lifter, LoadedBinaryComponent<'a>),
    Data(LoadedDataComponent<'a>),
}

impl<'a> LoadedComponent<'a> {
    pub fn id(&self) -> Uuid {
        match self {
            LoadedComponent::Binary(_, c) => c.id(),
            LoadedComponent::Data(c) => c.id(),
        }
    }

    pub fn platform(&self) -> &'static str {
        match self {
            LoadedComponent::Binary(_, c) => c.platform(),
            LoadedComponent::Data(c) => c.platform(),
        }
    }

    pub fn register_platform_attribute<T>(&mut self, attr: T)
    where
        T: DynamicPlatformAttribute,
    {
        match self {
            LoadedComponent::Binary(_, c) => c.register_platform_attribute(attr),
            LoadedComponent::Data(c) => c.register_platform_attribute(attr),
        }
    }

    pub fn into_binary_parts(self) -> Option<(Lifter, LoadedBinaryComponent<'a>)> {
        let Self::Binary(lifter, component) = self else {
            return None;
        };
        Some((lifter, component))
    }

    pub fn into_data_parts(self) -> Option<LoadedDataComponent<'a>> {
        let Self::Data(component) = self else {
            return None;
        };
        Some(component)
    }

    pub fn into_data(self) -> Self {
        Self::Data(match self {
            Self::Binary(_, component) => component.into_data(),
            Self::Data(component) => component,
        })
    }
}

pub struct LoadedDataComponent<'a> {
    id: Uuid,
    data: BytesOrMapping<'a>,
    platform: &'static str,
    attributes: Box<[Box<dyn PlatformAttributeProvider>]>,
    dattributes: BTreeMap<Uuid, Box<dyn DynamicPlatformAttribute>>,
}

impl<'a> LoadedDataComponent<'a> {
    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn bytes(&self) -> LoaderBytes<'_> {
        LoaderBytes::Borrowed(self.data.as_ref())
    }

    pub fn platform(&self) -> &'static str {
        self.platform
    }

    pub fn md5(&self) -> [u8; 16] {
        <md5::Md5 as md5::Digest>::digest(self.data.as_ref()).into()
    }

    pub fn sha1(&self) -> [u8; 20] {
        <sha1::Sha1 as sha1::Digest>::digest(self.data.as_ref()).into()
    }

    pub fn sha256(&self) -> [u8; 32] {
        <sha2::Sha256 as sha2::Digest>::digest(self.data.as_ref()).into()
    }

    pub fn container(&self) -> LoaderContainer<'_> {
        let mut container = LoaderContainer::new(self.data.as_ref());
        for attr in self.attributes.iter() {
            attr.apply_attribute(&mut container);
        }
        for (id, dattr) in self.dattributes.iter() {
            container.set_dyn_attr(*id, dattr.as_boxed_attr());
        }
        container
    }

    pub fn register_platform_attribute<T>(&mut self, attr: T)
    where
        T: DynamicPlatformAttribute,
    {
        self.dattributes.insert(attr.id(), Box::new(attr));
    }
}

#[ouroboros::self_referencing(pub_extras)]
pub struct LoadedBinaryComponent<'a> {
    id: Uuid,
    data: BytesOrMapping<'a>,
    platform: &'static str,
    platform_loader: PlatformComponentLoader,
    attributes: Box<[Box<dyn PlatformAttributeProvider>]>,
    dattributes: BTreeMap<Uuid, Box<dyn DynamicPlatformAttribute>>,
    #[borrows(data)]
    #[covariant]
    component: LoadedBinaryComponentData<'this>,
}

impl<'a> LoadedBinaryComponent<'a> {
    pub fn id(&self) -> Uuid {
        *self.borrow_id()
    }

    pub fn platform(&self) -> &'static str {
        *self.borrow_platform()
    }

    pub fn binary(&self) -> &LoadedBinaryComponentData<'_> {
        self.borrow_component()
    }

    pub fn md5(&self) -> [u8; 16] {
        <md5::Md5 as md5::Digest>::digest(self.borrow_data().as_ref()).into()
    }

    pub fn sha1(&self) -> [u8; 20] {
        <sha1::Sha1 as sha1::Digest>::digest(self.borrow_data().as_ref()).into()
    }

    pub fn sha256(&self) -> [u8; 32] {
        <sha2::Sha256 as sha2::Digest>::digest(self.borrow_data().as_ref()).into()
    }

    pub fn project_loader(&self) -> Option<&'static dyn PlatformComponentGuidedBinaryLoader> {
        if let PlatformComponentLoader::GuidedBinary(loader) = self.borrow_platform_loader() {
            Some(*loader)
        } else {
            None
        }
    }

    pub fn register_platform_attribute<T>(&mut self, attr: T)
    where
        T: DynamicPlatformAttribute,
    {
        self.with_dattributes_mut(|dattrs| dattrs.insert(attr.id(), Box::new(attr)));
    }

    pub fn into_data(self) -> LoadedDataComponent<'a> {
        let heads = self.into_heads();
        LoadedDataComponent {
            id: heads.id,
            data: heads.data,
            platform: heads.platform,
            attributes: heads.attributes,
            dattributes: heads.dattributes,
        }
    }
}

pub enum LoadedBinaryComponentData<'a> {
    EFI(LoadedEFI<'a>),
    ELF(LoadedELF<'a>),
    PE(LoadedPE<'a>),
    Other(Box<dyn bias_core::loader::ErasedLoadedBinary + 'a>),
}

impl<'a> LoadedBinary for LoadedBinaryComponent<'a> {
    fn for_each_region<'b, F>(&'b self, f: F)
    where
        F: FnMut(&LoaderRegion<'b>),
    {
        match &self.borrow_component() {
            LoadedBinaryComponentData::EFI(loaded) => loaded.for_each_region(f),
            LoadedBinaryComponentData::ELF(loaded) => loaded.for_each_region(f),
            LoadedBinaryComponentData::PE(loaded) => loaded.for_each_region(f),
            LoadedBinaryComponentData::Other(loaded) => loaded.for_each_region(f),
        }
    }

    fn for_each_region_with<'b, A, F>(&'b self, rebase: A, f: F)
    where
        A: Into<Option<Address>>,
        F: FnMut(&LoaderRegion<'b>),
    {
        match &self.borrow_component() {
            LoadedBinaryComponentData::EFI(loaded) => loaded.for_each_region_with(rebase, f),
            LoadedBinaryComponentData::ELF(loaded) => loaded.for_each_region_with(rebase, f),
            LoadedBinaryComponentData::PE(loaded) => loaded.for_each_region_with(rebase, f),
            LoadedBinaryComponentData::Other(loaded) => loaded.for_each_region_with(rebase, f),
        }
    }

    fn for_each_function<'b, F>(&'b self, f: F)
    where
        F: FnMut(&LoaderFunction<'b>),
    {
        match &self.borrow_component() {
            LoadedBinaryComponentData::EFI(loaded) => loaded.for_each_function(f),
            LoadedBinaryComponentData::ELF(loaded) => loaded.for_each_function(f),
            LoadedBinaryComponentData::PE(loaded) => loaded.for_each_function(f),
            LoadedBinaryComponentData::Other(loaded) => loaded.for_each_function(f),
        }
    }

    fn for_each_block<F>(&self, f: F)
    where
        F: FnMut(&LoaderBlock),
    {
        match &self.borrow_component() {
            LoadedBinaryComponentData::EFI(loaded) => loaded.for_each_block(f),
            LoadedBinaryComponentData::ELF(loaded) => loaded.for_each_block(f),
            LoadedBinaryComponentData::PE(loaded) => loaded.for_each_block(f),
            LoadedBinaryComponentData::Other(loaded) => loaded.for_each_block(f),
        }
    }

    fn for_each_import<'b, F>(&'b self, f: F)
    where
        F: FnMut(&LoaderImport<'b>),
    {
        match &self.borrow_component() {
            LoadedBinaryComponentData::EFI(loaded) => loaded.for_each_import(f),
            LoadedBinaryComponentData::ELF(loaded) => loaded.for_each_import(f),
            LoadedBinaryComponentData::PE(loaded) => loaded.for_each_import(f),
            LoadedBinaryComponentData::Other(loaded) => loaded.for_each_import(f),
        }
    }

    fn for_each_export<'b, F>(&'b self, f: F)
    where
        F: FnMut(&LoaderExport<'b>),
    {
        match &self.borrow_component() {
            LoadedBinaryComponentData::EFI(loaded) => loaded.for_each_export(f),
            LoadedBinaryComponentData::ELF(loaded) => loaded.for_each_export(f),
            LoadedBinaryComponentData::PE(loaded) => loaded.for_each_export(f),
            LoadedBinaryComponentData::Other(loaded) => loaded.for_each_export(f),
        }
    }

    fn for_each_critical_function<'b, F>(&'b self, context: &mut ICFGExtendedContext, f: F)
    where
        F: FnMut(Address),
    {
        match &self.borrow_component() {
            LoadedBinaryComponentData::EFI(loaded) => loaded.for_each_critical_function(context, f),
            LoadedBinaryComponentData::ELF(loaded) => loaded.for_each_critical_function(context, f),
            LoadedBinaryComponentData::PE(loaded) => loaded.for_each_critical_function(context, f),
            LoadedBinaryComponentData::Other(loaded) => {
                loaded.for_each_critical_function(context, f)
            }
        }
    }

    fn bytes<'b>(&'b self) -> LoaderBytes<'b> {
        match &self.borrow_component() {
            LoadedBinaryComponentData::EFI(loaded) => loaded.bytes().into(),
            LoadedBinaryComponentData::ELF(loaded) => loaded.bytes().into(),
            LoadedBinaryComponentData::PE(loaded) => loaded.bytes().into(),
            LoadedBinaryComponentData::Other(loaded) => loaded.bytes().into(),
        }
    }

    fn container<'b>(&'b self) -> LoaderContainer<'b> {
        let mut container = match self.borrow_component() {
            LoadedBinaryComponentData::EFI(loaded) => loaded.container(),
            LoadedBinaryComponentData::ELF(loaded) => loaded.container(),
            LoadedBinaryComponentData::PE(loaded) => loaded.container(),
            LoadedBinaryComponentData::Other(loaded) => loaded.container(),
        };

        for attr in self.borrow_attributes().iter() {
            attr.apply_attribute(&mut container);
        }

        for (id, dattr) in self.borrow_dattributes().iter() {
            container.set_dyn_attr(*id, dattr.as_boxed_attr());
        }

        container
    }

    fn entry_point(&self) -> Option<Address> {
        match self.borrow_component() {
            LoadedBinaryComponentData::EFI(loaded) => loaded.entry_point(),
            LoadedBinaryComponentData::ELF(loaded) => loaded.entry_point(),
            LoadedBinaryComponentData::PE(loaded) => loaded.entry_point(),
            LoadedBinaryComponentData::Other(loaded) => loaded.entry_point(),
        }
    }
}

impl<'a> Symbolise for LoadedBinaryComponent<'a> {
    fn apply_symbols(&self, project: &mut Project) -> Result<(), SymboliseError> {
        match self.borrow_component() {
            LoadedBinaryComponentData::EFI(loaded) => loaded.apply_symbols(project),
            LoadedBinaryComponentData::ELF(loaded) => loaded.apply_symbols(project),
            LoadedBinaryComponentData::PE(_loaded) => {
                // loaded.apply_symbols(project),
                Ok(())
            }
            LoadedBinaryComponentData::Other(_loaded) => Ok(()),
        }
    }
}

impl<'a> ComponentLoader<'a> {
    pub fn new(ldb: impl Into<Cow<'a, LanguageDB>>) -> Self {
        Self { ldb: ldb.into() }
    }

    pub fn new_with(path: impl AsRef<Path>) -> Result<Self, ComponentLoaderError> {
        let ldb = LanguageDB::from_directory_with(path, true)?;
        Ok(Self::new(Cow::Owned(ldb)))
    }

    pub fn languages(&self) -> &LanguageDB {
        &self.ldb
    }

    pub fn load_file(
        &self,
        id: Uuid,
        path: impl AsRef<Path>,
    ) -> Result<LoadedComponent<'static>, ComponentLoaderError> {
        self.load_file_with(id, path, None)
    }

    pub fn load_file_with(
        &self,
        id: Uuid,
        path: impl AsRef<Path>,
        platform: impl Into<Option<Platform>>,
    ) -> Result<LoadedComponent<'static>, ComponentLoaderError> {
        let path = path.as_ref().to_path_buf();
        let bytes = BytesOrMapping::from_file(&path)?;

        let mut loaded = self.load_with(id, bytes, platform)?;
        loaded.register_platform_attribute(SourceFilePathAttribute::from(path));

        Ok(loaded)
    }

    pub fn load_file_with_attrs<'b>(
        &self,
        id: Uuid,
        path: impl AsRef<Path>,
        attrs: impl Into<Option<PlatformAttributeMap>>,
    ) -> Result<LoadedComponent<'b>, ComponentLoaderError> {
        let path = path.as_ref().to_path_buf();
        let bytes = BytesOrMapping::from_file(&path)?;
        let platform = Platform::from_bytes_and_attrs(&*bytes, attrs)?;

        let mut loaded = self.load_with(id, bytes, platform)?;
        loaded.register_platform_attribute(SourceFilePathAttribute::from(path));

        Ok(loaded)
    }

    pub fn load_bytes<'b>(
        &self,
        id: Uuid,
        bytes: impl Into<Cow<'b, [u8]>>,
    ) -> Result<LoadedComponent<'b>, ComponentLoaderError> {
        self.load_bytes_with(id, bytes, None)
    }

    pub fn load_bytes_with<'b>(
        &self,
        id: Uuid,
        bytes: impl Into<Cow<'b, [u8]>>,
        platform: impl Into<Option<Platform>>,
    ) -> Result<LoadedComponent<'b>, ComponentLoaderError> {
        let bytes = BytesOrMapping::from_bytes(bytes);
        self.load_with(id, bytes, platform)
    }

    pub fn load_bytes_with_attrs<'b>(
        &self,
        id: Uuid,
        bytes: impl Into<Cow<'b, [u8]>>,
        attrs: impl Into<Option<PlatformAttributeMap>>,
    ) -> Result<LoadedComponent<'b>, ComponentLoaderError> {
        let bytes = bytes.into();
        let platform = Platform::from_bytes_and_attrs(&*bytes, attrs)?;
        self.load_with(id, bytes, platform)
    }

    pub fn load<'b>(
        &self,
        id: Uuid,
        bytes: impl Into<BytesOrMapping<'b>>,
    ) -> Result<LoadedComponent<'b>, ComponentLoaderError> {
        self.load_with(id, bytes, None)
    }

    pub fn load_with_attrs<'b>(
        &self,
        id: Uuid,
        bytes: impl Into<BytesOrMapping<'b>>,
        attrs: impl Into<Option<PlatformAttributeMap>>,
    ) -> Result<LoadedComponent<'b>, ComponentLoaderError> {
        let bytes = bytes.into();
        let platform = Platform::from_bytes_and_attrs(&*bytes, attrs)?;
        self.load_with(id, bytes, platform)
    }

    pub fn load_with<'b>(
        &self,
        id: Uuid,
        bytes: impl Into<BytesOrMapping<'b>>,
        platform: impl Into<Option<Platform>>,
    ) -> Result<LoadedComponent<'b>, ComponentLoaderError> {
        let bytes = bytes.into();
        let Platform {
            platform,
            attributes,
            loader,
        } = match platform.into() {
            None => Platform::from_bytes(&bytes)?,
            Some(platform) => platform,
        };

        match loader {
            PlatformComponentLoader::Data => Ok(LoadedComponent::Data(LoadedDataComponent {
                id,
                data: bytes,
                platform,
                attributes,
                dattributes: Default::default(),
            })),
            PlatformComponentLoader::Binary(bloader) => {
                let mut lifter = None;
                let loaded = LoadedBinaryComponent::try_new(
                    id,
                    bytes,
                    platform,
                    loader,
                    attributes,
                    Default::default(),
                    |bytes| -> Result<_, ComponentLoaderError> {
                        let PlatformComponentBinaryData(lift, loaded) =
                            bloader.load_bytes(&self.ldb, bytes)?;
                        lifter = Some(lift);

                        Ok(loaded)
                    },
                )?;

                Ok(LoadedComponent::Binary(lifter.unwrap(), loaded))
            }
            PlatformComponentLoader::GuidedBinary(bloader) => {
                let mut lifter = None;
                let loaded = LoadedBinaryComponent::try_new(
                    id,
                    bytes,
                    platform,
                    loader,
                    attributes,
                    Default::default(),
                    |bytes| -> Result<_, ComponentLoaderError> {
                        let PlatformComponentBinaryData(lift, loaded) =
                            bloader.load_bytes(&self.ldb, bytes)?;
                        lifter = Some(lift);

                        Ok(loaded)
                    },
                )?;

                Ok(LoadedComponent::Binary(lifter.unwrap(), loaded))
            }
        }
    }
}

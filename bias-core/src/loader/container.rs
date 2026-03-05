use std::ops::Deref;

use ahash::AHashMap;
pub use goblin::elf::Elf as ELF;
pub use goblin::pe::PE;
pub use goblin::te::TE;

pub use super::efi::EFI;
use super::{LoaderBytes, LoaderExport, LoaderImport};
use crate::any::{AnyLifetime, ProvidesStaticType};
use crate::kb::{uuid, Uuid};
use crate::project::analysis::{AnalysisState, AnalysisStateInfo};

enum RefOrOwned<'a, T> {
    Ref(&'a T),
    Owned(T),
}

impl<'a, T> AsRef<T> for RefOrOwned<'a, T> {
    fn as_ref(&self) -> &T {
        match self {
            Self::Ref(t) => t,
            Self::Owned(ref t) => t,
        }
    }
}

impl<'a, T> Deref for RefOrOwned<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

enum LoaderContainerRepr<'a> {
    ELF(RefOrOwned<'a, ELF<'a>>),
    PE(RefOrOwned<'a, PE<'a>>),
    TE(RefOrOwned<'a, TE<'a>>),
    RawBorrowed(&'a [u8]),
    RawOwned(Vec<u8>),
}

#[derive(ProvidesStaticType)]
pub struct LoaderContainer<'a> {
    inner: LoaderContainerRepr<'a>,
    attrs: AHashMap<Uuid, Box<dyn AnyLifetime<'a>>>,
}

impl<'a> From<&'a [u8]> for LoaderContainer<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self::from_repr(LoaderContainerRepr::RawBorrowed(value))
    }
}

impl<'a> From<Vec<u8>> for LoaderContainer<'a> {
    fn from(value: Vec<u8>) -> Self {
        Self::from_repr(LoaderContainerRepr::RawOwned(value))
    }
}

impl<'a> From<&'a LoaderBytes<'_>> for LoaderContainer<'a> {
    fn from(value: &'a LoaderBytes) -> Self {
        match value {
            LoaderBytes::Borrowed(bytes) => {
                Self::from_repr(LoaderContainerRepr::RawBorrowed(bytes))
            }
            LoaderBytes::Owned(bytes) => Self::from_repr(LoaderContainerRepr::RawBorrowed(bytes)),
        }
    }
}

impl<'a> From<LoaderBytes<'a>> for LoaderContainer<'a> {
    fn from(value: LoaderBytes<'a>) -> Self {
        match value {
            LoaderBytes::Borrowed(bytes) => {
                Self::from_repr(LoaderContainerRepr::RawBorrowed(bytes))
            }
            LoaderBytes::Owned(bytes) => Self::from_repr(LoaderContainerRepr::RawOwned(bytes)),
        }
    }
}

impl<'a> From<&'a EFI<'a>> for LoaderContainer<'a> {
    fn from(value: &'a EFI<'a>) -> Self {
        match value {
            EFI::PE(pe) => Self::from_repr(LoaderContainerRepr::PE(RefOrOwned::Ref(pe))),
            EFI::TE(te) => Self::from_repr(LoaderContainerRepr::TE(RefOrOwned::Ref(te))),
        }
    }
}

impl<'a> From<&'a ELF<'a>> for LoaderContainer<'a> {
    fn from(value: &'a ELF<'a>) -> Self {
        Self::from_repr(LoaderContainerRepr::ELF(RefOrOwned::Ref(value)))
    }
}

impl<'a> From<&'a PE<'a>> for LoaderContainer<'a> {
    fn from(value: &'a PE<'a>) -> Self {
        Self::from_repr(LoaderContainerRepr::PE(RefOrOwned::Ref(value)))
    }
}

impl<'a> From<&'a TE<'a>> for LoaderContainer<'a> {
    fn from(value: &'a TE<'a>) -> Self {
        Self::from_repr(LoaderContainerRepr::TE(RefOrOwned::Ref(value)))
    }
}

impl<'a> From<EFI<'a>> for LoaderContainer<'a> {
    fn from(value: EFI<'a>) -> Self {
        match value {
            EFI::PE(pe) => Self::from_repr(LoaderContainerRepr::PE(RefOrOwned::Owned(pe))),
            EFI::TE(te) => Self::from_repr(LoaderContainerRepr::TE(RefOrOwned::Owned(te))),
        }
    }
}

impl<'a> From<ELF<'a>> for LoaderContainer<'a> {
    fn from(value: ELF<'a>) -> Self {
        Self::from_repr(LoaderContainerRepr::ELF(RefOrOwned::Owned(value)))
    }
}

impl<'a> From<PE<'a>> for LoaderContainer<'a> {
    fn from(value: PE<'a>) -> Self {
        Self::from_repr(LoaderContainerRepr::PE(RefOrOwned::Owned(value)))
    }
}

impl<'a> From<TE<'a>> for LoaderContainer<'a> {
    fn from(value: TE<'a>) -> Self {
        Self::from_repr(LoaderContainerRepr::TE(RefOrOwned::Owned(value)))
    }
}

pub trait LoaderAttribute<'a>: AnyLifetime<'a> {
    const UUID: Uuid;
}

impl<'a> LoaderContainer<'a> {
    fn from_repr(repr: LoaderContainerRepr<'a>) -> Self {
        Self {
            inner: repr,
            attrs: AHashMap::with_capacity(0),
        }
    }

    pub fn new(value: impl Into<Self>) -> Self {
        value.into()
    }

    pub fn elf(&self) -> Option<&ELF<'a>> {
        use LoaderContainerRepr as R;
        if let R::ELF(ref v) = self.inner {
            Some(v.as_ref())
        } else {
            None
        }
    }

    pub fn pe(&self) -> Option<&PE<'a>> {
        use LoaderContainerRepr as R;
        if let R::PE(ref v) = self.inner {
            Some(v.as_ref())
        } else {
            None
        }
    }

    pub fn te(&self) -> Option<&TE<'a>> {
        use LoaderContainerRepr as R;
        if let R::TE(ref v) = self.inner {
            Some(v.as_ref())
        } else {
            None
        }
    }

    pub fn raw(&self) -> Option<&[u8]> {
        use LoaderContainerRepr as R;
        match self.inner {
            R::RawBorrowed(ref v) => Some(v),
            R::RawOwned(ref v) => Some(v),
            _ => None,
        }
    }

    pub fn is_elf(&self) -> bool {
        self.elf().is_some()
    }

    pub fn is_pe(&self) -> bool {
        self.pe().is_some()
    }

    pub fn is_te(&self) -> bool {
        self.te().is_some()
    }

    pub fn is_raw(&self) -> bool {
        self.raw().is_some()
    }

    pub fn set_attr<T>(&mut self, value: T)
    where
        T: LoaderAttribute<'a>,
    {
        self.attrs.insert(T::UUID, Box::new(value));
    }

    pub fn set_dyn_attr(&mut self, id: Uuid, value: Box<dyn AnyLifetime<'a>>) {
        self.attrs.insert(id, value);
    }

    pub fn get_attr<T>(&self) -> Option<&T>
    where
        T: LoaderAttribute<'a>,
    {
        self.attrs.get(&T::UUID).and_then(|v| v.downcast_ref())
    }

    pub fn get_attr_mut<T>(&mut self) -> Option<&mut T>
    where
        T: LoaderAttribute<'a>,
    {
        self.attrs.get_mut(&T::UUID).and_then(|v| v.downcast_mut())
    }

    pub fn for_each_import<'b, F>(&'b self, mut f: F)
    where
        F: FnMut(&LoaderImport<'b>),
    {
        use LoaderContainerRepr as R;
        match self.inner {
            R::PE(ref pe) => {
                pe.imports.iter().for_each(|import| {
                    f(&LoaderImport {
                        name: import.name.as_ref().into(),
                        address: Some(
                            (import.offset as u64)
                                .wrapping_add(pe.image_base as u64)
                                .into(),
                        ),
                        source: Some(import.dll.into()),
                        ..Default::default()
                    })
                });
            }
            _ => (),
        }
    }

    pub fn for_each_export<'b, F>(&'b self, _: F)
    where
        F: FnMut(&LoaderExport<'b>),
    {
    }

    pub fn bytes(&self) -> &[u8] {
        use LoaderContainerRepr as R;
        match self.inner {
            R::RawBorrowed(v) => v,
            R::RawOwned(ref v) => v,
            _ => self
                .get_attr::<LoaderBytes>()
                .map(LoaderBytes::as_ref)
                .unwrap_or_default(),
        }
    }
}

pub const LOADER_CONTAINER_DATA: Uuid = uuid("F5E89593-0701-4B23-9A4C-11A577C98D1A");

impl<'a> AnalysisStateInfo<'a> for LoaderContainer<'a> {
    const UUID: Uuid = LOADER_CONTAINER_DATA;
}

impl<'a> AnalysisState<'a> for LoaderContainer<'a> {
    fn id(&self) -> &Uuid {
        &Self::UUID
    }
}

use std::borrow::{Borrow, Cow};
use std::convert::Infallible;
use std::ops::{Deref, Range};
use std::path::Path;

use fugue::bytes::{ByteCast, Endian, BE, LE};
use fugue::ir::Address;
use smallvec::SmallVec;
use thiserror::Error;

use crate::any::ProvidesStaticType;
use crate::arch::ContextUpdates;
use crate::cfg::context::ICFGExtendedContext;
use crate::kb::function::FunctionInfo;
use crate::kb::{uuid, Uuid};
use crate::lifter::Lifter;
use crate::project::analysis::{AnalysisState, AnalysisStateInfo};
use crate::region::Region;

pub mod container;
pub mod efi;
pub mod elf;
pub mod externs;
pub mod pe;
pub mod shellcode;
pub mod te;

pub use container::{LoaderAttribute, LoaderContainer};
pub use efi::{EFIFirmwareLoader, EFILoader};
pub use elf::ELFLoader;
pub use externs::{
    ExternalLoader, ExternalSymbols, ExternalsProvider, ExternalsProviderError, HasExternals,
};
pub use pe::PELoader;
pub use shellcode::Shellcode;
pub use te::TELoader;

pub trait Loader {
    type Error: std::error::Error;
    type Loaded: LoadedBinary;

    fn load_file<P>(self, path: P) -> Result<(Lifter, Self::Loaded), Self::Error>
    where
        P: AsRef<Path>;
}

pub struct LoaderBlock {
    pub bounds: Range<Address>,
    pub targets: SmallVec<[Address; 2]>,
}

impl Default for LoaderBlock {
    fn default() -> Self {
        Self {
            bounds: Address::from(0u32)..Address::from(1u32),
            targets: SmallVec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, ProvidesStaticType)]
pub enum LoaderBytes<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl<'a> From<&'a [u8]> for LoaderBytes<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self::Borrowed(value)
    }
}

impl<'a> From<Vec<u8>> for LoaderBytes<'a> {
    fn from(value: Vec<u8>) -> Self {
        Self::Owned(value)
    }
}

impl<'a> Default for LoaderBytes<'a> {
    fn default() -> Self {
        Self::Borrowed(&[])
    }
}

impl<'a> AsRef<[u8]> for LoaderBytes<'a> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Owned(ref v) => v,
            Self::Borrowed(v) => v,
        }
    }
}

impl<'a> Borrow<[u8]> for LoaderBytes<'a> {
    fn borrow(&self) -> &[u8] {
        self.as_ref()
    }
}

impl<'a> Deref for LoaderBytes<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<'a> From<LoaderBytes<'a>> for Cow<'a, [u8]> {
    fn from(value: LoaderBytes<'a>) -> Self {
        match value {
            LoaderBytes::Borrowed(v) => Self::Borrowed(v),
            LoaderBytes::Owned(v) => Self::Owned(v),
        }
    }
}

impl<'a> From<Cow<'a, [u8]>> for LoaderBytes<'a> {
    fn from(value: Cow<'a, [u8]>) -> Self {
        match value {
            Cow::Borrowed(v) => Self::Borrowed(v),
            Cow::Owned(v) => Self::Owned(v),
        }
    }
}

impl<'a> LoaderBytes<'a> {
    pub fn into_owned(self) -> Vec<u8> {
        match self {
            Self::Owned(v) => v,
            Self::Borrowed(v) => v.to_owned(),
        }
    }

    pub fn to_mut(&mut self) -> &mut Vec<u8> {
        match self {
            Self::Owned(ref mut v) => v,
            Self::Borrowed(v) => {
                *self = Self::Owned(v.to_owned());
                match *self {
                    Self::Owned(ref mut v) => v,
                    Self::Borrowed(..) => unreachable!(),
                }
            }
        }
    }
}

pub const LOADER_BYTES_DATA: Uuid = uuid("68E7FE51-F58B-48AD-BE4E-B8DD32B73537");

impl<'a> AnalysisStateInfo<'a> for LoaderBytes<'a> {
    const UUID: Uuid = LOADER_BYTES_DATA;
}

impl<'a> AnalysisState<'a> for LoaderBytes<'a> {
    fn id(&self) -> &Uuid {
        &LOADER_BYTES_DATA
    }
}

impl<'a> LoaderAttribute<'a> for LoaderBytes<'a> {
    const UUID: Uuid = LOADER_BYTES_DATA;
}

#[derive(Default)]
pub struct LoaderImport<'a> {
    pub address: Option<Address>,
    pub source: Option<Cow<'a, str>>,
    pub name: Cow<'a, str>,
    pub context: ContextUpdates,
    pub properties: FunctionInfo,
}

pub struct LoaderExport<'a> {
    pub address: Address,
    pub name: Cow<'a, str>,
    pub context: ContextUpdates,
    pub properties: FunctionInfo,
}

impl<'a> Default for LoaderExport<'a> {
    fn default() -> Self {
        Self {
            address: Address::from(0u32),
            name: Default::default(),
            context: ContextUpdates::default(),
            properties: FunctionInfo::default(),
        }
    }
}

pub struct LoaderFunction<'a> {
    pub entry: Address,
    pub name: Option<Cow<'a, str>>,
    pub context: ContextUpdates,
    pub properties: FunctionInfo,
}

impl<'a> Default for LoaderFunction<'a> {
    fn default() -> Self {
        Self {
            entry: Address::from(0u32),
            name: None,
            context: ContextUpdates::default(),
            properties: FunctionInfo::default(),
        }
    }
}

pub struct LoaderRegion<'a> {
    pub name: Option<Cow<'a, str>>,
    pub code: bool,
    pub read_only: bool,
    pub uninitialised: Option<Range<Address>>,
    pub bounds: Range<Address>,
    pub endian: Endian,
    pub bytes: Cow<'a, [u8]>,
}

impl<'a> Default for LoaderRegion<'a> {
    fn default() -> Self {
        Self {
            name: None,
            code: false,
            read_only: false,
            uninitialised: None,
            bounds: Address::from(0u32)..Address::from(1u32),
            endian: Endian::Little,
            bytes: Cow::Borrowed(&[]),
        }
    }
}

impl<'a> LoaderRegion<'a> {
    pub fn read_value<T: ByteCast>(&self, offset: usize) -> Option<T> {
        let range = self.view_bytes(offset, T::SIZEOF)?;
        Some(if self.endian.is_little() {
            T::from_bytes::<LE>(range)
        } else {
            T::from_bytes::<BE>(range)
        })
    }

    pub fn update_value<T: ByteCast, F: FnOnce(T) -> T>(
        &mut self,
        offset: usize,
        f: F,
    ) -> Option<()> {
        let endian = self.endian;
        let range = self.view_bytes_mut(offset, T::SIZEOF)?;
        Some(if endian.is_little() {
            f(T::from_bytes::<LE>(range)).into_bytes::<LE>(range)
        } else {
            f(T::from_bytes::<BE>(range)).into_bytes::<BE>(range)
        })
    }

    pub fn write_value<T: ByteCast>(&mut self, offset: usize, value: T) -> Option<()> {
        let endian = self.endian;
        let range = self.view_bytes_mut(offset, T::SIZEOF)?;
        Some(if endian.is_little() {
            value.into_bytes::<LE>(range)
        } else {
            value.into_bytes::<BE>(range)
        })
    }

    pub fn view_bytes(&self, offset: usize, count: usize) -> Option<&[u8]> {
        let len = self.bytes.len();
        if offset >= len {
            return None;
        }

        if let Some(last_offset) = offset.checked_add(count) {
            if last_offset > len {
                None
            } else {
                Some(&self.bytes[offset..last_offset])
            }
        } else {
            None
        }
    }

    pub fn view_bytes_mut(&mut self, offset: usize, count: usize) -> Option<&mut [u8]> {
        let len = self.bytes.len();
        if offset >= len {
            return None;
        }

        if let Some(last_offset) = offset.checked_add(count) {
            if last_offset > len {
                None
            } else {
                Some(&mut self.bytes.to_mut()[offset..last_offset])
            }
        } else {
            None
        }
    }
}

pub trait LoadedBinary {
    #[allow(unused)]
    fn for_each_region<'a, F>(&'a self, f: F)
    where
        F: FnMut(&LoaderRegion<'a>),
    {
    }

    #[allow(unused)]
    fn for_each_region_with<'a, A, F>(&'a self, rebase: A, f: F)
    where
        A: Into<Option<Address>>,
        F: FnMut(&LoaderRegion<'a>),
    {
        if rebase.into().is_none() {
            self.for_each_region(f)
        }
    }

    #[allow(unused)]
    fn for_each_block<F>(&self, f: F)
    where
        F: FnMut(&LoaderBlock),
    {
    }

    #[allow(unused)]
    fn for_each_function<'a, F>(&'a self, f: F)
    where
        F: FnMut(&LoaderFunction<'a>),
    {
    }

    #[allow(unused)]
    fn for_each_import<'a, F>(&'a self, f: F)
    where
        F: FnMut(&LoaderImport<'a>),
    {
    }

    #[allow(unused)]
    fn for_each_export<'a, F>(&'a self, f: F)
    where
        F: FnMut(&LoaderExport<'a>),
    {
    }

    #[allow(unused)]
    fn for_each_critical_function<'a, F>(&'a self, context: &mut ICFGExtendedContext, f: F)
    where
        F: FnMut(Address),
    {
    }

    fn bytes<'a>(&'a self) -> LoaderBytes<'a> {
        LoaderBytes::Borrowed(&[])
    }

    fn container<'a>(&'a self) -> LoaderContainer<'a> {
        LoaderContainer::new(self.bytes())
    }

    fn entry_point(&self) -> Option<Address> {
        None
    }
}

pub trait ErasedLoadedBinary: Send + Sync {
    fn for_each_region<'a>(&'a self, f: &mut dyn FnMut(&LoaderRegion<'a>));
    fn for_each_region_with<'a>(
        &'a self,
        rebase: Option<Address>,
        f: &mut dyn FnMut(&LoaderRegion<'a>),
    );
    fn for_each_block(&self, f: &mut dyn FnMut(&LoaderBlock));
    fn for_each_function<'a>(&'a self, f: &mut dyn FnMut(&LoaderFunction<'a>));
    fn for_each_import<'a>(&'a self, f: &mut dyn FnMut(&LoaderImport<'a>));
    fn for_each_export<'a>(&'a self, f: &mut dyn FnMut(&LoaderExport<'a>));
    fn for_each_critical_function<'a>(
        &'a self,
        context: &mut ICFGExtendedContext,
        f: &mut dyn FnMut(Address),
    );
    fn bytes<'a>(&'a self) -> LoaderBytes<'a>;
    fn container<'a>(&'a self) -> LoaderContainer<'a>;
    fn entry_point(&self) -> Option<Address>;
}

impl<T> LoadedBinary for Box<T>
where
    T: LoadedBinary + ?Sized,
{
    fn for_each_region<'a, F>(&'a self, f: F)
    where
        F: FnMut(&LoaderRegion<'a>),
    {
        <T as LoadedBinary>::for_each_region(&**self, f)
    }

    fn for_each_region_with<'a, A, F>(&'a self, rebase: A, f: F)
    where
        A: Into<Option<Address>>,
        F: FnMut(&LoaderRegion<'a>),
    {
        <T as LoadedBinary>::for_each_region_with(&**self, rebase, f)
    }

    fn for_each_block<F>(&self, f: F)
    where
        F: FnMut(&LoaderBlock),
    {
        <T as LoadedBinary>::for_each_block(&**self, f)
    }

    fn for_each_function<'a, F>(&'a self, f: F)
    where
        F: FnMut(&LoaderFunction<'a>),
    {
        <T as LoadedBinary>::for_each_function(&**self, f)
    }

    fn for_each_import<'a, F>(&'a self, f: F)
    where
        F: FnMut(&LoaderImport<'a>),
    {
        <T as LoadedBinary>::for_each_import(&**self, f)
    }

    fn for_each_export<'a, F>(&'a self, f: F)
    where
        F: FnMut(&LoaderExport<'a>),
    {
        <T as LoadedBinary>::for_each_export(&**self, f)
    }

    fn for_each_critical_function<'a, F>(&'a self, context: &mut ICFGExtendedContext, f: F)
    where
        F: FnMut(Address),
    {
        <T as LoadedBinary>::for_each_critical_function(&**self, context, f)
    }

    fn bytes<'a>(&'a self) -> LoaderBytes<'a> {
        <T as LoadedBinary>::bytes(&**self)
    }

    fn container<'a>(&'a self) -> LoaderContainer<'a> {
        <T as LoadedBinary>::container(&**self)
    }

    fn entry_point(&self) -> Option<Address> {
        <T as LoadedBinary>::entry_point(&**self)
    }
}

impl<'erased> LoadedBinary for dyn ErasedLoadedBinary + 'erased {
    fn for_each_region<'a, F>(&'a self, mut f: F)
    where
        F: FnMut(&LoaderRegion<'a>),
    {
        ErasedLoadedBinary::for_each_region(self, &mut f)
    }

    fn for_each_region_with<'a, A, F>(&'a self, rebase: A, mut f: F)
    where
        A: Into<Option<Address>>,
        F: FnMut(&LoaderRegion<'a>),
    {
        ErasedLoadedBinary::for_each_region_with(self, rebase.into(), &mut f)
    }

    fn for_each_block<F>(&self, mut f: F)
    where
        F: FnMut(&LoaderBlock),
    {
        ErasedLoadedBinary::for_each_block(self, &mut f)
    }

    fn for_each_function<'a, F>(&'a self, mut f: F)
    where
        F: FnMut(&LoaderFunction<'a>),
    {
        ErasedLoadedBinary::for_each_function(self, &mut f)
    }

    fn for_each_import<'a, F>(&'a self, mut f: F)
    where
        F: FnMut(&LoaderImport<'a>),
    {
        ErasedLoadedBinary::for_each_import(self, &mut f)
    }

    fn for_each_export<'a, F>(&'a self, mut f: F)
    where
        F: FnMut(&LoaderExport<'a>),
    {
        ErasedLoadedBinary::for_each_export(self, &mut f)
    }

    fn for_each_critical_function<'a, F>(&'a self, context: &mut ICFGExtendedContext, mut f: F)
    where
        F: FnMut(Address),
    {
        ErasedLoadedBinary::for_each_critical_function(self, context, &mut f)
    }

    fn bytes<'a>(&'a self) -> LoaderBytes<'a> {
        ErasedLoadedBinary::bytes(self)
    }

    fn container<'a>(&'a self) -> LoaderContainer<'a> {
        ErasedLoadedBinary::container(self)
    }

    fn entry_point(&self) -> Option<Address> {
        ErasedLoadedBinary::entry_point(self)
    }
}

impl<T> ErasedLoadedBinary for T
where
    T: LoadedBinary + Send + Sync,
{
    fn for_each_region<'a>(&'a self, f: &mut dyn FnMut(&LoaderRegion<'a>)) {
        <T as LoadedBinary>::for_each_region(self, f)
    }

    fn for_each_region_with<'a>(
        &'a self,
        rebase: Option<Address>,
        f: &mut dyn FnMut(&LoaderRegion<'a>),
    ) {
        <T as LoadedBinary>::for_each_region_with(self, rebase, f)
    }

    fn for_each_block(&self, f: &mut dyn FnMut(&LoaderBlock)) {
        <T as LoadedBinary>::for_each_block(self, f)
    }

    fn for_each_function<'a>(&'a self, f: &mut dyn FnMut(&LoaderFunction<'a>)) {
        <T as LoadedBinary>::for_each_function(self, f)
    }

    fn for_each_import<'a>(&'a self, f: &mut dyn FnMut(&LoaderImport<'a>)) {
        <T as LoadedBinary>::for_each_import(self, f)
    }

    fn for_each_export<'a>(&'a self, f: &mut dyn FnMut(&LoaderExport<'a>)) {
        <T as LoadedBinary>::for_each_export(self, f)
    }

    fn for_each_critical_function<'a>(
        &'a self,
        context: &mut ICFGExtendedContext,
        f: &mut dyn FnMut(Address),
    ) {
        <T as LoadedBinary>::for_each_critical_function(self, context, f)
    }

    fn bytes<'a>(&'a self) -> LoaderBytes<'a> {
        <T as LoadedBinary>::bytes(self)
    }

    fn container<'a>(&'a self) -> LoaderContainer<'a> {
        <T as LoadedBinary>::container(self)
    }

    fn entry_point(&self) -> Option<Address> {
        <T as LoadedBinary>::entry_point(self)
    }
}

pub struct MockBinaryLoader {
    lifter: Lifter,
    regions: Vec<Region>,
}

impl MockBinaryLoader {
    pub fn new(lifter: Lifter) -> Self {
        Self {
            lifter,
            regions: Vec::default(),
        }
    }

    pub fn add_region(&mut self, region: Region) {
        self.regions.push(region);
    }
}

impl Loader for MockBinaryLoader {
    type Error = Infallible;
    type Loaded = Vec<Region>;

    fn load_file<P>(self, _path: P) -> Result<(Lifter, Self::Loaded), Self::Error>
    where
        P: AsRef<Path>,
    {
        Ok((self.lifter, self.regions))
    }
}

impl LoadedBinary for Vec<Region> {
    fn for_each_region<'a, F>(&'a self, mut f: F)
    where
        F: FnMut(&LoaderRegion<'a>),
    {
        for r in self.iter() {
            f(&LoaderRegion {
                name: Some(r.name().as_str().into()),
                code: r.is_code(),
                read_only: r.is_read_only(),
                uninitialised: r.uninitialised_interval().cloned(),
                bounds: *r.address()..*r.address() + r.len(),
                endian: r.endian(),
                bytes: Cow::Borrowed(r.bytes()),
            })
        }
    }
}

pub trait RelocatableBinary: LoadedBinary {
    fn rebase(&mut self, base: Address) -> Result<(), RelocationError>;
    fn mapping_alignment(&self) -> usize;
    fn mapping_size(&self) -> usize;
}

#[derive(Debug, Error)]
pub enum RelocationError {
    #[error("base address will cause integer overflow")]
    InvalidBaseAddress,
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
    #[error("relocation of this kind of binary is unsupported")]
    Unsupported,
}

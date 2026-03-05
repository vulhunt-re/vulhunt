use std::borrow::Cow;
use std::fs::File;
use std::path::{Path, PathBuf};

use fugue::bytes::Endian;
use fugue::ir::error::Error as LanguageDBError;
use fugue::ir::{Address, LanguageDB};
use goblin::pe::utils::PESectionTable;
use goblin::te::header::{TE_MACHINE_X86, TE_MACHINE_X86_64};
use goblin::te::section_table::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE};
use goblin::te::TE;
use memmap2::Mmap;
use thiserror::Error;

use super::{
    LoadedBinary, Loader, LoaderBlock, LoaderBytes, LoaderContainer, LoaderFunction, LoaderRegion,
};
use crate::arch::x86::X86;
use crate::lifter::{Lifter, LifterBuilder, LifterBuilderError};

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    LoaderFormat(#[from] goblin::error::Error),
    #[error(transparent)]
    LoaderIO(#[from] std::io::Error),
    #[error(transparent)]
    LanguageDB(#[from] LanguageDBError),
    #[error(transparent)]
    LifterBuilder(#[from] LifterBuilderError),
    #[error("unsupported architecture {0:x}")]
    UnsupportedArchitecture(u16),
    #[error("unsupported lifter convention: {0}")]
    UnsupportedConvention(Cow<'static, str>),
}

pub struct TELoader<'a> {
    ldb: Cow<'a, LanguageDB>,
    bytes: Option<Mmap>,
    convention: Cow<'static, str>,
}

impl<'a> TELoader<'a> {
    pub fn new(ldb: impl Into<Cow<'a, LanguageDB>>) -> Self {
        Self {
            ldb: ldb.into(),
            bytes: None,
            convention: "efi".into(),
        }
    }

    pub fn new_with<P>(language_dir: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let ldb = Cow::Owned(LanguageDB::from_directory_with(language_dir, true)?);
        Ok(Self::new(ldb))
    }

    #[inline]
    pub fn load_bytes<'b>(&self, bytes: &'b [u8]) -> Result<(Lifter, LoadedTE<'b>), Error> {
        self.load_bytes_with(bytes, None)
    }

    #[inline]
    pub fn load_bytes_with<'b>(
        &self,
        bytes: &'b [u8],
        path: impl Into<Option<PathBuf>>,
    ) -> Result<(Lifter, LoadedTE<'b>), Error> {
        let te = TE::parse(&bytes).map_err(Error::LoaderFormat)?;
        let arch = te.header.machine;

        let (arch_info, processor, bits) = match arch {
            TE_MACHINE_X86_64 => (X86::new(true), "x86", 64),
            TE_MACHINE_X86 => (X86::new(false), "x86", 32),
            _ => return Err(Error::UnsupportedArchitecture(arch)),
        };

        let builder = self
            .ldb
            .lookup(processor, Endian::Little, bits, "default")
            .ok_or_else(|| Error::UnsupportedArchitecture(arch))?;

        let translator = LifterBuilder::build_or_cached(&builder)?;

        let convention = translator
            .compiler_conventions()
            .get(&*self.convention)
            .cloned()
            .or_else(|| translator.compiler_conventions().get("default").cloned())
            .ok_or_else(|| Error::UnsupportedConvention(self.convention.clone()))?;

        let lifter = Lifter::new_with(translator, convention, arch_info);

        Ok((
            lifter,
            LoadedTE {
                te,
                path: path.into(),
                raw: bytes,
            },
        ))
    }

    pub fn with_convention<C>(mut self, convention: C) -> Self
    where
        C: Into<Cow<'static, str>>,
    {
        self.convention = convention.into();
        self
    }
}

impl<'a> Loader for &'a mut TELoader<'_> {
    type Error = Error;
    type Loaded = LoadedTE<'a>;

    fn load_file<P>(self, path: P) -> Result<(Lifter, Self::Loaded), Self::Error>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        let f = File::open(path).map_err(Error::LoaderIO)?;
        self.bytes = Some(unsafe { Mmap::map(&f) }.map_err(Error::LoaderIO)?);

        let bytes = self.bytes.as_ref().unwrap();

        self.load_bytes_with(bytes, path.to_owned())
    }
}

pub struct LoadedTE<'a> {
    te: TE<'a>,
    path: Option<PathBuf>,
    raw: &'a [u8],
}

impl<'a> LoadedTE<'a> {
    pub fn te(&self) -> &TE<'a> {
        &self.te
    }

    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }

    pub fn path(&self) -> Option<&PathBuf> {
        self.path.as_ref()
    }
}

impl<'a> LoadedBinary for LoadedTE<'a> {
    fn for_each_region<'b, F>(&'b self, mut f: F)
    where
        F: FnMut(&LoaderRegion<'b>),
    {
        for section in self.te.sections.iter() {
            if section.virtual_size() == 0 {
                continue;
            }

            let rstart = section.pointer_to_raw_data() as usize;
            let rsize = section.size_of_raw_data() as usize;

            let rend = match rstart.checked_add(rsize) {
                None => {
                    tracing::debug!("PointerToRawData + SizeOfRawData overflows");
                    continue;
                }
                Some(rend) => rend as usize,
            };

            if rend as usize > self.raw.len() {
                tracing::debug!("PointerToRawData + SizeOfRawData is out of bounds");
                continue;
            }

            let vstart = section.virtual_address() as usize;
            let vsize = section.virtual_size() as usize;

            let vbounds = match vstart.checked_add(vsize) {
                None => {
                    tracing::debug!("VirtualAddress + VirtualSize overflows");
                    continue;
                }
                Some(vend) => Address::from(vstart as u64)..Address::from(vend as u64),
            };

            if rsize > vsize {
                tracing::debug!("raw section size > virtual size");
            }

            let mut lrgn = LoaderRegion::default();

            lrgn.name = section.name().ok().map(Cow::Borrowed);
            lrgn.code =
                (section.characteristics() & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) != 0;
            lrgn.read_only = (section.characteristics() & IMAGE_SCN_MEM_WRITE) == 0;
            lrgn.bounds = vbounds;
            lrgn.endian = Endian::Little;

            // TODO: relocations!
            lrgn.bytes = if rsize < vsize {
                tracing::trace!("raw section size < virtual size; padding with zeros");
                let mut bytes = Vec::with_capacity(vsize);

                bytes.extend_from_slice(&self.raw[rstart..rend]);
                bytes.resize(vsize, 0u8);

                lrgn.uninitialised = Some(
                    (Address::from(vstart as u64) + rsize)..(Address::from(vstart as u64) + vsize),
                );

                Cow::Owned(bytes)
            } else {
                let vrend = rstart + rsize.min(vsize);
                Cow::Borrowed(&self.raw[rstart..vrend])
            };

            f(&lrgn)
        }
    }

    fn for_each_block<F>(&self, _f: F)
    where
        F: FnMut(&LoaderBlock),
    {
    }

    fn for_each_function<'b, F>(&'b self, mut f: F)
    where
        F: FnMut(&LoaderFunction<'b>),
    {
        f(&LoaderFunction {
            entry: self.entry_point().unwrap(),
            name: None,
            ..Default::default()
        })
    }

    fn bytes<'b>(&'b self) -> LoaderBytes<'b> {
        LoaderBytes::Borrowed(self.raw)
    }

    fn container<'b>(&'b self) -> LoaderContainer<'b> {
        let mut t = LoaderContainer::new(self.te());
        t.set_attr(LoaderBytes::Borrowed(self.raw));
        t
    }

    fn entry_point(&self) -> Option<Address> {
        Some(Address::from(self.te.entry_point()))
    }
}

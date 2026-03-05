use std::borrow::Cow;
use std::fs::File;
use std::path::{Path, PathBuf};

use fugue::bytes::Endian;
use fugue::ir::error::Error as LanguageDBError;
use fugue::ir::{Address, LanguageDB};
use goblin::pe::header::{COFF_MACHINE_X86, COFF_MACHINE_X86_64};
use goblin::pe::section_table::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE};
use goblin::pe::utils::PESectionTable;
use goblin::pe::PE;
use memmap2::Mmap;
use thiserror::Error;

use super::{
    LoadedBinary, Loader, LoaderBlock, LoaderBytes, LoaderContainer, LoaderFunction, LoaderImport,
    LoaderRegion,
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

pub struct PELoader<'a> {
    ldb: Cow<'a, LanguageDB>,
    bytes: Option<Mmap>,
    convention: Cow<'static, str>,
}

impl<'a> PELoader<'a> {
    pub fn new(ldb: impl Into<Cow<'a, LanguageDB>>) -> Self {
        Self {
            ldb: ldb.into(),
            bytes: None,
            convention: "efi".into(), // TODO: change to windows?
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
    pub fn load_bytes<'b>(&self, bytes: &'b [u8]) -> Result<(Lifter, LoadedPE<'b>), Error> {
        self.load_bytes_with(bytes, None)
    }

    #[inline]
    pub fn load_bytes_with<'b>(
        &self,
        bytes: &'b [u8],
        path: impl Into<Option<PathBuf>>,
    ) -> Result<(Lifter, LoadedPE<'b>), Error> {
        let pe = PE::parse(&bytes).map_err(Error::LoaderFormat)?;
        let arch = pe.header.coff_header.machine;

        let (arch_info, processor, bits) = match arch {
            COFF_MACHINE_X86_64 => (X86::new(true), "x86", 64),
            COFF_MACHINE_X86 => (X86::new(false), "x86", 32),
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

        let image_base = Address::from(pe.image_base as u64);

        Ok((
            lifter,
            LoadedPE {
                pe,
                image_base,
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

impl<'a> Loader for &'a mut PELoader<'_> {
    type Error = Error;
    type Loaded = LoadedPE<'a>;

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

pub struct LoadedPE<'a> {
    pe: PE<'a>,
    image_base: Address,
    path: Option<PathBuf>,
    raw: &'a [u8],
}

impl<'a> LoadedPE<'a> {
    pub fn pe(&self) -> &PE<'a> {
        &self.pe
    }

    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }

    pub fn path(&self) -> Option<&PathBuf> {
        self.path.as_ref()
    }
}

impl<'a> LoadedBinary for LoadedPE<'a> {
    fn for_each_region<'b, F>(&'b self, mut f: F)
    where
        F: FnMut(&LoaderRegion<'b>),
    {
        for section in self.pe.sections.iter() {
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

            let vstart = self.image_base + section.virtual_address() as usize;
            let vsize = section.virtual_size() as usize;
            let vend = vstart + vsize;

            let vbounds = if vend <= vstart {
                tracing::debug!("VirtualAddress + VirtualSize overflows");
                continue;
            } else {
                vstart..vend
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

                lrgn.uninitialised = Some((vstart + rsize)..(vstart + vsize));

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

    fn for_each_import<'b, F>(&'b self, mut f: F)
    where
        F: FnMut(&LoaderImport<'b>),
    {
        self.pe.imports.iter().for_each(|import| {
            f(&LoaderImport {
                name: Cow::Borrowed(import.name.as_ref()),
                address: Some(Address::from(
                    (import.offset as u64).wrapping_add(self.pe.image_base as u64),
                )),
                source: Some(import.dll.into()),
                ..Default::default()
            })
        });
    }

    fn bytes<'b>(&'b self) -> LoaderBytes<'b> {
        LoaderBytes::Borrowed(self.raw)
    }

    fn container<'b>(&'b self) -> LoaderContainer<'b> {
        let mut t = LoaderContainer::new(self.pe());
        t.set_attr(LoaderBytes::Borrowed(self.raw));
        t
    }

    fn entry_point(&self) -> Option<Address> {
        Some(Address::from(self.pe.entry as u64) + self.image_base)
    }
}

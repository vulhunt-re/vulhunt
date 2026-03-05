use std::borrow::Cow;
use std::fs::File;
use std::io::BufReader;
use std::ops::Deref;
use std::path::{Path, PathBuf};

use ahash::AHashSet;
use bias_loader_uefi::{MicrocodeInfo, Uefi, UefiData, UefiModule, UefiNvramVar, UefiSection};
use fugue::bytes::Endian;
use fugue::ir::error::Error as LanguageDBError;
use fugue::ir::{Address, LanguageDB};
use goblin::pe::header::{COFF_MACHINE_ARM64, COFF_MACHINE_X86, COFF_MACHINE_X86_64};
use goblin::pe::relocation::{
    BaseRelocations, IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGH,
    IMAGE_REL_BASED_HIGHADJ, IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_LOW,
};
use goblin::pe::section_table::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE};
use goblin::pe::utils::PESectionTable;
use goblin::pe::PE;
use goblin::te::TE;
use goblin::Object;
use memmap2::Mmap;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use super::{
    LoadedBinary, Loader, LoaderAttribute, LoaderBlock, LoaderBytes, LoaderContainer,
    LoaderFunction, LoaderImport, LoaderRegion,
};
use crate::any::ProvidesStaticType;
use crate::arch::aarch64::AARCH64;
use crate::arch::x86::X86;
use crate::data::strings::StringData;
use crate::lifter::{Lifter, LifterBuilder, LifterBuilderError};
use crate::symbols::pdb::PDBSymboliser;
use crate::symbols::{Symbolise, SymboliseError};
use crate::Project;

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
    UnsupportedConvention(&'static str),
    #[error("unsupported EFI binary format: {0}")]
    UnsupportedFormat(&'static str),
    #[error("firmware loading error: {0}")]
    UefiLoader(#[from] bias_loader_uefi::Error),
}

pub struct EFIFirmwareLoader<'a> {
    ldb: Cow<'a, LanguageDB>,
    modules: Vec<UefiModule<'static>>,
    variables: Vec<UefiNvramVar<'static>>,
    microcodes: Vec<MicrocodeInfo<'static>>,
    raw_sections: Vec<UefiData<'static>>,
    guid_defined_sections: Vec<UefiSection<'static>>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct EFIFirmwareLoaderConfig {
    pub unpack_firmware: bool,
    pub deduplicate: bool,
}

impl Default for EFIFirmwareLoaderConfig {
    fn default() -> Self {
        EFIFirmwareLoaderConfig {
            unpack_firmware: true,
            deduplicate: false,
        }
    }
}

pub struct EFIModule<'a> {
    ldb: &'a LanguageDB,
    module: &'a UefiModule<'static>,
}

impl<'a> EFIModule<'a> {
    pub fn new(ldb: &'a LanguageDB, module: &'a UefiModule<'static>) -> Self {
        Self { ldb, module }
    }

    pub fn module(&self) -> &UefiModule<'_> {
        &self.module
    }
}

impl<'a> Deref for EFIModule<'a> {
    type Target = UefiModule<'static>;

    fn deref(&self) -> &Self::Target {
        &self.module
    }
}

#[derive(ProvidesStaticType)]
#[repr(transparent)]
pub struct EFIModuleInfo<'a>(Cow<'a, UefiModule<'a>>);

impl<'a> EFIModuleInfo<'a> {
    pub fn new(value: impl Into<Self>) -> Self {
        value.into()
    }
}

impl<'a> From<&'a UefiModule<'a>> for EFIModuleInfo<'a> {
    fn from(value: &'a UefiModule<'a>) -> Self {
        Self(Cow::Borrowed(value))
    }
}

impl<'a> From<UefiModule<'a>> for EFIModuleInfo<'a> {
    fn from(value: UefiModule<'a>) -> Self {
        Self(Cow::Owned(value))
    }
}

impl<'a> AsRef<UefiModule<'a>> for EFIModuleInfo<'a> {
    fn as_ref(&self) -> &UefiModule<'a> {
        &self.0
    }
}

impl<'a> Deref for EFIModuleInfo<'a> {
    type Target = UefiModule<'a>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> LoaderAttribute<'a> for EFIModuleInfo<'a> {
    const UUID: Uuid = uuid::uuid!("E59C25AB-BA6D-4AD5-9D67-F3364832A37A");
}

pub struct LoadedEFIModule<'a> {
    module: &'a UefiModule<'static>,
    loaded: LoadedEFI<'a>,
}

impl<'a> LoadedEFIModule<'a> {
    pub fn new(module: &'a UefiModule<'static>, loaded: LoadedEFI<'a>) -> Self {
        Self { module, loaded }
    }

    pub fn efi(&self) -> &EFI<'_> {
        self.loaded.efi()
    }

    pub fn module(&self) -> &UefiModule<'_> {
        &self.module
    }
}

impl<'a> Deref for LoadedEFIModule<'a> {
    type Target = UefiModule<'static>;

    fn deref(&self) -> &Self::Target {
        &self.module
    }
}

impl<'a> LoadedBinary for LoadedEFIModule<'a> {
    fn for_each_region<'b, F>(&'b self, f: F)
    where
        F: FnMut(&LoaderRegion<'b>),
    {
        self.loaded.for_each_region(f)
    }

    fn for_each_function<'b, F>(&'b self, f: F)
    where
        F: FnMut(&LoaderFunction<'b>),
    {
        self.loaded.for_each_function(f)
    }

    fn for_each_block<F>(&self, f: F)
    where
        F: FnMut(&LoaderBlock),
    {
        self.loaded.for_each_block(f)
    }

    fn entry_point(&self) -> Option<Address> {
        self.loaded.entry_point()
    }

    fn bytes<'b>(&'b self) -> LoaderBytes<'b> {
        LoaderBytes::Borrowed(self.loaded.bytes())
    }

    fn container<'b>(&'b self) -> LoaderContainer<'b> {
        let mut t = LoaderContainer::new(self.efi());
        t.set_attr(LoaderBytes::Borrowed(self.loaded.bytes()));
        t.set_attr(EFIModuleInfo::from(self.module()));
        t
    }
}

impl<'a> Symbolise for LoadedEFIModule<'a> {
    fn apply_symbols(&self, target: &mut Project) -> Result<(), SymboliseError> {
        self.loaded.apply_symbols(target)
    }
}

impl<'a> EFIModule<'a> {
    pub fn load(&self) -> Result<(Lifter, LoadedEFIModule<'_>), Error> {
        let (arch, efi) = match Object::parse(self.module.bytes()).map_err(Error::LoaderFormat)? {
            Object::PE(pe) => (pe.header.coff_header.machine, EFI::PE(pe)),
            Object::TE(te) => (te.header.machine, EFI::TE(te)),
            Object::Elf(_) => return Err(Error::UnsupportedFormat("ELF")),
            Object::Mach(_) => return Err(Error::UnsupportedFormat("Mach-O")),
            _ => return Err(Error::UnsupportedFormat("unrecognized")),
        };

        let (arch_info, processor, bits, variant) = match arch {
            COFF_MACHINE_ARM64 => (AARCH64::new(), "AARCH64", 64, "v8A"),
            COFF_MACHINE_X86_64 => (X86::new(true), "x86", 64, "default"),
            COFF_MACHINE_X86 => (X86::new(false), "x86", 32, "default"),
            _ => return Err(Error::UnsupportedArchitecture(arch)),
        };

        let builder = self
            .ldb
            .lookup(processor, Endian::Little, bits, variant)
            .ok_or_else(|| Error::UnsupportedArchitecture(arch))?;

        let translator = LifterBuilder::build_or_cached(&builder)?;

        let convention = translator
            .compiler_conventions()
            .get("efi")
            .cloned()
            .ok_or_else(|| Error::UnsupportedConvention("efi"))?;

        let lifter = Lifter::new_with(translator, convention, arch_info);

        Ok((
            lifter,
            LoadedEFIModule {
                module: &self.module,
                loaded: LoadedEFI {
                    efi,
                    path: None,
                    raw: self.module.bytes(),
                },
            },
        ))
    }
}

impl<'a> EFIFirmwareLoader<'a> {
    pub fn new(ldb: impl Into<Cow<'a, LanguageDB>>) -> Self {
        Self {
            ldb: ldb.into(),
            modules: Vec::default(),
            variables: Vec::default(),
            microcodes: Vec::default(),
            raw_sections: Vec::default(),
            guid_defined_sections: Vec::default(),
        }
    }

    pub fn new_with<P>(language_dir: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let ldb = Cow::Owned(LanguageDB::from_directory_with(language_dir, true)?);
        Ok(Self::new(ldb))
    }

    pub fn load_file(&mut self, path: impl AsRef<Path>) -> Result<(), Error> {
        self.load_file_with(path, Default::default())
    }

    pub fn load_file_with(
        &mut self,
        path: impl AsRef<Path>,
        config: EFIFirmwareLoaderConfig,
    ) -> Result<(), Error> {
        let f = File::open(path).map_err(Error::LoaderIO)?;
        let bytes = unsafe { Mmap::map(&f) }.map_err(Error::LoaderIO)?;

        self.load_buffer_with(&bytes, config)
    }

    pub fn load_buffer(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.load_buffer_with(bytes, Default::default())
    }

    pub fn load_buffer_with(
        &mut self,
        bytes: &[u8],
        config: EFIFirmwareLoaderConfig,
    ) -> Result<(), Error> {
        let bytes = if config.unpack_firmware {
            bias_loader_uefi::try_unpack(bytes)?
        } else {
            Cow::Borrowed(bytes)
        };

        let uefi = Uefi::new(&*bytes)?;

        self.clear();

        if config.deduplicate {
            // dedup. on SHA256(module.bytes || module.guid || module.depex_guids)

            let mut seen = AHashSet::new();
            let mut hasher = Sha256::new();

            uefi.for_each(|module| {
                hasher.update(module.bytes());
                hasher.update(module.guid().as_bytes());

                for dguid in module.depex().iter().filter_map(|op| op.guid()) {
                    hasher.update(dguid);
                }

                let hash: [u8; 32] = hasher.finalize_reset().into();

                if seen.insert(hash) {
                    self.modules.push(module.into_owned())
                }
            });
            uefi.for_each_raw_section(|raw_section| {
                hasher.update(raw_section.bytes());
                hasher.update(raw_section.guid().as_bytes());

                for dguid in raw_section.depex().iter().filter_map(|op| op.guid()) {
                    hasher.update(dguid);
                }

                let hash: [u8; 32] = hasher.finalize_reset().into();

                if seen.insert(hash) {
                    self.raw_sections.push(raw_section.into_owned())
                }
            });
        } else {
            uefi.for_each(|module| self.modules.push(module.into_owned()));
            uefi.for_each_raw_section(|raw_section| {
                self.raw_sections.push(raw_section.into_owned())
            });
        }

        uefi.for_each_var(|var| self.variables.push(var.into_owned()));
        uefi.for_each_microcode(|m| self.microcodes.push(m.into_owned()));
        uefi.for_each_guid_defined_section(|section| {
            self.guid_defined_sections.push(section.into_owned())
        });

        Ok(())
    }

    #[inline]
    pub fn clear(&mut self) {
        self.clear_modules();
        self.clear_variables();
        self.clear_microcodes();
        self.clear_raw_sections();
        self.clear_guid_defined_sections();
    }

    #[inline]
    pub fn push_module(&mut self, module: impl Into<UefiModule<'static>>) {
        self.modules.push(module.into());
    }

    #[inline]
    pub fn extend_modules(&mut self, modules: impl Iterator<Item = UefiModule<'static>>) {
        self.modules.extend(modules);
    }

    #[inline]
    pub fn clear_modules(&mut self) {
        self.modules.clear()
    }

    #[inline]
    pub fn push_variable(&mut self, variable: impl Into<UefiNvramVar<'static>>) {
        self.variables.push(variable.into());
    }

    #[inline]
    pub fn extend_variables(&mut self, variables: impl Iterator<Item = UefiNvramVar<'static>>) {
        self.variables.extend(variables);
    }

    #[inline]
    pub fn clear_variables(&mut self) {
        self.variables.clear()
    }

    #[inline]
    pub fn push_microcode(&mut self, microcode: impl Into<MicrocodeInfo<'static>>) {
        self.microcodes.push(microcode.into());
    }

    #[inline]
    pub fn extend_microcodes(&mut self, microcodes: impl Iterator<Item = MicrocodeInfo<'static>>) {
        self.microcodes.extend(microcodes);
    }

    #[inline]
    pub fn clear_microcodes(&mut self) {
        self.microcodes.clear()
    }

    #[inline]
    pub fn push_raw_section(&mut self, raw_section: impl Into<UefiData<'static>>) {
        self.raw_sections.push(raw_section.into());
    }

    #[inline]
    pub fn extend_raw_sections(&mut self, raw_sections: impl Iterator<Item = UefiData<'static>>) {
        self.raw_sections.extend(raw_sections);
    }

    #[inline]
    pub fn clear_raw_sections(&mut self) {
        self.raw_sections.clear()
    }

    #[inline]
    pub fn push_guid_defined_section(&mut self, section: impl Into<UefiSection<'static>>) {
        self.guid_defined_sections.push(section.into());
    }

    #[inline]
    pub fn extend_guid_defined_section(
        &mut self,
        sections: impl Iterator<Item = UefiSection<'static>>,
    ) {
        self.guid_defined_sections.extend(sections);
    }

    #[inline]
    pub fn clear_guid_defined_sections(&mut self) {
        self.guid_defined_sections.clear()
    }

    #[inline]
    pub fn modules(&self) -> impl ExactSizeIterator<Item = EFIModule<'_>> {
        self.modules.iter().map(|module| EFIModule {
            ldb: &*self.ldb,
            module,
        })
    }

    #[inline]
    pub fn variables(&self) -> impl ExactSizeIterator<Item = &UefiNvramVar<'static>> {
        self.variables.iter()
    }

    #[inline]
    pub fn microcodes(&self) -> impl ExactSizeIterator<Item = &MicrocodeInfo<'static>> {
        self.microcodes.iter()
    }

    #[inline]
    pub fn raw_sections(&self) -> impl ExactSizeIterator<Item = &UefiData<'static>> {
        self.raw_sections.iter()
    }

    #[inline]
    pub fn guid_defined_sections(&self) -> impl ExactSizeIterator<Item = &UefiSection<'static>> {
        self.guid_defined_sections.iter()
    }

    #[inline]
    pub fn into_parts(
        self,
    ) -> (
        Vec<UefiModule<'static>>,
        Vec<UefiNvramVar<'static>>,
        Vec<MicrocodeInfo<'static>>,
        Vec<UefiData<'static>>,
        Vec<UefiSection<'static>>,
    ) {
        (
            self.modules,
            self.variables,
            self.microcodes,
            self.raw_sections,
            self.guid_defined_sections,
        )
    }
}

pub struct EFILoader<'a> {
    ldb: Cow<'a, LanguageDB>,
    bytes: Option<Mmap>,
}

impl<'a> EFILoader<'a> {
    pub fn new(ldb: impl Into<Cow<'a, LanguageDB>>) -> Self {
        Self {
            ldb: ldb.into(),
            bytes: None,
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
    pub fn load_bytes<'b>(&self, bytes: &'b [u8]) -> Result<(Lifter, LoadedEFI<'b>), Error> {
        self.load_bytes_with(bytes, None)
    }

    #[inline]
    pub fn load_bytes_with<'b>(
        &self,
        bytes: &'b [u8],
        path: impl Into<Option<PathBuf>>,
    ) -> Result<(Lifter, LoadedEFI<'b>), Error> {
        let (arch, efi) = match Object::parse(bytes).map_err(Error::LoaderFormat)? {
            Object::PE(pe) => (pe.header.coff_header.machine, EFI::PE(pe)),
            Object::TE(te) => (te.header.machine, EFI::TE(te)),
            Object::Elf(_) => return Err(Error::UnsupportedFormat("ELF")),
            Object::Mach(_) => return Err(Error::UnsupportedFormat("Mach-O")),
            _ => return Err(Error::UnsupportedFormat("unrecognized")),
        };

        let (arch_info, processor, bits, variant) = match arch {
            COFF_MACHINE_ARM64 => (AARCH64::new(), "AARCH64", 64, "v8A"),
            COFF_MACHINE_X86_64 => (X86::new(true), "x86", 64, "default"),
            COFF_MACHINE_X86 => (X86::new(false), "x86", 32, "default"),
            _ => return Err(Error::UnsupportedArchitecture(arch)),
        };

        let builder = self
            .ldb
            .lookup(processor, Endian::Little, bits, variant)
            .ok_or_else(|| Error::UnsupportedArchitecture(arch))?;

        let translator = LifterBuilder::build_or_cached(&builder)?;

        if translator.compiler_conventions().is_empty() {
            tracing::error!("no compiler conventions available for this translator");
        }

        let convention = translator
            .compiler_conventions()
            .get("efi")
            .cloned()
            .ok_or_else(|| Error::UnsupportedConvention("efi"))?;

        let lifter = Lifter::new_with(translator, convention, arch_info);

        Ok((
            lifter,
            LoadedEFI {
                efi,
                path: path.into(),
                raw: bytes,
            },
        ))
    }
}

impl<'a> Loader for &'a mut EFILoader<'_> {
    type Error = Error;
    type Loaded = LoadedEFI<'a>;

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

pub enum EFI<'a> {
    PE(PE<'a>),
    TE(TE<'a>),
}

impl<'a> EFI<'a> {
    #[inline]
    pub fn image_base(&self) -> Address {
        match self {
            EFI::PE(ref pe) => Address::from(pe.image_base as u64),
            EFI::TE(ref te) => Address::from(te.image_base()),
        }
    }

    #[inline]
    pub fn pdb_signature(&self) -> Option<Uuid> {
        let dbg = match self {
            EFI::PE(ref pe) => pe.debug_data,
            EFI::TE(ref te) => te.debug_data,
        }?;

        Some(Uuid::from_bytes_le(
            dbg.codeview_pdb70_debug_info?.signature,
        ))
    }

    #[inline]
    pub fn pdb_path(&self) -> Option<PathBuf> {
        let dbg = match self {
            EFI::PE(ref pe) => pe.debug_data,
            EFI::TE(ref te) => te.debug_data,
        }?;

        let name = dbg.codeview_pdb70_debug_info?.filename;

        Some(
            StringData::Utf8
                .decode(name)
                .unwrap_or_else(|_| String::from_utf8_lossy(name).into_owned())
                .into(),
        )
    }

    #[inline]
    pub fn pdb_age(&self) -> Option<u32> {
        let dbg = match self {
            EFI::PE(ref pe) => pe.debug_data,
            EFI::TE(ref te) => te.debug_data,
        }?;

        Some(dbg.codeview_pdb70_debug_info?.age)
    }
}

pub struct LoadedEFI<'a> {
    efi: EFI<'a>,
    path: Option<PathBuf>,
    raw: &'a [u8],
}

impl<'a> LoadedEFI<'a> {
    pub fn bytes(&self) -> &[u8] {
        &*self.raw
    }

    pub fn efi(&self) -> &EFI<'a> {
        &self.efi
    }

    pub fn path(&self) -> Option<&PathBuf> {
        self.path.as_ref()
    }

    pub fn image_base(&self) -> Address {
        self.efi.image_base()
    }

    pub fn mapping(&self) -> Vec<u8> {
        fn process<T: PESectionTable>(image_base: Address, sections: &[T], raw: &[u8]) -> Vec<u8> {
            let mut min_size = 0usize;
            let mut max_size = 0usize;

            let align_size = |size: u32| size.wrapping_add(0xfff) & !0xfff;

            for section in sections.iter() {
                if section.size_of_raw_data() == 0 {
                    continue;
                }

                if min_size == 0 || min_size > section.pointer_to_raw_data() as usize {
                    min_size = section.pointer_to_raw_data() as usize;
                }

                let aligned = align_size(section.virtual_size());
                let vend = usize::from(image_base)
                    .wrapping_add(section.virtual_address() as usize)
                    .wrapping_add(aligned as usize);

                if vend > max_size {
                    max_size = vend;
                }
            }

            let mut mapped = vec![0u8; max_size];

            for section in sections.iter() {
                if section.size_of_raw_data() == 0 {
                    continue;
                }

                let start =
                    usize::from(image_base).wrapping_add(section.virtual_address() as usize);
                let end = start.wrapping_add(section.size_of_raw_data() as usize);

                let rstart = section.pointer_to_raw_data() as usize;
                let rend = rstart.wrapping_add(section.size_of_raw_data() as usize);

                if end != start {
                    mapped[start..end].copy_from_slice(&raw[rstart..rend]);
                }
            }

            mapped[..min_size].copy_from_slice(&raw[..min_size]);

            mapped
        }

        match &self.efi {
            EFI::PE(pe) => process(self.image_base(), &pe.sections, &self.raw),
            EFI::TE(te) => process(self.image_base(), &te.sections, &self.raw),
        }
    }
}

#[derive(Debug, Error)]
pub enum SymboliseEFIError {
    #[error("PDB file is invalid: {0}")]
    PDB(#[from] pdb::Error),
    #[error("the PDB signature does not match the signature from the binary")]
    PDBSignatureMismatch,
    #[error("the PDB path is not a valid ASCII string")]
    PDBPathInvalid,
}

impl From<SymboliseEFIError> for SymboliseError {
    fn from(e: SymboliseEFIError) -> Self {
        SymboliseError::other(e)
    }
}

impl<'a> Symbolise for LoadedEFI<'a> {
    fn apply_symbols(&self, project: &mut Project) -> Result<(), SymboliseError> {
        let dbg = match self.efi {
            EFI::PE(ref pe) => pe.debug_data,
            EFI::TE(ref te) => te.debug_data,
        };

        let to_err = |e: pdb::Error| SymboliseError::other(SymboliseEFIError::from(e));

        let (sig, file) = if let Some(pdb_info) = dbg.and_then(|dbg| dbg.codeview_pdb70_debug_info)
        {
            let sig = Uuid::from_bytes_le(pdb_info.signature);
            let file = PathBuf::from(
                StringData::Ascii
                    .decode(pdb_info.filename)
                    .map_err(|_| SymboliseEFIError::PDBPathInvalid)?,
            );
            (sig, file)
        } else {
            tracing::trace!("loaded binary does not contain debug information");
            return Ok(());
        };

        let pdb_file = File::open(&file)
            .or_else(|e| {
                if let Some(file) = file.file_name() {
                    File::open(file).or_else(|_| {
                        if let Some(file) = self.path().map(|path| path.with_extension("pdb")) {
                            File::open(file)
                        } else {
                            Err(e)
                        }
                    })
                } else {
                    Err(e)
                }
            })
            .map_err(SymboliseError::Io)?;

        tracing::trace!("loading symbol information");

        let pdb_info = pdb::PDB::open(BufReader::new(pdb_file)).map_err(to_err)?;
        let symboliser = PDBSymboliser::new_with(pdb_info, self.image_base(), sig);

        symboliser.apply_symbols(project)?;

        Ok(())
    }
}

impl<'a> LoadedBinary for LoadedEFI<'a> {
    fn for_each_region_with<'b, A, F>(&'b self, rebase: A, f: F)
    where
        A: Into<Option<Address>>,
        F: FnMut(&LoaderRegion<'b>),
    {
        fn process<'c, T: PESectionTable, F: FnMut(&LoaderRegion<'c>)>(
            image_base: Address,
            rebase: Address,
            relocs: Option<BaseRelocations>,
            sections: &'c [T],
            raw: &'c [u8],
            mut f: F,
        ) {
            let rebase_shift = u32::from(rebase - image_base);

            'outer: for section in sections.iter() {
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

                if rend as usize > raw.len() {
                    tracing::debug!("PointerToRawData + SizeOfRawData is out of bounds");
                    continue 'outer;
                }

                let vstart = rebase + section.virtual_address() as usize;
                let vsize = section.virtual_size() as usize;

                let vbounds = if vstart + vsize < vstart {
                    tracing::debug!("rebased VirtualAddress + VirtualSize overflows");
                    continue;
                } else {
                    vstart..vstart + vsize
                };

                if rsize > vsize {
                    tracing::debug!("raw section size ({rsize:#x}) > virtual size ({vsize:#x})");
                }

                let mut lrgn = LoaderRegion::default();

                lrgn.name = section.name().ok().map(Cow::Borrowed);
                lrgn.code =
                    (section.characteristics() & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) != 0;
                lrgn.read_only = (section.characteristics() & IMAGE_SCN_MEM_WRITE) == 0;
                lrgn.bounds = vbounds;
                lrgn.endian = Endian::Little;

                lrgn.bytes = if rsize < vsize {
                    tracing::trace!("raw section size < virtual size; padding with zeros");
                    let mut bytes = Vec::with_capacity(vsize);

                    bytes.extend_from_slice(&raw[rstart..rend]);
                    bytes.resize(vsize, 0u8);

                    lrgn.uninitialised = Some((vstart + rsize)..(vstart + vsize));

                    Cow::Owned(bytes)
                } else {
                    let vrend = rstart + rsize.min(vsize);
                    Cow::Borrowed(&raw[rstart..vrend])
                };

                if let Some(relocs) = relocs.as_ref() {
                    let rva_bounds = section.virtual_address()
                        ..(section.virtual_address() + section.virtual_size());
                    let mut iter = relocs
                        .to_owned()
                        .filter(|reloc| rva_bounds.contains(&reloc.header.virtual_address));

                    while let Some(reloc) = iter.next() {
                        let Some(offset) = reloc
                            .header
                            .virtual_address
                            .checked_add(reloc.entry.offset() as u32)
                            .and_then(|v| v.checked_sub(rva_bounds.start))
                            .map(|v| v as usize)
                        else {
                            continue;
                        };
                        match reloc.entry.typ() {
                            IMAGE_REL_BASED_ABSOLUTE => (),
                            IMAGE_REL_BASED_HIGH => {
                                if lrgn
                                    .update_value::<u16, _>(offset, |old| {
                                        old.wrapping_add((rebase_shift >> 16) as u16)
                                    })
                                    .is_none()
                                {
                                    tracing::debug!("failed to apply IMAGE_REL_BASED_HIGH");
                                    continue 'outer;
                                }
                            }
                            IMAGE_REL_BASED_LOW => {
                                if lrgn
                                    .update_value::<u16, _>(offset, |old| {
                                        old.wrapping_add((rebase_shift & 0xffff) as u16)
                                    })
                                    .is_none()
                                {
                                    tracing::debug!("failed to apply IMAGE_REL_BASED_LOW");
                                    continue 'outer;
                                }
                            }
                            IMAGE_REL_BASED_HIGHLOW => {
                                if lrgn
                                    .update_value::<u32, _>(offset, |old| {
                                        old.wrapping_add(rebase_shift)
                                    })
                                    .is_none()
                                {
                                    tracing::debug!("failed to apply IMAGE_REL_BASED_HIGHLOW");
                                    continue 'outer;
                                }
                            }
                            IMAGE_REL_BASED_HIGHADJ => {
                                if let Some(next_reloc) = iter.next() {
                                    if next_reloc.header != reloc.header {
                                        // sanity check
                                        tracing::debug!("when applying IMAGE_REL_BASED_HIGHADJ adjacent entry is in different block")
                                    }
                                    let adj = next_reloc.entry.type_offset as u32;
                                    if lrgn
                                        .update_value::<u16, _>(offset, |old| {
                                            (((old as u32) << 16)
                                                .wrapping_add(rebase_shift & 0xffff_0000u32)
                                                .wrapping_add(adj)
                                                >> 16)
                                                as u16
                                        })
                                        .is_none()
                                    {
                                        tracing::debug!("failed to apply IMAGE_REL_BASED_HIGHADJ");
                                        continue 'outer;
                                    }
                                } else {
                                    // invalid reloc;
                                    tracing::debug!("when applying IMAGE_REL_BASED_HIGHADJ adjacent entry missing");
                                    continue 'outer;
                                }
                            }
                            IMAGE_REL_BASED_DIR64 => {
                                if lrgn
                                    .update_value::<u64, _>(offset, |old| {
                                        old.wrapping_add(rebase_shift as u64)
                                    })
                                    .is_none()
                                {
                                    tracing::debug!("failed to apply IMAGE_REL_BASED_DIR64");
                                    continue 'outer;
                                }
                            }
                            unsupported => {
                                tracing::debug!("unsupported relocation type {unsupported:x}");
                                continue 'outer;
                            }
                        }
                    }
                }
                f(&lrgn)
            }
        }

        let rebase = rebase.into();
        if rebase.is_none() || matches!(rebase, Some(base) if base != self.image_base()) {
            self.for_each_region(f)
        } else {
            let rebase = rebase.unwrap();
            match &self.efi {
                EFI::PE(pe) => process(
                    self.image_base(),
                    rebase,
                    pe.base_relocations(self.raw),
                    &pe.sections,
                    &self.raw,
                    f,
                ),
                EFI::TE(te) => process(
                    self.image_base(),
                    rebase,
                    te.base_relocations(self.raw),
                    &te.sections,
                    &self.raw,
                    f,
                ),
            }
        }
    }

    fn for_each_region<'b, F>(&'b self, f: F)
    where
        F: FnMut(&LoaderRegion<'b>),
    {
        fn process<'c, T: PESectionTable, F: FnMut(&LoaderRegion<'c>)>(
            image_base: Address,
            sections: &'c [T],
            raw: &'c [u8],
            mut f: F,
        ) {
            for section in sections.iter() {
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

                if rend as usize > raw.len() {
                    tracing::debug!("PointerToRawData + SizeOfRawData is out of bounds");
                    continue;
                }

                let vstart = image_base + section.virtual_address() as usize;
                let vsize = section.virtual_size() as usize;

                let vbounds = if vstart + vsize < vstart {
                    tracing::debug!("VirtualAddress + VirtualSize overflows");
                    continue;
                } else {
                    vstart..vstart + vsize
                };

                if rsize > vsize {
                    tracing::debug!("raw section size ({rsize:#x}) > virtual size ({vsize:#x})");
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

                    bytes.extend_from_slice(&raw[rstart..rend]);
                    bytes.resize(vsize, 0u8);

                    lrgn.uninitialised = Some((vstart + rsize)..(vstart + vsize));

                    Cow::Owned(bytes)
                } else {
                    let vrend = rstart + rsize.min(vsize);
                    Cow::Borrowed(&raw[rstart..vrend])
                };

                f(&lrgn)
            }
        }

        match &self.efi {
            EFI::PE(pe) => process(self.image_base(), &pe.sections, &self.raw, f),
            EFI::TE(te) => process(self.image_base(), &te.sections, &self.raw, f),
        }
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
        if let EFI::PE(pe) = self.efi() {
            pe.imports.iter().for_each(|import| {
                f(&LoaderImport {
                    name: Cow::Borrowed(import.name.as_ref()),
                    address: Some(Address::from(
                        (import.offset as u64).wrapping_add(pe.image_base as u64),
                    )),
                    source: Some(import.dll.into()),
                    ..Default::default()
                })
            });
        }
    }

    fn container<'b>(&'b self) -> LoaderContainer<'b> {
        let mut t = LoaderContainer::new(self.efi());
        t.set_attr(LoaderBytes::Borrowed(self.raw));
        t
    }

    fn bytes<'b>(&'b self) -> LoaderBytes<'b> {
        LoaderBytes::Borrowed(self.raw)
    }

    fn entry_point(&self) -> Option<Address> {
        Some(Address::from(match &self.efi {
            EFI::PE(pe) => (pe.entry as u64).wrapping_add(pe.image_base as u64),
            EFI::TE(te) => te.entry_point(),
        }))
    }
}

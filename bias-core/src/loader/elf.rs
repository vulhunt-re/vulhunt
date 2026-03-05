use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Cursor;
use std::ops::{Deref, Range};
use std::path::{Path, PathBuf};

use compact_str::format_compact;
use fugue::bytes::Endian;
use fugue::ir::error::Error as LanguageDBError;
use fugue::ir::{Address, LanguageDB};
use gimli::AttributeValue;
use goblin::elf::compression_header::{CompressionHeader, ELFCOMPRESS_ZLIB, ELFCOMPRESS_ZSTD};
use goblin::elf::dynamic::DT_PLTGOT;
use goblin::elf::header::{
    EM_386, EM_AARCH64, EM_ARM, EM_BPF, EM_X86_64, EM_XTENSA, ET_DYN, ET_REL,
};
use goblin::elf::section_header::{SHF_COMPRESSED, SHN_UNDEF, SHT_PROGBITS};
use goblin::elf::sym::{STT_GNU_IFUNC, STT_NOTYPE};
use goblin::elf::{Elf, Reloc, SectionHeader};
use goblin::error::Error::Malformed;
use itertools::Itertools;
use memmap2::Mmap;
use petgraph::graph::NodeIndex;
use range_set_blaze::RangeSetBlaze;
use thiserror::Error;
use ustr::{Ustr, UstrMap, UstrSet};

use super::{
    ExternalSymbols, HasExternals, LoadedBinary, Loader, LoaderAttribute, LoaderBlock, LoaderBytes,
    LoaderContainer, LoaderFunction, LoaderRegion, RelocatableBinary, RelocationError,
};
use crate::any::ProvidesStaticType;
use crate::arch::aarch64::AARCH64;
use crate::arch::arm::ARM;
use crate::arch::ebpf::EBPF;
use crate::arch::x86::{ARCH_X86, ARCH_X86_64, X86};
use crate::arch::xtensa::XTENSA;
use crate::arch::{AddressSet, ErasedArch, FunctionThunkTemplate};
use crate::cfg::block::BlockInfo;
use crate::cfg::context::ICFGExtendedContext;
use crate::cfg::FlowKind;
use crate::eval::observer::{Observer, ObserverError};
use crate::eval::{self, Bound, IREvalConfig, IREvaluator};
use crate::kb::function::FunctionInfo;
use crate::kb::id::Identifiable;
use crate::kb::{uuid, Uuid};
use crate::lifter::{Lifter, LifterBuilder, LifterBuilderError};
use crate::posix::non_returning::POSIX_NON_RETURNING;
use crate::symbols::{Symbolise, SymboliseError};
use crate::{ir, Project};

const MAX_DECOMPRESSED_SECTION_SIZE: u64 = 0x40000000; // 1 GiB

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

pub struct ELFLoader<'a> {
    ldb: Cow<'a, LanguageDB>,
    bytes: Option<Mmap>,
    convention: Cow<'static, str>,
    preferred_base: Address,
}

struct CtorDtor {
    init_funcs: Vec<Address>,
    fini_funcs: Vec<Address>,
}

impl<'a> ELFLoader<'a> {
    pub fn new(ldb: impl Into<Cow<'a, LanguageDB>>) -> Self {
        Self {
            ldb: ldb.into(),
            bytes: None,
            convention: "gcc".into(),
            preferred_base: Address::from(0u64),
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
    pub fn load_bytes<'b>(&self, bytes: &'b [u8]) -> Result<(Lifter, LoadedELF<'b>), Error> {
        self.load_bytes_with(bytes, None)
    }

    #[inline]
    pub fn load_bytes_with<'b>(
        &self,
        bytes: &'b [u8],
        path: impl Into<Option<PathBuf>>,
    ) -> Result<(Lifter, LoadedELF<'b>), Error> {
        let elf = Elf::parse(&bytes).map_err(Error::LoaderFormat)?;
        let arch = elf.header.e_machine;

        let (arch_info, processor, bits, variant) = match arch {
            EM_AARCH64 => (AARCH64::new(), "AARCH64", 64, "v8A"),
            EM_ARM => {
                let variant = ARM::check_variant(&elf, &bytes);
                (ARM::new(), "ARM", 32, variant)
            }
            EM_BPF => (EBPF::new(), "eBPF", 64, "default"),
            EM_X86_64 => (X86::new(true), "x86", 64, "default"),
            EM_386 => (X86::new(false), "x86", 32, "default"),
            EM_XTENSA => (XTENSA::new(), "Xtensa", 32, "default"),
            _ => return Err(Error::UnsupportedArchitecture(arch)),
        };

        let endian = elf.header.endianness().map_err(Error::LoaderFormat)?;

        let builder = self
            .ldb
            .lookup(
                processor,
                if endian.is_little() {
                    Endian::Little
                } else {
                    Endian::Big
                },
                bits,
                variant,
            )
            .ok_or_else(|| Error::UnsupportedArchitecture(arch))?;

        let translator = LifterBuilder::build_or_cached(&builder)?;

        let convention = translator
            .compiler_conventions()
            .get(&*self.convention)
            .cloned()
            .or_else(|| translator.compiler_conventions().get("default").cloned())
            .ok_or_else(|| Error::UnsupportedConvention(self.convention.clone()))?;

        let base = if matches!(elf.header.e_type, ET_DYN | ET_REL) {
            self.preferred_base
        } else {
            Address::from(0u64)
        };

        let lifter = Lifter::new_with(translator, convention, arch_info);
        let loaded = LoadedELF::new_with(elf, path, bytes, &lifter, base);

        Ok((lifter, loaded))
    }

    pub fn with_preferred_base(mut self, base: impl Into<Address>) -> Self {
        self.preferred_base = base.into();
        self
    }

    pub fn with_convention(mut self, convention: impl Into<Cow<'static, str>>) -> Self {
        self.convention = convention.into();
        self
    }
}

impl<'a> Loader for &'a mut ELFLoader<'_> {
    type Error = Error;
    type Loaded = LoadedELF<'a>;

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

#[derive(Debug, Clone)]
pub struct ELFExternalSymbols {
    base: Address,
    indices: BTreeMap<usize, Address>,
    sym_to_addr: UstrMap<Address>,
    addr_to_sym: BTreeMap<Address, Ustr>,
    template: FunctionThunkTemplate,
}

impl AddressSet for ELFExternalSymbols {
    fn contains_address(&self, address: impl Into<Address>) -> bool {
        self.contains_address(address)
    }
}

impl ELFExternalSymbols {
    pub fn new(elf: &Elf, template: FunctionThunkTemplate) -> Self {
        let addr_bytes = if elf.is_64 { 8usize } else { 4usize };
        let stub_size = template.len();

        let base = Address::from(if elf.is_object_file() {
            elf.section_headers.iter().fold(0, |vstart, section| {
                if section.sh_size == 0 || !section.is_alloc() {
                    vstart
                } else {
                    let aligned_start = ((vstart + (section.sh_addralign - 1))
                        & !(section.sh_addralign - 1))
                        as usize;
                    let section_end = aligned_start + section.sh_size as usize;
                    section_end as u64
                }
            })
        } else {
            let base = addr_bytes as u64
                + elf
                    .section_headers
                    .iter()
                    .map(|v| v.vm_range().end)
                    .chain(elf.program_headers.iter().map(|v| v.vm_range().end))
                    .max()
                    .unwrap_or(0) as u64;

            // ensure alignment to address-size boundary
            (base + addr_bytes.wrapping_sub(1) as u64) & !(addr_bytes as u64).wrapping_sub(1)
        });

        let mut new_self = ELFExternalSymbols {
            base: Address::from(base),
            indices: Default::default(),
            sym_to_addr: Default::default(),
            addr_to_sym: Default::default(),
            template,
        };

        let (syms, sym_tab) = if elf.is_object_file() {
            (&elf.syms, &elf.strtab)
        } else {
            (&elf.dynsyms, &elf.dynstrtab)
        };

        for (idx, addr, sym) in syms
            .iter()
            .enumerate()
            .filter(|(_oidx, sym)| {
                (sym.is_import() && !elf.is_object_file())
                    || (elf.is_object_file() && sym.is_import() && sym.st_type() == STT_NOTYPE)
            })
            .enumerate()
            .map(|(idx, (oidx, sym))| (oidx, base + (idx * stub_size), sym))
        {
            let sym = sym_tab.get_at(sym.st_name);
            new_self.insert(idx, addr, sym.map(ustr::ustr));
        }

        new_self
    }

    pub fn with_base(base: Address, template: FunctionThunkTemplate) -> Self {
        Self {
            base,
            indices: Default::default(),
            sym_to_addr: Default::default(),
            addr_to_sym: Default::default(),
            template,
        }
    }

    pub fn template(&self) -> &FunctionThunkTemplate {
        &self.template
    }

    pub fn insert(
        &mut self,
        index: usize,
        addr: impl Into<Address>,
        symbol: impl Into<Option<Ustr>>,
    ) {
        let addr = addr.into();
        let sym = symbol.into();

        self.indices.insert(index, addr);

        if let Some(sym) = sym {
            self.sym_to_addr.insert(sym, addr);
            self.addr_to_sym.insert(addr, sym);
        }
    }

    fn rebase(&mut self, old_base: Address, new_base: Address) {
        self.addr_to_sym.clear();

        for (sym, addr) in self.sym_to_addr.iter_mut() {
            *addr = *addr - old_base + new_base;
            self.addr_to_sym.insert(*addr, *sym);
        }

        for (_, addr) in self.indices.iter_mut() {
            *addr = *addr - old_base + new_base;
        }

        self.base = self.base - old_base + new_base;
    }

    pub fn symbol(&self, addr: impl Into<Address>) -> Option<Ustr> {
        self.addr_to_sym.get(&addr.into()).copied()
    }

    pub fn address(&self, sym: impl AsRef<str>) -> Option<Address> {
        let sym = Ustr::from_existing(sym.as_ref())?;
        self.sym_to_addr.get(&sym).copied()
    }

    pub fn get_address(&self, index: usize) -> Option<Address> {
        self.indices.get(&index).copied()
    }

    pub fn get_symbol(&self, index: usize) -> Option<Ustr> {
        self.indices
            .get(&index)
            .and_then(|addr| self.addr_to_sym.get(addr))
            .copied()
    }

    pub fn contains_address(&self, addr: impl Into<Address>) -> bool {
        self.addr_to_sym.contains_key(&addr.into())
    }

    pub fn contains_symbol(&self, sym: impl AsRef<str>) -> bool {
        let Some(sym) = Ustr::from_existing(sym.as_ref()) else {
            return false;
        };

        self.sym_to_addr.contains_key(&sym)
    }

    pub fn iter<'a>(&'a self) -> impl ExactSizeIterator<Item = (Address, Ustr)> + 'a {
        self.addr_to_sym.iter().map(|(&addr, &sym)| (addr, sym))
    }

    pub fn base(&self) -> Address {
        self.base
    }

    pub fn size(&self) -> usize {
        self.indices.len() * self.template.len()
    }

    pub fn len(&self) -> usize {
        self.indices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ExternalSymbols for ELFExternalSymbols {
    fn base(&self) -> Address {
        self.base()
    }

    fn size(&self) -> usize {
        self.size()
    }

    fn address(&self, sym: impl AsRef<str>) -> Option<Address> {
        self.address(sym)
    }

    fn symbol(&self, addr: impl Into<Address>) -> Option<Ustr> {
        self.symbol(addr)
    }

    fn contains_address(&self, addr: impl Into<Address>) -> bool {
        self.contains_address(addr)
    }

    fn contains_symbol(&self, sym: impl AsRef<str>) -> bool {
        self.contains_symbol(sym)
    }

    fn symbols<'a>(&'a self) -> impl Iterator<Item = (Address, Ustr)> + 'a {
        self.iter()
    }

    fn number_of_symbols(&self) -> usize {
        self.len()
    }
}

#[derive(ProvidesStaticType)]
#[repr(transparent)]
pub struct ELFExternalSymbolsRef<'a>(pub &'a ELFExternalSymbols);

impl<'a> ELFExternalSymbolsRef<'a> {
    pub fn new(externs: &'a ELFExternalSymbols) -> Self {
        Self(externs)
    }
}

impl<'a> Deref for ELFExternalSymbolsRef<'a> {
    type Target = ELFExternalSymbols;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> LoaderAttribute<'a> for ELFExternalSymbolsRef<'a> {
    const UUID: Uuid = uuid("C3FDC800-2A68-4699-AB3B-CAEA22D87399");
}

pub struct LoadedELF<'a> {
    elf: Elf<'a>,
    path: Option<PathBuf>,
    base: Address,
    raw: &'a [u8],
    externs: ELFExternalSymbols,
    arch: Box<dyn ErasedArch>,
}

impl<'a> LoadedELF<'a> {
    pub fn elf(&self) -> &Elf<'a> {
        &self.elf
    }

    pub fn path(&self) -> Option<&PathBuf> {
        self.path.as_ref()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }

    pub fn externs(&self) -> &ELFExternalSymbols {
        &self.externs
    }

    fn pltgot_via_program_header(&self) -> Option<Range<Address>> {
        self.elf
            .section_headers
            .is_empty()
            .then(|| {
                let start = self.elf.dynamic.as_ref().and_then(|dynamic| {
                    dynamic
                        .dyns
                        .iter()
                        .find_map(|d| (d.d_tag == DT_PLTGOT).then(|| d.d_val))
                })?;

                self.elf.program_headers.iter().find_map(|ph| {
                    let ph_range = ph.vm_range();
                    let ph_start = ph_range.start as u64;
                    let ph_end = ph_range.end as u64;

                    if ph_start <= start && ph_end > start {
                        Some((self.base + start)..(self.base + ph_end))
                    } else {
                        None
                    }
                })
            })
            .flatten()
    }

    pub fn import_ranges<'b>(&'b self) -> impl Iterator<Item = Range<Address>> + 'b {
        // .got or .plt
        self.elf
            .section_headers
            .iter()
            .filter_map(|sh| {
                if matches!(
                    self.elf.shdr_strtab.get_at(sh.sh_name),
                    Some(".plt.sec" | ".plt" | ".got" | ".got.plt" | ".plt.got")
                ) {
                    let start = sh.vm_range().start as u64;
                    let end = sh.vm_range().end as u64;

                    if end <= start {
                        // range is empty
                        return None;
                    }

                    let range = (self.base + start)..(self.base + end);

                    Some(range)
                } else {
                    None
                }
            })
            .chain(self.pltgot_via_program_header())
    }

    pub fn endian(&self) -> Endian {
        if self.elf.little_endian {
            Endian::Little
        } else {
            Endian::Big
        }
    }

    pub fn new<'b>(
        elf: Elf<'a>,
        path: impl Into<Option<PathBuf>>,
        raw: &'a [u8],
        lifter: &'b Lifter,
    ) -> Self {
        Self::new_with(elf, path, raw, lifter, 0u64)
    }

    pub(crate) fn new_with<'b>(
        elf: Elf<'a>,
        path: impl Into<Option<PathBuf>>,
        raw: &'a [u8],
        lifter: &'b Lifter,
        preferred_base: impl Into<Address>,
    ) -> Self {
        let arch = lifter.arch().to_owned();
        let mut externs =
            ELFExternalSymbols::new(&elf, arch.external_thunk_template(lifter.translator()));

        // NOTE(sanity): we check that base is selected such that we will not
        // overflow, if it will then we assume a base of 0.
        let preferred_base = preferred_base.into();
        let base = if preferred_base < preferred_base + usize::from(externs.base() + externs.size())
        {
            // NOTE: initially externs are located relative to 0, so old_base = 0
            externs.rebase(Address::from(0u64), preferred_base);
            preferred_base
        } else {
            Address::from(0u64)
        };

        Self {
            elf,
            path: path.into(),
            raw,
            externs,
            arch,
            base,
        }
    }

    fn extern_region(&self) -> Option<LoaderRegion<'static>> {
        if self.externs.len() == 0 {
            return None;
        }

        let stub_size = self.externs.template.len();
        let extern_size = self.externs.len() * stub_size;
        let range = self.externs.base..(self.externs.base + extern_size);

        let mut mapping = Vec::with_capacity(extern_size);

        for _ in 0..self.externs.len() {
            mapping.extend_from_slice(self.externs.template.bytes());
        }

        Some(LoaderRegion {
            name: Some("extern".into()),
            code: true,
            read_only: true,
            uninitialised: None,
            bounds: range,
            endian: self.endian(),
            bytes: Cow::Owned(mapping),
        })
    }

    fn apply_relocations(&self, region: &mut LoaderRegion) {
        if self.elf.header.e_machine == EM_ARM {
            tracing::trace!("applying relocations for ARM");
            self.apply_arm_relocations(region);
            return;
        }

        if self.elf.header.e_machine == EM_AARCH64 {
            tracing::trace!("applying relocations for AArch64");
            self.apply_aarch64_relocations(region);
            return;
        }

        if self.elf.header.e_machine == EM_X86_64 {
            tracing::trace!("applying relocations for x86-64");
            self.apply_x86_64_relocations(region);
            return;
        }
    }

    fn apply_object_file_relocations(&self, regions: &mut Vec<Option<LoaderRegion>>) {
        if self.elf.header.e_machine == EM_X86_64 {
            tracing::trace!("applying relocations for x86-64");
            self.apply_x86_64_object_file_relocations(regions);
            return;
        }
    }

    fn apply_x86_64_object_file_relocations(&self, regions: &mut Vec<Option<LoaderRegion>>) {
        use goblin::elf::reloc::*;

        for (sec_idx, rel_section) in self.elf.shdr_relocs.iter() {
            let base_section_idx = sec_idx - 1;
            let Some(ref region) = regions[base_section_idx] else {
                continue;
            };
            let curr_section_start = u64::from(region.bounds.start);

            for curr_reloc in rel_section.iter() {
                let r_type = curr_reloc.r_type;

                let Some(target_sym) = self.elf.syms.get(curr_reloc.r_sym) else {
                    tracing::trace!("skipping relocation ({r_type}); cannot resolve symbol");
                    continue;
                };

                let target_name = self.elf.strtab.get_at(target_sym.st_name);
                let target_base = if let Some(ext_sym_addr) =
                    target_name.and_then(|name| self.externs.address(name))
                {
                    u64::from(ext_sym_addr)
                } else {
                    // NOTE:
                    // We use a simple bounds-check to invalidate special section
                    // header index values that would lead to OOB accesses; some might
                    // require manual processing to get relocations etc.
                    //
                    // We check against and skip SHN_UNDEF (value = 0) section
                    // references while applying relocations/symbols:
                    // - although index 0 is in-bounds for section tables, this is
                    //   usually a sentinel section with a sh_type of SHT_NULL (meaning
                    //   it's empty)
                    // - referencing SHN_UNDEF is not referencing section 0
                    // - SHN_UNDEF marks a reference to a "missing, irrelevant, or
                    //   otherwise meaningless" section
                    // - it is hence correct to skip, in the general case
                    //
                    // We deem it correct to not check for SHN_UNDEF for external
                    // symbols, i.e., the position of the check inside the else branch
                    // is sane:
                    // - the default type for section references in unallocated
                    //   external symbols (or relocations targeting those) is SHN_UNDEF
                    //   but should not be skipped
                    //
                    if target_sym.st_shndx == SHN_UNDEF as usize
                        || target_sym.st_shndx >= regions.len()
                    {
                        tracing::debug!("skipping special section header index");
                        continue;
                    }

                    match regions[target_sym.st_shndx]
                        .as_ref()
                        .and_then(|r| r.bounds.start.offset().checked_add(target_sym.st_value))
                    {
                        Some(base_addr) => base_addr,
                        None => {
                            tracing::debug!("skipping relocation ({r_type}): integer overflow when calculating symbol address by offsetting into section");
                            continue;
                        }
                    }
                };

                match curr_reloc.r_type {
                    R_X86_64_RELATIVE | R_X86_64_RELATIVE64 => {
                        let Some(patch_addr) = curr_section_start.checked_add(curr_reloc.r_offset)
                        else {
                            tracing::debug!("skipping relocation ({r_type}): integer overflow when calculating patch address");
                            continue;
                        };

                        let patch_bytes = self
                            .base
                            .offset()
                            .wrapping_add_signed(curr_reloc.r_addend.unwrap_or(0));

                        regions[base_section_idx]
                            .as_mut()
                            .expect("mapped section")
                            .write_value(curr_reloc.r_offset as usize, patch_bytes);

                        tracing::trace!(
                            "applying object file relocation ({r_type}): writing bytes {patch_bytes:x} at address {patch_addr:x}",
                        );
                    }
                    R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                        let Some(patch_addr) = curr_section_start.checked_add(curr_reloc.r_offset)
                        else {
                            tracing::debug!("skipping relocation ({r_type}): integer overflow when calculating patch address");
                            continue;
                        };

                        let patch_bytes = target_base;

                        regions[base_section_idx]
                            .as_mut()
                            .expect("mapped section")
                            .write_value(curr_reloc.r_offset as usize, patch_bytes);

                        tracing::trace!(
                            "applying object file relocation ({r_type}): writing bytes {patch_bytes:x} at address {patch_addr:x}",
                        );
                    }
                    R_X86_64_64 | R_X86_64_GOT64 => {
                        let Some(patch_addr) = curr_section_start.checked_add(curr_reloc.r_offset)
                        else {
                            tracing::debug!("skipping relocation ({r_type}): integer overflow when calculating patch address");
                            continue;
                        };

                        let patch_bytes =
                            target_base.wrapping_add_signed(curr_reloc.r_addend.unwrap_or(0));

                        regions[base_section_idx]
                            .as_mut()
                            .expect("mapped section")
                            .write_value(curr_reloc.r_offset as usize, patch_bytes);

                        tracing::trace!(
                            "applying object file relocation ({r_type}): writing bytes {patch_bytes:x} at address {patch_addr:x}",
                        );
                    }
                    R_X86_64_32 => {
                        let Some(patch_addr) = curr_section_start.checked_add(curr_reloc.r_offset)
                        else {
                            tracing::debug!("skipping relocation ({r_type}): integer overflow when calculating patch address");
                            continue;
                        };

                        let target_addr =
                            target_base.wrapping_add_signed(curr_reloc.r_addend.unwrap_or(0));

                        let patch_bytes = target_addr as u32;

                        if patch_bytes as u64 != target_addr {
                            tracing::debug!("skipping relocation ({r_type}): verification of R_X86_64_32 zero extension failed");
                        }

                        regions[base_section_idx]
                            .as_mut()
                            .expect("mapped section")
                            .write_value(curr_reloc.r_offset as usize, patch_bytes);

                        tracing::trace!(
                            "applying object file relocation ({r_type}): writing bytes {patch_bytes:x} at address {patch_addr:x}",
                        );
                    }
                    R_X86_64_32S => {
                        let Some(patch_addr) = curr_section_start.checked_add(curr_reloc.r_offset)
                        else {
                            tracing::debug!("skipping relocation ({r_type}): integer overflow when calculating patch address");
                            continue;
                        };

                        let target_addr =
                            target_base.wrapping_add_signed(curr_reloc.r_addend.unwrap_or(0));

                        let patch_bytes = target_addr as u32;

                        if (patch_bytes as i32 as i64) as u64 != target_addr {
                            tracing::debug!("skipping relocation ({r_type}): verification of R_X86_64_32S sign extension failed");
                        }

                        regions[base_section_idx]
                            .as_mut()
                            .expect("mapped section")
                            .write_value(curr_reloc.r_offset as usize, patch_bytes);

                        tracing::trace!(
                            "applying object file relocation ({r_type}): writing bytes {patch_bytes:x} at address {patch_addr:x}",
                        );
                    }
                    R_X86_64_PLT32
                    | R_X86_64_PC32
                    | R_X86_64_GOTPCREL
                    | R_X86_64_GOTPCRELX
                    | R_X86_64_REX_GOTPCRELX => {
                        let Some(patch_addr) = curr_section_start.checked_add(curr_reloc.r_offset)
                        else {
                            tracing::debug!("skipping relocation ({r_type}): integer overflow when calculating patch address");
                            continue;
                        };

                        let target_addr =
                            target_base.wrapping_add_signed(curr_reloc.r_addend.unwrap_or(0));

                        let patch_bytes = (target_addr as u32).wrapping_sub(patch_addr as u32);

                        regions[base_section_idx]
                            .as_mut()
                            .expect("mapped section")
                            .write_value(curr_reloc.r_offset as usize, patch_bytes);

                        tracing::trace!(
                            "applying object file relocation ({r_type}): writing bytes {patch_bytes:x} at address {patch_addr:x}",
                        );
                    }
                    kind => {
                        tracing::debug!("unhandled relocation kind {kind}: {curr_reloc:?}");
                    }
                }
            }
        }
    }

    fn apply_aarch64_relocations(&self, region: &mut LoaderRegion) {
        use goblin::elf::reloc::*;

        let val_or_extern = |rel: Reloc| -> Option<Address> {
            let sym = self.elf.dynsyms.get(rel.r_sym)?;
            let val = self.base + sym.st_value;

            let Some(name) = self
                .elf
                .dynstrtab
                .get_at(sym.st_name)
                .and_then(Ustr::from_existing)
            else {
                return Some(val);
            };

            tracing::trace!("applying relocation for {name}");

            Some(self.externs.sym_to_addr.get(&name).copied().unwrap_or(val))
        };

        for rel in self
            .elf
            .pltrelocs
            .iter()
            .chain(self.elf.dynrels.iter())
            .chain(self.elf.dynrelas.iter())
        {
            match rel.r_type {
                R_AARCH64_GLOB_DAT | R_AARCH64_JUMP_SLOT | R_AARCH64_ABS64 => {
                    let patch_addr = self.base + rel.r_offset;

                    // overflow check (assuming adversarial input)
                    if patch_addr < self.base {
                        tracing::debug!("skipping relocation ({}): integer overflow when calculating patch address", rel.r_type);
                        continue;
                    }

                    if !region.bounds.contains(&patch_addr) {
                        continue;
                    }

                    let Some(patch_bytes) = val_or_extern(rel) else {
                        continue;
                    };

                    let patch_bytes = patch_bytes
                        .offset()
                        .wrapping_add_signed(rel.r_addend.unwrap_or(0));

                    tracing::trace!(
                        "applying file relocation ({}): writing bytes {patch_bytes:x} at address {patch_addr}",
                        rel.r_type
                    );

                    let offset = usize::from(patch_addr - region.bounds.start);

                    region.write_value(offset, patch_bytes);
                }
                R_AARCH64_RELATIVE => {
                    let patch_addr = self.base + rel.r_offset;

                    if patch_addr < self.base {
                        tracing::debug!("skipping relocation ({}): integer overflow when calculating patch address", rel.r_type);
                        continue;
                    }

                    if !region.bounds.contains(&patch_addr) {
                        continue;
                    }

                    let base = self.base.offset();
                    let addend = rel.r_addend.unwrap();
                    let patch_bytes = base.wrapping_add_signed(addend);

                    tracing::trace!(
                        "applying file relocation ({}): writing bytes {patch_bytes:#x} at address {patch_addr}",
                        rel.r_type
                    );

                    let offset = usize::from(patch_addr - region.bounds.start);

                    region.write_value(offset, patch_bytes);
                }
                kind => {
                    tracing::debug!("unhandled relocation kind {kind}: {rel:?}");
                }
            }
        }
    }

    fn apply_arm_relocations(&self, region: &mut LoaderRegion) {
        use goblin::elf::reloc::*;

        let val_or_extern = |rel: Reloc| -> Option<(bool, Address)> {
            let sym = self.elf.dynsyms.get(rel.r_sym)?;
            let val = self.base + sym.st_value;
            let is_func = sym.is_function();

            let Some(name) = self
                .elf
                .dynstrtab
                .get_at(sym.st_name)
                .and_then(Ustr::from_existing)
            else {
                return Some((is_func, val));
            };

            tracing::trace!("applying relocation for {name}");

            let addr = self.externs.sym_to_addr.get(&name).copied().unwrap_or(val);

            Some((is_func, addr))
        };

        for rel in self
            .elf
            .pltrelocs
            .iter()
            .chain(self.elf.dynrels.iter())
            .chain(self.elf.dynrelas.iter())
        {
            match rel.r_type {
                R_ARM_ABS32 => {
                    let patch_addr = self.base + rel.r_offset;

                    // overflow check (assuming adversarial input)
                    if patch_addr < self.base {
                        tracing::debug!("skipping relocation ({}): integer overflow when calculating patch address", rel.r_type);
                        continue;
                    }

                    if !region.bounds.contains(&patch_addr) {
                        continue;
                    }

                    let Some((is_func, patch_bytes)) = val_or_extern(rel) else {
                        continue;
                    };

                    let thumb = (is_func as u64) & (patch_bytes.offset() & 1);

                    let patch_bytes = patch_bytes
                        .offset()
                        .wrapping_add_signed(rel.r_addend.unwrap_or(0))
                        | thumb;

                    tracing::trace!(
                        "applying file relocation ({}): writing bytes {patch_bytes:#x} at address {patch_addr}",
                        rel.r_type
                    );

                    let offset = usize::from(patch_addr - region.bounds.start);

                    region.write_value(offset, patch_bytes as u32);
                }
                R_ARM_GLOB_DAT | R_ARM_JUMP_SLOT => {
                    let patch_addr = self.base + rel.r_offset;

                    if patch_addr < self.base {
                        tracing::debug!("skipping relocation ({}): integer overflow when calculating patch address", rel.r_type);
                        continue;
                    }

                    if !region.bounds.contains(&patch_addr) {
                        continue;
                    }

                    let Some((_, patch_bytes)) = val_or_extern(rel) else {
                        continue;
                    };

                    let patch_bytes = patch_bytes
                        .offset()
                        .wrapping_add_signed(rel.r_addend.unwrap_or(0));

                    tracing::trace!(
                        "applying file relocation ({}): writing bytes {patch_bytes:#x} at address {patch_addr}",
                        rel.r_type
                    );

                    let offset = usize::from(patch_addr - region.bounds.start);

                    region.write_value(offset, patch_bytes as u32);
                }
                R_ARM_RELATIVE => {
                    let patch_addr = self.base + rel.r_offset;

                    if patch_addr < self.base {
                        tracing::debug!("skipping relocation ({}): integer overflow when calculating patch address", rel.r_type);
                        continue;
                    }

                    if !region.bounds.contains(&patch_addr) {
                        continue;
                    }

                    // get the addend
                    let addend = rel.r_addend.unwrap_or_else(|| {
                        // compute implicit addend
                        if let Some(offset) = rel.r_offset.checked_sub(region.bounds.start.offset()) {
                            let add = region.read_value::<u32>(offset as usize).unwrap_or(0);
                            add as i64
                        } else {
                            tracing::debug!("calculating the implicit addend offset caused an underflow; setting addend to 0");
                            0
                        }
                    });

                    // the loader base, usually 0
                    let base = self.base.offset();
                    let patch_bytes = base.wrapping_add_signed(addend);

                    tracing::trace!(
                        "applying file relocation ({}): writing bytes {patch_bytes:#x} at address {patch_addr}",
                        rel.r_type
                    );

                    let offset = usize::from(patch_addr - region.bounds.start);

                    region.write_value(offset, patch_bytes as u32);
                }
                kind => {
                    tracing::debug!("unhandled relocation kind {kind}: {rel:?}");
                }
            }
        }
    }

    fn apply_x86_64_relocations(&self, region: &mut LoaderRegion) {
        use goblin::elf::reloc::*;

        let val_or_extern = |rel: Reloc| -> Option<Address> {
            let sym = self.elf.dynsyms.get(rel.r_sym)?;
            let val = self.base + sym.st_value;

            let Some(name) = self
                .elf
                .dynstrtab
                .get_at(sym.st_name)
                .and_then(Ustr::from_existing)
            else {
                return Some(val);
            };

            tracing::trace!("applying relocation for {name}");

            Some(self.externs.sym_to_addr.get(&name).copied().unwrap_or(val))
        };

        for rel in self
            .elf
            .pltrelocs
            .iter()
            .chain(self.elf.dynrels.iter())
            .chain(self.elf.dynrelas.iter())
        {
            match rel.r_type {
                R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                    let patch_addr = self.base + rel.r_offset;

                    // overflow check (assuming adversarial input)
                    if patch_addr < self.base {
                        tracing::debug!("skipping relocation ({}): integer overflow when calculating patch address", rel.r_type);
                        continue;
                    }

                    if !region.bounds.contains(&patch_addr) {
                        continue;
                    }

                    let Some(patch_bytes) = val_or_extern(rel) else {
                        continue;
                    };

                    tracing::trace!(
                        "applying file relocation ({}): writing bytes {patch_bytes} at address {patch_addr}",
                        rel.r_type
                    );

                    let offset = usize::from(patch_addr - region.bounds.start);

                    region.write_value(offset, patch_bytes.offset());
                }
                R_X86_64_IRELATIVE => {
                    let patch_addr = self.base + rel.r_offset;

                    if patch_addr < self.base {
                        tracing::debug!("skipping relocation ({}): integer overflow when calculating patch address", rel.r_type);
                        continue;
                    }

                    if !region.bounds.contains(&patch_addr) {
                        continue;
                    }

                    // R_X86_64_IRELATIVE is similar to R_X86_64_RELATIVE except that the value
                    // used in this relocation is the program address returned by the function,
                    // which takes no arguments, at the address of the result of the corresponding
                    // R_X86_64_RELATIVE relocation
                    //
                    // A = addend; B = base address
                    //

                    let base = self.base.offset();
                    let addend = rel.r_addend.unwrap();

                    tracing::trace!(
                        "applying R_X86_64_IRELATIVE relocation at {patch_addr} (A: {addend:x}, B: {base:x})",
                    );

                    let offset = usize::from(patch_addr - region.bounds.start);

                    region.write_value(offset, base.wrapping_add_signed(addend));
                }
                R_X86_64_64 | R_X86_64_GOT64 => {
                    let patch_addr = self.base + rel.r_offset;

                    if patch_addr < self.base {
                        tracing::debug!("skipping relocation ({}): integer overflow when calculating patch address", rel.r_type);
                        continue;
                    }

                    if !region.bounds.contains(&patch_addr) {
                        continue;
                    }

                    let Some(target_base) = val_or_extern(rel) else {
                        continue;
                    };

                    let patch_bytes = target_base
                        .offset()
                        .wrapping_add_signed(rel.r_addend.unwrap_or(0));

                    let offset = usize::from(patch_addr - region.bounds.start);

                    region.write_value(offset, patch_bytes);

                    tracing::trace!(
                        "applying relocation ({}): writing bytes {patch_bytes} at address {patch_addr}",
                        rel.r_type,
                    );
                }
                R_X86_64_32 => {
                    let patch_addr = self.base + rel.r_offset;

                    if patch_addr < self.base {
                        tracing::debug!("skipping relocation ({}): integer overflow when calculating patch address", rel.r_type);
                        continue;
                    }

                    if !region.bounds.contains(&patch_addr) {
                        continue;
                    }

                    let Some(target_base) = val_or_extern(rel) else {
                        continue;
                    };

                    let target_addr = target_base
                        .offset()
                        .wrapping_add_signed(rel.r_addend.unwrap_or(0));

                    let patch_bytes = target_addr as u32;

                    if patch_bytes as u64 != target_addr {
                        tracing::debug!("skipping relocation ({}): verification of R_X86_64_32 zero extension failed", rel.r_type);
                    }

                    let offset = usize::from(patch_addr - region.bounds.start);

                    region.write_value(offset, patch_bytes);

                    tracing::trace!(
                        "applying relocation ({}): writing bytes {patch_bytes} at address {patch_addr}",
                        rel.r_type,
                    );
                }
                R_X86_64_32S => {
                    let patch_addr = self.base + rel.r_offset;

                    if patch_addr < self.base {
                        tracing::debug!("skipping relocation ({}): integer overflow when calculating patch address", rel.r_type);
                        continue;
                    }

                    if !region.bounds.contains(&patch_addr) {
                        continue;
                    }

                    let Some(target_base) = val_or_extern(rel) else {
                        continue;
                    };

                    let target_addr = target_base
                        .offset()
                        .wrapping_add_signed(rel.r_addend.unwrap_or(0));

                    let patch_bytes = target_addr as u32;

                    if (patch_bytes as i32 as i64) as u64 != target_addr {
                        tracing::debug!("skipping relocation ({}): verification of R_X86_64_32S sign extension failed", rel.r_type);
                    }

                    let offset = usize::from(patch_addr - region.bounds.start);

                    region.write_value(offset, patch_bytes);

                    tracing::trace!(
                        "applying relocation ({}): writing bytes {patch_bytes} at address {patch_addr}",
                        rel.r_type,
                    );
                }
                R_X86_64_PLT32
                | R_X86_64_PC32
                | R_X86_64_GOTPCREL
                | R_X86_64_GOTPCRELX
                | R_X86_64_REX_GOTPCRELX => {
                    let patch_addr = self.base + rel.r_offset;

                    if patch_addr < self.base {
                        tracing::debug!("skipping relocation ({}): integer overflow when calculating patch address", rel.r_type);
                        continue;
                    }

                    if !region.bounds.contains(&patch_addr) {
                        continue;
                    }

                    let Some(target_base) = val_or_extern(rel) else {
                        continue;
                    };

                    let target_addr = target_base
                        .offset()
                        .wrapping_add_signed(rel.r_addend.unwrap_or(0));

                    let patch_bytes = (target_addr as u32).wrapping_sub(patch_addr.offset() as u32);

                    let offset = usize::from(patch_addr - region.bounds.start);

                    region.write_value(offset as usize, patch_bytes);

                    tracing::trace!(
                        "applying relocation ({}): writing bytes {patch_bytes} at address {patch_addr}",
                        rel.r_type,
                    );
                }
                kind => {
                    tracing::debug!("unhandled relocation kind {kind}: {rel:?}");
                }
            }
        }
    }

    fn for_each_region_linked<'b, F>(&'b self, mut f: F)
    where
        F: FnMut(&LoaderRegion<'b>),
    {
        let mut covered_sh = RangeSetBlaze::<u64>::new();

        let endian = if self.elf().little_endian {
            Endian::Little
        } else {
            Endian::Big
        };

        for section in self.elf.section_headers.iter() {
            if section.sh_size == 0 || !section.is_alloc() {
                let mut lrgn = LoaderRegion::default();
                lrgn.name = self.elf.shdr_strtab.get_at(section.sh_name).map(Cow::Borrowed);
                continue;
            }

            let rbounds = section.file_range().unwrap_or(Default::default());

            let rstart = rbounds.start;
            let rend = rbounds.end;
            let rsize = rend - rstart;

            if rend > self.raw.len() {
                tracing::debug!("p_offset + p_filesz is out of bounds; skipping");
                continue;
            }

            let vbounds = section.vm_range();
            let vstart = self.base + vbounds.start;
            let vend = self.base + vbounds.end;
            let vsize = usize::from(vend - vstart);
            let vrange = vstart.offset()..=vend.offset() - 1;

            if !covered_sh.is_disjoint(&RangeSetBlaze::from_iter([vrange.clone()])) {
                tracing::debug!("overlapping region {vstart}-{vend}");
                continue;
            }

            covered_sh.ranges_insert(vrange);

            let mut lrgn = LoaderRegion::default();

            lrgn.name = self.elf.shdr_strtab.get_at(section.sh_name).map(Cow::Borrowed);
            lrgn.code = section.is_executable();
            lrgn.read_only = !section.is_writable();
            lrgn.bounds = vstart..vend;
            lrgn.endian = endian;

            tracing::trace!("loading region {}-{}", lrgn.bounds.start, lrgn.bounds.end);

            lrgn.bytes = if rsize < vsize {
                tracing::trace!("section file size < section loaded size; padding with zeros");
                let mut bytes = Vec::with_capacity(vsize);

                bytes.extend_from_slice(&self.raw[rbounds]);
                bytes.resize(vsize, 0u8);

                lrgn.uninitialised = Some((vstart + rsize)..(vstart + vsize));

                Cow::Owned(bytes)
            } else {
                let vrend = rstart + rsize.min(vsize);
                Cow::Borrowed(&self.raw[rstart..vrend])
            };

            self.apply_relocations(&mut lrgn);

            f(&lrgn);
        }

        let mut covered = RangeSetBlaze::new();

        for section in self.elf.program_headers.iter() {
            if section.p_memsz == 0 || section.p_type != SHT_PROGBITS {
                continue;
            }

            let rbounds = section.file_range();

            let rstart = rbounds.start;
            let rend = rbounds.end;
            let rsize = rend - rstart;

            if rend > self.raw.len() {
                tracing::debug!("p_offset + p_filesz is out of bounds; skipping");
                continue;
            }

            if section.p_filesz > section.p_memsz {
                tracing::debug!("p_filesz > p_memsz");
            }

            let vbounds = section.vm_range();

            let vstart = self.base + vbounds.start;
            let vend = self.base + vbounds.end;

            covered.clear();
            covered.ranges_insert(vstart.offset()..=vend.offset() - 1);
            covered = covered - &covered_sh;

            if covered.is_empty() {
                continue;
            }

            for range in covered.ranges() {
                let mut lrgn = LoaderRegion::default();

                let rvsize = (*range.end() + 1 - *range.start()) as usize;

                let rvstart = (*range.start() - vstart.offset()) as usize;
                let rvend = rvsize + rvstart;

                let rvbounds = rstart + rvstart..rstart + rvend;

                lrgn.name = None;
                lrgn.code = covered_sh.is_empty() && section.is_executable();
                lrgn.read_only = !section.is_write();
                lrgn.endian = endian;
                lrgn.bounds = Address::from(*range.start())..Address::from(*range.end() + 1);

                tracing::trace!("loading region {}-{}", lrgn.bounds.start, lrgn.bounds.end);

                lrgn.bytes = if rsize < rvend {
                    let mut bytes = Vec::with_capacity(rvsize);

                    if rvstart < rsize {
                        bytes.extend_from_slice(&self.raw[rstart + rvstart..rstart + rsize]);
                    }

                    let ustart = Address::from(*range.start()) + bytes.len();
                    let uend = Address::from(*range.start()) + rvsize;

                    lrgn.uninitialised = Some(ustart..uend);

                    bytes.resize(rvsize, 0u8);

                    Cow::Owned(bytes)
                } else {
                    Cow::Borrowed(&self.raw[rvbounds])
                };

                self.apply_relocations(&mut lrgn);

                f(&lrgn)
            }
        }

        if let Some(externs) = self.extern_region() {
            f(&externs);
        }
    }

    fn for_each_region_unlinked<'b, F>(&'b self, mut f: F)
    where
        F: FnMut(&LoaderRegion<'b>),
    {
        let mut covered_sh = RangeSetBlaze::<u64>::new();

        let endian = if self.elf().little_endian {
            Endian::Little
        } else {
            Endian::Big
        };

        let mut last_section_end = self.base;
        let mut sections = Vec::<Option<LoaderRegion>>::with_capacity(512);

        for section in self.elf.section_headers.iter() {
            if section.sh_size == 0 || !section.is_alloc() {
                sections.push(None); // pad out the regions to preserve indices
                continue;
            }

            let rbounds = section.file_range().unwrap_or_default();

            let rstart = rbounds.start;
            let rend = rbounds.end;
            let rsize = rend - rstart;

            if rend > self.raw.len() {
                tracing::debug!("p_offset + p_filesz is out of bounds; skipping");
                continue;
            }

            let alignment_mask = section.sh_addralign - 1;
            let vstart =
                Address::from((last_section_end + alignment_mask).offset() & !alignment_mask);

            let vsize = section.sh_size as usize;
            let vend = vstart + vsize;

            if vend > vstart {
                last_section_end = vend;
            } else {
                tracing::debug!(
                    "overflow in calculating section bounds; start: {vstart}; size: {vsize}",
                );
                continue;
            };

            let vrange = vstart.offset()..=vend.offset() - 1;

            if !covered_sh.is_disjoint(&RangeSetBlaze::from_iter([vrange.clone()])) {
                tracing::debug!("overlapping region {vstart}-{vend}");
                continue;
            }

            covered_sh.ranges_insert(vrange);

            let mut lrgn = LoaderRegion::default();

            lrgn.name = self.elf.shdr_strtab.get_at(section.sh_name).map(Cow::Borrowed);
            lrgn.code = section.is_executable();
            lrgn.read_only = !section.is_writable();
            lrgn.bounds = vstart..vend;
            lrgn.endian = endian;

            tracing::trace!(
                "loading region from object file: {}-{}",
                lrgn.bounds.start,
                lrgn.bounds.end
            );

            lrgn.bytes = if rsize < vsize {
                tracing::trace!("section file size < section loaded size; padding with zeros");
                let mut bytes = Vec::with_capacity(vsize);

                bytes.extend_from_slice(&self.raw[rbounds]);
                bytes.resize(vsize, 0u8);

                lrgn.uninitialised = Some((vstart + rsize)..(vstart + vsize));

                Cow::Owned(bytes)
            } else {
                let vrend = rstart + rsize.min(vsize);
                Cow::Borrowed(&self.raw[rstart..vrend])
            };

            sections.push(Some(lrgn));
        }

        self.apply_object_file_relocations(&mut sections);

        for region in sections.into_iter().filter_map(|r| r) {
            f(&region);
        }

        if let Some(externs) = self.extern_region() {
            tracing::trace!(
                "loading extern region for object file: {}-{}",
                externs.bounds.start,
                externs.bounds.end
            );
            f(&externs);
        }
    }

    fn apply_symbols_for_unlinked_object(
        &self,
        project: &mut Project,
    ) -> Result<(), SymboliseError> {
        for sym in self.elf.syms.iter() {
            if sym.is_function() || sym.st_type() == STT_NOTYPE || sym.st_type() == STT_GNU_IFUNC {
                if let Some(name) = self.elf.strtab.get_at(sym.st_name) {
                    if sym.st_shndx == SHN_UNDEF as usize
                        || sym.st_shndx >= self.elf.section_headers.len()
                    {
                        tracing::debug!("skipping special section header index");
                        continue;
                    }

                    let curr_sec_name =
                        &self.elf.shdr_strtab[self.elf.section_headers[sym.st_shndx].sh_name];
                    let region_base =
                        project
                            .memory()
                            .regions()
                            .unsorted_values()
                            .find_map(|reg| {
                                if curr_sec_name == reg.name().as_str() {
                                    Some(*reg.address())
                                } else {
                                    None
                                }
                            });

                    if let Some(base) = region_base {
                        let sym_addr = base + sym.st_value;

                        let Some(fid) = project.functions().get_point(sym_addr).map(|f| f.id())
                        else {
                            continue;
                        };

                        tracing::trace!(
                            "applying symbol {name} from object file to function at {sym_addr}"
                        );

                        let name = project.symbols_mut().insert_fresh_with_prefix(name, fid);
                        project.functions_mut()[fid].update_name(name);
                    }
                }
            }
        }

        Ok(())
    }

    fn link_plt<'b>(&self, context: &mut ICFGExtendedContext) {
        let mut eval = context
            .evaluator(IREvalConfig {
                ignore_failures: true,
                enable_restores: true,
                ..Default::default()
            })
            .expect("successfully built evaluator for PLT recovery");

        struct LastLoad(Option<Address>);
        impl Observer for LastLoad {
            fn observe_pre_var_read(
                &mut self,
                _context: &mut Box<dyn eval::IRContext>,
                _location: ir::Location,
                var: &ir::Var,
            ) -> Result<(), ObserverError> {
                if let Some(addr) = var.address() {
                    self.0 = Some(addr);
                }
                Ok(())
            }
        }
        let obs_id = eval.register_observer(LastLoad(None));

        // adjust for IA32 GOT offset-based loading
        let got_base = if self.elf.header.e_machine == EM_386 {
            self.elf.dynamic.as_ref().and_then(|dynamic| {
                dynamic
                    .dyns
                    .iter()
                    .find_map(|d| (d.d_tag == DT_PLTGOT).then(|| d.d_val))
            })
        } else {
            None
        };

        for plt in self.elf.section_headers.iter().filter(|sh| {
            matches!(
                self.elf.shdr_strtab.get_at(sh.sh_name),
                Some(".plt.sec" | ".plt" | ".plt.got")
            )
        }) {
            let range = (self.base + plt.vm_range().start)..(self.base + plt.vm_range().end);

            let mut got_entries = Vec::new();
            for curr_blk in context
                .block_table
                .values()
                .filter_map(|blk| {
                    if blk.has_insns() && range.contains(&blk.start()) {
                        Some(blk)
                    } else {
                        None
                    }
                })
                .into_iter()
            {
                let end = curr_blk.last_insn().address();
                if eval
                    .eval(
                        context.tables(),
                        curr_blk.first_insn().address(),
                        Bound::StopAfterOr(end, 10),
                    )
                    .is_ok()
                {
                    if let Some(mut offset) = eval
                        .get_observer_mut::<LastLoad>(obs_id)
                        .and_then(|v| v.0.take())
                        .map(|addr| addr.offset())
                    {
                        // FIXME: should this be self.base???
                        offset += got_base.map_or(0, |base| if offset < base { base } else { 0 });
                        got_entries.push((curr_blk.node(), offset));
                    }
                }
                eval.restore().ok();
            }
            got_entries.sort_by_key(|(_nx, v)| *v);
            for (plt_node, got_offset) in got_entries {
                self.add_got_entry(context, got_offset.into(), &plt_node);
            }
        }
    }

    // create new block for GOT entry and link to PLT jump pad via flow
    fn add_got_entry(
        &self,
        context: &mut ICFGExtendedContext,
        got_addr: Address,
        plt_node: &NodeIndex,
    ) {
        if let Entry::Vacant(entry) = context.block_map.entry(got_addr) {
            entry.insert(Default::default());
            context.block_table.insert_with(got_addr, |_addr, id| {
                let nx = context.icfg.add_node(id);
                tracing::debug!("adding block: {got_addr} -> {nx:?}");

                let mut block = BlockInfo::default();

                block.update_id(id);
                block.update_node(nx);

                block
            });
        }

        if let Some(got_blk) = context.block_table.get_point(got_addr) {
            tracing::debug!(
                "adding flow from .plt ({:?}) to .got at {}",
                plt_node,
                got_addr
            );
            context
                .icfg
                .update_edge(*plt_node, got_blk.node(), FlowKind::TailCallBranch);
        }
    }

    fn parse_ctor_dtor(&self) -> Result<CtorDtor, Error> {
        let mut result = CtorDtor {
            init_funcs: Vec::new(),
            fini_funcs: Vec::new(),
        };

        for section in &self.elf.section_headers {
            let section_name = self
                .elf
                .shdr_strtab
                .get_at(section.sh_name)
                .ok_or_else(|| {
                    Error::LoaderFormat(Malformed(String::from("failed to get section name")))
                })?;

            if !section.is_alloc() {
                continue;
            }

            match section_name {
                ".init_array" | ".fini_array" => {
                    let entry_size = if self.elf().is_64 { 8 } else { 4 };

                    if section.sh_size % entry_size != 0 {
                        return Err(Error::LoaderFormat(Malformed(String::from(
                            "section size is not a multiple of pointer size",
                        ))));
                    }

                    let data = self
                        .raw
                        .get(
                            (section.sh_offset as usize)
                                ..(section.sh_offset as usize)
                                    .saturating_add(section.sh_size as usize),
                        )
                        .ok_or_else(|| {
                            Error::LoaderFormat(Malformed(format!(
                                "invalid section (sh_offset: {:#x}, sh_size: {:#x})",
                                section.sh_offset, section.sh_size
                            )))
                        })?;

                    let funcs = data
                        .chunks_exact(entry_size as usize)
                        .filter_map(|chunk| {
                            let addr = Address::from(if self.elf().is_64 {
                                u64::from_le_bytes(chunk.try_into().unwrap())
                            } else {
                                u32::from_le_bytes(chunk.try_into().unwrap()) as u64
                            });

                            if addr != 0u64 {
                                Some(self.base + addr)
                            } else {
                                None
                            }
                        })
                        .collect();

                    match section_name {
                        ".init_array" => result.init_funcs = funcs,
                        ".fini_array" => result.fini_funcs = funcs,
                        _ => unreachable!(),
                    }
                }
                _ => continue,
            }
        }

        if result.fini_funcs.is_empty() && result.init_funcs.is_empty() {
            Err(Error::LoaderFormat(Malformed(String::from(
                "no init/fini sections found",
            ))))
        } else {
            Ok(result)
        }
    }
}

impl HasExternals for LoadedELF<'_> {
    fn externs(&self) -> &impl ExternalSymbols {
        self.externs()
    }
}

#[derive(Debug, Error)]
pub enum CompressionError {
    #[error("cannot allocate buffer")]
    Allocation,
    #[error("invalid compressed data")]
    CompressedData,
    #[error("cannot parse compressed header: {0}")]
    Parse(#[from] goblin::error::Error),
    #[error("invalid uncompressed size")]
    UncompressedSize,
    #[error("unsupported compression")]
    Unsupported,
    #[error("cannot decompress zlib: {0}")]
    ZlibDecompress(#[from] flate2::DecompressError),
    #[error("cannot decompress zstd: {0}")]
    ZstdDecompress(#[from] std::io::Error),
}

#[derive(Debug, Error)]
pub enum SymboliseELFError {
    #[error("invalid compressed section: {0}")]
    Compression(#[from] CompressionError),
    #[error("DWARF information is invalid: {0}")]
    Dwarf(#[from] gimli::Error),
    #[error("cannot trace .plt entry: {0}")]
    Tracer(#[from] eval::EvalError),
}

impl From<SymboliseELFError> for SymboliseError {
    fn from(e: SymboliseELFError) -> Self {
        SymboliseError::other(e)
    }
}

struct ELFSymboliser<'a> {
    raw: &'a [u8],
    elf: &'a Elf<'a>,
    base: Address,
    externs: Option<&'a ELFExternalSymbols>,
}

impl<'a> ELFSymboliser<'a> {
    fn fallback_plt_ranges(&self, project: &Project) -> Option<Range<Address>> {
        if !self.elf.section_headers.is_empty() {
            return None;
        }

        // when section headers are empty there is no way to get PLT ranges
        // other then checking all functions (with emulation/signatures)
        //
        // use the start of the last function as range end,
        // as we only need an approximate boundary
        project
            .functions()
            .values()
            .minmax_by_key(|f| f.address())
            .into_option()
            .map(|(start, end)| start.address()..end.address())
    }

    fn plt_ranges<'b>(&'b self) -> impl Iterator<Item = Range<Address>> + 'b {
        self.elf.section_headers.iter().filter_map(|sh| {
            if matches!(
                self.elf.shdr_strtab.get_at(sh.sh_name),
                Some(".plt.sec" | ".plt" | ".plt.got")
            ) {
                Some((self.base + sh.vm_range().start)..(self.base + sh.vm_range().end))
            } else {
                None
            }
        })
    }

    fn decompressed_data(&self, sh: &SectionHeader) -> Result<Cow<'_, [u8]>, CompressionError> {
        if sh.sh_flags & SHF_COMPRESSED as u64 == 0 {
            return Ok(sh
                .file_range()
                .and_then(|range| {
                    (range.start < self.raw.len() && range.end <= self.raw.len())
                        .then(|| Cow::Borrowed(&self.raw[range]))
                })
                .unwrap_or_default());
        }

        let bytes = sh
            .file_range()
            .and_then(|range| {
                (range.start < self.raw.len() && range.end <= self.raw.len())
                    .then(|| &self.raw[range])
            })
            .unwrap_or_default();

        let ctx = goblin::container::Ctx {
            container: if self.elf.is_64 {
                goblin::container::Container::Big
            } else {
                goblin::container::Container::Little
            },
            le: if self.elf.little_endian {
                goblin::container::Endian::Little
            } else {
                goblin::container::Endian::Big
            },
        };

        let ch = CompressionHeader::parse(&bytes, 0, ctx).map_err(CompressionError::from)?;

        let start = CompressionHeader::size(ctx);

        if ch.ch_type == ELFCOMPRESS_ZLIB {
            if ch.ch_size > MAX_DECOMPRESSED_SECTION_SIZE {
                return Err(CompressionError::UncompressedSize)?;
            }

            let compressed_data = bytes.get(start..).ok_or(CompressionError::CompressedData)?;

            let mut decompressed = Vec::new();
            decompressed
                .try_reserve_exact(ch.ch_size as usize)
                .map_err(|_| CompressionError::Allocation)?;

            let mut decompress = flate2::Decompress::new(true);
            decompress
                .decompress_vec(
                    &compressed_data,
                    &mut decompressed,
                    flate2::FlushDecompress::Finish,
                )
                .map_err(CompressionError::from)?;

            Ok(Cow::Owned(decompressed))
        } else if ch.ch_type == ELFCOMPRESS_ZSTD {
            let compressed_data = bytes.get(start..).ok_or(CompressionError::CompressedData)?;

            let decompressed = zstd::decode_all(compressed_data).map_err(CompressionError::from)?;

            Ok(Cow::Owned(decompressed))
        } else {
            Err(CompressionError::Unsupported)
        }
    }
}

pub struct ELFBytes<'a> {
    raw: &'a [u8],
    elf: Elf<'a>,
    base: Address,
}

impl<'a> ELFBytes<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        Self::new_with(bytes, Address::from(0u64))
    }

    pub fn new_with(bytes: &'a [u8], base: Address) -> Result<Self, Error> {
        Ok(Self {
            elf: Elf::parse(bytes)?,
            raw: bytes,
            base,
        })
    }
}

impl<'a> Symbolise for ELFBytes<'a> {
    fn apply_symbols(&self, project: &mut Project) -> Result<(), SymboliseError> {
        let symboliser = ELFSymboliser {
            elf: &self.elf,
            raw: self.raw,
            base: self.base,
            externs: None,
        };
        symboliser.apply_symbols(project)
    }
}

impl<'a> Symbolise for LoadedELF<'a> {
    fn apply_symbols(&self, project: &mut Project) -> Result<(), SymboliseError> {
        if self.elf.is_object_file() {
            self.apply_symbols_for_unlinked_object(project)
        } else {
            let symboliser = ELFSymboliser {
                elf: &self.elf,
                raw: self.raw,
                base: self.base,
                externs: Some(&self.externs),
            };
            symboliser.apply_symbols(project)
        }
    }
}

impl<'a> ELFSymboliser<'a> {
    pub fn apply_mini_debug_info(
        &self,
        debugdata: &SectionHeader,
        project: &mut Project,
    ) -> Option<()> {
        // https://github.com/rizinorg/rizin/issues/3560
        // https://github.com/rizinorg/rizin/blob/e56fe8ac7f8328c1aa5c8de66c1392b0ea92da91/librz/bin/format/elf/elf_symbols.c#L366

        let mut comp = Cursor::new(self.raw.get(debugdata.file_range()?)?);

        let mut decomp = Vec::new();
        lzma_rs::xz_decompress(&mut comp, &mut decomp).ok()?;

        let debug = Elf::parse(&decomp).ok()?;
        for sym in debug
            .syms
            .iter()
            .filter(|s| (s.is_function() || s.st_type() == STT_NOTYPE) && !s.is_import())
        {
            let addr = self.base + sym.st_value;
            let fid = match project.functions().get_point(&addr) {
                Some(f) if f.name().is_none() => f.id(),
                _ => continue,
            };

            let Some(name) = debug.strtab.get_at(sym.st_name) else {
                continue;
            };

            tracing::trace!("applying MiniDebugInfo symbol {name} to function at {addr}");

            let name = project.symbols_mut().insert_fresh_with_prefix(name, fid);
            project.functions_mut()[fid].update_name(name);
        }

        Some(())
    }

    pub fn resolve_x86_64_ifunc_symbol(&self, project: &Project, rel: &Reloc) -> Option<&str> {
        use goblin::elf::reloc::R_X86_64_IRELATIVE;

        if rel.r_type == R_X86_64_IRELATIVE {
            // TODO: check this is correct
            // assuming base addr is 0
            let addr = self.base + rel.r_addend.unwrap() as u64;
            let fname = project.functions().get_point(addr)?;
            return fname.name().as_ref().map(Ustr::as_str);
        }

        None
    }

    pub fn resolve_ifunc_symbol(&self, project: &Project, rel: &Reloc) -> Option<&str> {
        if self.elf.header.e_machine == EM_X86_64 {
            return self.resolve_x86_64_ifunc_symbol(project, rel);
        }

        None
    }
}

impl<'a> Symbolise for ELFSymboliser<'a> {
    fn apply_symbols(&self, project: &mut Project) -> Result<(), SymboliseError> {
        let arch = project.lifter().arch().to_owned();
        // alignment should always be >= 1
        let align_mask = project.lifter().translator().alignment() as u64 - 1;

        // Apply symbols from imports
        for sym in self.elf.dynsyms.iter() {
            if (sym.is_function() || sym.st_type() == STT_GNU_IFUNC) && !sym.is_import() {
                let addr = Address::from((self.base.offset() + sym.st_value) & !align_mask);

                tracing::trace!("attempting to apply symbol at {addr}");

                let Some(fid) = project.functions().get_point(&addr).map(|f| f.id()) else {
                    continue;
                };

                if let Some(name) = self.elf.dynstrtab.get_at(sym.st_name) {
                    if sym.st_bind() == 0 && arch.is_mapping_symbol(name) {
                        continue;
                    }

                    tracing::trace!("applying symbol {name} to function at {addr}");

                    let name = project.symbols_mut().insert_fresh_with_prefix(name, fid);
                    project.functions_mut()[fid].update_name(name);
                }
            }
        }

        let mut plt_to_got = BTreeMap::new();

        // on IA32 binaries last load address may not pointing in .got/.got.plt
        // instead, we get an offset relative to the PLTGOT base address, which is stored in EBX
        //
        // thus, we will save the got base for Intel 80386 to apply it in the future
        // for other architectures it will be None
        let got_base = if self.elf.header.e_machine == EM_386 {
            self.elf.dynamic.as_ref().and_then(|dynamic| {
                dynamic
                    .dyns
                    .iter()
                    .find_map(|d| (d.d_tag == DT_PLTGOT).then(|| d.d_val))
            })
        } else {
            None
        };

        for range in self.plt_ranges().chain(self.fallback_plt_ranges(&project)) {
            tracing::trace!("linking .plt sections {}-{}", range.start, range.end);

            struct LastLoad(Option<Address>);

            impl Observer for LastLoad {
                fn observe_pre_var_read(
                    &mut self,
                    _context: &mut Box<dyn eval::IRContext>,
                    _location: ir::Location,
                    var: &ir::Var,
                ) -> Result<(), ObserverError> {
                    if let Some(addr) = var.address() {
                        self.0 = Some(addr);
                    }
                    Ok(())
                }
            }

            let mut eval = IREvaluator::new_with(
                &*project,
                IREvalConfig {
                    ignore_failures: true,
                    enable_restores: true,
                    ..Default::default()
                },
            )
            .map_err(SymboliseELFError::from)?;

            let obs_id = eval.register_observer(LastLoad(None));

            for f in project.functions().values().filter(|f| {
                if !self.elf.section_headers.is_empty() {
                    range.contains(&f.address()) && f.blocks().len() >= 1
                } else {
                    // when we are using fall-back plt ranges, check only functions with 1 block
                    f.blocks().len() == 1
                }
            }) {
                tracing::trace!("resolving entry at {}", f.address());

                // find last address in function
                let end = f
                    .blocks_with(project.code_blocks())
                    .map(|blk| blk.last_address())
                    .max()
                    .unwrap();

                // should not require more than 10 instructions...
                if eval
                    .eval(&*project, f.address(), Bound::StopAfterOr(end, 10))
                    .is_ok()
                {
                    if let Some(mut offset) = eval
                        .get_observer_mut::<LastLoad>(obs_id)
                        .and_then(|v| v.0.take())
                        .map(|addr| addr.offset())
                    {
                        offset += got_base.map_or(0, |base| if offset < base { base } else { 0 });
                        tracing::trace!(
                            "mapped .plt entry at {} to .got at {:#x}",
                            f.address(),
                            offset
                        );
                        plt_to_got.insert(Address::from(offset), f.id());
                    }
                }

                eval.restore().map_err(SymboliseELFError::from)?;
            }
        }

        // Apply symbols from symbol table
        for sym in self.elf.syms.iter() {
            if (sym.is_function() || sym.st_type() == STT_NOTYPE || sym.st_type() == STT_GNU_IFUNC)
                && !sym.is_import()
            {
                let addr = Address::from((self.base.offset() + sym.st_value) & !align_mask);

                tracing::trace!("attempting to apply function symbol at {addr}");

                let Some(fid) = project.functions().get_point(&addr).map(|f| f.id()) else {
                    continue;
                };

                if let Some(name) = self.elf.strtab.get_at(sym.st_name) {
                    if (sym.st_bind() == 0 && arch.is_mapping_symbol(name)) || name.is_empty() {
                        continue;
                    }

                    tracing::trace!("applying symbol {name} to function at {addr}");

                    let name = project.symbols_mut().insert_fresh_with_prefix(name, fid);
                    project.functions_mut()[fid].update_name(name);
                }
            }
        }

        for (rel, sym) in self
            .elf
            .pltrelocs
            .iter()
            .filter_map(|r| self.elf.dynsyms.get(r.r_sym).map(|s| (r, s)))
        {
            let addr = self.base + rel.r_offset;
            tracing::trace!("attempting to link .plt relocation at {addr}");

            let Some(name) = self.elf.dynstrtab.get_at(sym.st_name) else {
                continue;
            };

            let Some(&fid) = plt_to_got.get(&addr) else {
                if !name.is_empty() {
                    tracing::trace!("skipping symbol {name}_ptr at {:#x}", rel.r_offset);
                }
                continue;
            };

            let name = if name.is_empty() {
                self.resolve_ifunc_symbol(&project, &rel).unwrap_or(name)
            } else {
                name
            };

            if name.is_empty() {
                continue;
            }

            tracing::trace!(
                "applying symbol {name} to .plt entry at {}",
                project.functions()[fid].address(),
            );

            // first try to label with the desired name, if that fails, then we fall-back to use
            // `imp.` as a prefix to disambiguate
            //
            // either way, we bind to the `imp` prefix version.

            let name = if project.symbols().contains(name) {
                project
                    .symbols_mut()
                    .insert_fresh_with_prefix(format!("imp.{name}"), fid)
            } else {
                let name = Ustr::from(name);
                project.symbols_mut().insert(name, fid);
                project.symbols_mut().insert(format!("imp.{name}"), fid);
                name
            };

            project.functions_mut()[fid].update_name(name);
        }

        // Apply .plt.got symbols table
        for (rel, sym) in self
            .elf
            .dynrelas
            .iter()
            .filter_map(|r| self.elf.dynsyms.get(r.r_sym).map(|s| (r, s)))
        {
            let addr = self.base + rel.r_offset;

            tracing::trace!("attempting to link .plt dynamic relocation at {addr}",);

            let Some(name) = self.elf.dynstrtab.get_at(sym.st_name) else {
                continue;
            };

            let Some(&fid) = plt_to_got.get(&addr) else {
                if !name.is_empty() {
                    tracing::trace!("skipping symbol {name}_ptr at {addr}");
                }
                continue;
            };

            if name.is_empty() {
                continue;
            }

            let f = &project.functions()[fid];

            if f.name().is_some() {
                // already applied in a previous pass
                continue;
            }

            tracing::trace!(
                "applying symbol {name} to .plt.got entry at {}",
                f.address(),
            );

            let name = if project.symbols().contains(name) {
                project
                    .symbols_mut()
                    .insert_fresh_with_prefix(format!("imp.{name}"), fid)
            } else {
                let name = Ustr::from(name);
                project.symbols_mut().insert(name, fid);
                project.symbols_mut().insert(format!("imp.{name}"), fid);
                name
            };

            project.functions_mut()[fid].update_name(name);
        }

        // Use .gnu_debugdata information, if available
        if let Some(gnu_debugdata) = self.elf.section_headers.iter().find(|sh| {
            matches!(
                self.elf.shdr_strtab.get_at(sh.sh_name),
                Some(".gnu_debugdata")
            )
        }) {
            tracing::trace!("attempting to apply symbols from MiniDebugInfo");

            self.apply_mini_debug_info(gnu_debugdata, project);
        }

        // Use DWARF information, if available
        let load_section = |id: gimli::SectionId| -> Result<Cow<[u8]>, SymboliseError> {
            match self.elf.section_headers.iter().find(
                |sh| {
                    matches!(self.elf.shdr_strtab.get_at(sh.sh_name), Some(name) if name == id.name())
                },
            ) {
                Some(ref sh) => Ok(self.decompressed_data(sh).map_err(SymboliseELFError::from)?),
                None => Ok(Cow::Borrowed(&[][..])),
            }
        };

        let endian = if self.elf.little_endian {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };

        let dwarf_cow = gimli::Dwarf::load(&load_section)?;

        let borrow_section: &dyn for<'s> Fn(
            &'s Cow<[u8]>,
        )
            -> gimli::EndianSlice<'s, gimli::RunTimeEndian> =
            &|section| gimli::EndianSlice::new(&*section, endian);

        let dwarf = dwarf_cow.borrow(&borrow_section);
        let mut iter = dwarf.units();
        let debug_str = dwarf.debug_str;

        tracing::trace!("attempting to apply symbols from DWARF information");

        while let Some(header) = iter.next().map_err(SymboliseELFError::from)? {
            let unit = dwarf.unit(header).map_err(SymboliseELFError::from)?;
            let mut entries = unit.entries();

            while let Some((_, entry)) = entries.next_dfs().map_err(SymboliseELFError::from)? {
                if entry.tag() == gimli::DW_TAG_subprogram {
                    let name = entry
                        .attr(gimli::DW_AT_name)
                        .map_err(SymboliseELFError::from)?
                        .and_then(|name| name.string_value(&debug_str));

                    let low_pc = entry
                        .attr(gimli::DW_AT_low_pc)
                        .map_err(SymboliseELFError::from)?
                        .and_then(|addr| {
                            if let AttributeValue::Addr(addr) = addr.value() {
                                Some(addr)
                            } else {
                                None
                            }
                        });

                    if let (Some(name), Some(low_pc)) = (name, low_pc) {
                        let name = name.to_string_lossy();
                        let addr = self.base + low_pc;
                        let Some(fid) = project.functions().get_point(&addr).map(|f| f.id()) else {
                            continue;
                        };

                        tracing::trace!(
                            "found subprogram tag referencing {name} with DW_AT_low_pc {addr}"
                        );

                        let name = project.symbols_mut().insert_fresh_with_prefix(name, fid);
                        project.functions_mut()[fid].update_name(name);
                    }
                }
            }
        }

        // apply names from externals
        for (addr, name) in self
            .externs
            .map(|externs| externs.addr_to_sym.iter())
            .into_iter()
            .flatten()
        {
            let Some(fid) = project.function_at(*addr).map(|f| f.id()) else {
                continue;
            };

            if project.functions()[fid].name().is_some() {
                continue;
            }

            let name = if project.symbols().contains(name) {
                project
                    .symbols_mut()
                    .insert_fresh_with_prefix_or_rebind(format!("imp.{name}"), fid)
            } else {
                let name = Ustr::from(name);
                project.symbols_mut().insert(name, fid);
                project.symbols_mut().insert(format!("imp.{name}"), fid);
                name
            };

            project.functions_mut()[fid].update_name(name);
        }

        Ok(())
    }
}

impl<'a> LoadedBinary for LoadedELF<'a> {
    fn for_each_region<'b, F>(&'b self, f: F)
    where
        F: FnMut(&LoaderRegion<'b>),
    {
        if self.elf.is_object_file() {
            self.for_each_region_unlinked(f)
        } else {
            self.for_each_region_linked(f)
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
        if let Some(entry) = self.entry_point() {
            f(&LoaderFunction {
                entry,
                name: None,
                ..Default::default()
            });
        }

        for sym in self.elf.dynsyms.iter() {
            if (sym.is_function() || sym.st_type() == STT_GNU_IFUNC) && !sym.is_import() {
                if let Some(name) = self.elf.dynstrtab.get_at(sym.st_name) {
                    let (entry, context) = self
                        .arch
                        .compute_function_start_context(self.base + sym.st_value);

                    tracing::trace!(
                        "loader provided candidate function from symbol table at {entry}"
                    );

                    f(&LoaderFunction {
                        entry,
                        name: Some(name.into()),
                        context,
                        properties: Default::default(),
                    })
                }
            }
        }

        // calculate begin of .text section to properly offset symbol addresses
        let text_sect_offset = if self.elf.is_object_file() {
            self.elf
                .section_headers
                .iter()
                .fold((0u64, None), |(vstart, found_text), section| {
                    if found_text.is_some() {
                        return (vstart, found_text);
                    }

                    let size = if section.sh_size == 0 || !section.is_alloc() {
                        vstart
                    } else {
                        let alignment_mask = section.sh_addralign as u64 - 1;
                        let aligned_start = (vstart + alignment_mask) & !alignment_mask;
                        aligned_start + section.sh_size
                    };

                    if self.elf.shdr_strtab.get_at(section.sh_name).unwrap() == ".text" {
                        let alignment_mask = section.sh_addralign as u64 - 1;
                        let aligned_start = (vstart + alignment_mask) & !alignment_mask;
                        (size, Some(aligned_start))
                    } else {
                        (size, None)
                    }
                })
                .1
                .unwrap_or(0)
        } else {
            0
        };

        for sym in self.elf.syms.iter() {
            if (sym.is_function() || sym.st_type() == STT_GNU_IFUNC) && !sym.is_import() {
                if let Some(name) = self.elf.strtab.get_at(sym.st_name) {
                    let (entry, context) = self.arch.compute_function_start_context(
                        self.base + sym.st_value + text_sect_offset,
                    );

                    tracing::trace!(
                        "loader provided candidate function from symbol table at {entry}"
                    );

                    f(&LoaderFunction {
                        entry,
                        name: Some(name.into()),
                        context,
                        properties: Default::default(),
                    })
                }
            }
        }

        // handle (de)constructors
        if let Ok(constructors) = self.parse_ctor_dtor() {
            static INIT_NAMES: [&str; 8] = [
                "_INIT_0", "_INIT_1", "_INIT_2", "_INIT_3", "_INIT_4", "_INIT_5", "_INIT_6",
                "_INIT_7",
            ];
            static FINI_NAMES: [&str; 8] = [
                "_FINI_0", "_FINI_1", "_FINI_2", "_FINI_3", "_FINI_4", "_FINI_5", "_FINI_6",
                "_FINI_7",
            ];

            for (i, ctor_addr) in constructors.init_funcs.iter().enumerate() {
                f(&LoaderFunction {
                    entry: *ctor_addr,
                    name: Some(Cow::Borrowed(
                        *INIT_NAMES
                            .get(i)
                            .unwrap_or(&Ustr::from(&format_compact!("_INIT_{}", i)).as_str()),
                    )),
                    ..Default::default()
                });
            }

            for (i, dtor_addr) in constructors.fini_funcs.iter().enumerate() {
                f(&LoaderFunction {
                    entry: *dtor_addr,
                    name: Some(Cow::Borrowed(
                        *FINI_NAMES
                            .get(i)
                            .unwrap_or(&Ustr::from(&format_compact!("_FINI_{}", i)).as_str()),
                    )),
                    ..Default::default()
                });
            }
        }

        if self.externs.is_empty() {
            tracing::trace!("loader has no external functions");
            return;
        }

        let context = self.externs.template.context();

        for (entry, sym) in self.externs.iter() {
            tracing::trace!("loader provided candidate function from mapped externs at {entry}");
            f(&LoaderFunction {
                entry,
                name: Some(sym.as_str().into()),
                context: context.clone(),
                properties: FunctionInfo::EXTERN,
            })
        }
    }

    // returns (func_addr, is_non_returning, Option<PLT_JUMP_PAD>)
    fn for_each_critical_function<'b, F>(&'b self, context: &mut ICFGExtendedContext, mut f: F)
    where
        F: FnMut(Address),
    {
        // these functions are non-returning and calls to such should terminate a function
        let mut named_non_returning = (*POSIX_NON_RETURNING).to_owned();

        // these are usually tail jumps so we want to mark them
        // as functions before starting normal functions recovery
        let mut named_return_thunks = if matches!(self.arch.id(), ARCH_X86 | ARCH_X86_64) {
            UstrSet::from_iter([Ustr::from("__x86_return_thunk")])
        } else {
            UstrSet::default()
        };

        named_non_returning.extend(context.specifications.named_non_returning());
        named_return_thunks.extend(context.specifications.named_return_thunks());

        // if it's an object file, we can just rely on relocations
        // as jumps will go directly to .extern
        if self.elf.is_object_file() {
            for (addr, name) in self.externs().iter() {
                if named_non_returning.contains(&name) {
                    context.mark_non_returning_flows(addr);
                    context.non_returning_functions.insert(addr);
                    f(addr);
                } else if named_return_thunks.contains(&name) {
                    context.tail_functions.insert(addr);
                    f(addr);
                }
            }
        } else {
            self.link_plt(context);

            // mark plt jump pads and special functions
            for rel in self.elf.pltrelocs.iter() {
                // get the GOT entry address from the .plt.rel
                let Some(sym) = self.elf.dynsyms.get(rel.r_sym) else {
                    continue;
                };

                let name = Ustr::from(self.elf.dynstrtab.get_at(sym.st_name).unwrap_or_default());

                // get PLT jump pad addr by incoming flow
                let addr = self.base + rel.r_offset;
                let plt_addr = if let Some(caller_addr) = context.get_caller_for(&addr) {
                    caller_addr
                } else {
                    tracing::debug!("failed to resolve PLT jump pad");
                    continue;
                };

                if named_non_returning.contains(&name) {
                    context.non_returning_functions.insert(plt_addr);
                    context.mark_non_returning_flows(plt_addr);
                } else if named_return_thunks.contains(&name) {
                    context.tail_functions.insert(plt_addr);
                }

                f(plt_addr);
            }
        }
    }

    fn bytes<'b>(&'b self) -> LoaderBytes<'b> {
        LoaderBytes::Borrowed(self.raw)
    }

    fn container<'b>(&'b self) -> LoaderContainer<'b> {
        let mut c = LoaderContainer::new(self.elf());
        c.set_attr(LoaderBytes::Borrowed(self.raw));
        c.set_attr(ELFExternalSymbolsRef(&self.externs));
        c
    }

    fn entry_point(&self) -> Option<Address> {
        if self.elf.entry != 0 {
            Some(Address::from(self.elf.entry))
        } else {
            None
        }
    }
}

impl RelocatableBinary for LoadedELF<'_> {
    fn rebase(&mut self, base: Address) -> Result<(), RelocationError> {
        if !matches!(self.elf.header.e_type, ET_DYN | ET_REL) {
            return Err(RelocationError::Unsupported);
        }

        if base >= base + self.mapping_size() {
            return Err(RelocationError::InvalidBaseAddress);
        }

        self.externs.rebase(self.base, base);
        self.base = base;

        Ok(())
    }

    fn mapping_alignment(&self) -> usize {
        let align = self
            .elf
            .section_headers
            .iter()
            .map(|sh| sh.sh_addralign)
            .chain(self.elf.program_headers.iter().map(|ph| ph.p_align))
            .max()
            .unwrap_or(if self.elf.is_64 { 8 } else { 4 });
        align as _
    }

    fn mapping_size(&self) -> usize {
        let externs = self.externs();
        let lowest_address = self.base;
        let highest_address = externs.base() + externs.size();
        usize::from(highest_address - lowest_address)
    }
}

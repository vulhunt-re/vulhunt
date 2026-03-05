pub mod kv;

pub use kv::{KeyValParseError, KeyValue};

use std::collections::BTreeSet;
use std::ops::{Deref, Range};
use std::path::{Path, PathBuf};

use crate::types::standards::PackageType;
use bias_core::any::ProvidesStaticType;
use bias_core::prelude::*;

use goblin::elf::header::{EM_386, EM_AARCH64, EM_ARM, EM_BPF, EM_X86_64, EM_XTENSA};
use goblin::pe::header::{
    COFF_MACHINE_ARM, COFF_MACHINE_ARM64, COFF_MACHINE_X86, COFF_MACHINE_X86_64,
};

use serde::{Deserialize, Serialize};

use crate::platform::PlatformAttribute;

#[derive(ProvidesStaticType)]
pub struct ComponentArch<'a>(pub(crate) &'a ArchitectureDef);
impl<'a> LoaderAttribute<'a> for ComponentArch<'a> {
    const UUID: Uuid = uuid("80D945E7-0C9B-4290-AE85-D283436B7F62");
}

impl<'a> ComponentArch<'a> {
    pub fn from_object(object: &goblin::Object) -> Option<ArchitectureDef> {
        match object {
            goblin::Object::Elf(elf) => {
                let endian = if elf.header.endianness().ok()?.is_little() {
                    Endian::Little
                } else {
                    Endian::Big
                };

                Some(match elf.header.e_machine {
                    EM_AARCH64 => ArchitectureDef::new("AARCH64", endian, 64, "v8A"),
                    EM_ARM => ArchitectureDef::new("ARM", endian, 32, "v7"),
                    EM_BPF => ArchitectureDef::new("eBPF", endian, 64, "default"),
                    EM_X86_64 => ArchitectureDef::new("x86", endian, 64, "default"),
                    EM_386 => ArchitectureDef::new("x86", endian, 32, "default"),
                    EM_XTENSA => ArchitectureDef::new("Xtensa", endian, 32, "default"),
                    _ => return None,
                })
            }
            goblin::Object::PE(pe) => Some(match pe.header.coff_header.machine {
                COFF_MACHINE_ARM64 => ArchitectureDef::new("AARCH64", Endian::Little, 64, "v8A"),
                COFF_MACHINE_ARM => ArchitectureDef::new("ARM", Endian::Little, 32, "v7"),
                COFF_MACHINE_X86_64 => ArchitectureDef::new("x86", Endian::Little, 64, "default"),
                COFF_MACHINE_X86 => ArchitectureDef::new("x86", Endian::Little, 32, "default"),
                _ => return None,
            }),
            goblin::Object::TE(te) => Some(match te.header.machine {
                COFF_MACHINE_ARM64 => ArchitectureDef::new("AARCH64", Endian::Little, 64, "v8A"),
                COFF_MACHINE_ARM => ArchitectureDef::new("ARM", Endian::Little, 32, "v7"),
                COFF_MACHINE_X86_64 => ArchitectureDef::new("x86", Endian::Little, 64, "default"),
                COFF_MACHINE_X86 => ArchitectureDef::new("x86", Endian::Little, 32, "default"),
                _ => return None,
            }),
            _ => None,
        }
    }

    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Option<ArchitectureDef> {
        let bytes = bytes.as_ref();
        goblin::Object::parse(bytes)
            .ok()
            .as_ref()
            .and_then(Self::from_object)
    }
}

impl<'a> AsRef<ArchitectureDef> for ComponentArch<'a> {
    fn as_ref(&self) -> &ArchitectureDef {
        self.0
    }
}

impl<'a> Deref for ComponentArch<'a> {
    type Target = ArchitectureDef;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct ComponentEcosystem<'a>(pub(crate) &'a str);
impl<'a> LoaderAttribute<'a> for ComponentEcosystem<'a> {
    const UUID: Uuid = uuid("55192540-0923-4CA0-8F24-D60AEFC0D718");
}

impl<'a> AsRef<str> for ComponentEcosystem<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for ComponentEcosystem<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct ComponentEcosystemDiscriminant<'a>(pub(crate) &'a str);
impl<'a> LoaderAttribute<'a> for ComponentEcosystemDiscriminant<'a> {
    const UUID: Uuid = uuid("5A1EF346-316E-4B21-9114-F229ECB6EE72");
}

impl<'a> AsRef<str> for ComponentEcosystemDiscriminant<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for ComponentEcosystemDiscriminant<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Ecosystem {
    ecosystem: String,
    ecosystem_discriminant: Option<String>,
}

impl Ecosystem {
    pub fn new(ecosystem: impl Into<String>) -> Self {
        Self {
            ecosystem: ecosystem.into(),
            ..Default::default()
        }
    }

    pub fn set_ecosystem_discriminant(&mut self, ecosystem_discriminant: impl Into<String>) {
        self.ecosystem_discriminant = Some(ecosystem_discriminant.into())
    }

    pub fn with_ecosystem_discriminant(
        mut self,
        ecosystem_discriminant: impl Into<String>,
    ) -> Self {
        self.set_ecosystem_discriminant(ecosystem_discriminant);
        self
    }

    pub fn ecosystem(&self) -> &str {
        &self.ecosystem
    }

    pub fn ecosystem_discriminant(&self) -> Option<&str> {
        self.ecosystem_discriminant.as_deref()
    }
}

pub type Ecosystems = BTreeSet<Ecosystem>;

#[derive(ProvidesStaticType)]
pub struct ComponentEcosystemCandidates<'a>(pub(crate) &'a Ecosystems);
impl<'a> LoaderAttribute<'a> for ComponentEcosystemCandidates<'a> {
    const UUID: Uuid = uuid("028AFA24-7CA4-43E5-A297-DDFDAFA7C7E6");
}

impl<'a> AsRef<Ecosystems> for ComponentEcosystemCandidates<'a> {
    fn as_ref(&self) -> &Ecosystems {
        self.0
    }
}

impl<'a> Deref for ComponentEcosystemCandidates<'a> {
    type Target = Ecosystems;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct ComponentLinkedPaths<'a> {
    paths: &'a BTreeSet<String>,
    names: BTreeSet<&'a str>,
}

impl<'a> LoaderAttribute<'a> for ComponentLinkedPaths<'a> {
    const UUID: Uuid = uuid("5BDD82FF-F6E8-4409-9752-8943FBE340BA");
}

impl<'a> ComponentLinkedPaths<'a> {
    pub fn new(paths: &'a BTreeSet<String>) -> Self {
        Self {
            paths,
            names: paths
                .iter()
                .filter_map(|nm| Some(Path::new(nm).file_name()?.to_str().expect("valid utf-8")))
                .collect(),
        }
    }

    pub fn contains_path(&self, path: impl AsRef<str>) -> bool {
        self.paths.contains(path.as_ref())
    }

    pub fn paths(&self) -> impl ExactSizeIterator<Item = &str> {
        self.paths.iter().map(|nm| &**nm)
    }

    pub fn contains_name(&self, name: impl AsRef<str>) -> bool {
        self.names.contains(name.as_ref())
    }

    pub fn names(&self) -> impl ExactSizeIterator<Item = &str> {
        self.names.iter().copied()
    }
}

#[derive(ProvidesStaticType)]
pub struct ComponentDynamicLinker<'a>(&'a str);

impl<'a> LoaderAttribute<'a> for ComponentDynamicLinker<'a> {
    const UUID: Uuid = uuid("04A8C117-B289-43EF-9053-3615933AAC3E");
}

impl<'a> AsRef<str> for ComponentDynamicLinker<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for ComponentDynamicLinker<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> ComponentDynamicLinker<'a> {
    pub fn new(linker: &'a str) -> Self {
        Self(linker)
    }
}

#[derive(ProvidesStaticType)]
pub struct ComponentDynamicLibraries<'a>(&'a BTreeSet<String>);

impl<'a> LoaderAttribute<'a> for ComponentDynamicLibraries<'a> {
    const UUID: Uuid = uuid("A6F9C3BC-EB88-48E8-8AB8-6274CFB35E27");
}

impl<'a> ComponentDynamicLibraries<'a> {
    pub fn new(libraries: &'a BTreeSet<String>) -> Self {
        Self(libraries)
    }

    pub fn contains_library(&self, library: impl AsRef<str>) -> bool {
        self.0.contains(library.as_ref())
    }

    pub fn libraries(&self) -> impl ExactSizeIterator<Item = &str> {
        self.0.iter().map(|lib| &**lib)
    }
}

#[derive(ProvidesStaticType)]
pub struct ComponentDynamicLibrarySearchPaths<'a>(&'a BTreeSet<String>);

impl<'a> LoaderAttribute<'a> for ComponentDynamicLibrarySearchPaths<'a> {
    const UUID: Uuid = uuid("F303D7BA-C228-494F-A7DA-0E47349A62B1");
}

impl<'a> ComponentDynamicLibrarySearchPaths<'a> {
    pub fn new(paths: &'a BTreeSet<String>) -> Self {
        Self(paths)
    }

    pub fn contains_path(&self, path: impl AsRef<str>) -> bool {
        self.0.contains(path.as_ref())
    }

    pub fn paths(&self) -> impl ExactSizeIterator<Item = &str> {
        self.0.iter().map(|path| &**path)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PackageMetadata {
    epoch: Option<usize>,
    name: Option<String>,
    version: Option<String>,
    release: Option<String>,
    arch: Option<String>,
    source: Option<String>,
    vendor: Option<String>,
    #[serde(default)]
    package_type: Option<PackageType>,
}

impl PackageMetadata {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_epoch(&mut self, epoch: usize) {
        self.epoch = Some(epoch);
    }

    pub fn with_epoch(mut self, epoch: usize) -> Self {
        self.set_epoch(epoch);
        self
    }

    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = Some(name.into());
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.set_name(name);
        self
    }

    pub fn set_version(&mut self, version: impl Into<String>) {
        self.version = Some(version.into());
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.set_version(version);
        self
    }

    pub fn set_release(&mut self, release: impl Into<String>) {
        self.release = Some(release.into());
    }

    pub fn with_release(mut self, release: impl Into<String>) -> Self {
        self.set_release(release);
        self
    }

    pub fn set_arch(&mut self, arch: impl Into<String>) {
        self.arch = Some(arch.into());
    }

    pub fn with_arch(mut self, arch: impl Into<String>) -> Self {
        self.set_arch(arch);
        self
    }

    pub fn set_source(&mut self, source: impl Into<String>) {
        self.source = Some(source.into());
    }

    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.set_source(source);
        self
    }

    pub fn set_vendor(&mut self, vendor: impl Into<String>) {
        self.vendor = Some(vendor.into());
    }

    pub fn with_vendor(mut self, vendor: impl Into<String>) -> Self {
        self.set_vendor(vendor);
        self
    }

    pub fn set_package_type(&mut self, package_type: PackageType) {
        self.package_type = Some(package_type);
    }

    pub fn with_package_type(mut self, package_type: PackageType) -> Self {
        self.set_package_type(package_type);
        self
    }

    pub fn epoch(self) -> Option<usize> {
        self.epoch
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    pub fn release(&self) -> Option<&str> {
        self.release.as_deref()
    }

    pub fn arch(&self) -> Option<&str> {
        self.arch.as_deref()
    }

    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    pub fn vendor(&self) -> Option<&str> {
        self.vendor.as_deref()
    }

    pub fn package_type(&self) -> Option<PackageType> {
        self.package_type
    }
}

#[derive(ProvidesStaticType)]
pub struct ComponentPackageMetadata<'a>(pub(crate) &'a PackageMetadata);
impl<'a> LoaderAttribute<'a> for ComponentPackageMetadata<'a> {
    const UUID: Uuid = uuid("D04159D5-2C72-42E5-8E58-3CB88D3AA5AF");
}

impl<'a> AsRef<PackageMetadata> for ComponentPackageMetadata<'a> {
    fn as_ref(&self) -> &PackageMetadata {
        self.0
    }
}

impl<'a> Deref for ComponentPackageMetadata<'a> {
    type Target = PackageMetadata;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CompilerInformation {
    name: String,
    version: Option<String>,
    version_string: Option<String>,
}

impl CompilerInformation {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    pub fn set_version(&mut self, version: impl Into<String>) {
        self.version = Some(version.into())
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.set_version(version);
        self
    }

    pub fn set_version_string(&mut self, version_string: impl Into<String>) {
        self.version_string = Some(version_string.into())
    }

    pub fn with_version_string(mut self, version_string: impl Into<String>) -> Self {
        self.set_version_string(version_string);
        self
    }

    pub fn new_clang() -> Self {
        Self::new("clang")
    }

    pub fn new_fpc() -> Self {
        Self::new("fpc")
    }

    pub fn new_gcc() -> Self {
        Self::new("gcc")
    }

    pub fn new_ghc() -> Self {
        Self::new("ghc")
    }

    pub fn new_go() -> Self {
        Self::new("go")
    }

    pub fn new_msvc() -> Self {
        Self::new("msvc")
    }

    pub fn new_ocaml() -> Self {
        Self::new("ocaml")
    }

    pub fn new_rust() -> Self {
        Self::new("rust")
    }

    pub fn new_tcc() -> Self {
        Self::new("tcc")
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    pub fn version_string(&self) -> Option<&str> {
        self.version_string.as_deref()
    }
}

pub type Compilers = BTreeSet<CompilerInformation>;

#[derive(ProvidesStaticType)]
pub struct ComponentCompilerInformation<'a>(pub(crate) &'a Compilers);
impl<'a> LoaderAttribute<'a> for ComponentCompilerInformation<'a> {
    const UUID: Uuid = uuid("65A40883-D494-4156-AA57-66981DF7A29F");
}

impl<'a> AsRef<Compilers> for ComponentCompilerInformation<'a> {
    fn as_ref(&self) -> &Compilers {
        self.0
    }
}

impl<'a> Deref for ComponentCompilerInformation<'a> {
    type Target = Compilers;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BinaryLoaderMetadata {
    code_size: usize,
    data_size: usize,
    binary_size: usize,
}

impl BinaryLoaderMetadata {
    pub fn code_size(&self) -> usize {
        self.code_size
    }

    pub fn data_size(&self) -> usize {
        self.data_size
    }

    pub fn binary_size(&self) -> usize {
        self.binary_size
    }
}

impl BinaryLoaderMetadata {
    pub fn new(code_size: usize, data_size: usize, binary_size: usize) -> Self {
        Self {
            code_size,
            data_size,
            binary_size,
        }
    }

    pub fn from_object(object: &goblin::Object, size: usize) -> Self {
        match object {
            goblin::Object::Elf(elf) => {
                let mut code_size = 0usize;
                let mut data_size = 0usize;

                for phdr in elf.program_headers.iter() {
                    if phdr.is_executable() {
                        code_size = code_size.saturating_add(phdr.p_memsz as _);
                        continue;
                    }

                    if phdr.is_read() && phdr.is_write() {
                        data_size = data_size.saturating_add(phdr.p_memsz as _);
                    }
                }

                if code_size == 0 && data_size == 0 {
                    for shdr in elf.section_headers.iter().filter(|shdr| shdr.is_alloc()) {
                        if shdr.is_executable() {
                            let Range { start, end } = shdr.vm_range();
                            code_size = code_size.saturating_add((end - start) as _);
                            continue;
                        }

                        if shdr.is_writable() {
                            let Range { start, end } = shdr.vm_range();
                            data_size = data_size.saturating_add((end - start) as _);
                        }
                    }
                }

                Self::new(code_size, data_size, size)
            }
            goblin::Object::PE(pe) => {
                use goblin::pe::section_table::{
                    IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE,
                };
                use goblin::pe::utils::PESectionTable;

                let mut code_size = 0usize;
                let mut data_size = 0usize;

                for sect in pe.sections.iter() {
                    if (sect.characteristics() & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) != 0
                    {
                        code_size = code_size.saturating_add(sect.virtual_size as _);
                        continue;
                    }

                    if (sect.characteristics() & IMAGE_SCN_MEM_WRITE) != 0 {
                        data_size = data_size.saturating_add(sect.virtual_size as _);
                    }
                }

                Self::new(code_size, data_size, size)
            }
            goblin::Object::TE(te) => {
                use goblin::pe::utils::PESectionTable;
                use goblin::te::section_table::{
                    IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE,
                };

                let mut code_size = 0usize;
                let mut data_size = 0usize;

                for sect in te.sections.iter() {
                    if (sect.characteristics() & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) != 0
                    {
                        code_size = code_size.saturating_add(sect.virtual_size as _);
                        continue;
                    }

                    if (sect.characteristics() & IMAGE_SCN_MEM_WRITE) != 0 {
                        data_size = data_size.saturating_add(sect.virtual_size as _);
                    }
                }

                Self::new(code_size, data_size, size)
            }
            _ => Self::new(0, 0, size),
        }
    }

    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        let bytes = bytes.as_ref();
        let binary_size = bytes.len();

        goblin::Object::parse(bytes).map_or_else(
            |_| Self::new(0, 0, binary_size),
            |object| Self::from_object(&object, binary_size),
        )
    }
}

#[derive(ProvidesStaticType)]
pub struct ComponentBinaryLoaderMetadata<'a>(pub(crate) &'a BinaryLoaderMetadata);
impl<'a> LoaderAttribute<'a> for ComponentBinaryLoaderMetadata<'a> {
    const UUID: Uuid = uuid("246C7233-CD40-401E-B827-47757F9BC8C1");
}

impl<'a> AsRef<BinaryLoaderMetadata> for ComponentBinaryLoaderMetadata<'a> {
    fn as_ref(&self) -> &BinaryLoaderMetadata {
        self.0
    }
}

impl<'a> Deref for ComponentBinaryLoaderMetadata<'a> {
    type Target = BinaryLoaderMetadata;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct PlatformDataDirectory<'a>(pub(crate) &'a Path);
impl<'a> LoaderAttribute<'a> for PlatformDataDirectory<'a> {
    const UUID: Uuid = uuid("FF9A603C-2111-4724-8C20-01A793A2D228");
}

impl<'a> PlatformDataDirectory<'a> {
    pub fn root(&self) -> &Path {
        self.0
    }

    pub fn with(&self, path: impl AsRef<Path>) -> PathBuf {
        self.0.join(path.as_ref())
    }
}

impl<'a> AsRef<Path> for PlatformDataDirectory<'a> {
    fn as_ref(&self) -> &Path {
        self.0
    }
}

impl<'a> Deref for PlatformDataDirectory<'a> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(Debug, Clone)]
pub struct PlatformDataDirectoryAttribute(PathBuf);

impl<T> From<T> for PlatformDataDirectoryAttribute
where
    T: Into<PathBuf>,
{
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl AsRef<Path> for PlatformDataDirectoryAttribute {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Deref for PlatformDataDirectoryAttribute {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PlatformAttribute for PlatformDataDirectoryAttribute {
    type T<'a> = PlatformDataDirectory<'a>;

    fn as_attr<'a>(&'a self) -> PlatformDataDirectory<'a> {
        PlatformDataDirectory(&self.0)
    }
}

#[derive(ProvidesStaticType)]
pub struct SourceFilePath<'a>(&'a Path);
impl<'a> LoaderAttribute<'a> for SourceFilePath<'a> {
    const UUID: Uuid = uuid("ACB25B36-6498-472B-97E0-5DFC1BE00C3F");
}

impl<'a> AsRef<Path> for SourceFilePath<'a> {
    fn as_ref(&self) -> &Path {
        self.0
    }
}

impl<'a> Deref for SourceFilePath<'a> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(Debug, Clone)]
pub struct SourceFilePathAttribute(PathBuf);

impl<T> From<T> for SourceFilePathAttribute
where
    T: Into<PathBuf>,
{
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl AsRef<Path> for SourceFilePathAttribute {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Deref for SourceFilePathAttribute {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PlatformAttribute for SourceFilePathAttribute {
    type T<'a> = SourceFilePath<'a>;

    fn as_attr<'a>(&'a self) -> SourceFilePath<'a> {
        SourceFilePath(&self.0)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[non_exhaustive]
pub enum VCSKind {
    #[default]
    #[serde(rename = "git")]
    Git,
    #[serde(rename = "hg")]
    Mercurial,
    #[serde(rename = "svn")]
    Subversion,
    #[serde(rename = "bzr")]
    Bazaar,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct VCSMetadata {
    #[serde(default)]
    kind: VCSKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    branch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subdirectory: Option<String>,
}

impl VCSMetadata {
    pub fn new(kind: VCSKind) -> Self {
        Self {
            kind,
            ..Default::default()
        }
    }

    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    pub fn set_url(&mut self, url: impl Into<String>) {
        self.url = Some(url.into());
    }

    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.set_url(url);
        self
    }

    pub fn commit(&self) -> Option<&str> {
        self.commit.as_deref()
    }

    pub fn set_commit(&mut self, commit: impl Into<String>) {
        self.commit = Some(commit.into());
    }

    pub fn with_commit(mut self, commit: impl Into<String>) -> Self {
        self.set_commit(commit);
        self
    }

    pub fn branch(&self) -> Option<&str> {
        self.branch.as_deref()
    }

    pub fn set_branch(&mut self, branch: impl Into<String>) {
        self.branch = Some(branch.into());
    }

    pub fn with_branch(mut self, branch: impl Into<String>) -> Self {
        self.set_branch(branch);
        self
    }

    pub fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    pub fn set_tag(&mut self, tag: impl Into<String>) {
        self.tag = Some(tag.into());
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.set_tag(tag);
        self
    }

    pub fn subdirectory(&self) -> Option<&str> {
        self.subdirectory.as_deref()
    }

    pub fn set_subdirectory(&mut self, subdirectory: impl Into<String>) {
        self.subdirectory = Some(subdirectory.into());
    }

    pub fn with_subdirectory(mut self, subdirectory: impl Into<String>) -> Self {
        self.set_subdirectory(subdirectory);
        self
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct PathMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path: Option<PathBuf>,
}

impl PathMetadata {
    pub fn path(&self) -> Option<&PathBuf> {
        self.path.as_ref()
    }
}

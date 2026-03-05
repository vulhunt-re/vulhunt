use std::borrow::Cow;
use std::fs::File;
use std::io::{Cursor, Read, Seek};
use std::path::Path;

use bias_core::prelude::*;
use crate::component::{
    Component, ComponentIdentityBuilder, ComponentLoader, HasComponentIdentity, LoadedComponent,
};
use crate::package::{
    Package, PackageBuilder, PackageComponentData, PackageData, PackageError, PackageHashes,
};
use crate::pipeline::source::{
    AnalysisGroupFilter, PackageComponentItemQueue, PackageDependencyGraph, PackageItem,
    PackageItemQueue, Source, SourceError,
};
use crate::pipeline::{PackageComponentItem, PipelineAnalysisGroups, PipelineError};
use crate::platform::android::AndroidPackage;
use crate::platform::bytecode::Bytecode;
use crate::platform::crypto::{
    CertificateDer, CertificatePem, Crypto, Pkcs12Der, Pkcs12Pem, Pkcs7Der, Pkcs7Pem,
    PrivateKeyDer, PrivateKeyPem, PrivateKeyPgp, PrivateKeySsh, PrivateKeyTss2, PublicKeyDer,
    PublicKeyPem, PublicKeyPgp, PublicKeySsh, PublicKeyTss2,
};
use crate::platform::docker::{DockerConfig, DockerShadow};
use crate::platform::efi::{
    EFIAmdMicrocode, EFIFirmwareImage, EFIIntelMicrocode, EFIModule, EFIRawSection, EFIStandalone,
    EFIVariable,
};
use crate::platform::git::GitDiff;
use crate::platform::java::JavaArchive;
use crate::platform::linux::LinuxKernel;
use crate::platform::optee::OPTEEKernel;
use crate::platform::posix::{PosixBinary, PosixFirmwareImage};
use crate::platform::python::PythonPackage;
use crate::platform::secrets::{Generic as GenericSecret, Secret};
use crate::platform::source::{
    CLikeHeader, CPlusPlus, Html, Java, JavaScript, Json, Julia, Lisp, Lua, Ocaml, Perl, Php,
    Plaintext, PosixLikeShellScript, Python, Rlang, Ruby, SourceCode, Xml, Yaml, C,
};
use crate::platform::windows::WindowsBinary;
use crate::types::common::AttributeMap;
use crate::util::{BytesOrMapping, SharedBytesOrMapping};
use thiserror::Error;
use zip::ZipArchive;

pub mod builder;
pub mod meta;
pub mod platform;
mod util;

use meta::{
    BA2ComponentAttributes, BA2ComponentMetadata, BA2ComponentMetadataSource, BA2Metadata,
    BA2MetadataError,
};
use platform::common::PrimaryComponents;

// NOTE:
// We are doing this to maintain compatibility until all downstream
// crates switch to use BA2Loader.
//
pub type FirmwareLoaderConfig = BA2LoaderConfig;
pub type FirmwareLoaderError = BA2LoaderError;
pub type FirmwareLoader<'a> = BA2Loader<'a>;

pub type BA2ArchiveReader<'a> = ZipArchive<Cursor<SharedBytesOrMapping<'a>>>;

#[ouroboros::self_referencing]
struct BA2ComponentFileReader<'a> {
    archive: BA2ArchiveReader<'a>,
    #[borrows(mut archive)]
    #[covariant]
    component: Box<dyn Read + 'this>,
}

pub struct BA2ComponentReader<'a, 'b> {
    meta: &'b BA2ComponentMetadata,
    reader: BA2ComponentFileReader<'a>,
}

impl<'a, 'b> BA2ComponentReader<'a, 'b> {
    fn new(meta: &'b BA2ComponentMetadata, reader: BA2ComponentFileReader<'a>) -> Self {
        Self { meta, reader }
    }

    pub fn id(&self) -> Uuid {
        self.meta.id()
    }

    pub fn meta(&self) -> &BA2ComponentMetadata {
        self.meta
    }
}

impl<'a, 'b> Read for BA2ComponentReader<'a, 'b> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.with_component_mut(|reader| reader.read(buf))
    }
}

#[derive(Error, Debug)]
pub enum BA2LoaderError {
    #[error("component could not be unpacked: {0}")]
    Archive(#[from] zip::result::ZipError),
    #[error("component `{0}` not found")]
    ComponentNotFound(Uuid),
    #[error("component dependency with `{0}` and `{1}` invalid: {2}")]
    Dependency(Uuid, Uuid, SourceError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("could not construct package metadata: {0}")]
    Package(#[from] PackageError),
    #[error("partitioned archives are not supported: supply the complete BA2 archive instead")]
    PartitionedArchiveNotSupported,
    #[error("metadata could not be decompressed: {0}")]
    MetaDecompressionError(std::io::Error),
    #[error("metadata could not be deserialised: {0}")]
    MetaNotDeserialised(#[from] BA2MetadataError),
    #[error("metadata could not be found")]
    MetaNotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BA2LoaderConfig {
    pub ignore_missing_components: bool,
    pub package_identifier: Option<Uuid>,
    pub mark_primary_components: bool,
    pub load_partitioned_archives: bool,
    pub attributes: AttributeMap,
}

impl Default for BA2LoaderConfig {
    fn default() -> Self {
        Self {
            ignore_missing_components: false,
            package_identifier: None,
            mark_primary_components: true,
            load_partitioned_archives: true,
            attributes: AttributeMap::default(),
        }
    }
}

impl BA2LoaderConfig {
    pub fn with_package_identifier(mut self, id: Uuid) -> Self {
        self.package_identifier = Some(id);
        self
    }
}

pub struct BA2Loader<'a> {
    config: BA2LoaderConfig,
    archive: BA2ArchiveReader<'a>,
    package: Package,
    metadata: BA2Metadata,
    dependencies: PackageDependencyGraph,
}

impl<'a> BA2Loader<'a> {
    pub fn from_bytes(bytes: impl Into<Cow<'a, [u8]>>) -> Result<Self, BA2LoaderError> {
        Self::from_bytes_with(bytes, None)
    }

    pub fn from_bytes_with(
        bytes: impl Into<Cow<'a, [u8]>>,
        config: impl Into<Option<BA2LoaderConfig>>,
    ) -> Result<Self, BA2LoaderError> {
        Self::from_bytes_or_file(
            BytesOrMapping::from_bytes(bytes),
            config.into().unwrap_or_default(),
        )
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, BA2LoaderError> {
        let path = path.as_ref();
        let mut slf = Self::from_file_with(path, None)?;
        slf.package.set_path(path.to_string_lossy());
        Ok(slf)
    }

    pub fn from_file_with(
        path: impl AsRef<Path>,
        config: impl Into<Option<BA2LoaderConfig>>,
    ) -> Result<Self, BA2LoaderError> {
        let path = path.as_ref();
        let mut slf = Self::from_bytes_or_file(
            BytesOrMapping::from_file(path).map_err(BA2LoaderError::Io)?,
            config.into().unwrap_or_default(),
        )?;
        slf.package.set_path(path.to_string_lossy());
        Ok(slf)
    }

    fn check_supported_meta(
        meta: BA2Metadata,
        config: &BA2LoaderConfig,
    ) -> Result<BA2Metadata, BA2LoaderError> {
        if !config.load_partitioned_archives && meta.is_partitioned() {
            return Err(BA2LoaderError::PartitionedArchiveNotSupported);
        }
        Ok(meta)
    }

    fn unpack_meta<R>(
        archive: &mut ZipArchive<R>,
        config: &BA2LoaderConfig,
    ) -> Result<BA2Metadata, BA2LoaderError>
    where
        R: Read + Seek,
    {
        if let Ok(meta) = archive.by_name("meta.json") {
            return Self::check_supported_meta(
                BA2Metadata::from_reader_with(meta, config.package_identifier)?,
                config,
            );
        }

        let metaz = archive
            .by_name("meta.json.zstd")
            .map_err(|_| BA2LoaderError::MetaNotFound)?;

        Self::check_supported_meta(
            BA2Metadata::from_reader_with(
                zstd::Decoder::new(metaz).map_err(BA2LoaderError::MetaDecompressionError)?,
                config.package_identifier,
            )?,
            config,
        )
    }

    pub fn is_ba2(path: impl AsRef<Path>) -> Result<bool, BA2LoaderError> {
        let mut file = File::open(path)?;

        let mut buffer = [0; 4];
        file.read_exact(&mut buffer)?;

        if &buffer == b"PK\x03\x04" {
            let archive = ZipArchive::new(file)?;

            // `index_for_name` should be faster than `by_name`
            let contains_meta = archive.index_for_name("meta.json").is_some()
                || archive.index_for_name("meta.json.zstd").is_some();

            return Ok(contains_meta);
        }

        Ok(false)
    }

    fn from_bytes_or_file(
        mapping: BytesOrMapping<'a>,
        config: BA2LoaderConfig,
    ) -> Result<Self, BA2LoaderError> {
        tracing::debug!("decompressing firmware package");

        let bytes = mapping.into_shared();

        let mut archive = ZipArchive::new(Cursor::new(bytes.clone()))?;
        let mut metadata = Self::unpack_meta(&mut archive, &config)?;
        let mut dependencies = PackageDependencyGraph::new();

        let add_entity = |dependencies: &mut PackageDependencyGraph,
                          metadata: &BA2Metadata,
                          id: Uuid|
         -> Result<(), BA2LoaderError> {
            use BA2ComponentAttributes as A;

            let component = metadata
                .by_uuid(&id)
                .ok_or(BA2LoaderError::ComponentNotFound(id))?;

            match component.attributes() {
                A::AndroidPackage(_) => {
                    dependencies.add_entity::<AndroidPackage>(id);
                }

                A::EFIModulePE(_) | A::EFIModuleTE(_) => {
                    dependencies.add_entity::<EFIModule>(id);
                }
                A::EFIStandalonePE(_) | A::EFIStandaloneTE(_) => {
                    dependencies.add_entity::<EFIStandalone>(id);
                }
                A::EFIAmdMicrocode(_) => {
                    dependencies.add_entity::<EFIAmdMicrocode>(id);
                }
                A::EFIIntelMicrocode(_) => {
                    dependencies.add_entity::<EFIIntelMicrocode>(id);
                }
                A::EFIVariable(_) => {
                    dependencies.add_entity::<EFIVariable>(id);
                }
                A::EFIRawSection(_) => {
                    dependencies.add_entity::<EFIRawSection>(id);
                }
                A::EFIFirmwareImage(_) => {
                    dependencies.add_entity::<EFIFirmwareImage>(id);
                }

                A::JavaArchive(_) => {
                    dependencies.add_entity::<JavaArchive>(id);
                }

                A::LinuxKernel(_) => {
                    dependencies.add_entity::<LinuxKernel>(id);
                }

                A::OPTEEKernel(_) => {
                    dependencies.add_entity::<OPTEEKernel>(id);
                }

                A::PosixELF(_) => {
                    dependencies.add_entity::<PosixBinary>(id);
                }
                A::PosixFirmwareImage(_) => {
                    dependencies.add_entity::<PosixFirmwareImage>(id);
                }

                A::PythonPackage(_) => {
                    dependencies.add_entity::<PythonPackage>(id);
                }

                A::SecretGeneric(_) => {
                    dependencies.add_entity::<Secret<GenericSecret>>(id);
                }

                A::SourceC(_) => {
                    dependencies.add_entity::<SourceCode<C>>(id);
                }
                A::SourceCLikeHeader(_) => {
                    dependencies.add_entity::<SourceCode<CLikeHeader>>(id);
                }
                A::SourceCPlusPlus(_) => {
                    dependencies.add_entity::<SourceCode<CPlusPlus>>(id);
                }
                A::SourceHtml(_) => {
                    dependencies.add_entity::<SourceCode<Html>>(id);
                }
                A::SourceJava(_) => {
                    dependencies.add_entity::<SourceCode<Java>>(id);
                }
                A::SourceJavaScript(_) => {
                    dependencies.add_entity::<SourceCode<JavaScript>>(id);
                }
                A::SourceJson(_) => {
                    dependencies.add_entity::<SourceCode<Json>>(id);
                }
                A::SourceJulia(_) => {
                    dependencies.add_entity::<SourceCode<Julia>>(id);
                }
                A::SourceLisp(_) => {
                    dependencies.add_entity::<SourceCode<Lisp>>(id);
                }
                A::SourceLua(_) => {
                    dependencies.add_entity::<SourceCode<Lua>>(id);
                }
                A::SourceOcaml(_) => {
                    dependencies.add_entity::<SourceCode<Ocaml>>(id);
                }
                A::SourcePerl(_) => {
                    dependencies.add_entity::<SourceCode<Perl>>(id);
                }
                A::SourcePhp(_) => {
                    dependencies.add_entity::<SourceCode<Php>>(id);
                }
                A::SourcePlaintext(_) => {
                    dependencies.add_entity::<SourceCode<Plaintext>>(id);
                }
                A::SourcePosixLikeShellScript(_) => {
                    dependencies.add_entity::<SourceCode<PosixLikeShellScript>>(id);
                }
                A::SourcePython(_) => {
                    dependencies.add_entity::<SourceCode<Python>>(id);
                }
                A::SourceRlang(_) => {
                    dependencies.add_entity::<SourceCode<Rlang>>(id);
                }
                A::SourceRuby(_) => {
                    dependencies.add_entity::<SourceCode<Ruby>>(id);
                }
                A::SourceXml(_) => {
                    dependencies.add_entity::<SourceCode<Xml>>(id);
                }
                A::SourceYaml(_) => {
                    dependencies.add_entity::<SourceCode<Yaml>>(id);
                }

                A::BytecodeJava(_) => {
                    dependencies.add_entity::<Bytecode<Java>>(id);
                }
                A::BytecodeLua(_) => {
                    dependencies.add_entity::<Bytecode<Lua>>(id);
                }
                A::BytecodePython(_) => {
                    dependencies.add_entity::<Bytecode<Python>>(id);
                }

                A::CryptoCertificateDer(_) => {
                    dependencies.add_entity::<Crypto<CertificateDer>>(id);
                }
                A::CryptoCertificatePem(_) => {
                    dependencies.add_entity::<Crypto<CertificatePem>>(id);
                }

                A::CryptoPkcs7Der(_) => {
                    dependencies.add_entity::<Crypto<Pkcs7Der>>(id);
                }
                A::CryptoPkcs7Pem(_) => {
                    dependencies.add_entity::<Crypto<Pkcs7Pem>>(id);
                }

                A::CryptoPkcs12Der(_) => {
                    dependencies.add_entity::<Crypto<Pkcs12Der>>(id);
                }
                A::CryptoPkcs12Pem(_) => {
                    dependencies.add_entity::<Crypto<Pkcs12Pem>>(id);
                }

                A::CryptoPrivateKeyDer(_) => {
                    dependencies.add_entity::<Crypto<PrivateKeyDer>>(id);
                }
                A::CryptoPrivateKeyPem(_) => {
                    dependencies.add_entity::<Crypto<PrivateKeyPem>>(id);
                }
                A::CryptoPrivateKeyPgp(_) => {
                    dependencies.add_entity::<Crypto<PrivateKeyPgp>>(id);
                }
                A::CryptoPrivateKeySsh(_) => {
                    dependencies.add_entity::<Crypto<PrivateKeySsh>>(id);
                }
                A::CryptoPrivateKeyTss2(_) => {
                    dependencies.add_entity::<Crypto<PrivateKeyTss2>>(id);
                }

                A::CryptoPublicKeyDer(_) => {
                    dependencies.add_entity::<Crypto<PublicKeyDer>>(id);
                }
                A::CryptoPublicKeyPem(_) => {
                    dependencies.add_entity::<Crypto<PublicKeyPem>>(id);
                }
                A::CryptoPublicKeyPgp(_) => {
                    dependencies.add_entity::<Crypto<PublicKeyPgp>>(id);
                }
                A::CryptoPublicKeySsh(_) => {
                    dependencies.add_entity::<Crypto<PublicKeySsh>>(id);
                }
                A::CryptoPublicKeyTss2(_) => {
                    dependencies.add_entity::<Crypto<PublicKeyTss2>>(id);
                }

                A::GitDiff(_) => {
                    dependencies.add_entity::<GitDiff>(id);
                }

                A::DockerConfig(_) => {
                    dependencies.add_entity::<DockerConfig>(id);
                }
                A::DockerShadow(_) => {
                    dependencies.add_entity::<DockerShadow>(id);
                }

                A::WindowsPE(_) => {
                    dependencies.add_entity::<WindowsBinary>(id);
                }

                _ => {
                    // NOTE:
                    // Previously we avoided adding unsupported components, however, it's sometimes
                    // useful to understand how analysable component relate to unsupported ones.
                    //
                    tracing::debug!("adding unsupported component dependency: {id}");
                    dependencies.add_entity_with_platform(id, component.kind());
                }
            }
            Ok(())
        };

        // add all analysable entities
        for component in metadata.components() {
            add_entity(&mut dependencies, &metadata, component.id())?;
        }

        // add all relations
        for (source, target, kind) in metadata.dependencies() {
            dependencies
                .add_dependency(source, target, kind)
                .map_err(|e| BA2LoaderError::Dependency(source, target, e))?;
        }

        // mark primary components for deduplication (in versions >=2
        // marking has been done)
        if config.mark_primary_components && metadata.is_v1() {
            let mut seen = PrimaryComponents::new();

            for entity in metadata.components_mut() {
                let id = entity.id();
                let platform = entity.kind();

                let (gid, pid) = seen.get_or_insert_with_full(id, &*entity, platform);

                // NOTE: we set to "None" to ensure we do not encounter unexpected behaviour
                // if the primary component was previously set by a different scheme.
                entity.set_primary_component_id(if pid != id { Some(pid) } else { None });
                entity.set_global_component_id(gid);
            }
        }

        if metadata.version() < 3 {
            // ensure all global identifiers are set
            let mut builder = ComponentIdentityBuilder::new();
            for entity in metadata.components_mut() {
                if entity.global_component_id().is_none() {
                    let gid = entity.compute_identity_with(&mut builder);
                    entity.set_global_component_id(gid);
                }
            }
        }

        let mut package = PackageBuilder::new()
            .with_id(metadata.id())
            .with_hashes(PackageHashes::new(bytes))
            .build()
            .map_err(BA2LoaderError::Package)?;

        // set additional attributes on the package from the metadata
        package.set_attr("environment", metadata.environment());

        Ok(BA2Loader {
            archive,
            config,
            package,
            metadata,
            dependencies,
        })
    }

    pub fn meta(&self) -> &BA2Metadata {
        &self.metadata
    }

    pub fn into_meta(self) -> BA2Metadata {
        self.metadata
    }

    pub fn archive(&self) -> &BA2ArchiveReader {
        &self.archive
    }

    pub fn upgrade(&mut self) -> bool {
        self.metadata.upgrade()
    }

    pub fn get_by_path(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<PackageComponentData<'a>, PipelineError> {
        let path = path.as_ref();
        let Some(meta) = self.metadata.by_path(path) else {
            return Err(PipelineError::source_with(format!(
                "could not load `{}`: not found in package",
                path.display()
            )));
        };
        self.get_by_uuid(meta.id())
    }

    pub fn get_by_uuid(&self, id: Uuid) -> Result<PackageComponentData<'a>, PipelineError> {
        let Some(meta) = self.metadata.by_uuid(&id) else {
            return Err(PipelineError::source_with(format!(
                "could not load `{id}`: not found in package"
            )));
        };

        let Some(path) = meta.container_path() else {
            return Err(PipelineError::source_with(format!(
                "could not load `{id}`: component has no associated data"
            )));
        };

        let Some(platform) = meta.platform() else {
            return Err(PipelineError::source_with(format!(
                "could not load `{id}` (`{path}`): no platform information",
            )));
        };

        let mut archive = self.archive.clone();

        let component = match archive.by_name(path) {
            Ok(component) => component,
            Err(e) => {
                return Err(PipelineError::source_with(format!(
                    "could not load `{id}` (`{path}`) from package: {e}",
                )))
            }
        };

        let bytes = zstd::stream::decode_all(component).map_err(|e| {
            PipelineError::source_with(format!(
                "could not load `{id}` (`{path}`) from package: {e}",
            ))
        })?;

        Ok(PackageComponentData::new(
            id,
            Component::try_from(meta)
                .map_err(PipelineError::source)?
                .with_package_id(self.package.id()),
            bytes,
            platform,
        )
        .with_package(self.package.id()))
    }

    pub fn read_by_path<'b>(
        &'b self,
        path: impl AsRef<Path>,
        decompress: bool,
    ) -> Result<BA2ComponentReader<'a, 'b>, PipelineError> {
        let path = path.as_ref();
        let Some(meta) = self.metadata.by_path(path) else {
            return Err(PipelineError::source_with(format!(
                "could not load `{}`: not found in package",
                path.display()
            )));
        };
        self.read_by_uuid(meta.id(), decompress)
    }

    pub fn read_by_uuid<'b>(
        &'b self,
        id: Uuid,
        decompress: bool,
    ) -> Result<BA2ComponentReader<'a, 'b>, PipelineError> {
        let Some(meta) = self.metadata.by_uuid(&id) else {
            return Err(PipelineError::source_with(format!(
                "could not load `{id}`: not found in package"
            )));
        };

        let Some(path) = meta.container_path() else {
            return Err(PipelineError::source_with(format!(
                "could not load `{id}`: component has no associated data"
            )));
        };

        let archive = self.archive.clone();

        Ok(BA2ComponentReader::new(
            meta,
            BA2ComponentFileReader::try_new(archive, |archive| -> Result<_, PipelineError> {
                let component = archive.by_name(path).map_err(|e| {
                    PipelineError::source_with(format!(
                        "could not load `{id}` (`{path}`) from package: {e}",
                    ))
                })?;

                let reader = if decompress {
                    Box::new(zstd::stream::Decoder::new(component).map_err(|e| {
                        PipelineError::source_with(format!(
                            "could not load `{id}` (`{path}`) from package: {e}",
                        ))
                    })?) as Box<dyn Read>
                } else {
                    Box::new(component) as Box<dyn Read>
                };

                Ok(reader)
            })?,
        ))
    }

    pub fn load_by_path(
        &self,
        loader: &ComponentLoader,
        path: impl AsRef<Path>,
    ) -> Result<LoadedComponent, PipelineError> {
        let path = path.as_ref();
        let (id, bytes, platform) = self.get_by_path(path)?.into_parts();
        loader
            .load_with(id, bytes, platform.into_owned())
            .map_err(|e| {
                PipelineError::source_with(format!(
                    "could not load `{id}` (`{}`) from package: {e}",
                    path.display(),
                ))
            })
    }

    pub fn load_by_uuid(
        &self,
        loader: &ComponentLoader,
        id: Uuid,
    ) -> Result<LoadedComponent, PipelineError> {
        let (id, bytes, platform) = self.get_by_uuid(id)?.into_parts();
        loader
            .load_with(id, bytes, platform.into_owned())
            .map_err(|e| {
                PipelineError::source_with(format!("could not load `{id}` from package: {e}",))
            })
    }
}

impl BA2ComponentMetadataSource for BA2Loader<'_> {
    fn component_meta_by_uuid<'a>(
        &'a self,
        pid: &Uuid,
        cid: &Uuid,
    ) -> Result<Option<Cow<'a, BA2ComponentMetadata>>, PipelineError> {
        self.meta().component_meta_by_uuid(pid, cid)
    }
}

#[async_trait::async_trait]
impl<'source> Source for BA2Loader<'source> {
    async fn fetch_component_if<'a>(
        &'a self,
        component: PackageComponentItem,
        filter: AnalysisGroupFilter<'_>,
    ) -> Result<Option<PackageComponentData<'a>>, PipelineError> {
        if component.package().id() != self.package.id() {
            return Ok(None);
        }

        let id = component.id();
        let pid = component.package().id();

        let Some(meta) = self.metadata.by_uuid(&id) else {
            return Ok(None);
        };

        // NOTE: we only fetch components that are in the current partition
        if self.metadata.partition_id() != meta.partition_id() {
            return Ok(None);
        }

        let Some(platform) = meta.platform() else {
            return Ok(None);
        };

        if !filter.should_analyse(&platform) {
            return Ok(None);
        }

        match meta.container_path() {
            Some(path) => {
                // NOTE: the clone below is cheap; the reader is an Arc + u64.
                let mut archive = self.archive.clone();

                let component = match archive.by_name(path) {
                    Ok(component) => component,
                    Err(_) if self.config.ignore_missing_components => return Ok(None),
                    Err(e) => {
                        return Err(PipelineError::source_with(format!(
                            "could not extract `{path}` from package: {e}",
                        )))
                    }
                };

                let bytes = zstd::stream::decode_all(component).map_err(PipelineError::source)?;

                Ok(Some(
                    PackageComponentData::new(
                        id,
                        Component::try_from(meta)
                            .map_err(PipelineError::source)?
                            .with_package_id(pid),
                        bytes,
                        platform,
                    )
                    .with_package(pid),
                ))
            }
            None => {
                // NOTE: this is pure meta-data; provide no bytes, but allow it to load
                Ok(Some(
                    PackageComponentData::new(
                        id,
                        Component::try_from(meta)
                            .map_err(PipelineError::source)?
                            .with_package_id(pid),
                        &[][..],
                        platform,
                    )
                    .with_package(pid),
                ))
            }
        }
    }

    async fn fetch_package<'a>(
        &'a self,
        pid: PackageItem,
    ) -> Result<Option<PackageData<'a>>, PipelineError> {
        if pid.id() != self.package.id() {
            return Ok(None);
        }

        let package = PackageData::new(self.package.clone(), Cow::Borrowed(&self.dependencies));

        Ok(Some(package))
    }

    async fn stream_packages(&self, queue: PackageItemQueue) -> Result<(), PipelineError> {
        queue
            .send_async(PackageItem::new(self.package.id()))
            .await
            .map_err(PipelineError::source)
    }

    async fn stream_package_components(
        &self,
        pid: PackageItem,
        analysis_groups: PipelineAnalysisGroups,
        queue: PackageComponentItemQueue,
    ) -> Result<(), PipelineError> {
        if pid.id() != self.package.id() {
            return Ok(());
        }

        let partition_id = self.metadata.partition_id();
        let components = self.metadata.components_map();

        // NOTE: we filter components that are not in the current partition to
        // avoid producing duplicate properties.
        for (&uuid, meta) in self.dependencies.entities().filter(|(id, meta)| {
            partition_id == components[id].partition_id() && analysis_groups.should_analyse(meta)
        }) {
            queue
                .send_async(PackageComponentItem::new(uuid, pid.clone(), meta))
                .await
                .map_err(PipelineError::source)?;
        }

        Ok(())
    }
}

pub trait BA2PackageLoader<'a>: BA2ComponentMetadataSource + Source + Sized {
    fn from_file_and_config(
        path: impl AsRef<Path>,
        config: impl Into<Option<BA2LoaderConfig>>,
    ) -> Result<Self, PipelineError>;

    fn should_analyse(path: impl AsRef<Path>) -> bool;

    fn package_by_uuid<'loader>(&'loader self, pid: &Uuid) -> Option<Cow<'loader, Package>>;

    fn component_by_uuid(
        &self,
        pid: &Uuid,
        cid: &Uuid,
    ) -> Result<Option<PackageComponentData>, PipelineError>;

    fn components<'loader>(&'loader self, pid: &Uuid) -> impl Iterator<Item = Uuid> + 'loader;
}

impl<'a> BA2PackageLoader<'a> for BA2Loader<'a> {
    fn from_file_and_config(
        path: impl AsRef<Path>,
        config: impl Into<Option<BA2LoaderConfig>>,
    ) -> Result<Self, PipelineError> {
        Self::from_file_with(path, config).map_err(PipelineError::source)
    }

    fn should_analyse(path: impl AsRef<Path>) -> bool {
        matches!(path.as_ref().extension(), Some(ext) if ext == "ba2")
    }

    fn package_by_uuid<'loader>(&'loader self, pid: &Uuid) -> Option<Cow<'loader, Package>> {
        if *pid == self.package.id() {
            Some(Cow::Borrowed(&self.package))
        } else {
            None
        }
    }

    fn component_by_uuid(
        &self,
        pid: &Uuid,
        cid: &Uuid,
    ) -> Result<Option<PackageComponentData<'a>>, PipelineError> {
        if *pid != self.package.id() {
            return Ok(None);
        }

        self.get_by_uuid(*cid)
            .map(Some)
            .map_err(PipelineError::source)
    }

    fn components<'loader>(&'loader self, _pid: &Uuid) -> impl Iterator<Item = Uuid> + 'loader {
        self.meta().components().map(|meta| meta.id())
    }
}

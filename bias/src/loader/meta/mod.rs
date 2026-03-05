use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use bias_core::prelude::graph::graph::DiGraph;
use bias_core::prelude::*;
use hex::ToHex;
use serde::de::{DeserializeSeed, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::component::{
    Component, ComponentBuilder, ComponentError, ComponentHashes, ComponentIdentity,
    ComponentIdentityBuilder, HasComponentIdentity,
};
use crate::loader::platform::common::PrimaryComponents;
use crate::loader::util::AsArchStr;
use crate::pipeline::source::PackageDependencyKind;
use crate::pipeline::PipelineError;
use crate::platform::android::{AndroidPackage, AndroidPackageAttribute};
use crate::platform::bytecode::{Bytecode, BytecodeAttribute};
use crate::platform::common::{BinaryLoaderMetadata, ComponentArch, PlatformAttributeMap};
use crate::platform::crypto::{
    CertificateDer, CertificatePem, Crypto, CryptoAttribute, Pkcs12Der, Pkcs12Pem, Pkcs7Der,
    Pkcs7Pem, PrivateKeyDer, PrivateKeyPem, PrivateKeyPgp, PrivateKeySsh, PrivateKeyTss2,
    PublicKeyDer, PublicKeyPem, PublicKeyPgp, PublicKeySsh, PublicKeyTss2,
};
use crate::platform::docker::{
    DockerConfig, DockerConfigAttribute, DockerShadow, DockerShadowAttribute,
};
use crate::platform::efi::{
    EFIAmdMicrocode, EFIAmdMicrocodeAttribute, EFIFirmwareAttribute, EFIFirmwareImage,
    EFIIntelMicrocode, EFIIntelMicrocodeAttribute, EFIModule, EFIModuleAttribute, EFIRawSection,
    EFIRawSectionAttribute, EFIStandalone, EFIStandaloneAttribute, EFIVariable,
    EFIVariableAttribute,
};
use crate::platform::git::{GitDiff, GitDiffAttribute};
use crate::platform::java::{JavaArchive, JavaArchiveAttribute};
use crate::platform::link::{HardLink, Link, LinkAttribute, SoftLink};
use crate::platform::linux::{LinuxKernel, LinuxKernelAttribute};
use crate::platform::optee::{OPTEEKernel, OPTEEKernelAttribute};
use crate::platform::posix::{
    PosixBinary, PosixBinaryAttribute, PosixFirmwareAttribute, PosixFirmwareImage,
};
use crate::platform::python::{PythonPackage, PythonPackageAttribute};
use crate::platform::secrets::{Generic as GenericSecret, Secret, SecretAttribute};
use crate::platform::source::{
    CLikeHeader, CPlusPlus, Html, Java, JavaScript, Json, Julia, Lisp, Lua, Ocaml, Perl, Php,
    Plaintext, PosixLikeShellScript, Python, Rlang, Ruby, SourceCode, SourceCodeAttribute, Xml,
    Yaml, C,
};
use crate::platform::windows::{WindowsBinary, WindowsBinaryAttribute};
use crate::platform::{Platform, PlatformBuilder};

pub mod android;
pub mod bytecode;
pub mod crypto;
pub mod docker;
pub mod efi;
pub mod git;
pub mod java;
pub mod linux;
pub mod optee;
pub mod posix;
pub mod python;
pub mod secrets;
pub mod source;
pub mod util;
pub mod windows;

pub use crate::pipeline::types::component::{
    ComponentError as BA2ComponentMetadataError, ComponentHashes as BA2ComponentHashes,
};
pub use crate::pipeline::types::standards::EnvironmentKind;

pub use android::AndroidPackageAttributes;
pub use bytecode::BytecodeAttributes;
pub use crypto::CryptoAttributes;
pub use docker::{DockerConfigAttributes, DockerShadowAttributes};
pub use efi::{
    EFIAmdMicrocodeAttributes, EFIFirmwareImageAttributes, EFIIntelMicrocodeAttributes,
    EFIModuleAttributes, EFIRawSectionAttributes, EFIStandaloneAttributes, EFIVariableAttributes,
};
pub use git::GitDiffAttributes;
pub use java::JavaArchiveAttributes;
pub use linux::LinuxKernelAttributes;
pub use optee::OPTEEKernelAttributes;
pub use posix::{PosixELFAttributes, PosixFirmwareImageAttributes};
pub use python::PythonPackageAttributes;
pub use secrets::SecretAttributes;
pub use source::SourceCodeAttributes;
pub use windows::WindowsPEAttributes;

pub type FirmwareDependencies = BA2Dependencies;
pub type FirmwareMetadata = BA2Metadata;
pub type FirmwareMetadataError = BA2MetadataError;
pub type FirmwareComponentAttributes = BA2ComponentAttributes;
pub type FirmwareComponentMetadata = BA2ComponentMetadata;

#[derive(Debug, Error)]
pub enum BA2MetadataError {
    #[error(transparent)]
    Deserialise(serde_json::Error),
    #[error("component with ID {0} does not exist")]
    InvalidComponent(Uuid),
    #[error(transparent)]
    Io(std::io::Error),
    #[error("partitioning is not supported by archive version {0}")]
    PartitionedArchiveNotSupported(u32),
    #[error("specifying an execution environment is not supported by archive version {0}")]
    EnvironmentNotSupported(u32),
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum BA2ComponentAttributes {
    #[serde(rename = "android.package")]
    AndroidPackage(AndroidPackageAttributes),

    #[serde(rename = "firmware.uefi.PE")]
    EFIModulePE(EFIModuleAttributes),
    #[serde(rename = "firmware.uefi.TE")]
    EFIModuleTE(EFIModuleAttributes),
    #[serde(rename = "firmware.uefi.standalone.PE")]
    EFIStandalonePE(EFIStandaloneAttributes),
    #[serde(rename = "firmware.uefi.standalone.TE")]
    EFIStandaloneTE(EFIStandaloneAttributes),
    #[serde(rename = "firmware.uefi.microcode.amd")]
    EFIAmdMicrocode(EFIAmdMicrocodeAttributes),
    #[serde(
        rename = "firmware.uefi.microcode.intel",
        // in older ba2 firmware.uefi.microcode is Intel microcode kind
        alias = "firmware.uefi.microcode"
    )]
    EFIIntelMicrocode(EFIIntelMicrocodeAttributes),
    #[serde(rename = "firmware.uefi.nvram-variable")]
    EFIVariable(EFIVariableAttributes),
    #[serde(rename = "firmware.uefi.raw-section")]
    EFIRawSection(EFIRawSectionAttributes),
    #[serde(rename = "firmware.uefi")]
    EFIFirmwareImage(EFIFirmwareImageAttributes),
    #[serde(
        rename = "firmware.uefi.Unsupported",
        alias = "firmware.uefi.unsupported",
        alias = "firmware.uefi.lib"
    )]
    EFIUnsupported,

    #[serde(rename = "java.archive")]
    JavaArchive(JavaArchiveAttributes),

    #[serde(rename = "linux.kernel", alias = "firmware.linux.kernel")]
    LinuxKernel(LinuxKernelAttributes),

    #[serde(rename = "optee.kernel", alias = "firmware.optee.kernel")]
    OPTEEKernel(OPTEEKernelAttributes),

    #[serde(
        rename = "firmware.linux.ELF",
        alias = "firmware.posix.ELF",
        alias = "docker.linux.ELF",
        alias = "docker.posix.ELF",
        alias = "posix.ELF",
        alias = "generic.ELF"
    )]
    PosixELF(PosixELFAttributes),
    #[serde(rename = "firmware.linux", alias = "firmware.posix")]
    PosixFirmwareImage(PosixFirmwareImageAttributes),
    #[serde(
        rename = "firmware.linux.Unsupported",
        alias = "firmware.linux.unsupported",
        alias = "firmware.posix.Unsupported",
        alias = "firmware.posix.unsupported",
        alias = "linux.Unsupported",
        alias = "linux.unsupported",
        alias = "posix.Unsupported",
        alias = "posix.unsupported",
        alias = "posix.a",
        alias = "posix.ar",
        alias = "posix.lib"
    )]
    PosixUnsupported,

    #[serde(rename = "python.package")]
    PythonPackage(PythonPackageAttributes),

    #[serde(rename = "secret.generic")]
    SecretGeneric(SecretAttributes),

    #[serde(rename = "source.c", alias = "source.C")]
    SourceC(SourceCodeAttributes),
    #[serde(rename = "source.h")]
    SourceCLikeHeader(SourceCodeAttributes),
    #[serde(
        rename = "source.c++",
        alias = "source.C++",
        alias = "source.cpp",
        alias = "source.CPP",
        alias = "source.CPlusPlus"
    )]
    SourceCPlusPlus(SourceCodeAttributes),
    #[serde(rename = "source.html", alias = "source.HTML")]
    SourceHtml(SourceCodeAttributes),
    #[serde(rename = "source.java")]
    SourceJava(SourceCodeAttributes),
    #[serde(
        rename = "source.js",
        alias = "source.javascript",
        alias = "source.JavaScript"
    )]
    SourceJavaScript(SourceCodeAttributes),
    #[serde(rename = "source.json")]
    SourceJson(SourceCodeAttributes),
    #[serde(rename = "source.julia")]
    SourceJulia(SourceCodeAttributes),
    #[serde(rename = "source.lisp")]
    SourceLisp(SourceCodeAttributes),
    #[serde(rename = "source.lua")]
    SourceLua(SourceCodeAttributes),
    #[serde(rename = "source.ocaml")]
    SourceOcaml(SourceCodeAttributes),
    #[serde(rename = "source.perl")]
    SourcePerl(SourceCodeAttributes),
    #[serde(rename = "source.php")]
    SourcePhp(SourceCodeAttributes),
    #[serde(rename = "source.plaintext")]
    SourcePlaintext(SourceCodeAttributes),
    #[serde(rename = "source.posix.sh")]
    SourcePosixLikeShellScript(SourceCodeAttributes),
    #[serde(rename = "source.python")]
    SourcePython(SourceCodeAttributes),
    #[serde(rename = "source.rlang")]
    SourceRlang(SourceCodeAttributes),
    #[serde(rename = "source.ruby")]
    SourceRuby(SourceCodeAttributes),
    #[serde(rename = "source.xml")]
    SourceXml(SourceCodeAttributes),
    #[serde(rename = "source.yaml")]
    SourceYaml(SourceCodeAttributes),

    #[serde(rename = "bytecode.java")]
    BytecodeJava(BytecodeAttributes),
    #[serde(rename = "bytecode.lua")]
    BytecodeLua(BytecodeAttributes),
    #[serde(rename = "bytecode.python")]
    BytecodePython(BytecodeAttributes),

    #[serde(rename = "crypto.public-key.pem")]
    CryptoPublicKeyPem(CryptoAttributes),
    #[serde(rename = "crypto.public-key.der")]
    CryptoPublicKeyDer(CryptoAttributes),
    #[serde(rename = "crypto.public-key.pgp")]
    CryptoPublicKeyPgp(CryptoAttributes),
    #[serde(rename = "crypto.public-key.ssh")]
    CryptoPublicKeySsh(CryptoAttributes),
    #[serde(rename = "crypto.public-key.tss2")]
    CryptoPublicKeyTss2(CryptoAttributes),

    #[serde(rename = "crypto.private-key.pem")]
    CryptoPrivateKeyPem(CryptoAttributes),
    #[serde(rename = "crypto.private-key.der")]
    CryptoPrivateKeyDer(CryptoAttributes),
    #[serde(rename = "crypto.private-key.pgp")]
    CryptoPrivateKeyPgp(CryptoAttributes),
    #[serde(rename = "crypto.private-key.ssh")]
    CryptoPrivateKeySsh(CryptoAttributes),
    #[serde(rename = "crypto.private-key.tss2")]
    CryptoPrivateKeyTss2(CryptoAttributes),

    #[serde(rename = "crypto.certificate.pem")]
    CryptoCertificatePem(CryptoAttributes),
    #[serde(rename = "crypto.certificate.der")]
    CryptoCertificateDer(CryptoAttributes),

    #[serde(rename = "crypto.pkcs7.pem")]
    CryptoPkcs7Pem(CryptoAttributes),
    #[serde(rename = "crypto.pkcs7.der")]
    CryptoPkcs7Der(CryptoAttributes),

    #[serde(rename = "crypto.pkcs12.pem")]
    CryptoPkcs12Pem(CryptoAttributes),
    #[serde(rename = "crypto.pkcs12.der")]
    CryptoPkcs12Der(CryptoAttributes),

    #[serde(rename = "link.hard")]
    HardLink,
    #[serde(rename = "link.soft")]
    SoftLink,

    #[serde(rename = "git.diff")]
    GitDiff(GitDiffAttributes),

    #[serde(rename = "docker.config")]
    DockerConfig(DockerConfigAttributes),
    #[serde(rename = "docker.shadow")]
    DockerShadow(DockerShadowAttributes),

    #[serde(rename = "windows.PE", alias = "generic.PE")]
    WindowsPE(WindowsPEAttributes),

    #[serde(
        rename = "firmware.Unsupported",
        alias = "firmware.unsupported",
        alias = "docker.Unsupported",
        alias = "docker.unsupported",
        alias = "Unsupported",
        alias = "unsupported"
    )]
    Unsupported,
}

impl BA2ComponentAttributes {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::AndroidPackage(_) => "android.package",

            Self::EFIModulePE(_) => "firmware.uefi.PE",
            Self::EFIModuleTE(_) => "firmware.uefi.TE",
            Self::EFIStandalonePE(_) => "firmware.uefi.standalone.PE",
            Self::EFIStandaloneTE(_) => "firmware.uefi.standalone.TE",
            Self::EFIAmdMicrocode(_) => "firmware.uefi.microcode.amd",
            Self::EFIIntelMicrocode(_) => "firmware.uefi.microcode.intel",
            Self::EFIVariable(_) => "firmware.uefi.nvram-variable",
            Self::EFIRawSection(_) => "firmware.uefi.raw-section",

            Self::EFIFirmwareImage(_) => "firmware.uefi",
            Self::EFIUnsupported => "firmware.uefi.unsupported",

            Self::JavaArchive(_) => "java.archive",

            Self::LinuxKernel(_) => "linux.kernel",

            Self::OPTEEKernel(_) => "optee.kernel",

            Self::PosixELF(_) => "posix.ELF",
            Self::PosixFirmwareImage(_) => "firmware.posix",
            Self::PosixUnsupported => "posix.unsupported",

            Self::PythonPackage(_) => "python.package",

            Self::SecretGeneric(_) => "secret.generic",

            Self::SourceC(_) => "source.c",
            Self::SourceCLikeHeader(_) => "source.h",
            Self::SourceCPlusPlus(_) => "source.c++",
            Self::SourceHtml(_) => "source.html",
            Self::SourceJava(_) => "source.java",
            Self::SourceJavaScript(_) => "source.javascript",
            Self::SourceJson(_) => "source.json",
            Self::SourceJulia(_) => "source.julia",
            Self::SourceLisp(_) => "source.lisp",
            Self::SourceLua(_) => "source.lua",
            Self::SourceOcaml(_) => "source.ocaml",
            Self::SourcePerl(_) => "source.perl",
            Self::SourcePhp(_) => "source.php",
            Self::SourcePlaintext(_) => "source.plaintext",
            Self::SourcePosixLikeShellScript(_) => "source.posix.sh",
            Self::SourcePython(_) => "source.python",
            Self::SourceRlang(_) => "source.rlang",
            Self::SourceRuby(_) => "source.ruby",
            Self::SourceXml(_) => "source.xml",
            Self::SourceYaml(_) => "source.yaml",

            Self::BytecodeJava(_) => "bytecode.java",
            Self::BytecodeLua(_) => "bytecode.lua",
            Self::BytecodePython(_) => "bytecode.python",

            Self::CryptoPublicKeyPem(_) => "crypto.public-key.pem",
            Self::CryptoPublicKeyDer(_) => "crypto.public-key.der",
            Self::CryptoPublicKeyPgp(_) => "crypto.public-key.pgp",
            Self::CryptoPublicKeySsh(_) => "crypto.public-key.ssh",
            Self::CryptoPublicKeyTss2(_) => "crypto.public-key.tss2",

            Self::CryptoPrivateKeyPem(_) => "crypto.private-key.pem",
            Self::CryptoPrivateKeyDer(_) => "crypto.private-key.der",
            Self::CryptoPrivateKeyPgp(_) => "crypto.private-key.pgp",
            Self::CryptoPrivateKeySsh(_) => "crypto.private-key.ssh",
            Self::CryptoPrivateKeyTss2(_) => "crypto.private-key.tss2",

            Self::CryptoCertificatePem(_) => "crypto.certificate.pem",
            Self::CryptoCertificateDer(_) => "crypto.certificate.der",

            Self::CryptoPkcs7Pem(_) => "crypto.pkcs7.pem",
            Self::CryptoPkcs7Der(_) => "crypto.pkcs7.der",

            Self::CryptoPkcs12Pem(_) => "crypto.pkcs12.pem",
            Self::CryptoPkcs12Der(_) => "crypto.pkcs12.der",

            Self::HardLink => "link.hard",
            Self::SoftLink => "link.soft",

            Self::GitDiff(_) => "git.diff",

            Self::DockerConfig(_) => "docker.config",
            Self::DockerShadow(_) => "docker.shadow",

            Self::WindowsPE(_) => "windows.PE",

            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum BA2ComponentPlatformDetails<'a> {
    AndroidPackage(&'a AndroidPackageAttributes),
    EFIModule(&'a EFIModuleAttributes),
    EFIStandalone(&'a EFIStandaloneAttributes),
    EFIAmdMicrocode(&'a EFIAmdMicrocodeAttributes),
    EFIIntelMicrocode(&'a EFIIntelMicrocodeAttributes),
    EFIVariable(&'a EFIVariableAttributes),
    EFIRawSection(&'a EFIRawSectionAttributes),
    EFIFirmwareImage(&'a EFIFirmwareImageAttributes),
    JavaArchive(&'a JavaArchiveAttributes),
    LinuxKernel(&'a LinuxKernelAttributes),
    OPTEEKernel(&'a OPTEEKernelAttributes),
    PosixELF(&'a PosixELFAttributes),
    PosixFirmwareImage(&'a PosixFirmwareImageAttributes),
    PythonPackage(&'a PythonPackageAttributes),
    SecretGeneric(&'a SecretAttributes),
    SourceC(&'a SourceCodeAttributes),
    SourceCLikeHeader(&'a SourceCodeAttributes),
    SourceCPlusPlus(&'a SourceCodeAttributes),
    SourceHtml(&'a SourceCodeAttributes),
    SourceJava(&'a SourceCodeAttributes),
    SourceJavaScript(&'a SourceCodeAttributes),
    SourceJson(&'a SourceCodeAttributes),
    SourceJulia(&'a SourceCodeAttributes),
    SourceLisp(&'a SourceCodeAttributes),
    SourceLua(&'a SourceCodeAttributes),
    SourceOcaml(&'a SourceCodeAttributes),
    SourcePerl(&'a SourceCodeAttributes),
    SourcePhp(&'a SourceCodeAttributes),
    SourcePlaintext(&'a SourceCodeAttributes),
    SourcePosixLikeShellScript(&'a SourceCodeAttributes),
    SourcePython(&'a SourceCodeAttributes),
    SourceRlang(&'a SourceCodeAttributes),
    SourceRuby(&'a SourceCodeAttributes),
    SourceXml(&'a SourceCodeAttributes),
    SourceYaml(&'a SourceCodeAttributes),
    BytecodeJava(&'a BytecodeAttributes),
    BytecodeLua(&'a BytecodeAttributes),
    BytecodePython(&'a BytecodeAttributes),
    CryptoPublicKeyPem(&'a CryptoAttributes),
    CryptoPublicKeyDer(&'a CryptoAttributes),
    CryptoPublicKeyPgp(&'a CryptoAttributes),
    CryptoPublicKeySsh(&'a CryptoAttributes),
    CryptoPublicKeyTss2(&'a CryptoAttributes),
    CryptoPrivateKeyPem(&'a CryptoAttributes),
    CryptoPrivateKeyDer(&'a CryptoAttributes),
    CryptoPrivateKeyPgp(&'a CryptoAttributes),
    CryptoPrivateKeySsh(&'a CryptoAttributes),
    CryptoPrivateKeyTss2(&'a CryptoAttributes),
    CryptoCertificatePem(&'a CryptoAttributes),
    CryptoCertificateDer(&'a CryptoAttributes),
    CryptoPkcs7Pem(&'a CryptoAttributes),
    CryptoPkcs7Der(&'a CryptoAttributes),
    CryptoPkcs12Pem(&'a CryptoAttributes),
    CryptoPkcs12Der(&'a CryptoAttributes),
    GitDiff(&'a GitDiffAttributes),
    DockerConfig(&'a DockerConfigAttributes),
    DockerShadow(&'a DockerShadowAttributes),
    WindowsPE(&'a WindowsPEAttributes),
    NoAttributes {},
}

impl<'a> From<&'a BA2ComponentAttributes> for BA2ComponentPlatformDetails<'a> {
    fn from(value: &'a BA2ComponentAttributes) -> Self {
        use BA2ComponentAttributes as A;

        match value {
            A::AndroidPackage(a) => Self::AndroidPackage(a),
            A::EFIModulePE(a) | A::EFIModuleTE(a) => Self::EFIModule(a),
            A::EFIStandalonePE(a) | A::EFIStandaloneTE(a) => Self::EFIStandalone(a),
            A::EFIAmdMicrocode(a) => Self::EFIAmdMicrocode(a),
            A::EFIIntelMicrocode(a) => Self::EFIIntelMicrocode(a),
            A::EFIVariable(a) => Self::EFIVariable(a),
            A::EFIRawSection(a) => Self::EFIRawSection(a),
            A::EFIFirmwareImage(a) => Self::EFIFirmwareImage(a),
            A::JavaArchive(a) => Self::JavaArchive(a),
            A::LinuxKernel(a) => Self::LinuxKernel(a),
            A::OPTEEKernel(a) => Self::OPTEEKernel(a),
            A::PosixELF(a) => Self::PosixELF(a),
            A::PosixFirmwareImage(a) => Self::PosixFirmwareImage(a),
            A::PythonPackage(a) => Self::PythonPackage(a),
            A::SecretGeneric(a) => Self::SecretGeneric(a),
            A::SourceC(a) => Self::SourceC(a),
            A::SourceCLikeHeader(a) => Self::SourceCLikeHeader(a),
            A::SourceCPlusPlus(a) => Self::SourceCPlusPlus(a),
            A::SourceHtml(a) => Self::SourceHtml(a),
            A::SourceJava(a) => Self::SourceJava(a),
            A::SourceJavaScript(a) => Self::SourceJavaScript(a),
            A::SourceJson(a) => Self::SourceJson(a),
            A::SourceJulia(a) => Self::SourceJulia(a),
            A::SourceLisp(a) => Self::SourceLisp(a),
            A::SourceLua(a) => Self::SourceLua(a),
            A::SourceOcaml(a) => Self::SourceOcaml(a),
            A::SourcePerl(a) => Self::SourcePerl(a),
            A::SourcePhp(a) => Self::SourcePhp(a),
            A::SourcePlaintext(a) => Self::SourcePlaintext(a),
            A::SourcePosixLikeShellScript(a) => Self::SourcePosixLikeShellScript(a),
            A::SourcePython(a) => Self::SourcePython(a),
            A::SourceRlang(a) => Self::SourceRlang(a),
            A::SourceRuby(a) => Self::SourceRuby(a),
            A::SourceXml(a) => Self::SourceXml(a),
            A::SourceYaml(a) => Self::SourceYaml(a),
            A::BytecodeJava(a) => Self::BytecodeJava(a),
            A::BytecodeLua(a) => Self::BytecodeLua(a),
            A::BytecodePython(a) => Self::BytecodePython(a),
            A::CryptoPublicKeyPem(a) => Self::CryptoPublicKeyPem(a),
            A::CryptoPublicKeyDer(a) => Self::CryptoPublicKeyDer(a),
            A::CryptoPublicKeyPgp(a) => Self::CryptoPublicKeyPgp(a),
            A::CryptoPublicKeySsh(a) => Self::CryptoPublicKeySsh(a),
            A::CryptoPublicKeyTss2(a) => Self::CryptoPublicKeyTss2(a),
            A::CryptoPrivateKeyPem(a) => Self::CryptoPrivateKeyPem(a),
            A::CryptoPrivateKeyDer(a) => Self::CryptoPrivateKeyDer(a),
            A::CryptoPrivateKeyPgp(a) => Self::CryptoPrivateKeyPgp(a),
            A::CryptoPrivateKeySsh(a) => Self::CryptoPrivateKeySsh(a),
            A::CryptoPrivateKeyTss2(a) => Self::CryptoPrivateKeyTss2(a),
            A::CryptoCertificatePem(a) => Self::CryptoCertificatePem(a),
            A::CryptoCertificateDer(a) => Self::CryptoCertificateDer(a),
            A::CryptoPkcs7Pem(a) => Self::CryptoPkcs7Pem(a),
            A::CryptoPkcs7Der(a) => Self::CryptoPkcs7Der(a),
            A::CryptoPkcs12Pem(a) => Self::CryptoPkcs12Pem(a),
            A::CryptoPkcs12Der(a) => Self::CryptoPkcs12Der(a),
            A::GitDiff(a) => Self::GitDiff(a),
            A::DockerConfig(a) => Self::DockerConfig(a),
            A::DockerShadow(a) => Self::DockerShadow(a),
            A::WindowsPE(a) => Self::WindowsPE(a),
            // no attributes for links and unsupported kinds
            _ => Self::NoAttributes {},
        }
    }
}

#[derive(Debug, Clone)]
pub struct BA2ComponentMetadataBuilder {
    id: Option<Uuid>,
    partition_id: Option<u32>,
    name: Option<String>,
    meta: bool,
    path: Option<String>,
    virtual_path: Option<String>,
    global_component_id: Option<ComponentIdentity>,
    primary_component_id: Option<Uuid>,
    hashes: Option<BA2ComponentHashes>,
    attrs: BA2ComponentAttributes,
}

impl BA2ComponentMetadataBuilder {
    pub fn new(attrs: impl Into<BA2ComponentAttributes>) -> Self {
        Self {
            id: None,
            partition_id: None,
            name: None,
            meta: false,
            path: None,
            virtual_path: None,
            global_component_id: None,
            primary_component_id: None,
            hashes: None,
            attrs: attrs.into(),
        }
    }

    pub fn set_id(&mut self, id: impl Into<Uuid>) {
        self.id = Some(id.into());
    }

    pub fn with_id(mut self, id: impl Into<Uuid>) -> Self {
        self.set_id(id);
        self
    }

    pub fn set_partition_id(&mut self, id: u32) {
        self.partition_id = Some(id);
    }

    pub fn with_partition_id(mut self, id: u32) -> Self {
        self.set_partition_id(id);
        self
    }

    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = Some(name.into());
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.set_name(name);
        self
    }

    pub fn set_meta(&mut self, meta: bool) {
        self.meta = meta;
    }

    pub fn with_meta(mut self, meta: bool) -> Self {
        self.set_meta(meta);
        self
    }

    pub fn set_path(&mut self, path: impl Into<String>) {
        self.path = Some(path.into());
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.set_path(path);
        self
    }

    pub fn set_virtual_path(&mut self, path: impl Into<String>) {
        self.virtual_path = Some(path.into());
    }

    pub fn with_virtual_path(mut self, path: impl Into<String>) -> Self {
        self.set_virtual_path(path);
        self
    }

    pub fn set_primary_component_id(&mut self, id: impl Into<Uuid>) {
        self.primary_component_id = Some(id.into());
    }

    pub fn with_primary_component_id(mut self, id: impl Into<Uuid>) -> Self {
        self.set_primary_component_id(id);
        self
    }

    pub fn set_global_component_id(&mut self, id: impl Into<ComponentIdentity>) {
        self.global_component_id = Some(id.into());
    }

    pub fn with_global_component_id(mut self, id: impl Into<ComponentIdentity>) -> Self {
        self.set_global_component_id(id);
        self
    }

    pub fn set_hashes(&mut self, hashes: impl Into<BA2ComponentHashes>) {
        self.hashes = Some(hashes.into());
    }

    pub fn with_hashes(mut self, hashes: impl Into<BA2ComponentHashes>) -> Self {
        self.set_hashes(hashes);
        self
    }

    pub fn build(self) -> Result<BA2ComponentMetadata, BA2ComponentMetadataError> {
        let Some(name) = self.name else {
            return Err(BA2ComponentMetadataError::NoName);
        };

        let Some(path) = self.path.map(PathBuf::from) else {
            return Err(BA2ComponentMetadataError::NoPath);
        };

        let Some(hashes) = self.hashes else {
            return Err(BA2ComponentMetadataError::NoHashes);
        };

        let id = self.id.unwrap_or_else(Uuid::new_v4);

        let container_path = if self.meta {
            None
        } else {
            let file = hashes.sha256().encode_hex::<String>();
            Some(format!("{}/{}", &file[..2], file))
        };

        Ok(BA2ComponentMetadata {
            id,
            partition_id: self.partition_id,
            name,
            path,
            container_path,
            primary_component_id: self.primary_component_id,
            global_component_id: self.global_component_id,
            virtual_path: self.virtual_path,
            md5: *hashes.md5(),
            sha1: *hashes.sha1(),
            sha256: *hashes.sha256(),
            attributes: self.attrs,
        })
    }
}

#[derive(Debug, Clone)]
pub struct BA2ComponentMetadataWith<T> {
    pub meta: BA2ComponentMetadata,
    pub data: T,
}

impl<T> BA2ComponentMetadataWith<T> {
    pub fn new(meta: BA2ComponentMetadata, data: T) -> Self {
        Self { meta, data }
    }

    pub fn meta(&self) -> &BA2ComponentMetadata {
        &self.meta
    }

    pub fn data(&self) -> &T {
        &self.data
    }

    pub fn into_parts(self) -> (BA2ComponentMetadata, T) {
        (self.meta, self.data)
    }
}

pub trait BA2ComponentMetadataSource {
    fn component_meta_by_uuid<'a>(
        &'a self,
        pid: &Uuid,
        cid: &Uuid,
    ) -> Result<Option<Cow<'a, BA2ComponentMetadata>>, PipelineError>;
}

#[derive(Debug, Clone, Serialize)]
pub struct BA2ComponentMetadata {
    id: Uuid,
    #[serde(default)]
    partition_id: Option<u32>,

    name: String,
    path: PathBuf,
    #[serde(default)]
    container_path: Option<String>,
    #[serde(default)]
    virtual_path: Option<String>,
    #[serde(default)]
    global_component_id: Option<ComponentIdentity>,
    #[serde(default)]
    primary_component_id: Option<Uuid>,

    #[serde(serialize_with = "hex::serialize")]
    md5: [u8; 16],
    #[serde(serialize_with = "hex::serialize")]
    sha1: [u8; 20],
    #[serde(serialize_with = "hex::serialize")]
    sha256: [u8; 32],

    attributes: BA2ComponentAttributes,
}

impl BA2ComponentMetadata {
    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn partition_id(&self) -> Option<u32> {
        self.partition_id
    }

    pub fn set_partition_id(&mut self, id: u32) {
        self.partition_id = Some(id);
    }

    pub fn with_partition_id(mut self, id: u32) -> Self {
        self.set_partition_id(id);
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn kind(&self) -> &'static str {
        self.attributes.kind()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn container_path(&self) -> Option<&str> {
        self.container_path.as_deref()
    }

    pub fn virtual_path(&self) -> Option<&str> {
        self.virtual_path.as_deref()
    }

    pub fn set_virtual_path(&mut self, path: impl Into<String>) {
        self.virtual_path = Some(path.into());
    }

    pub fn with_virtual_path(mut self, path: impl Into<String>) -> Self {
        self.set_virtual_path(path);
        self
    }

    pub fn is_meta(&self) -> bool {
        self.container_path.is_none()
    }

    pub fn set_meta(&mut self) {
        self.container_path = None;
    }

    pub fn into_meta(mut self) -> Self {
        self.set_meta();
        self
    }

    pub fn primary_component_id(&self) -> Option<Uuid> {
        self.primary_component_id
    }

    pub fn set_primary_component_id(&mut self, id: impl Into<Option<Uuid>>) {
        self.primary_component_id = id.into();
    }

    pub fn with_primary_component_id(mut self, id: impl Into<Option<Uuid>>) -> Self {
        self.set_primary_component_id(id);
        self
    }

    pub fn global_component_id(&self) -> Option<ComponentIdentity> {
        self.global_component_id
    }

    pub fn set_global_component_id(&mut self, id: impl Into<Option<ComponentIdentity>>) {
        self.global_component_id = id.into();
    }

    pub fn with_global_component_id(mut self, id: impl Into<Option<ComponentIdentity>>) -> Self {
        self.set_global_component_id(id);
        self
    }

    pub fn is_duplicate(&self) -> bool {
        self.primary_component_id.is_some()
    }

    pub fn md5(&self) -> [u8; 16] {
        self.md5
    }

    pub fn sha1(&self) -> [u8; 20] {
        self.sha1
    }

    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    pub fn attributes(&self) -> &BA2ComponentAttributes {
        &self.attributes
    }

    pub fn attributes_mut(&mut self) -> &mut BA2ComponentAttributes {
        &mut self.attributes
    }

    pub fn set_attributes(&mut self, attributes: BA2ComponentAttributes) {
        self.attributes = attributes
    }

    pub fn platform(&self) -> Option<Platform> {
        use BA2ComponentAttributes as A;

        match self.attributes() {
            A::AndroidPackage(_attrs) => Some(
                PlatformBuilder::<AndroidPackage>::from_iter([
                    AndroidPackageAttribute::name(self.name()),
                    AndroidPackageAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::EFIModulePE(attrs) | A::EFIModuleTE(attrs) => {
                let mut builder = PlatformBuilder::<EFIModule>::from_iter([
                    EFIModuleAttribute::name(self.name()),
                    EFIModuleAttribute::guid(attrs.guid()),
                    EFIModuleAttribute::kind(attrs.kind()),
                    EFIModuleAttribute::depex(attrs.depex()),
                    EFIModuleAttribute::compiler_information(
                        attrs.compiler_information().to_owned(),
                    ),
                ]);

                if let Some(architecture) = attrs.architecture() {
                    builder.push(EFIModuleAttribute::architecture(architecture.to_owned()));
                }

                if let Some(meta) = attrs.loader_metadata() {
                    builder.push(EFIModuleAttribute::loader_metadata(meta.to_owned()));
                }

                Some(builder.build())
            }
            A::EFIStandalonePE(attrs) | A::EFIStandaloneTE(attrs) => {
                let mut builder = PlatformBuilder::<EFIStandalone>::from_iter([
                    EFIStandaloneAttribute::name(self.name()),
                    EFIStandaloneAttribute::path(self.path()),
                    EFIStandaloneAttribute::kind(attrs.kind()),
                ]);

                if let Some(architecture) = attrs.architecture() {
                    builder.push(EFIStandaloneAttribute::architecture(
                        architecture.to_owned(),
                    ));
                }

                if let Some(meta) = attrs.loader_metadata() {
                    builder.push(EFIStandaloneAttribute::loader_metadata(meta.to_owned()));
                }

                Some(builder.build())
            }
            A::EFIAmdMicrocode(attrs) => Some(
                PlatformBuilder::<EFIAmdMicrocode>::from_iter([
                    EFIAmdMicrocodeAttribute::cpu_signature(attrs.cpu_signature()),
                    EFIAmdMicrocodeAttribute::date(attrs.date()),
                    EFIAmdMicrocodeAttribute::update_revision(attrs.update_revision()),
                ])
                .build(),
            ),
            A::EFIIntelMicrocode(attrs) => Some(
                PlatformBuilder::<EFIIntelMicrocode>::from_iter([
                    EFIIntelMicrocodeAttribute::cpu_signature(attrs.cpu_signature()),
                    EFIIntelMicrocodeAttribute::date(attrs.date()),
                    EFIIntelMicrocodeAttribute::processor_flags(attrs.processor_flags()),
                    EFIIntelMicrocodeAttribute::update_revision(attrs.update_revision()),
                ])
                .build(),
            ),
            A::EFIVariable(attrs) => Some(
                PlatformBuilder::<EFIVariable>::from_iter([
                    EFIVariableAttribute::name(attrs.name()),
                    EFIVariableAttribute::guid(attrs.guid()),
                    EFIVariableAttribute::attrs(attrs.attrs()),
                    EFIVariableAttribute::var_type(attrs.var_type()),
                ])
                .build(),
            ),
            A::EFIRawSection(attrs) => Some(
                PlatformBuilder::<EFIRawSection>::from_iter([
                    EFIRawSectionAttribute::name(attrs.name()),
                    EFIRawSectionAttribute::guid(attrs.guid()),
                ])
                .build(),
            ),
            A::EFIFirmwareImage(_attrs) => Some(
                PlatformBuilder::<EFIFirmwareImage>::from_iter([EFIFirmwareAttribute::name(
                    self.name(),
                )])
                .build(),
            ),
            A::JavaArchive(_attrs) => Some(
                PlatformBuilder::<JavaArchive>::from_iter([
                    JavaArchiveAttribute::name(self.name()),
                    JavaArchiveAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::LinuxKernel(_attrs) => Some(
                PlatformBuilder::<LinuxKernel>::from_iter([
                    LinuxKernelAttribute::name(self.name()),
                    LinuxKernelAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::OPTEEKernel(_attrs) => Some(
                PlatformBuilder::<OPTEEKernel>::from_iter([
                    OPTEEKernelAttribute::name(self.name()),
                    OPTEEKernelAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::PosixELF(attrs) => {
                let mut builder = PlatformBuilder::<PosixBinary>::from_iter([
                    PosixBinaryAttribute::name(self.name()),
                    PosixBinaryAttribute::path(self.path()),
                    PosixBinaryAttribute::linked_paths(attrs.links().to_owned()),
                    PosixBinaryAttribute::compiler_information(
                        attrs.compiler_information().to_owned(),
                    ),
                ]);

                if let Some(architecture) = attrs.architecture() {
                    builder.push(PosixBinaryAttribute::architecture(architecture.to_owned()));
                }

                if let Some(ecosystem) = attrs.ecosystem() {
                    builder.push(PosixBinaryAttribute::ecosystem(ecosystem));
                }

                if let Some(ecosystem) = attrs.ecosystem_discriminant() {
                    builder.push(PosixBinaryAttribute::ecosystem_discriminant(ecosystem));
                }

                if let Some(package) = attrs.package() {
                    builder.push(PosixBinaryAttribute::package(package.to_owned()));
                }

                if let Some(meta) = attrs.loader_metadata() {
                    builder.push(PosixBinaryAttribute::loader_metadata(meta.to_owned()));
                }

                Some(builder.build())
            }
            A::PosixFirmwareImage(_attrs) => Some(
                PlatformBuilder::<PosixFirmwareImage>::from_iter([PosixFirmwareAttribute::name(
                    self.name(),
                )])
                .build(),
            ),

            A::PythonPackage(attrs) => {
                let mut builder = PlatformBuilder::<PythonPackage>::from_iter([
                    PythonPackageAttribute::name(self.name()),
                    PythonPackageAttribute::path(self.path()),
                ]);

                if let Some(installation_provenance) = attrs.installation_provenance() {
                    builder.push(PythonPackageAttribute::installation_provenance(
                        installation_provenance.to_owned(),
                    ));
                }
                if let Some(source_provenance) = attrs.source_provenance() {
                    builder.push(PythonPackageAttribute::source_provenance(
                        source_provenance.to_owned(),
                    ));
                }
                Some(builder.build())
            }

            A::SecretGeneric(_attrs) => Some(
                PlatformBuilder::<Secret<GenericSecret>>::from_iter([
                    SecretAttribute::name(self.name()),
                    SecretAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::SourceC(_attrs) => Some(
                PlatformBuilder::<SourceCode<C>>::from_iter([
                    SourceCodeAttribute::name(self.name()),
                    SourceCodeAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::SourceCLikeHeader(_attrs) => Some(
                PlatformBuilder::<SourceCode<CLikeHeader>>::from_iter([
                    SourceCodeAttribute::name(self.name()),
                    SourceCodeAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::SourceCPlusPlus(_attrs) => Some(
                PlatformBuilder::<SourceCode<CPlusPlus>>::from_iter([
                    SourceCodeAttribute::name(self.name()),
                    SourceCodeAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::SourceHtml(_attrs) => Some(
                PlatformBuilder::<SourceCode<Html>>::from_iter([
                    SourceCodeAttribute::name(self.name()),
                    SourceCodeAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::SourceJava(_attrs) => Some(
                PlatformBuilder::<SourceCode<Java>>::from_iter([
                    SourceCodeAttribute::name(self.name()),
                    SourceCodeAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::SourceJavaScript(_attrs) => Some(
                PlatformBuilder::<SourceCode<JavaScript>>::from_iter([
                    SourceCodeAttribute::name(self.name()),
                    SourceCodeAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::SourceJson(_attrs) => Some(
                PlatformBuilder::<SourceCode<Json>>::from_iter([
                    SourceCodeAttribute::name(self.name()),
                    SourceCodeAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::SourceJulia(_attrs) => Some(
                PlatformBuilder::<SourceCode<Julia>>::from_iter([
                    SourceCodeAttribute::name(self.name()),
                    SourceCodeAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::SourceLisp(_attrs) => Some(
                PlatformBuilder::<SourceCode<Lisp>>::from_iter([
                    SourceCodeAttribute::name(self.name()),
                    SourceCodeAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::SourceLua(_attrs) => Some(
                PlatformBuilder::<SourceCode<Lua>>::from_iter([
                    SourceCodeAttribute::name(self.name()),
                    SourceCodeAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::SourceOcaml(_attrs) => Some(
                PlatformBuilder::<SourceCode<Ocaml>>::from_iter([
                    SourceCodeAttribute::name(self.name()),
                    SourceCodeAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::SourcePerl(_attrs) => Some(
                PlatformBuilder::<SourceCode<Perl>>::from_iter([
                    SourceCodeAttribute::name(self.name()),
                    SourceCodeAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::SourcePhp(_attrs) => Some(
                PlatformBuilder::<SourceCode<Php>>::from_iter([
                    SourceCodeAttribute::name(self.name()),
                    SourceCodeAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::SourcePlaintext(_attrs) => Some(
                PlatformBuilder::<SourceCode<Plaintext>>::from_iter([
                    SourceCodeAttribute::name(self.name()),
                    SourceCodeAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::SourcePosixLikeShellScript(_attrs) => Some(
                PlatformBuilder::<SourceCode<PosixLikeShellScript>>::from_iter([
                    SourceCodeAttribute::name(self.name()),
                    SourceCodeAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::SourcePython(_attrs) => Some(
                PlatformBuilder::<SourceCode<Python>>::from_iter([
                    SourceCodeAttribute::name(self.name()),
                    SourceCodeAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::SourceRlang(_attrs) => Some(
                PlatformBuilder::<SourceCode<Rlang>>::from_iter([
                    SourceCodeAttribute::name(self.name()),
                    SourceCodeAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::SourceRuby(_attrs) => Some(
                PlatformBuilder::<SourceCode<Ruby>>::from_iter([
                    SourceCodeAttribute::name(self.name()),
                    SourceCodeAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::SourceXml(_attrs) => Some(
                PlatformBuilder::<SourceCode<Xml>>::from_iter([
                    SourceCodeAttribute::name(self.name()),
                    SourceCodeAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::SourceYaml(_attrs) => Some(
                PlatformBuilder::<SourceCode<Yaml>>::from_iter([
                    SourceCodeAttribute::name(self.name()),
                    SourceCodeAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::BytecodeJava(_attrs) => Some(
                PlatformBuilder::<Bytecode<Java>>::from_iter([
                    BytecodeAttribute::name(self.name()),
                    BytecodeAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::BytecodeLua(_attrs) => Some(
                PlatformBuilder::<Bytecode<Lua>>::from_iter([
                    BytecodeAttribute::name(self.name()),
                    BytecodeAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::BytecodePython(_attrs) => Some(
                PlatformBuilder::<Bytecode<Python>>::from_iter([
                    BytecodeAttribute::name(self.name()),
                    BytecodeAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::CryptoPublicKeyPem(_attrs) => Some(
                PlatformBuilder::<Crypto<PublicKeyPem>>::from_iter([
                    CryptoAttribute::name(self.name()),
                    CryptoAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::CryptoPublicKeyDer(_attrs) => Some(
                PlatformBuilder::<Crypto<PublicKeyDer>>::from_iter([
                    CryptoAttribute::name(self.name()),
                    CryptoAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::CryptoPublicKeyPgp(_attrs) => Some(
                PlatformBuilder::<Crypto<PublicKeyPgp>>::from_iter([
                    CryptoAttribute::name(self.name()),
                    CryptoAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::CryptoPublicKeySsh(_attrs) => Some(
                PlatformBuilder::<Crypto<PublicKeySsh>>::from_iter([
                    CryptoAttribute::name(self.name()),
                    CryptoAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::CryptoPublicKeyTss2(_attrs) => Some(
                PlatformBuilder::<Crypto<PublicKeyTss2>>::from_iter([
                    CryptoAttribute::name(self.name()),
                    CryptoAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::CryptoPrivateKeyPem(_attrs) => Some(
                PlatformBuilder::<Crypto<PrivateKeyPem>>::from_iter([
                    CryptoAttribute::name(self.name()),
                    CryptoAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::CryptoPrivateKeyDer(_attrs) => Some(
                PlatformBuilder::<Crypto<PrivateKeyDer>>::from_iter([
                    CryptoAttribute::name(self.name()),
                    CryptoAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::CryptoPrivateKeyPgp(_attrs) => Some(
                PlatformBuilder::<Crypto<PrivateKeyPgp>>::from_iter([
                    CryptoAttribute::name(self.name()),
                    CryptoAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::CryptoPrivateKeySsh(_attrs) => Some(
                PlatformBuilder::<Crypto<PrivateKeySsh>>::from_iter([
                    CryptoAttribute::name(self.name()),
                    CryptoAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::CryptoPrivateKeyTss2(_attrs) => Some(
                PlatformBuilder::<Crypto<PrivateKeyTss2>>::from_iter([
                    CryptoAttribute::name(self.name()),
                    CryptoAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::CryptoCertificatePem(_attrs) => Some(
                PlatformBuilder::<Crypto<CertificatePem>>::from_iter([
                    CryptoAttribute::name(self.name()),
                    CryptoAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::CryptoCertificateDer(_attrs) => Some(
                PlatformBuilder::<Crypto<CertificateDer>>::from_iter([
                    CryptoAttribute::name(self.name()),
                    CryptoAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::CryptoPkcs7Pem(_attrs) => Some(
                PlatformBuilder::<Crypto<Pkcs7Pem>>::from_iter([
                    CryptoAttribute::name(self.name()),
                    CryptoAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::CryptoPkcs7Der(_attrs) => Some(
                PlatformBuilder::<Crypto<Pkcs7Der>>::from_iter([
                    CryptoAttribute::name(self.name()),
                    CryptoAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::CryptoPkcs12Pem(_attrs) => Some(
                PlatformBuilder::<Crypto<Pkcs12Pem>>::from_iter([
                    CryptoAttribute::name(self.name()),
                    CryptoAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::CryptoPkcs12Der(_attrs) => Some(
                PlatformBuilder::<Crypto<Pkcs12Der>>::from_iter([
                    CryptoAttribute::name(self.name()),
                    CryptoAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::HardLink => Some(
                PlatformBuilder::<Link<HardLink>>::from_iter([
                    LinkAttribute::name(self.name()),
                    LinkAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::SoftLink => Some(
                PlatformBuilder::<Link<SoftLink>>::from_iter([
                    LinkAttribute::name(self.name()),
                    LinkAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::GitDiff(_attrs) => Some(
                PlatformBuilder::<GitDiff>::from_iter([
                    GitDiffAttribute::name(self.name()),
                    GitDiffAttribute::path(self.path()),
                ])
                .build(),
            ),
            A::DockerConfig(attrs) => Some(
                PlatformBuilder::<DockerConfig>::from_iter([
                    DockerConfigAttribute::name(self.name()),
                    DockerConfigAttribute::path(self.path()),
                    DockerConfigAttribute::layer(attrs.layer().to_owned()),
                    DockerConfigAttribute::config(attrs.image_config().to_owned()),
                ])
                .build(),
            ),
            A::DockerShadow(attrs) => Some(
                PlatformBuilder::<DockerShadow>::from_iter([
                    DockerShadowAttribute::name(self.name()),
                    DockerShadowAttribute::path(self.path()),
                    DockerShadowAttribute::layer(attrs.layer().to_owned()),
                ])
                .build(),
            ),
            A::WindowsPE(attrs) => {
                let mut builder = PlatformBuilder::<WindowsBinary>::from_iter([
                    WindowsBinaryAttribute::name(self.name()),
                    WindowsBinaryAttribute::path(self.path()),
                    WindowsBinaryAttribute::linked_paths(attrs.links().to_owned()),
                    WindowsBinaryAttribute::compiler_information(
                        attrs.compiler_information().to_owned(),
                    ),
                ]);

                if let Some(architecture) = attrs.architecture() {
                    builder.push(WindowsBinaryAttribute::architecture(
                        architecture.to_owned(),
                    ));
                }

                if let Some(meta) = attrs.loader_metadata() {
                    builder.push(WindowsBinaryAttribute::loader_metadata(meta.to_owned()));
                }

                Some(builder.build())
            }
            _ => None,
        }
    }

    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, ComponentError> {
        Self::from_bytes_with(bytes, None)
    }

    pub fn from_bytes_with(
        bytes: impl AsRef<[u8]>,
        path: impl Into<Option<PathBuf>>,
    ) -> Result<Self, ComponentError> {
        Self::from_bytes_and_attrs_with(bytes, path, None)
    }

    pub fn from_bytes_and_attrs(
        bytes: impl AsRef<[u8]>,
        attrs: impl Into<Option<PlatformAttributeMap>>,
    ) -> Result<Self, ComponentError> {
        Self::from_bytes_and_attrs_with(bytes, None, attrs)
    }

    pub fn from_bytes_and_attrs_with(
        bytes: impl AsRef<[u8]>,
        path: impl Into<Option<PathBuf>>,
        attrs: impl Into<Option<PlatformAttributeMap>>,
    ) -> Result<Self, ComponentError> {
        let bytes = bytes.as_ref();
        if bytes.len() < 16 {
            return Err(ComponentError::UnknownFormat);
        }

        let mut attrs = attrs.into().unwrap_or_default();

        let fpath = path
            .into()
            .or_else(|| attrs.get_attr::<PathBuf>("path"))
            .unwrap_or_default();

        let fname = fpath
            .file_name()
            .map(|fname| fname.to_string_lossy().into_owned())
            .unwrap_or_default();

        let fpath = fpath.to_string_lossy();

        let object = goblin::Object::parse(bytes).map_err(|_| ComponentError::UnknownFormat)?;

        let Some(architecture) = ComponentArch::from_object(&object) else {
            return Err(ComponentError::UnsupportedFormat);
        };
        attrs.set_attr("architecture", AsArchStr::new(&architecture));

        let loader_meta = BinaryLoaderMetadata::from_object(&object, bytes.len());
        attrs.set_attr("loader_metadata", loader_meta);

        let efi_kind = EFIModule::object_kind_with(&object, &attrs);
        let has_guid = attrs.get_attr::<Uuid>("guid").is_some();
        let is_efi = efi_kind.is_some();

        let attrs_obj = Value::from(attrs);
        let attrs = match object {
            goblin::Object::PE(_) if is_efi => {
                let kind = BA2ComponentKind::new(if has_guid {
                    "firmware.uefi.PE"
                } else {
                    "firmware.uefi.standalone.PE"
                });

                kind.deserialize(attrs_obj).map_err(ComponentError::from)
            }
            goblin::Object::TE(_) if is_efi => {
                let kind = BA2ComponentKind::new(if has_guid {
                    "firmware.uefi.TE"
                } else {
                    "firmware.uefi.standalone.TE"
                });

                kind.deserialize(attrs_obj).map_err(ComponentError::from)
            }
            goblin::Object::PE(_) => BA2ComponentKind::new("windows.PE")
                .deserialize(attrs_obj)
                .map_err(ComponentError::from),
            goblin::Object::Elf(_) => BA2ComponentKind::new("generic.ELF")
                .deserialize(attrs_obj)
                .map_err(ComponentError::from),
            _ => Err(ComponentError::UnsupportedFormat),
        }?;

        BA2ComponentMetadataBuilder::new(attrs)
            .with_id(Uuid::now_v7())
            .with_name(fname)
            .with_path(&*fpath)
            .with_virtual_path(&*fpath)
            .with_hashes(ComponentHashes::new(bytes))
            .build()
    }

    fn platform_details(&self) -> (&'static str, BA2ComponentPlatformDetails) {
        (
            self.attributes.kind(),
            BA2ComponentPlatformDetails::from(self.attributes()),
        )
    }
}

impl TryFrom<&'_ BA2ComponentMetadata> for Component {
    type Error = ComponentError;

    fn try_from(value: &'_ BA2ComponentMetadata) -> Result<Self, Self::Error> {
        let (kind, attrs) = value.platform_details();

        let mut builder = ComponentBuilder::new(kind)
            .with_id(value.id())
            .with_name(value.name())
            .with_path(value.path().to_string_lossy())
            .with_virtual_path(value.virtual_path().map(ToOwned::to_owned))
            .with_container_path(value.container_path())
            .with_hashes(ComponentHashes::from_parts(
                value.md5(),
                value.sha1(),
                value.sha256(),
            ))
            .with_attrs(attrs);

        if let Some(partition_id) = value.partition_id() {
            builder.set_partition_id(partition_id);
        }

        if let Some(primary_id) = value.primary_component_id() {
            builder.set_primary_component_id(primary_id);
        }

        if let Some(global_id) = value.global_component_id() {
            builder.set_global_component_id(global_id);
        }

        builder.build()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BA2ComponentKind<'a>(&'a str);

impl<'a> BA2ComponentKind<'a> {
    pub fn new(kind: &'a str) -> Self {
        Self(kind)
    }
}

impl<'de> DeserializeSeed<'de> for BA2ComponentKind<'_> {
    type Value = BA2ComponentAttributes;

    fn deserialize<D>(self, deserialiser: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let attributes = match self.0 {
            "android.package" => BA2ComponentAttributes::AndroidPackage(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),

            // UEFI
            "firmware.uefi.PE" => {
                BA2ComponentAttributes::EFIModulePE(<_ as Deserialize>::deserialize(deserialiser)?)
            }
            "firmware.uefi.TE" => {
                BA2ComponentAttributes::EFIModuleTE(<_ as Deserialize>::deserialize(deserialiser)?)
            }
            "firmware.uefi.standalone.PE" => BA2ComponentAttributes::EFIStandalonePE(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "firmware.uefi.standalone.TE" => BA2ComponentAttributes::EFIStandaloneTE(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "firmware.uefi.microcode.amd" => BA2ComponentAttributes::EFIAmdMicrocode(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "firmware.uefi.microcode.intel" | "firmware.uefi.microcode" => {
                BA2ComponentAttributes::EFIIntelMicrocode(<_ as Deserialize>::deserialize(
                    deserialiser,
                )?)
            }
            "firmware.uefi.nvram-variable" => {
                BA2ComponentAttributes::EFIVariable(<_ as Deserialize>::deserialize(deserialiser)?)
            }
            "firmware.uefi.raw-section" => BA2ComponentAttributes::EFIRawSection(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "firmware.uefi" => BA2ComponentAttributes::EFIFirmwareImage(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "firmware.uefi.unsupported" | "firmware.uefi.Unsupported" => {
                BA2ComponentAttributes::EFIUnsupported
            }

            "java.archive" => {
                BA2ComponentAttributes::JavaArchive(<_ as Deserialize>::deserialize(deserialiser)?)
            }

            // Linux/BMC
            "linux.kernel" | "firmware.linux.kernel" => {
                BA2ComponentAttributes::LinuxKernel(<_ as Deserialize>::deserialize(deserialiser)?)
            }

            "optee.kernel" | "firmware.optee.kernel" => {
                BA2ComponentAttributes::OPTEEKernel(<_ as Deserialize>::deserialize(deserialiser)?)
            }

            "firmware.linux.ELF" | "firmware.posix.ELF" | "docker.linux.ELF"
            | "docker.posix.ELF" | "generic.ELF" | "posix.ELF" => {
                BA2ComponentAttributes::PosixELF(<_ as Deserialize>::deserialize(deserialiser)?)
            }
            "firmware.linux" | "firmware.posix" => BA2ComponentAttributes::PosixFirmwareImage(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "firmware.linux.Unsupported"
            | "firmware.linux.unsupported"
            | "firmware.posix.Unsupported"
            | "firmware.posix.unsupported"
            | "linux.Unsupported"
            | "linux.unsupported"
            | "posix.Unsupported"
            | "posix.unsupported"
            | "posix.a"
            | "posix.ar"
            | "posix.lib" => BA2ComponentAttributes::PosixUnsupported,

            "python.package" => BA2ComponentAttributes::PythonPackage(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),

            // Secrets
            "secret.generic" => BA2ComponentAttributes::SecretGeneric(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),

            // Source code
            "source.c" | "source.C" => {
                BA2ComponentAttributes::SourceC(<_ as Deserialize>::deserialize(deserialiser)?)
            }
            "source.h" => BA2ComponentAttributes::SourceCLikeHeader(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "source.c++" | "source.C++" | "source.cpp" | "source.CPP" | "source.CPlusPlus" => {
                BA2ComponentAttributes::SourceCPlusPlus(<_ as Deserialize>::deserialize(
                    deserialiser,
                )?)
            }
            "source.html" | "source.HTML" => {
                BA2ComponentAttributes::SourceHtml(<_ as Deserialize>::deserialize(deserialiser)?)
            }
            "source.java" => {
                BA2ComponentAttributes::SourceJava(<_ as Deserialize>::deserialize(deserialiser)?)
            }
            "source.js" | "source.javascript" | "source.JavaScript" => {
                BA2ComponentAttributes::SourceJavaScript(<_ as Deserialize>::deserialize(
                    deserialiser,
                )?)
            }
            "source.json" => {
                BA2ComponentAttributes::SourceJson(<_ as Deserialize>::deserialize(deserialiser)?)
            }
            "source.julia" => {
                BA2ComponentAttributes::SourceJulia(<_ as Deserialize>::deserialize(deserialiser)?)
            }
            "source.lisp" => {
                BA2ComponentAttributes::SourceLisp(<_ as Deserialize>::deserialize(deserialiser)?)
            }
            "source.lua" => {
                BA2ComponentAttributes::SourceLua(<_ as Deserialize>::deserialize(deserialiser)?)
            }
            "source.ocaml" => {
                BA2ComponentAttributes::SourceOcaml(<_ as Deserialize>::deserialize(deserialiser)?)
            }
            "source.perl" => {
                BA2ComponentAttributes::SourcePerl(<_ as Deserialize>::deserialize(deserialiser)?)
            }
            "source.php" => {
                BA2ComponentAttributes::SourcePhp(<_ as Deserialize>::deserialize(deserialiser)?)
            }
            "source.plaintext" => BA2ComponentAttributes::SourcePlaintext(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "source.posix.sh" => BA2ComponentAttributes::SourcePosixLikeShellScript(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "source.python" => {
                BA2ComponentAttributes::SourcePython(<_ as Deserialize>::deserialize(deserialiser)?)
            }
            "source.rlang" => {
                BA2ComponentAttributes::SourceRlang(<_ as Deserialize>::deserialize(deserialiser)?)
            }
            "source.ruby" => {
                BA2ComponentAttributes::SourceRuby(<_ as Deserialize>::deserialize(deserialiser)?)
            }
            "source.xml" => {
                BA2ComponentAttributes::SourceXml(<_ as Deserialize>::deserialize(deserialiser)?)
            }
            "source.yaml" => {
                BA2ComponentAttributes::SourceYaml(<_ as Deserialize>::deserialize(deserialiser)?)
            }

            // Bytecode
            "bytecode.java" => {
                BA2ComponentAttributes::BytecodeJava(<_ as Deserialize>::deserialize(deserialiser)?)
            }
            "bytecode.lua" => {
                BA2ComponentAttributes::BytecodeLua(<_ as Deserialize>::deserialize(deserialiser)?)
            }
            "bytecode.python" => BA2ComponentAttributes::BytecodePython(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),

            // Crypto
            "crypto.public-key.pem" => BA2ComponentAttributes::CryptoPublicKeyPem(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "crypto.public-key.der" => BA2ComponentAttributes::CryptoPublicKeyDer(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "crypto.public-key.pgp" => BA2ComponentAttributes::CryptoPublicKeyPgp(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "crypto.public-key.ssh" => BA2ComponentAttributes::CryptoPublicKeySsh(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "crypto.public-key.tss2" => BA2ComponentAttributes::CryptoPublicKeyTss2(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "crypto.private-key.pem" => BA2ComponentAttributes::CryptoPrivateKeyPem(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "crypto.private-key.der" => BA2ComponentAttributes::CryptoPrivateKeyDer(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "crypto.private-key.pgp" => BA2ComponentAttributes::CryptoPrivateKeyPgp(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "crypto.private-key.ssh" => BA2ComponentAttributes::CryptoPrivateKeySsh(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "crypto.private-key.tss2" => BA2ComponentAttributes::CryptoPrivateKeyTss2(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "crypto.certificate.pem" => BA2ComponentAttributes::CryptoCertificatePem(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "crypto.certificate.der" => BA2ComponentAttributes::CryptoCertificateDer(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "crypto.pkcs7.pem" => BA2ComponentAttributes::CryptoPkcs7Pem(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "crypto.pkcs7.der" => BA2ComponentAttributes::CryptoPkcs7Der(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "crypto.pkcs12.pem" => BA2ComponentAttributes::CryptoPkcs12Pem(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),
            "crypto.pkcs12.der" => BA2ComponentAttributes::CryptoPkcs12Der(
                <_ as Deserialize>::deserialize(deserialiser)?,
            ),

            // Symbolic links
            "link.hard" => BA2ComponentAttributes::HardLink,
            "link.soft" => BA2ComponentAttributes::SoftLink,

            // Git repo diffs
            "git.diff" => {
                BA2ComponentAttributes::GitDiff(<_ as Deserialize>::deserialize(deserialiser)?)
            }

            // Docker config file
            "docker.config" => {
                BA2ComponentAttributes::DockerConfig(<_ as Deserialize>::deserialize(deserialiser)?)
            }
            // Docker shadow files
            "docker.shadow" => {
                BA2ComponentAttributes::DockerShadow(<_ as Deserialize>::deserialize(deserialiser)?)
            }

            // Windows PE
            "windows.PE" | "generic.PE" => {
                BA2ComponentAttributes::WindowsPE(<_ as Deserialize>::deserialize(deserialiser)?)
            }

            _ => BA2ComponentAttributes::Unsupported,
        };

        Ok(attributes)
    }
}

impl<'de> Deserialize<'de> for BA2ComponentMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Metadata {
            id: Uuid,
            #[serde(default)]
            partition_id: Option<u32>,
            name: String,
            path: PathBuf,
            #[serde(default)]
            container_path: Option<String>,
            #[serde(default)]
            virtual_path: Option<String>,
            #[serde(default)]
            global_component_id: Option<ComponentIdentity>,
            #[serde(default)]
            primary_component_id: Option<Uuid>,

            kind: String,
            #[serde(default)]
            platform_details: Value,

            #[serde(with = "hex::serde")]
            md5: [u8; 16],
            #[serde(with = "hex::serde")]
            sha1: [u8; 20],
            #[serde(with = "hex::serde")]
            sha256: [u8; 32],
        }

        let meta = Metadata::deserialize(deserializer)?;
        let attributes = BA2ComponentKind::new(&meta.kind)
            .deserialize(meta.platform_details)
            .map_err(serde::de::Error::custom)?;

        Ok(BA2ComponentMetadata {
            id: meta.id,
            partition_id: meta.partition_id,
            name: meta.name,
            path: meta.path,
            container_path: meta.container_path,
            virtual_path: meta.virtual_path,
            global_component_id: meta.global_component_id,
            primary_component_id: meta.primary_component_id,
            attributes,
            md5: meta.md5,
            sha1: meta.sha1,
            sha256: meta.sha256,
        })
    }
}

impl HasComponentIdentity for BA2ComponentMetadata {
    fn compute_identity_with(&self, builder: &mut ComponentIdentityBuilder) -> ComponentIdentity {
        use BA2ComponentAttributes as A;

        builder.update(self.kind());
        builder.update(self.md5());
        builder.update(self.sha1());
        builder.update(self.sha256());

        match self.attributes() {
            A::EFIModulePE(m) | A::EFIModuleTE(m) => {
                builder.update(m.guid().as_bytes());

                for dguid in m.depex().iter().filter_map(|op| op.guid()) {
                    builder.update(dguid);
                }
            }
            A::EFIRawSection(m) => {
                builder.update(m.guid().as_bytes());
            }
            A::EFIAmdMicrocode(m) => {
                builder.update(m.cpu_signature().to_be_bytes());
                builder.update(m.date().as_bytes());
                builder.update(m.update_revision().to_be_bytes());
            }
            A::EFIIntelMicrocode(m) => {
                builder.update(m.cpu_signature().to_be_bytes());
                builder.update(m.date().as_bytes());
                builder.update(m.update_revision().to_be_bytes());
                builder.update(m.processor_flags().to_be_bytes());
            }
            A::EFIVariable(v) => {
                builder.update(v.name().as_bytes());
                builder.update(v.guid().as_bytes());
                builder.update(v.attrs().to_be_bytes());
                builder.update([v.var_type() as u8]);
            }
            A::PosixELF(_) => {
                // handle case of shared objects (we want to use the canonical "soname")
                let nm = posix::SONAME_RE.replace(self.name(), ".so");
                builder.update(nm.as_bytes());
            }
            A::WindowsPE(_) => {
                // case insensitive name
                builder.update(self.name().to_lowercase());
            }
            A::OPTEEKernel(_) | A::LinuxKernel(_) => {
                // self.name() is autogenerated in this case, eg "6-724690.image"
            }
            _ => {
                builder.update(self.name());
            }
        }

        builder.build()
    }
}

fn component_deserialiser<'de, D>(
    deserialiser: D,
) -> Result<BTreeMap<Uuid, BA2ComponentMetadata>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Components;

    impl<'de> Visitor<'de> for Components {
        type Value = BTreeMap<Uuid, BA2ComponentMetadata>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("sequence of component definitions")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut components = BTreeMap::new();

            while let Some(component) = seq.next_element::<BA2ComponentMetadata>()? {
                components.insert(component.id, component);
            }

            Ok(components)
        }
    }

    deserialiser.deserialize_any(Components)
}

#[derive(Debug, Clone, Default)]
pub struct BA2Dependencies {
    graph: DiGraph<Uuid, PackageDependencyKind>,
    nodes: BTreeMap<Uuid, NodeIndex>,
}

impl<'de> Deserialize<'de> for BA2Dependencies {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Dependency {
            source: Uuid,
            target: Uuid,
            kind: PackageDependencyKind,
        }

        struct DependenciesT;

        impl<'de> Visitor<'de> for DependenciesT {
            type Value = BA2Dependencies;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("sequence of dependency definitions")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let size = seq.size_hint().unwrap_or(4096);

                let mut graph = DiGraph::with_capacity(size, size * 2);
                let mut nodes = BTreeMap::new();
                let mut edges = BTreeSet::new();

                while let Some(dependency) = seq.next_element::<Dependency>()? {
                    let sx = *nodes
                        .entry(dependency.source)
                        .or_insert_with(|| graph.add_node(dependency.source));
                    let tx = *nodes
                        .entry(dependency.target)
                        .or_insert_with(|| graph.add_node(dependency.target));

                    edges.insert((sx, tx, dependency.kind));
                }

                for (sx, tx, kind) in edges.into_iter() {
                    graph.add_edge(sx, tx, kind);
                }

                Ok(BA2Dependencies { graph, nodes })
            }
        }

        deserializer.deserialize_any(DependenciesT)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "version")]
pub enum BA2Metadata {
    #[serde(rename = "1")]
    V1 {
        #[serde(skip, default = "uuid::Uuid::new_v4")]
        id: Uuid,
        #[serde(deserialize_with = "component_deserialiser")]
        components: BTreeMap<Uuid, BA2ComponentMetadata>,
        dependencies: BA2Dependencies,
    },
    #[serde(rename = "2")]
    V2 {
        #[serde(skip, default = "uuid::Uuid::new_v4")]
        id: Uuid,
        #[serde(deserialize_with = "component_deserialiser")]
        components: BTreeMap<Uuid, BA2ComponentMetadata>,
        dependencies: BA2Dependencies,
    },
    #[serde(rename = "3")]
    V3 {
        #[serde(default = "uuid::Uuid::now_v7")]
        id: Uuid,
        #[serde(default)]
        partition_id: Option<u32>,
        #[serde(deserialize_with = "component_deserialiser")]
        components: BTreeMap<Uuid, BA2ComponentMetadata>,
        dependencies: BA2Dependencies,
    },
    #[serde(rename = "4")]
    V4 {
        #[serde(default = "uuid::Uuid::now_v7")]
        id: Uuid,
        #[serde(default)]
        partition_id: Option<u32>,
        #[serde(default)]
        environment: EnvironmentKind,
        #[serde(deserialize_with = "component_deserialiser")]
        components: BTreeMap<Uuid, BA2ComponentMetadata>,
        dependencies: BA2Dependencies,
    },
}

impl BA2Metadata {
    pub fn new_v1() -> Self {
        Self::V1 {
            id: Uuid::new_v4(),
            components: Default::default(),
            dependencies: BA2Dependencies {
                graph: Default::default(),
                nodes: Default::default(),
            },
        }
    }

    pub fn new_v2() -> Self {
        Self::V2 {
            id: Uuid::new_v4(),
            components: Default::default(),
            dependencies: BA2Dependencies {
                graph: Default::default(),
                nodes: Default::default(),
            },
        }
    }

    pub fn new_v3() -> Self {
        Self::V3 {
            id: Uuid::now_v7(),
            partition_id: None,
            components: Default::default(),
            dependencies: BA2Dependencies {
                graph: Default::default(),
                nodes: Default::default(),
            },
        }
    }

    pub fn new_v4() -> Self {
        Self::V4 {
            id: Uuid::now_v7(),
            partition_id: None,
            environment: EnvironmentKind::default(),
            components: Default::default(),
            dependencies: BA2Dependencies {
                graph: Default::default(),
                nodes: Default::default(),
            },
        }
    }

    pub fn set_id(&mut self, pid: Uuid) {
        match self {
            BA2Metadata::V1 { ref mut id, .. }
            | BA2Metadata::V2 { ref mut id, .. }
            | BA2Metadata::V3 { ref mut id, .. }
            | BA2Metadata::V4 { ref mut id, .. } => *id = pid,
        }
    }

    pub fn with_id(mut self, pid: Uuid) -> Self {
        self.set_id(pid);
        self
    }

    pub fn add_component(&mut self, component: impl Into<BA2ComponentMetadata>) {
        let component = component.into();
        match self {
            BA2Metadata::V1 { components, .. }
            | BA2Metadata::V2 { components, .. }
            | BA2Metadata::V3 { components, .. }
            | BA2Metadata::V4 { components, .. } => {
                components.insert(component.id(), component);
            }
        }
    }

    pub fn add_dependency(
        &mut self,
        source: impl Into<Uuid>,
        target: impl Into<Uuid>,
        kind: impl Into<PackageDependencyKind>,
    ) -> Result<(), BA2MetadataError> {
        let source = source.into();
        let target = target.into();
        let kind = kind.into();

        match self {
            BA2Metadata::V1 {
                components,
                dependencies,
                ..
            }
            | BA2Metadata::V2 {
                components,
                dependencies,
                ..
            }
            | BA2Metadata::V3 {
                components,
                dependencies,
                ..
            }
            | BA2Metadata::V4 {
                components,
                dependencies,
                ..
            } => {
                if !components.contains_key(&source) {
                    return Err(BA2MetadataError::InvalidComponent(source));
                }

                if !components.contains_key(&target) {
                    return Err(BA2MetadataError::InvalidComponent(target));
                }

                let sx = *dependencies
                    .nodes
                    .entry(source)
                    .or_insert_with(|| dependencies.graph.add_node(source));
                let tx = *dependencies
                    .nodes
                    .entry(target)
                    .or_insert_with(|| dependencies.graph.add_node(target));

                if !dependencies
                    .graph
                    .edges_connecting(sx, tx)
                    .any(|edge| *edge.weight() == kind)
                {
                    dependencies.graph.add_edge(sx, tx, kind);
                }
            }
        }

        Ok(())
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<BA2Metadata, BA2MetadataError> {
        Self::from_file_with(path, None)
    }

    pub fn from_file_with(
        path: impl AsRef<Path>,
        id: impl Into<Option<Uuid>>,
    ) -> Result<BA2Metadata, BA2MetadataError> {
        Self::from_reader_with(
            BufReader::new(File::open(path).map_err(FirmwareMetadataError::Io)?),
            id,
        )
    }

    pub fn from_reader(reader: impl Read) -> Result<BA2Metadata, BA2MetadataError> {
        Self::from_reader_with(reader, None)
    }

    pub fn from_reader_with(
        reader: impl Read,
        id: impl Into<Option<Uuid>>,
    ) -> Result<BA2Metadata, BA2MetadataError> {
        let mut meta = serde_json::from_reader::<_, Self>(reader)
            .map_err(FirmwareMetadataError::Deserialise)?;
        if let Some(id) = id.into() {
            meta.set_id(id);
        }
        Ok(meta)
    }

    pub fn from_str(value: impl AsRef<str>) -> Result<BA2Metadata, BA2MetadataError> {
        Self::from_str_with(value, None)
    }

    pub fn from_str_with(
        value: impl AsRef<str>,
        id: impl Into<Option<Uuid>>,
    ) -> Result<BA2Metadata, BA2MetadataError> {
        let mut meta = serde_json::from_str::<Self>(value.as_ref())
            .map_err(FirmwareMetadataError::Deserialise)?;
        if let Some(id) = id.into() {
            meta.set_id(id);
        }
        Ok(meta)
    }

    pub fn id(&self) -> Uuid {
        match &self {
            BA2Metadata::V1 { id, .. }
            | BA2Metadata::V2 { id, .. }
            | BA2Metadata::V3 { id, .. }
            | BA2Metadata::V4 { id, .. } => *id,
        }
    }

    pub fn version(&self) -> u32 {
        match self {
            BA2Metadata::V1 { .. } => 1,
            BA2Metadata::V2 { .. } => 2,
            BA2Metadata::V3 { .. } => 3,
            BA2Metadata::V4 { .. } => 4,
        }
    }

    pub fn is_v1(&self) -> bool {
        matches!(self, BA2Metadata::V1 { .. })
    }

    pub fn is_v2(&self) -> bool {
        matches!(self, BA2Metadata::V2 { .. })
    }

    pub fn is_v3(&self) -> bool {
        matches!(self, BA2Metadata::V3 { .. })
    }

    pub fn is_v4(&self) -> bool {
        matches!(self, BA2Metadata::V4 { .. })
    }

    pub fn partition_id(&self) -> Option<u32> {
        match self {
            BA2Metadata::V3 { partition_id, .. } | BA2Metadata::V4 { partition_id, .. } => {
                *partition_id
            }
            _ => None,
        }
    }

    pub fn set_partition_id(
        &mut self,
        pid: impl Into<Option<u32>>,
    ) -> Result<(), BA2MetadataError> {
        match self {
            BA2Metadata::V3 { partition_id, .. } | BA2Metadata::V4 { partition_id, .. } => {
                *partition_id = pid.into();
                Ok(())
            }
            _ => Err(BA2MetadataError::PartitionedArchiveNotSupported(
                self.version(),
            )),
        }
    }

    pub fn with_partition_id(
        mut self,
        pid: impl Into<Option<u32>>,
    ) -> Result<Self, BA2MetadataError> {
        self.set_partition_id(pid)?;
        Ok(self)
    }

    pub fn environment(&self) -> EnvironmentKind {
        match self {
            BA2Metadata::V4 { environment, .. } => *environment,
            _ => EnvironmentKind::default(),
        }
    }

    pub fn set_environment(&mut self, env: EnvironmentKind) -> Result<(), BA2MetadataError> {
        match self {
            BA2Metadata::V4 { environment, .. } => {
                *environment = env;
                Ok(())
            }
            _ => Err(BA2MetadataError::EnvironmentNotSupported(self.version())),
        }
    }

    pub fn with_environment(mut self, env: EnvironmentKind) -> Result<Self, BA2MetadataError> {
        self.set_environment(env)?;
        Ok(self)
    }

    pub fn is_partitioned(&self) -> bool {
        matches!(
            self,
            BA2Metadata::V3 {
                partition_id: Some(_),
                ..
            } | BA2Metadata::V4 {
                partition_id: Some(_),
                ..
            }
        )
    }

    pub fn is_complete(&self) -> bool {
        !self.is_partitioned()
    }

    pub fn upgrade(&mut self) -> bool {
        // no need to upgrade
        if self.is_v4() {
            return false;
        }

        let update_version = |slf: &mut Self| match slf {
            BA2Metadata::V1 {
                id,
                components,
                dependencies,
            }
            | BA2Metadata::V2 {
                id,
                components,
                dependencies,
            } => {
                *slf = BA2Metadata::V4 {
                    id: *id,
                    partition_id: None,
                    environment: EnvironmentKind::default(),
                    components: std::mem::take(components),
                    dependencies: std::mem::take(dependencies),
                };
            }
            BA2Metadata::V3 {
                id,
                partition_id,
                components,
                dependencies,
            } => {
                *slf = BA2Metadata::V4 {
                    id: *id,
                    partition_id: *partition_id,
                    environment: EnvironmentKind::default(),
                    components: std::mem::take(components),
                    dependencies: std::mem::take(dependencies),
                };
            }
            BA2Metadata::V4 { .. } => {}
        };

        // check if we require an upgrade
        if !self.components().any(|c| c.global_component_id().is_none()) {
            update_version(self);
            return true;
        }

        let mut seen = PrimaryComponents::new();

        for entity in self.components_mut() {
            let id = entity.id();
            let platform = entity.kind();

            let (gid, pid) = seen.get_or_insert_with_full(id, &*entity, platform);

            entity.set_primary_component_id(if pid != id { Some(pid) } else { None });
            entity.set_global_component_id(gid);
        }

        update_version(self);
        true
    }

    pub fn by_uuid(&self, uuid: &Uuid) -> Option<&BA2ComponentMetadata> {
        match &self {
            BA2Metadata::V1 { components, .. }
            | BA2Metadata::V2 { components, .. }
            | BA2Metadata::V3 { components, .. }
            | BA2Metadata::V4 { components, .. } => components.get(uuid),
        }
    }

    pub fn by_uuid_mut(&mut self, uuid: &Uuid) -> Option<&mut BA2ComponentMetadata> {
        match self {
            BA2Metadata::V1 { components, .. }
            | BA2Metadata::V2 { components, .. }
            | BA2Metadata::V3 { components, .. }
            | BA2Metadata::V4 { components, .. } => components.get_mut(uuid),
        }
    }

    pub fn by_path(&self, path: impl AsRef<Path>) -> Option<&BA2ComponentMetadata> {
        match &self {
            BA2Metadata::V1 { components, .. }
            | BA2Metadata::V2 { components, .. }
            | BA2Metadata::V3 { components, .. }
            | BA2Metadata::V4 { components, .. } => {
                components.values().find(|c| c.path == path.as_ref())
            }
        }
    }

    pub fn is_container(&self, uuid: &Uuid) -> bool {
        match &self {
            BA2Metadata::V1 { dependencies, .. }
            | BA2Metadata::V2 { dependencies, .. }
            | BA2Metadata::V3 { dependencies, .. }
            | BA2Metadata::V4 { dependencies, .. } => {
                let Some(node) = dependencies.nodes.get(uuid).copied() else {
                    return false;
                };
                dependencies
                    .graph
                    .edges_directed(node, Direction::Outgoing)
                    .any(|edge| *edge.weight() == PackageDependencyKind::Contains)
            }
        }
    }

    pub fn components(&self) -> impl ExactSizeIterator<Item = &BA2ComponentMetadata> {
        match &self {
            BA2Metadata::V1 { components, .. }
            | BA2Metadata::V2 { components, .. }
            | BA2Metadata::V3 { components, .. }
            | BA2Metadata::V4 { components, .. } => components.values(),
        }
    }

    pub fn components_mut(&mut self) -> impl ExactSizeIterator<Item = &mut BA2ComponentMetadata> {
        match self {
            BA2Metadata::V1 { components, .. }
            | BA2Metadata::V2 { components, .. }
            | BA2Metadata::V3 { components, .. }
            | BA2Metadata::V4 { components, .. } => components.values_mut(),
        }
    }

    pub(crate) fn components_map(&self) -> &BTreeMap<Uuid, BA2ComponentMetadata> {
        match &self {
            BA2Metadata::V1 { components, .. }
            | BA2Metadata::V2 { components, .. }
            | BA2Metadata::V3 { components, .. }
            | BA2Metadata::V4 { components, .. } => components,
        }
    }

    pub fn dependencies<'a>(
        &'a self,
    ) -> impl ExactSizeIterator<Item = (Uuid, Uuid, PackageDependencyKind)> + 'a {
        match self {
            BA2Metadata::V1 { dependencies, .. }
            | BA2Metadata::V2 { dependencies, .. }
            | BA2Metadata::V3 { dependencies, .. }
            | BA2Metadata::V4 { dependencies, .. } => {
                dependencies.graph.raw_edges().iter().map(|edge| {
                    (
                        dependencies.graph[edge.source()],
                        dependencies.graph[edge.target()],
                        edge.weight,
                    )
                })
            }
        }
    }
}

impl BA2ComponentMetadataSource for BA2Metadata {
    fn component_meta_by_uuid<'a>(
        &'a self,
        pid: &Uuid,
        cid: &Uuid,
    ) -> Result<Option<Cow<'a, BA2ComponentMetadata>>, PipelineError> {
        if *pid != self.id() {
            return Ok(None);
        }

        Ok(self.by_uuid(cid).map(Cow::Borrowed))
    }
}

impl Serialize for BA2Metadata {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        #[serde(tag = "version")]
        enum MetadataT<'a> {
            #[serde(rename = "1")]
            V1 {
                components: ComponentMetadataT<'a>,
                dependencies: DependenciesT<'a>,
            },
            #[serde(rename = "2")]
            V2 {
                components: ComponentMetadataT<'a>,
                dependencies: DependenciesT<'a>,
            },
            #[serde(rename = "3")]
            V3 {
                id: Uuid,
                #[serde(skip_serializing_if = "Option::is_none")]
                partition_id: Option<u32>,
                components: ComponentMetadataT<'a>,
                dependencies: DependenciesT<'a>,
            },
            #[serde(rename = "4")]
            V4 {
                id: Uuid,
                #[serde(skip_serializing_if = "Option::is_none")]
                partition_id: Option<u32>,
                environment: EnvironmentKind,
                components: ComponentMetadataT<'a>,
                dependencies: DependenciesT<'a>,
            },
        }

        #[repr(transparent)]
        struct ComponentMetadataT<'a>(&'a BTreeMap<Uuid, BA2ComponentMetadata>);

        impl Serialize for ComponentMetadataT<'_> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::SerializeSeq;

                #[derive(Serialize)]
                struct Metadata<'a> {
                    id: Uuid,
                    partition_id: Option<u32>,

                    name: &'a str,
                    path: &'a Path,
                    container_path: Option<&'a str>,
                    virtual_path: Option<&'a str>,
                    global_component_id: Option<ComponentIdentity>,
                    primary_component_id: Option<Uuid>,

                    kind: &'a str,

                    #[serde(with = "hex::serde")]
                    md5: [u8; 16],
                    #[serde(with = "hex::serde")]
                    sha1: [u8; 20],
                    #[serde(with = "hex::serde")]
                    sha256: [u8; 32],

                    platform_details: BA2ComponentPlatformDetails<'a>,
                }

                let mut seq = serializer.serialize_seq(Some(self.0.len()))?;

                for component in self.0.values() {
                    let (kind, platform_details) = component.platform_details();

                    seq.serialize_element(&Metadata {
                        id: component.id(),
                        partition_id: component.partition_id(),
                        name: component.name(),
                        path: component.path(),
                        container_path: component.container_path(),
                        virtual_path: component.virtual_path(),
                        global_component_id: component.global_component_id(),
                        primary_component_id: component.primary_component_id(),
                        kind,
                        md5: component.md5(),
                        sha1: component.sha1(),
                        sha256: component.sha256(),
                        platform_details,
                    })?;
                }

                seq.end()
            }
        }

        #[repr(transparent)]
        struct DependenciesT<'a>(&'a BA2Dependencies);

        impl Serialize for DependenciesT<'_> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::SerializeSeq;

                #[derive(Serialize)]
                struct Dependency {
                    source: Uuid,
                    target: Uuid,
                    kind: PackageDependencyKind,
                }

                let mut seq = serializer.serialize_seq(Some(self.0.graph.edge_count()))?;

                for edge in self.0.graph.raw_edges() {
                    seq.serialize_element(&Dependency {
                        source: self.0.graph[edge.source()],
                        target: self.0.graph[edge.target()],
                        kind: edge.weight,
                    })?;
                }

                seq.end()
            }
        }

        let t = match self {
            Self::V1 {
                components,
                dependencies,
                ..
            } => MetadataT::V1 {
                components: ComponentMetadataT(components),
                dependencies: DependenciesT(dependencies),
            },
            Self::V2 {
                components,
                dependencies,
                ..
            } => MetadataT::V2 {
                components: ComponentMetadataT(components),
                dependencies: DependenciesT(dependencies),
            },
            Self::V3 {
                id,
                partition_id,
                components,
                dependencies,
                ..
            } => MetadataT::V3 {
                id: *id,
                components: ComponentMetadataT(components),
                dependencies: DependenciesT(dependencies),
                partition_id: *partition_id,
            },
            Self::V4 {
                id,
                partition_id,
                environment,
                components,
                dependencies,
            } => MetadataT::V4 {
                id: *id,
                partition_id: *partition_id,
                environment: *environment,
                components: ComponentMetadataT(components),
                dependencies: DependenciesT(dependencies),
            },
        };
        t.serialize(serializer)
    }
}

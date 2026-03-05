use std::borrow::Cow;
use std::ops::Deref;
use std::path::{Path, PathBuf};

use bias_core::any::ProvidesStaticType;
use bias_core::efi::image::depex::DepExOpcode;
use bias_core::efi::{EFIModuleType, EFINvramVarType};
use bias_core::kb::{uuid, Uuid};
use bias_core::loader::{LoaderAttribute, LoaderContainer};
use bias_core::prelude::*;

use thiserror::Error;

use crate::component::{ComponentLoaderError, LoadedBinaryComponent, LoadedBinaryComponentData};
use crate::pipeline::PipelineError;
use crate::util::BytesOrMapping;

pub use super::common::{
    ComponentArch as EFIComponentArch, ComponentBinaryLoaderMetadata as EFIModuleLoaderMetadata,
    ComponentCompilerInformation as EFIModuleCompilerInformation,
};

use super::common::{BinaryLoaderMetadata, Compilers};
use super::{
    PlatformAttributeMap, PlatformAttributeProvider, PlatformBuilder, PlatformComponentBinaryData,
    PlatformComponentBinaryLoader, PlatformComponentLoader, PlatformProvider,
};

pub mod analysis;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EFIModule;

impl EFIModule {
    pub fn is_efi(object: &goblin::Object) -> bool {
        Self::object_kind(object).is_some()
    }

    pub fn is_efi_with<'a, A>(object: &goblin::Object, attrs: A) -> bool
    where
        A: Into<Option<&'a PlatformAttributeMap>>,
    {
        Self::object_kind_with(object, attrs).is_some()
    }

    pub fn object_kind(object: &goblin::Object) -> Option<EFIModuleType> {
        Self::object_kind_with(object, None)
    }

    pub fn object_kind_with<'a, A>(object: &goblin::Object, attrs: A) -> Option<EFIModuleType>
    where
        A: Into<Option<&'a PlatformAttributeMap>>,
    {
        if let Some(kind) = attrs
            .into()
            .and_then(|attrs| attrs.get_attr::<EFIModuleType>("kind"))
        {
            return Some(kind);
        }

        match object {
            goblin::Object::PE(pe) => {
                let Some(oh) = pe.header.optional_header else {
                    return None;
                };

                (oh.windows_fields.subsystem >= 10 && oh.windows_fields.subsystem <= 12)
                    .then_some(EFIModuleType::DxeDriver)
            }
            goblin::Object::TE(_) => Some(EFIModuleType::PeiModule),
            _ => None,
        }
    }
}

pub mod depex {
    use std::fmt;

    use bias_core::efi::image::depex::DepExOpcode;

    use serde::de::value::StrDeserializer;
    use serde::de::{Deserialize, DeserializeSeed, Deserializer, SeqAccess, Visitor};
    use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};

    use uuid::Uuid;

    pub fn deserialize<'de, D>(deserialiser: D) -> Result<Vec<DepExOpcode>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Depex;

        impl<'de> Visitor<'de> for Depex {
            type Value = DepExOpcode;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("dependency expression")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                DepExOpcode::deserialize(StrDeserializer::new(v))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let entry = map.next_entry::<String, Uuid>()?;
                let op = match entry.as_ref().map(|(k, v)| (k.as_ref(), v.into_bytes())) {
                    Some(("After", guid)) => DepExOpcode::After(guid),
                    Some(("Before", guid)) => DepExOpcode::Before(guid),
                    Some(("Push", guid)) => DepExOpcode::Push(guid),
                    _ => return Err(serde::de::Error::custom("invalid dependency expression")),
                };

                Ok(op)
            }
        }

        impl<'de> DeserializeSeed<'de> for Depex {
            type Value = DepExOpcode;

            fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                deserializer.deserialize_any(Depex)
            }
        }

        struct DepexOps;

        impl<'de> Visitor<'de> for DepexOps {
            type Value = Vec<DepExOpcode>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("dependency expressions")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut ops = seq.size_hint().map(Vec::with_capacity).unwrap_or_default();

                while let Some(op) = seq.next_element_seed(Depex)? {
                    ops.push(op);
                }

                Ok(ops)
            }
        }

        deserialiser.deserialize_any(DepexOps)
    }

    pub fn serialize<S>(value: &Vec<DepExOpcode>, serialiser: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        struct Depex<'a>(&'a DepExOpcode);

        fn serialize_guid<S>(serializer: S, name: &str, guid: &[u8; 16]) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let uuid = Uuid::from_bytes_le(*guid);
            let mut map = serializer.serialize_map(Some(1))?;
            map.serialize_entry(name, &uuid)?;
            map.end()
        }

        impl<'a> Serialize for Depex<'a> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                match self.0 {
                    DepExOpcode::And => serializer.serialize_str("And"),
                    DepExOpcode::Or => serializer.serialize_str("Or"),
                    DepExOpcode::Sor => serializer.serialize_str("Sor"),
                    DepExOpcode::Not => serializer.serialize_str("Not"),
                    DepExOpcode::End => serializer.serialize_str("End"),
                    DepExOpcode::True => serializer.serialize_str("True"),
                    DepExOpcode::False => serializer.serialize_str("False"),
                    DepExOpcode::After(guid) => serialize_guid(serializer, "After", guid),
                    DepExOpcode::Before(guid) => serialize_guid(serializer, "Before", guid),
                    DepExOpcode::Push(guid) => serialize_guid(serializer, "Push", guid),
                }
            }
        }

        struct DepexOps<'a>(&'a Vec<DepExOpcode>);

        impl<'a> Serialize for DepexOps<'a> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
                for e in self.0.iter() {
                    seq.serialize_element(&Depex(e))?;
                }
                seq.end()
            }
        }

        DepexOps(value).serialize(serialiser)
    }
}

pub type EFIModuleBuilder = PlatformBuilder<EFIModule>;

impl EFIModuleBuilder {
    pub fn from_attrs<'a, A>(kind: EFIModuleType, attrs: A) -> PlatformBuilder<EFIModule>
    where
        A: Into<Option<&'a PlatformAttributeMap>>,
    {
        let mut builder = Self::new();

        builder.push(EFIModuleAttribute::kind(kind));

        let Some(attrs) = attrs.into() else {
            return builder;
        };

        let guid = attrs.get_attr::<Uuid>("guid").unwrap_or_default();
        builder.push(EFIModuleAttribute::guid(guid));

        #[derive(serde::Deserialize)]
        struct DepEx {
            #[serde(with = "depex")]
            inner: Vec<DepExOpcode>,
        }

        let depex = attrs
            .get_attr::<DepEx>("depex")
            .map(|depex| depex.inner)
            .unwrap_or_default();

        builder.push(EFIModuleAttribute::depex(depex));

        let compilers = attrs
            .get_attr::<Compilers>("compiler_information")
            .unwrap_or_default();
        builder.push(EFIModuleAttribute::compiler_information(compilers));

        builder
    }
}

#[derive(Default)]
pub struct EFIModuleLoader;

impl EFIModuleLoader {
    pub const fn new() -> &'static Self {
        &EFIModuleLoader
    }
}

impl PlatformComponentBinaryLoader for EFIModuleLoader {
    fn load_bytes_with<'data, 'bytes>(
        &self,
        ldb: &LanguageDB,
        bytes: &'data BytesOrMapping<'bytes>,
        path: Option<PathBuf>,
    ) -> Result<PlatformComponentBinaryData<'data>, ComponentLoaderError> {
        let (lifter, loaded) =
            EFILoader::new(Cow::Borrowed(ldb)).load_bytes_with(bytes.as_ref(), path)?;
        Ok(PlatformComponentBinaryData(
            lifter,
            LoadedBinaryComponentData::EFI(loaded),
        ))
    }
}

#[derive(Default)]
pub struct EFIStandaloneLoader;

impl EFIStandaloneLoader {
    pub const fn new() -> &'static Self {
        &EFIStandaloneLoader
    }
}

impl PlatformComponentBinaryLoader for EFIStandaloneLoader {
    fn load_bytes_with<'data, 'bytes>(
        &self,
        ldb: &LanguageDB,
        bytes: &'data BytesOrMapping<'bytes>,
        path: Option<PathBuf>,
    ) -> Result<PlatformComponentBinaryData<'data>, ComponentLoaderError> {
        let (lifter, loaded) =
            EFILoader::new(Cow::Borrowed(ldb)).load_bytes_with(bytes.as_ref(), path)?;
        Ok(PlatformComponentBinaryData(
            lifter,
            LoadedBinaryComponentData::EFI(loaded),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EFIStandalone;

pub type EFIStandaloneBuilder = PlatformBuilder<EFIStandalone>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EFIAmdMicrocode;

pub type EFIAmdMicrocodeBuilder = PlatformBuilder<EFIAmdMicrocode>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EFIIntelMicrocode;

pub type EFIIntelMicrocodeBuilder = PlatformBuilder<EFIIntelMicrocode>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EFIVariable;

pub type EFIVariableBuilder = PlatformBuilder<EFIVariable>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EFIRawSection;

pub type EFIRawSectionBuilder = PlatformBuilder<EFIRawSection>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EFIFirmwareImage;

pub type EFIFirmwareImageBuilder = PlatformBuilder<EFIFirmwareImage>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EFIModuleAttribute {
    Name(String),
    Arch(ArchitectureDef),
    Kind(EFIModuleType),
    Guid(Uuid),
    Depex(Vec<DepExOpcode>),
    LoaderMetadata(BinaryLoaderMetadata),
    CompilerInformation(Compilers),
}

impl EFIModuleAttribute {
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }

    pub fn architecture(arch: impl Into<ArchitectureDef>) -> Self {
        Self::Arch(arch.into())
    }

    pub fn guid(guid: impl Into<Uuid>) -> Self {
        Self::Guid(guid.into())
    }

    pub fn kind(kind: EFIModuleType) -> Self {
        Self::Kind(kind)
    }

    pub fn depex(depex: impl Into<Vec<DepExOpcode>>) -> Self {
        Self::Depex(depex.into())
    }

    pub fn loader_metadata(meta: BinaryLoaderMetadata) -> Self {
        Self::LoaderMetadata(meta)
    }

    pub fn compiler_information(compilers: impl Into<Compilers>) -> Self {
        Self::CompilerInformation(compilers.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EFIStandaloneAttribute {
    Name(String),
    Path(PathBuf),
    Arch(ArchitectureDef),
    Kind(EFIModuleType),
    LoaderMetadata(BinaryLoaderMetadata),
    CompilerInformation(Compilers),
}

impl EFIStandaloneAttribute {
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }

    pub fn path(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }

    pub fn architecture(arch: impl Into<ArchitectureDef>) -> Self {
        Self::Arch(arch.into())
    }

    pub fn kind(kind: EFIModuleType) -> Self {
        Self::Kind(kind)
    }

    pub fn loader_metadata(meta: BinaryLoaderMetadata) -> Self {
        Self::LoaderMetadata(meta)
    }

    pub fn compiler_information(compilers: impl Into<Compilers>) -> Self {
        Self::CompilerInformation(compilers.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EFIAmdMicrocodeAttribute {
    CpuSignature(u32),
    Date(String),
    UpdateRevision(u32),
}

impl EFIAmdMicrocodeAttribute {
    pub fn cpu_signature(cpu_signature: u32) -> Self {
        Self::CpuSignature(cpu_signature)
    }

    pub fn date(date: impl Into<String>) -> Self {
        Self::Date(date.into())
    }

    pub fn update_revision(update_revision: u32) -> Self {
        Self::UpdateRevision(update_revision)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EFIIntelMicrocodeAttribute {
    CpuSignature(u32),
    Date(String),
    UpdateRevision(u32),
    ProcessorFlags(u8),
}

impl EFIIntelMicrocodeAttribute {
    pub fn cpu_signature(cpu_signature: u32) -> Self {
        Self::CpuSignature(cpu_signature)
    }

    pub fn date(date: impl Into<String>) -> Self {
        Self::Date(date.into())
    }

    pub fn update_revision(update_revision: u32) -> Self {
        Self::UpdateRevision(update_revision)
    }

    pub fn processor_flags(processor_flags: u8) -> Self {
        Self::ProcessorFlags(processor_flags)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EFIVariableAttribute {
    Name(String),
    Guid(Uuid),
    Attrs(u32),
    VarType(EFINvramVarType),
}

impl EFIVariableAttribute {
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }

    pub fn guid(guid: impl Into<Uuid>) -> Self {
        Self::Guid(guid.into())
    }

    pub fn attrs(attrs: u32) -> Self {
        Self::Attrs(attrs)
    }

    pub fn var_type(var_type: impl Into<EFINvramVarType>) -> Self {
        Self::VarType(var_type.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EFIRawSectionAttribute {
    Name(String),
    Guid(Uuid),
}

impl EFIRawSectionAttribute {
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }

    pub fn guid(guid: impl Into<Uuid>) -> Self {
        Self::Guid(guid.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EFIFirmwareAttribute {
    Name(String),
}

impl EFIFirmwareAttribute {
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }
}

#[derive(ProvidesStaticType)]
pub struct EFIComponentName<'a>(&'a str);
impl<'a> LoaderAttribute<'a> for EFIComponentName<'a> {
    const UUID: Uuid = uuid("EEED4203-A859-442C-9D41-D8FCDC4ECF36");
}

impl<'a> AsRef<str> for EFIComponentName<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for EFIComponentName<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct EFIComponentKind(EFIModuleType);
impl<'a> LoaderAttribute<'a> for EFIComponentKind {
    const UUID: Uuid = uuid("A973FADF-EDA7-4CDD-9B8D-0A602173EEDA");
}

impl AsRef<EFIModuleType> for EFIComponentKind {
    fn as_ref(&self) -> &EFIModuleType {
        &self.0
    }
}

impl<'a> Deref for EFIComponentKind {
    type Target = EFIModuleType;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct EFIComponentGuid(Uuid);
impl<'a> LoaderAttribute<'a> for EFIComponentGuid {
    const UUID: Uuid = uuid("A6EBEDF0-4C2A-4A59-9346-A4A5963664B4");
}

impl AsRef<Uuid> for EFIComponentGuid {
    fn as_ref(&self) -> &Uuid {
        &self.0
    }
}

impl<'a> Deref for EFIComponentGuid {
    type Target = Uuid;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct EFIComponentDepex<'a>(&'a [DepExOpcode]);
impl<'a> LoaderAttribute<'a> for EFIComponentDepex<'a> {
    const UUID: Uuid = uuid("CC9041B7-8840-44B8-BD23-12E7EC50F3B4");
}

impl<'a> AsRef<[DepExOpcode]> for EFIComponentDepex<'a> {
    fn as_ref(&self) -> &[DepExOpcode] {
        self.0
    }
}

impl<'a> Deref for EFIComponentDepex<'a> {
    type Target = [DepExOpcode];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct EFIMicrocodeDate<'a>(&'a str);
impl<'a> LoaderAttribute<'a> for EFIMicrocodeDate<'a> {
    const UUID: Uuid = uuid("72F802BA-21B2-4E72-9C89-733D4D8582CB");
}

impl<'a> AsRef<str> for EFIMicrocodeDate<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for EFIMicrocodeDate<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct EFIMicrocodeCpuSignature(u32);
impl LoaderAttribute<'_> for EFIMicrocodeCpuSignature {
    const UUID: Uuid = uuid("12299358-0D1F-4912-955B-F13B98A2E456");
}

impl AsRef<u32> for EFIMicrocodeCpuSignature {
    fn as_ref(&self) -> &u32 {
        &self.0
    }
}

impl Deref for EFIMicrocodeCpuSignature {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct EFIMicrocodeUpdateRevision(u32);
impl LoaderAttribute<'_> for EFIMicrocodeUpdateRevision {
    const UUID: Uuid = uuid("2D843C3D-E381-4133-964C-86B05221347B");
}

impl AsRef<u32> for EFIMicrocodeUpdateRevision {
    fn as_ref(&self) -> &u32 {
        &self.0
    }
}

impl Deref for EFIMicrocodeUpdateRevision {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct EFIMicrocodeProcessorFlags(u8);
impl LoaderAttribute<'_> for EFIMicrocodeProcessorFlags {
    const UUID: Uuid = uuid("3ADE1A47-7C3B-41BC-871B-B0F4055A369A");
}

impl AsRef<u8> for EFIMicrocodeProcessorFlags {
    fn as_ref(&self) -> &u8 {
        &self.0
    }
}

impl Deref for EFIMicrocodeProcessorFlags {
    type Target = u8;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct EFIVariableName<'a>(&'a str);
impl<'a> LoaderAttribute<'a> for EFIVariableName<'a> {
    const UUID: Uuid = uuid("9ED1F742-7BE6-4D65-9760-EFA520CB7CA3");
}

impl<'a> AsRef<str> for EFIVariableName<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for EFIVariableName<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct EFIVariableGuid(Uuid);
impl<'a> LoaderAttribute<'a> for EFIVariableGuid {
    const UUID: Uuid = uuid("407479F4-B23A-4F16-8133-14518387FF34");
}

impl AsRef<Uuid> for EFIVariableGuid {
    fn as_ref(&self) -> &Uuid {
        &self.0
    }
}

impl<'a> Deref for EFIVariableGuid {
    type Target = Uuid;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct EFIVariableAttrs(u32);
impl LoaderAttribute<'_> for EFIVariableAttrs {
    const UUID: Uuid = uuid("027EC9CE-CE62-4C9A-8761-2D15F3EA185C");
}

impl AsRef<u32> for EFIVariableAttrs {
    fn as_ref(&self) -> &u32 {
        &self.0
    }
}

impl Deref for EFIVariableAttrs {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct EFIVariableVarType(EFINvramVarType);
impl LoaderAttribute<'_> for EFIVariableVarType {
    const UUID: Uuid = uuid("89F18E6E-BC4C-42F4-ADF4-689CEE9CE227");
}

impl AsRef<EFINvramVarType> for EFIVariableVarType {
    fn as_ref(&self) -> &EFINvramVarType {
        &self.0
    }
}

impl Deref for EFIVariableVarType {
    type Target = EFINvramVarType;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct EFIRawSectionName<'a>(&'a str);
impl<'a> LoaderAttribute<'a> for EFIRawSectionName<'a> {
    const UUID: Uuid = uuid("1AA70F15-8E37-4466-B403-7069CB6DF917");
}

impl<'a> AsRef<str> for EFIRawSectionName<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for EFIRawSectionName<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct EFIRawSectionGuid(Uuid);
impl<'a> LoaderAttribute<'a> for EFIRawSectionGuid {
    const UUID: Uuid = uuid("D0E83D0D-4DF1-4AD2-846F-5726D2BC5318");
}

impl AsRef<Uuid> for EFIRawSectionGuid {
    fn as_ref(&self) -> &Uuid {
        &self.0
    }
}

impl<'a> Deref for EFIRawSectionGuid {
    type Target = Uuid;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PlatformProvider for EFIModule {
    type Attribute = EFIModuleAttribute;

    const NAME: &'static str = "efi-module";
    const LOADER: PlatformComponentLoader = PlatformComponentLoader::binary(EFIModuleLoader::new());
}

impl PlatformAttributeProvider for EFIModuleAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::Name(name) => {
                container.set_attr(EFIComponentName(name));
            }
            Self::Arch(arch) => {
                container.set_attr(EFIComponentArch(arch));
            }
            Self::Kind(kind) => {
                container.set_attr(EFIComponentKind(*kind));
            }
            Self::Guid(guid) => {
                container.set_attr(EFIComponentGuid(*guid));
            }
            Self::Depex(depex) => {
                container.set_attr(EFIComponentDepex(depex));
            }
            Self::LoaderMetadata(meta) => {
                container.set_attr(EFIModuleLoaderMetadata(meta));
            }
            Self::CompilerInformation(compilers) => {
                container.set_attr(EFIModuleCompilerInformation(compilers));
            }
        }
    }
}

#[derive(ProvidesStaticType)]
pub struct EFIStandaloneName<'a>(&'a str);
impl<'a> LoaderAttribute<'a> for EFIStandaloneName<'a> {
    const UUID: Uuid = uuid("A5F4764F-DA88-486E-AE19-59F957402092");
}

impl<'a> AsRef<str> for EFIStandaloneName<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for EFIStandaloneName<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct EFIStandalonePath<'a>(&'a Path);
impl<'a> LoaderAttribute<'a> for EFIStandalonePath<'a> {
    const UUID: Uuid = uuid("C4D06768-E1E6-4D2E-9816-DF7DDD87E9A1");
}

impl<'a> AsRef<Path> for EFIStandalonePath<'a> {
    fn as_ref(&self) -> &Path {
        self.0
    }
}

impl<'a> Deref for EFIStandalonePath<'a> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl PlatformProvider for EFIStandalone {
    type Attribute = EFIStandaloneAttribute;

    const NAME: &'static str = "efi-standalone";
    const LOADER: PlatformComponentLoader =
        PlatformComponentLoader::binary(EFIStandaloneLoader::new());
}

impl PlatformAttributeProvider for EFIStandaloneAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::Name(name) => {
                container.set_attr(EFIStandaloneName(name));
            }
            Self::Path(path) => {
                container.set_attr(EFIStandalonePath(path));
            }
            Self::Arch(arch) => {
                container.set_attr(EFIComponentArch(arch));
            }
            Self::Kind(kind) => {
                container.set_attr(EFIComponentKind(*kind));
            }
            Self::LoaderMetadata(meta) => {
                container.set_attr(EFIModuleLoaderMetadata(meta));
            }
            Self::CompilerInformation(compilers) => {
                container.set_attr(EFIModuleCompilerInformation(compilers));
            }
        }
    }
}

impl PlatformProvider for EFIAmdMicrocode {
    type Attribute = EFIAmdMicrocodeAttribute;

    const NAME: &'static str = "efi-microcode-amd";
    const LOADER: PlatformComponentLoader = PlatformComponentLoader::data();
}

impl PlatformAttributeProvider for EFIAmdMicrocodeAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::CpuSignature(cpu_signature) => {
                container.set_attr(EFIMicrocodeCpuSignature(*cpu_signature));
            }
            Self::Date(date) => {
                container.set_attr(EFIMicrocodeDate(date));
            }
            Self::UpdateRevision(update_revision) => {
                container.set_attr(EFIMicrocodeUpdateRevision(*update_revision));
            }
        }
    }
}

impl PlatformProvider for EFIIntelMicrocode {
    type Attribute = EFIIntelMicrocodeAttribute;

    const NAME: &'static str = "efi-microcode-intel";
    const LOADER: PlatformComponentLoader = PlatformComponentLoader::data();
}

impl PlatformAttributeProvider for EFIIntelMicrocodeAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::CpuSignature(cpu_signature) => {
                container.set_attr(EFIMicrocodeCpuSignature(*cpu_signature));
            }
            Self::Date(date) => {
                container.set_attr(EFIMicrocodeDate(date));
            }
            Self::ProcessorFlags(processor_flags) => {
                container.set_attr(EFIMicrocodeProcessorFlags(*processor_flags));
            }
            Self::UpdateRevision(update_revision) => {
                container.set_attr(EFIMicrocodeUpdateRevision(*update_revision));
            }
        }
    }
}

impl PlatformProvider for EFIVariable {
    type Attribute = EFIVariableAttribute;

    const NAME: &'static str = "efi-variable";
    const LOADER: PlatformComponentLoader = PlatformComponentLoader::data();
}

impl PlatformAttributeProvider for EFIVariableAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::Name(name) => {
                container.set_attr(EFIVariableName(name));
            }
            Self::Guid(guid) => {
                container.set_attr(EFIVariableGuid(*guid));
            }
            Self::Attrs(attrs) => {
                container.set_attr(EFIVariableAttrs(*attrs));
            }
            Self::VarType(var_type) => {
                container.set_attr(EFIVariableVarType(*var_type));
            }
        }
    }
}

impl PlatformProvider for EFIRawSection {
    type Attribute = EFIRawSectionAttribute;

    const NAME: &'static str = "efi-raw-section";
    const LOADER: PlatformComponentLoader = PlatformComponentLoader::data();
}

impl PlatformAttributeProvider for EFIRawSectionAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::Name(name) => {
                container.set_attr(EFIRawSectionName(name));
            }
            Self::Guid(guid) => {
                container.set_attr(EFIRawSectionGuid(*guid));
            }
        }
    }
}

impl PlatformProvider for EFIFirmwareImage {
    type Attribute = EFIFirmwareAttribute;

    const NAME: &'static str = "efi-firmware";
    const LOADER: PlatformComponentLoader = PlatformComponentLoader::data();
}

impl PlatformAttributeProvider for EFIFirmwareAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::Name(name) => {
                container.set_attr(EFIComponentName(name));
            }
        }
    }
}

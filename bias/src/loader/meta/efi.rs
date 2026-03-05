use std::fmt;

use bias_core::efi::image::depex::DepExOpcode;
use bias_core::efi::{EFIModuleType, EFINvramVarType};
use bias_core::prelude::*;

use crate::platform::common::{BinaryLoaderMetadata, CompilerInformation, Compilers};

use serde::de::value::StrDeserializer;
use serde::de::{DeserializeSeed, SeqAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Serialize};

use crate::loader::util::{arch_deserialiser, arch_serialiser};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct EFIModuleAttributes {
    #[serde(default)]
    guid: Uuid,
    kind: EFIModuleType,
    #[serde(
        default,
        deserialize_with = "depex_deserialiser",
        serialize_with = "depex_serialiser"
    )]
    depex: Vec<DepExOpcode>,
    #[serde(
        default,
        deserialize_with = "arch_deserialiser",
        serialize_with = "arch_serialiser"
    )]
    architecture: Option<ArchitectureDef>,
    #[serde(default)]
    loader_metadata: Option<BinaryLoaderMetadata>,
    #[serde(default)]
    compiler_information: Compilers,
}

impl EFIModuleAttributes {
    pub fn new(guid: impl Into<Uuid>, kind: impl Into<EFIModuleType>) -> Self {
        Self::new_with(guid, kind, Vec::with_capacity(0))
    }

    pub fn new_with(
        guid: impl Into<Uuid>,
        kind: impl Into<EFIModuleType>,
        depex: impl Into<Vec<DepExOpcode>>,
    ) -> Self {
        Self {
            guid: guid.into(),
            kind: kind.into(),
            depex: depex.into(),
            ..Default::default()
        }
    }

    pub fn guid(&self) -> Uuid {
        self.guid
    }

    pub fn kind(&self) -> EFIModuleType {
        self.kind
    }

    pub fn depex(&self) -> &[DepExOpcode] {
        &self.depex
    }

    pub fn set_depex(&mut self, depex: impl Into<Vec<DepExOpcode>>) {
        self.depex = depex.into();
    }

    pub fn with_depex(mut self, depex: impl Into<Vec<DepExOpcode>>) -> Self {
        self.set_depex(depex);
        self
    }

    pub fn architecture(&self) -> Option<&ArchitectureDef> {
        self.architecture.as_ref()
    }

    pub fn set_architecture(&mut self, architecture: impl Into<Option<ArchitectureDef>>) {
        self.architecture = architecture.into()
    }

    pub fn with_architecture(mut self, architecture: impl Into<Option<ArchitectureDef>>) -> Self {
        self.set_architecture(architecture);
        self
    }

    pub fn loader_metadata(&self) -> Option<&BinaryLoaderMetadata> {
        self.loader_metadata.as_ref()
    }

    pub fn set_loader_metadata(&mut self, meta: impl Into<Option<BinaryLoaderMetadata>>) {
        self.loader_metadata = meta.into();
    }

    pub fn with_loader_metadata(mut self, meta: impl Into<Option<BinaryLoaderMetadata>>) -> Self {
        self.set_loader_metadata(meta);
        self
    }

    pub fn compiler_information(&self) -> &Compilers {
        &self.compiler_information
    }

    pub fn set_compiler_information(
        &mut self,
        compiler_information: impl IntoIterator<Item = CompilerInformation>,
    ) {
        self.compiler_information = compiler_information.into_iter().collect();
    }

    pub fn add_compiler_information(
        &mut self,
        compiler_information: impl Into<CompilerInformation>,
    ) {
        self.compiler_information
            .insert(compiler_information.into());
    }

    pub fn with_compiler_information(
        mut self,
        compilers: impl IntoIterator<Item = CompilerInformation>,
    ) -> Self {
        self.set_compiler_information(compilers);
        self
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct EFIStandaloneAttributes {
    kind: EFIModuleType,
    #[serde(
        default,
        deserialize_with = "arch_deserialiser",
        serialize_with = "arch_serialiser"
    )]
    architecture: Option<ArchitectureDef>,
    #[serde(default)]
    loader_metadata: Option<BinaryLoaderMetadata>,
    #[serde(default)]
    compiler_information: Compilers,
}

impl EFIStandaloneAttributes {
    pub fn new(kind: impl Into<EFIModuleType>) -> Self {
        Self {
            kind: kind.into(),
            ..Default::default()
        }
    }

    pub fn kind(&self) -> EFIModuleType {
        self.kind
    }

    pub fn architecture(&self) -> Option<&ArchitectureDef> {
        self.architecture.as_ref()
    }

    pub fn set_architecture(&mut self, architecture: impl Into<Option<ArchitectureDef>>) {
        self.architecture = architecture.into()
    }

    pub fn with_architecture(mut self, architecture: impl Into<Option<ArchitectureDef>>) -> Self {
        self.set_architecture(architecture);
        self
    }

    pub fn loader_metadata(&self) -> Option<&BinaryLoaderMetadata> {
        self.loader_metadata.as_ref()
    }

    pub fn set_loader_metadata(&mut self, meta: impl Into<Option<BinaryLoaderMetadata>>) {
        self.loader_metadata = meta.into();
    }

    pub fn with_loader_metadata(mut self, meta: impl Into<Option<BinaryLoaderMetadata>>) -> Self {
        self.set_loader_metadata(meta);
        self
    }

    pub fn compiler_information(&self) -> &Compilers {
        &self.compiler_information
    }

    pub fn set_compiler_information(
        &mut self,
        compiler_information: impl IntoIterator<Item = CompilerInformation>,
    ) {
        self.compiler_information = compiler_information.into_iter().collect();
    }

    pub fn add_compiler_information(
        &mut self,
        compiler_information: impl Into<CompilerInformation>,
    ) {
        self.compiler_information
            .insert(compiler_information.into());
    }

    pub fn with_compiler_information(
        mut self,
        compilers: impl IntoIterator<Item = CompilerInformation>,
    ) -> Self {
        self.set_compiler_information(compilers);
        self
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EFIAmdMicrocodeAttributes {
    cpu_signature: u32,
    date: String,
    update_revision: u32,
}

impl EFIAmdMicrocodeAttributes {
    pub fn new(cpu_signature: u32, date: impl Into<String>, update_revision: u32) -> Self {
        Self {
            cpu_signature,
            date: date.into(),
            update_revision,
        }
    }

    pub fn cpu_signature(&self) -> u32 {
        self.cpu_signature
    }

    pub fn date(&self) -> &str {
        &self.date
    }

    pub fn update_revision(&self) -> u32 {
        self.update_revision
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EFIIntelMicrocodeAttributes {
    cpu_signature: u32,
    date: String,
    update_revision: u32,
    processor_flags: u8,
}

impl EFIIntelMicrocodeAttributes {
    pub fn new(
        cpu_signature: u32,
        date: impl Into<String>,
        update_revision: u32,
        processor_flags: u8,
    ) -> Self {
        Self {
            cpu_signature,
            date: date.into(),
            update_revision,
            processor_flags,
        }
    }

    pub fn cpu_signature(&self) -> u32 {
        self.cpu_signature
    }

    pub fn date(&self) -> &str {
        &self.date
    }

    pub fn update_revision(&self) -> u32 {
        self.update_revision
    }

    pub fn processor_flags(&self) -> u8 {
        self.processor_flags
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EFIVariableAttributes {
    name: String,
    guid: Uuid,
    attrs: u32,
    var_type: EFINvramVarType,
}

impl EFIVariableAttributes {
    pub fn new(
        name: impl Into<String>,
        guid: impl Into<Uuid>,
        attrs: u32,
        var_type: EFINvramVarType,
    ) -> Self {
        Self {
            name: name.into(),
            guid: guid.into(),
            attrs,
            var_type,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn guid(&self) -> Uuid {
        self.guid
    }

    pub fn attrs(&self) -> u32 {
        self.attrs
    }

    pub fn var_type(&self) -> EFINvramVarType {
        self.var_type
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EFIRawSectionAttributes {
    name: String,
    guid: Uuid,
}

impl EFIRawSectionAttributes {
    pub fn new(name: impl Into<String>, guid: impl Into<Uuid>) -> Self {
        Self {
            name: name.into(),
            guid: guid.into(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn guid(&self) -> Uuid {
        self.guid
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EFIFirmwareImageAttributes;

impl EFIFirmwareImageAttributes {
    pub fn new() -> Self {
        Self
    }
}

pub fn depex_deserialiser<'de, D>(deserialiser: D) -> Result<Vec<DepExOpcode>, D::Error>
where
    D: serde::Deserializer<'de>,
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

pub fn depex_serialiser<S>(value: &Vec<DepExOpcode>, serialiser: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    struct Depex<'a>(&'a DepExOpcode);

    fn serialize_guid<S>(serializer: S, name: &str, guid: &[u8; 16]) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
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

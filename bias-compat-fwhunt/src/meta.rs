use std::hash::Hash;
use std::iter::{self, repeat};

use ahash::{AHashMap as Map, AHashSet as Set};

use bias_core::fugue::bytes::Endian;
use bias_core::kb::Lazy;
use bias_core::prelude::{ArchitectureDef, Lifter};

use bias::pipeline::types::Severity;

use serde::{de, Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use crate::severity::meta_severity;

#[derive(Debug, Clone, PartialEq, Eq, Hash, getset::Getters, getset::MutGetters, serde::Deserialize, serde::Serialize)]
pub struct Link {
    #[getset(get = "pub", get_mut = "pub")]
    title: String,
    #[getset(get = "pub", get_mut = "pub")]
    link: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, getset::Getters, getset::MutGetters, serde::Deserialize, serde::Serialize)]
pub struct Advisory {
    #[getset(get = "pub", get_mut = "pub")]
    title: String,
    #[getset(get = "pub", get_mut = "pub")]
    links: Vec<Link>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, getset::Getters, getset::MutGetters, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct VolumeGuid {
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(deserialize_with = "crate::guids::deserialize_guid")]
    uuid: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum RuleTarget {
    #[serde(rename = "firmware")]
    Firmware,
    #[serde(rename = "module")]
    Module,
    #[serde(rename = "boot-loader", alias = "bootloader", alias = "boot loader")]
    BootLoader,
    #[serde(rename = "raw section or variable")]
    RawSectionOrVariable,
}

impl Default for RuleTarget {
    fn default() -> Self {
        Self::Module
    }
}

impl RuleTarget {
    #[inline]
    pub fn is_firmware(&self) -> bool {
        matches!(self, Self::Firmware)
    }

    #[inline]
    pub fn is_module(&self) -> bool {
        matches!(self, Self::Module)
    }

    #[inline]
    pub fn is_bootloader(&self) -> bool {
        matches!(self, Self::BootLoader)
    }

    #[inline]
    pub fn is_raw_section_or_variable(&self) -> bool {
        matches!(self, Self::RawSectionOrVariable)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, getset::Getters, getset::MutGetters)]
pub struct RuleArch {
    #[getset(get = "pub", get_mut = "pub")]
    processor: Option<String>,
    #[getset(get = "pub", get_mut = "pub")]
    endian: Option<Endian>,
    #[getset(get = "pub", get_mut = "pub")]
    bits: Option<u32>,
}

impl RuleArch {
    pub fn new(processor: impl Into<String>, endian: Endian) -> Self {
        Self::new_with(processor, endian, None)
    }

    pub fn new_with(
        processor: impl Into<String>,
        endian: Endian,
        bits: impl Into<Option<u32>>,
    ) -> Self {
        Self {
            processor: Some(processor.into()),
            endian: Some(endian),
            bits: bits.into(),
        }
    }

    pub fn x86() -> Self {
        Self::new("X86", Endian::Little)
    }

    pub fn amd64() -> Self {
        Self::new_with("X86", Endian::Little, 64)
    }

    pub fn i386() -> Self {
        Self::new_with("X86", Endian::Little, 32)
    }

    pub fn aarch64() -> Self {
        Self::new_with("AARCH64", Endian::Little, 64)
    }

    pub fn arm64() -> Self {
        Self::aarch64()
    }

    pub fn matches_with(&self, larch: &ArchitectureDef) -> bool {
        (self.processor.is_none()
            || matches!(self.processor.as_ref(), Some(processor) if larch.processor().eq_ignore_ascii_case(processor)))
            && (self.endian.is_none()
                || matches!(self.endian, Some(endian) if larch.endian() == endian))
            && (self.bits.is_none()
                || matches!(self.bits, Some(bits) if bits == larch.bits() as u32))
    }
}

impl<'de> Deserialize<'de> for RuleArch {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let parts = s.splitn(3, ':').collect::<Vec<_>>();
        if parts.len() != 3 {
            return Err(de::Error::custom("architecture format is incorrect"));
        }

        let processor = if parts[0] == "*" {
            None
        } else {
            Some(parts[0].to_owned())
        };

        let endian = match parts[1] {
            "*" => None,
            "le" | "LE" => Some(Endian::Little),
            "be" | "BE" => Some(Endian::Big),
            _ => {
                return Err(de::Error::custom(
                    "invalid architecture endian (should be LE or BE)",
                ))
            }
        };

        let bits = if parts[2] == "*" {
            None
        } else {
            match parts[2].parse::<u32>() {
                Ok(bits) => Some(bits),
                Err(_) => {
                    return Err(de::Error::custom(
                        "invalid architecture bits (should be numeric or '*')",
                    ))
                }
            }
        };

        Ok(RuleArch {
            processor,
            endian,
            bits,
        })
    }
}

impl Serialize for RuleArch {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let endian = match self.endian {
            Some(Endian::Big) => "BE",
            Some(Endian::Little) => "LE",
            None => "*",
        };

        let bits = self
            .bits
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "*".to_owned());

        let parts = format!(
            "{}:{}:{}",
            self.processor.as_deref().unwrap_or("*"),
            endian,
            bits
        );

        serializer.serialize_str(&parts)
    }
}

fn empty_volume_guids(guids: &Set<VolumeGuid>) -> bool {
    guids.is_empty()
}

fn empty_urls(urls: &Set<Link>) -> bool {
    urls.is_empty()
}

fn empty_advisories(advisories: &Set<Advisory>) -> bool {
    advisories.is_empty()
}

fn deserialise_cve_numbers<'de, D>(deserialiser: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum R {
        One(String),
        Many(Vec<String>),
    }

    Ok(match R::deserialize(deserialiser)? {
        R::One(n) => vec![n],
        R::Many(ns) => ns,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, getset::Getters, getset::MutGetters, serde::Deserialize, serde::Serialize)]
pub struct CVSS {
    #[getset(get = "pub", get_mut = "pub")]
    version: String,
    #[getset(get = "pub", get_mut = "pub")]
    score: Option<String>,
    #[getset(get = "pub", get_mut = "pub")]
    severity: String,
    #[getset(get = "pub", get_mut = "pub")]
    vector: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, getset::Getters, getset::MutGetters, serde::Serialize, serde::Deserialize)]
pub struct Meta {
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    author: String,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    license: String,
    #[getset(get = "pub", get_mut = "pub")]
    name: String,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    version: String,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    namespace: String,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    vendor_id: String,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(
        rename = "CVE number",
        alias = "CVE numbers",
        default,
        deserialize_with = "deserialise_cve_numbers",
        skip_serializing_if = "Vec::is_empty"
    )]
    cve_numbers: Vec<String>,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cvss: Option<CVSS>,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    advisory: String,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    url: String,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    description: String,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(default, skip_serializing_if = "RuleTarget::is_module")]
    target: RuleTarget,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(default)]
    architecture: RuleArch,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(
        rename = "volume guids",
        default,
        skip_serializing_if = "empty_volume_guids"
    )]
    volume_guids: Set<VolumeGuid>,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(rename = "title", default, skip_serializing_if = "String::is_empty")]
    title: String,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(
        rename = "long_description",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    long_description: String,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(rename = "impact", default, skip_serializing_if = "String::is_empty")]
    impact: String,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(
        rename = "recommended_action",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    recommended_action: String,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(rename = "urls", default, skip_serializing_if = "empty_urls")]
    urls: Set<Link>,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(
        rename = "advisories",
        default,
        skip_serializing_if = "empty_advisories"
    )]
    advisories: Set<Advisory>,
    #[getset(get = "pub", get_mut = "pub")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tags: Vec<Tag>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize)]
pub struct Tag {
    kind: String,
    value: String,
}

impl Tag {
    pub fn new(kind: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            value: value.into(),
        }
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

const KNOWN_NAMESPACES: Lazy<Map<&'static str, Severity>> = Lazy::new(|| {
    let mut known = Map::default();
    known.insert("vulnerabilities", Severity::Critical);
    known.extend(
        [
            "mitigationfailures",
            "mitigation-failures",
            "mitigation failures",
        ]
        .into_iter()
        .zip(repeat(Severity::Medium)),
    );
    known.extend(
        ["supplychain", "supply-chain", "supply chain"]
            .into_iter()
            .zip(repeat(Severity::High)),
    );
    known.insert("threats", Severity::High);
    known
});

impl Meta {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    pub fn namespace_severity(&self) -> Severity {
        KNOWN_NAMESPACES
            .get(&&*self.namespace().to_lowercase())
            .copied()
            .unwrap_or(Severity::High)
    }

    pub fn has_known_namespace(&self) -> bool {
        KNOWN_NAMESPACES.contains_key(&&*self.namespace().to_lowercase())
    }

    pub fn severity(&self) -> Severity {
        meta_severity(self)
    }

    pub fn cve_number(&self) -> Option<&str> {
        self.cve_numbers.first().map(String::as_str)
    }

    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = author.into();
        self
    }

    pub fn set_author(&mut self, author: impl Into<String>) {
        self.author = author.into();
    }

    pub fn with_license(mut self, license: impl Into<String>) -> Self {
        self.license = license.into();
        self
    }

    pub fn set_license(&mut self, license: impl Into<String>) {
        self.license = license.into();
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    pub fn set_version(&mut self, version: impl Into<String>) {
        self.version = version.into();
    }

    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = namespace.into();
        self
    }

    pub fn set_namespace(&mut self, namespace: impl Into<String>) {
        self.namespace = namespace.into();
    }

    pub fn with_vendor(mut self, vendor: impl Into<String>) -> Self {
        self.vendor_id = vendor.into();
        self
    }

    pub fn set_vendor(&mut self, vendor: impl Into<String>) {
        self.vendor_id = vendor.into();
    }

    pub fn with_cve_number(mut self, cve_number: impl Into<String>) -> Self {
        self.cve_numbers.push(cve_number.into());
        self
    }

    pub fn set_cve_number(&mut self, cve_number: impl Into<String>) {
        self.cve_numbers.push(cve_number.into());
    }

    pub fn with_advisory(mut self, advisory: impl Into<String>) -> Self {
        self.advisory = advisory.into();
        self
    }

    pub fn set_advisory(&mut self, advisory: impl Into<String>) {
        self.advisory = advisory.into();
    }

    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = url.into();
        self
    }

    pub fn set_url(&mut self, url: impl Into<String>) {
        self.url = url.into();
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    pub fn set_description(&mut self, description: impl Into<String>) {
        self.description = description.into();
    }

    pub fn with_target(mut self, target: RuleTarget) -> Self {
        self.target = target;
        self
    }

    pub fn set_target(&mut self, target: RuleTarget) {
        self.target = target;
    }

    pub fn with_architecture(mut self, architecture: RuleArch) -> Self {
        self.architecture = architecture;
        self
    }

    pub fn set_architecture(&mut self, architecture: RuleArch) {
        self.architecture = architecture;
    }

    pub fn with_tags(mut self, tags: impl Iterator<Item = Tag>) -> Self {
        self.tags = tags.collect();
        self
    }

    pub fn set_tag(&mut self, tag: Tag) {
        self.tags.clear();
        self.tags.push(tag);
    }

    pub fn with_tag(self, tag: Tag) -> Self {
        self.with_tags(iter::once(tag))
    }

    pub fn with_volume_guids(mut self, guids: impl Iterator<Item = Uuid>) -> Self {
        self.volume_guids = guids.into_iter().map(|uuid| VolumeGuid { uuid }).collect();
        self
    }

    pub fn set_volume_guid(&mut self, guid: Uuid) {
        self.volume_guids.clear();
        self.volume_guids.insert(VolumeGuid { uuid: guid });
    }

    pub fn with_volume_guid(self, guid: Uuid) -> Self {
        self.with_volume_guids(iter::once(guid))
    }

    pub fn should_scan(&self, uuid: &Uuid) -> bool {
        self.target.is_module()
            && (self.volume_guids.is_empty()
                || self.volume_guids.contains(&VolumeGuid { uuid: *uuid }))
    }

    pub fn should_scan_target(&self, target: &RuleTarget) -> bool {
        &self.target == target
    }

    pub fn should_scan_standalone(&self) -> bool {
        self.target.is_bootloader() || (self.target().is_module() && self.volume_guids().is_empty())
    }

    pub fn should_scan_arch(&self, lifter: &Lifter) -> bool {
        let arch = &self.architecture;
        let larch = lifter.translator().architecture();

        arch.matches_with(larch)
    }

    pub fn should_scan_raw_section(&self, uuid: &Uuid) -> bool {
        self.target.is_raw_section_or_variable()
            && (self.volume_guids.is_empty()
                || self.volume_guids.contains(&VolumeGuid { uuid: *uuid }))
    }
}

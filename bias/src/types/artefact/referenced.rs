use std::borrow::Cow;
use std::fmt::Display;
use std::str::FromStr;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::types::artefact::data::{OffsetRange, OffsetRangeError};
use crate::types::artefact::BIAS_ARTEFACT_NAMESPACE;
use crate::types::common::{AttributeMap, Fingerprint, Note, Reference};
use crate::types::standards::{CPEError, PURLError, CPE, PURL};

pub use spdx;

#[derive(Debug, Clone, PartialEq)]
pub enum LicenseExpression {
    Proprietary,
    Spdx(spdx::Expression),
}

impl<'de> Deserialize<'de> for LicenseExpression {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <Cow<str> as serde::Deserialize>::deserialize(deserializer)?;

        match s.as_ref() {
            "proprietary" | "Proprietary" => Ok(Self::Proprietary),
            s => spdx::Expression::parse_mode(s, spdx::ParseMode::LAX)
                .map(Self::Spdx)
                .map_err(serde::de::Error::custom),
        }
    }
}

impl Serialize for LicenseExpression {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        <String as serde::Serialize>::serialize(&self.to_string(), serializer)
    }
}

#[derive(Debug, Error)]
pub enum LicenseError {
    #[error("invalid license expression")]
    Invalid(spdx::ParseError),
    #[error("missing license error")]
    Missing,
}

impl Display for LicenseExpression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proprietary { .. } => f.write_str("Proprietary"),
            Self::Spdx(ref spdx) => spdx.fmt(f),
        }
    }
}

impl FromStr for LicenseExpression {
    type Err = LicenseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("proprietary") {
            return Ok(LicenseExpression::Proprietary {});
        }

        Ok(LicenseExpression::Spdx(
            spdx::Expression::parse_mode(s, spdx::ParseMode::LAX).map_err(LicenseError::Invalid)?,
        ))
    }
}

impl Eq for LicenseExpression {}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ReferencedArtefactIdentity {
    #[serde(with = "hex")]
    md5: [u8; 16],
    #[serde(with = "hex")]
    sha1: [u8; 20],
    #[serde(with = "hex")]
    sha256: [u8; 32],
}

#[derive(Debug, Error)]
pub enum ReferencedArtefactIdentityError {
    #[error("invalid md5 hash")]
    InvalidMd5,
    #[error("invalid sha-1 hash")]
    InvalidSha1,
    #[error("invalid sha-256 hash")]
    InvalidSha256,
}

impl ReferencedArtefactIdentity {
    pub fn new(bytes: impl AsRef<[u8]>) -> Self {
        let bytes = bytes.as_ref();
        Self::from_parts(
            <md5::Md5 as md5::Digest>::digest(bytes),
            <sha1::Sha1 as sha1::Digest>::digest(bytes),
            <sha2::Sha256 as sha2::Digest>::digest(bytes),
        )
    }

    pub fn from_parts(
        md5: impl Into<[u8; 16]>,
        sha1: impl Into<[u8; 20]>,
        sha256: impl Into<[u8; 32]>,
    ) -> Self {
        Self {
            md5: md5.into(),
            sha1: sha1.into(),
            sha256: sha256.into(),
        }
    }

    pub fn id(&self) -> Uuid {
        let mut bytes = [0u8; 16 + 20 + 32];

        bytes[..16].copy_from_slice(self.md5());
        bytes[16..36].copy_from_slice(self.sha1());
        bytes[36..].copy_from_slice(self.sha256());

        Uuid::new_v5(&BIAS_ARTEFACT_NAMESPACE, bytes.as_ref())
    }

    pub fn md5(&self) -> &[u8; 16] {
        &self.md5
    }

    pub fn sha1(&self) -> &[u8; 20] {
        &self.sha1
    }

    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub enum ReferencedArtefactLinkage {
    #[serde(rename = "unspecified")]
    Unspecified,
    #[serde(rename = "derived")]
    Derived,
    #[serde(rename = "embedded")]
    Embedded,
    #[serde(rename = "external")]
    External,
    #[serde(rename = "project")]
    Project,
    #[serde(rename = "build")]
    Build,
    #[serde(rename = "vendored")]
    Vendored,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ReferencedArtefactProvenance {
    vendor: Cow<'static, str>,
    product: Cow<'static, str>,
    #[serde(default)]
    version: Option<Cow<'static, str>>,
    #[serde(default)]
    license: Option<LicenseExpression>,
    #[serde(default)]
    cpe: Option<CPE>,
    #[serde(default)]
    purl: Option<PURL>,
    #[serde(default)]
    references: Vec<Reference>,
    #[serde(default)]
    notes: Vec<Note>,
}

#[derive(Debug, Error)]
pub enum ReferencedArtefactProvenanceError {
    #[error("invalid CPE: {0}")]
    InvalidCPE(#[from] CPEError),
    #[error("invalid license/SPDX license expression")]
    InvalidLicense,
    #[error("invalid PURL: {0}")]
    InvalidPURL(#[from] PURLError),
}

impl ReferencedArtefactProvenance {
    pub fn new(
        vendor: impl Into<Cow<'static, str>>,
        product: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            vendor: vendor.into(),
            product: product.into(),
            version: None,
            license: None,
            cpe: None,
            purl: None,
            references: Vec::new(),
            notes: Vec::new(),
        }
    }

    pub fn set_vendor(&mut self, vendor: impl Into<Cow<'static, str>>) {
        self.vendor = vendor.into();
    }

    pub fn with_vendor(mut self, vendor: impl Into<Cow<'static, str>>) -> Self {
        self.set_vendor(vendor);
        self
    }

    pub fn vendor(&self) -> &str {
        self.vendor.as_ref()
    }

    pub fn set_product(&mut self, product: impl Into<Cow<'static, str>>) {
        self.product = product.into();
    }

    pub fn with_product(mut self, product: impl Into<Cow<'static, str>>) -> Self {
        self.set_product(product);
        self
    }

    pub fn product(&self) -> &str {
        self.product.as_ref()
    }

    pub fn set_version(&mut self, version: impl Into<Cow<'static, str>>) {
        self.version = Some(version.into());
    }

    pub fn with_version(mut self, version: impl Into<Cow<'static, str>>) -> Self {
        self.set_version(version);
        self
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    // If the license is invalid this clears the current license, and returns false.
    pub fn try_set_license(&mut self, license: impl AsRef<str>) -> bool {
        let Ok(license) = license.as_ref().parse::<LicenseExpression>() else {
            self.license = None;
            return false;
        };

        self.license = Some(license);
        true
    }

    // If the license is invalid this function panics; for the non-panicing version see
    // [`Self::try_set_license`].
    pub fn set_license(&mut self, license: impl AsRef<str>) {
        self.license = Some(license.as_ref().parse::<LicenseExpression>().unwrap());
    }

    // If the license is invalid this has the same behaviour as [`Self::try_set_license`].
    pub fn with_license(mut self, license: impl AsRef<str>) -> Self {
        self.try_set_license(license);
        self
    }

    pub fn license(&self) -> Option<&LicenseExpression> {
        self.license.as_ref()
    }

    pub fn set_cpe(&mut self, cpe: impl Into<CPE>) {
        self.cpe = Some(cpe.into());
    }

    pub fn with_cpe(mut self, cpe: impl Into<CPE>) -> Self {
        self.set_cpe(cpe);
        self
    }

    pub fn cpe(&self) -> Option<&CPE> {
        self.cpe.as_ref()
    }

    pub fn set_purl(&mut self, purl: impl Into<PURL>) {
        self.purl = Some(purl.into());
    }

    pub fn with_purl(mut self, purl: impl Into<PURL>) -> Self {
        self.set_purl(purl);
        self
    }

    pub fn purl(&self) -> Option<&PURL> {
        self.purl.as_ref()
    }

    pub fn add_reference(&mut self, reference: impl Into<Reference>) {
        self.references.push(reference.into());
    }

    pub fn with_reference(mut self, reference: impl Into<Reference>) -> Self {
        self.add_reference(reference);
        self
    }

    pub fn add_references<T>(&mut self, references: impl IntoIterator<Item = T>)
    where
        T: Into<Reference>,
    {
        for reference in references.into_iter() {
            self.add_reference(reference);
        }
    }

    pub fn with_references<T>(mut self, references: impl IntoIterator<Item = T>) -> Self
    where
        T: Into<Reference>,
    {
        self.add_references(references);
        self
    }

    pub fn references(&self) -> &[Reference] {
        &self.references
    }

    pub fn references_mut(&mut self) -> &mut Vec<Reference> {
        &mut self.references
    }

    pub fn has_references(&self) -> bool {
        !self.references.is_empty()
    }

    pub fn add_note(&mut self, note: impl Into<Note>) {
        self.notes.push(note.into());
    }

    pub fn with_note(mut self, note: impl Into<Note>) -> Self {
        self.add_note(note);
        self
    }

    pub fn add_notes<T>(&mut self, notes: impl IntoIterator<Item = T>)
    where
        T: Into<Note>,
    {
        for note in notes.into_iter() {
            self.add_note(note);
        }
    }

    pub fn with_notes<T>(mut self, notes: impl IntoIterator<Item = T>) -> Self
    where
        T: Into<Note>,
    {
        self.add_notes(notes);
        self
    }

    pub fn notes(&self) -> &[Note] {
        &self.notes
    }

    pub fn notes_mut(&mut self) -> &mut Vec<Note> {
        &mut self.notes
    }

    pub fn has_notes(&self) -> bool {
        !self.notes.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum ReferencedArtefactParentKind {
    #[serde(rename = "component")]
    Component,
    #[serde(rename = "artefact")]
    Artefact,
}

impl ReferencedArtefactParentKind {
    pub fn is_component(&self) -> bool {
        matches!(self, Self::Component)
    }

    pub fn is_artefact(&self) -> bool {
        matches!(self, Self::Artefact)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ReferencedArtefact {
    id: Uuid,
    parent_id: Uuid,
    parent_kind: ReferencedArtefactParentKind,
    external_artefact_id: Option<Uuid>,
    name: Cow<'static, str>,
    kind: Cow<'static, str>,
    ranges: Vec<OffsetRange>,
    hashes: Option<ReferencedArtefactIdentity>,
    provenance: Option<ReferencedArtefactProvenance>,
    linkage: ReferencedArtefactLinkage,
    attributes: AttributeMap,
}

#[derive(Debug, Error)]
pub enum ReferencedArtefactError {
    #[error("missing ID")]
    NoId,
    #[error("missing parent ID")]
    NoParentId,
    #[error(transparent)]
    InvalidRange(#[from] OffsetRangeError),
    #[error(transparent)]
    InvalidIdentity(#[from] ReferencedArtefactIdentityError),
    #[error(transparent)]
    InvalidProvenance(#[from] ReferencedArtefactProvenanceError),
    #[error("unsupported parent kind")]
    UnsupportedParentKind,
    #[error("unsupported linkage kind")]
    UnsupportedLinkage,
}

impl ReferencedArtefact {
    pub fn new(
        id: impl Into<Uuid>,
        parent: impl Into<Uuid>,
        name: impl Into<Cow<'static, str>>,
        kind: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            id: id.into(),
            parent_id: parent.into(),
            parent_kind: ReferencedArtefactParentKind::Component,
            external_artefact_id: None,
            name: name.into(),
            kind: kind.into(),
            ranges: Vec::new(),
            hashes: None,
            provenance: None,
            linkage: ReferencedArtefactLinkage::Unspecified,
            attributes: AttributeMap::new(),
        }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn set_parent(&mut self, id: impl Into<Uuid>) {
        self.parent_id = id.into();
    }

    pub fn with_parent(mut self, id: impl Into<Uuid>) -> Self {
        self.set_parent(id);
        self
    }

    pub fn parent(&self) -> Uuid {
        self.parent_id
    }

    pub fn set_parent_kind(&mut self, kind: impl Into<ReferencedArtefactParentKind>) {
        self.parent_kind = kind.into();
    }

    pub fn with_parent_kind(mut self, id: impl Into<ReferencedArtefactParentKind>) -> Self {
        self.set_parent_kind(id);
        self
    }

    pub fn parent_kind(&self) -> ReferencedArtefactParentKind {
        self.parent_kind
    }

    pub fn set_external_artefact(&mut self, id: impl Into<Uuid>) {
        self.external_artefact_id = Some(id.into());
    }

    pub fn with_external_artefact(mut self, id: impl Into<Uuid>) -> Self {
        self.set_external_artefact(id);
        self
    }

    pub fn external_artefact(&self) -> Option<Uuid> {
        self.external_artefact_id
    }

    pub fn set_name(&mut self, name: impl Into<Cow<'static, str>>) {
        self.name = name.into();
    }

    pub fn with_name(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        self.set_name(name);
        self
    }

    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    pub fn set_kind(&mut self, kind: impl Into<Cow<'static, str>>) {
        self.kind = kind.into();
    }

    pub fn with_kind(mut self, kind: impl Into<Cow<'static, str>>) -> Self {
        self.set_kind(kind);
        self
    }

    pub fn kind(&self) -> &str {
        self.kind.as_ref()
    }

    pub fn add_range(&mut self, range: impl Into<OffsetRange>) {
        self.ranges.push(range.into());
    }

    pub fn with_range(mut self, range: impl Into<OffsetRange>) -> Self {
        self.add_range(range);
        self
    }

    pub fn add_ranges<T>(&mut self, ranges: impl IntoIterator<Item = T>)
    where
        T: Into<OffsetRange>,
    {
        for range in ranges.into_iter() {
            self.add_range(range);
        }
    }

    pub fn with_ranges<T>(mut self, ranges: impl IntoIterator<Item = T>) -> Self
    where
        T: Into<OffsetRange>,
    {
        self.add_ranges(ranges);
        self
    }

    pub fn ranges(&self) -> &[OffsetRange] {
        &self.ranges
    }

    pub fn set_hashes(&mut self, hashes: impl Into<ReferencedArtefactIdentity>) {
        self.hashes = Some(hashes.into());
    }

    pub fn with_hashes(mut self, hashes: impl Into<ReferencedArtefactIdentity>) -> Self {
        self.set_hashes(hashes);
        self
    }

    pub fn hashes(&self) -> Option<&ReferencedArtefactIdentity> {
        self.hashes.as_ref()
    }

    pub fn set_provenance(&mut self, provenance: impl Into<ReferencedArtefactProvenance>) {
        self.provenance = Some(provenance.into());
    }

    pub fn with_provenance(mut self, provenance: impl Into<ReferencedArtefactProvenance>) -> Self {
        self.set_provenance(provenance);
        self
    }

    pub fn provenance(&self) -> Option<&ReferencedArtefactProvenance> {
        self.provenance.as_ref()
    }

    pub fn set_linkage(&mut self, linkage: impl Into<ReferencedArtefactLinkage>) {
        self.linkage = linkage.into();
    }

    pub fn with_linkage(mut self, linkage: impl Into<ReferencedArtefactLinkage>) -> Self {
        self.set_linkage(linkage);
        self
    }

    pub fn linkage(&self) -> ReferencedArtefactLinkage {
        self.linkage
    }

    pub fn set_attr(&mut self, name: impl Into<Cow<'static, str>>, value: impl Serialize) {
        self.attributes
            .insert(name.into(), serde_json::json!(value));
    }

    pub fn get_attr<V: DeserializeOwned>(&self, name: impl AsRef<str>) -> Option<V> {
        self.attributes
            .get(name.as_ref())
            .and_then(|v| serde_json::from_value(v.to_owned()).ok())
    }

    pub fn remove_attr(&mut self, name: impl AsRef<str>) -> Option<serde_json::Value> {
        self.attributes.remove(name.as_ref())
    }

    pub fn remove_attr_as<V: DeserializeOwned>(&mut self, name: impl AsRef<str>) -> Option<V> {
        self.attributes
            .remove(name.as_ref())
            .and_then(|v| serde_json::from_value(v).ok())
    }

    pub fn set_attrs(&mut self, values: impl Serialize) {
        let serde_json::Value::Object(object) = serde_json::json!(values) else {
            return;
        };

        self.attributes
            .extend(object.into_iter().map(|(k, v)| (Cow::Owned(k), v)));
    }

    pub fn get_attrs<V: DeserializeOwned>(&self) -> Option<V> {
        let object = serde_json::Value::Object(
            self.attributes
                .iter()
                .map(|(k, v)| (k.as_ref().to_owned(), v.to_owned()))
                .collect(),
        );

        serde_json::from_value(object).ok()
    }

    pub fn fingerprint(&self) -> Option<Fingerprint> {
        Some(Fingerprint::new_attrs(&self.attributes))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_license() -> Result<(), Box<dyn std::error::Error>> {
        assert!("MIT".parse::<LicenseExpression>().is_ok());
        assert!("Proprietary".parse::<LicenseExpression>().is_ok());
        assert!("".parse::<LicenseExpression>().is_err());

        let license_json = serde_json::json!({
            "license1": LicenseExpression::Proprietary,
            "license2": "MIT".parse::<LicenseExpression>()?,
        });

        assert_eq!(license_json["license1"].as_str(), Some("Proprietary"));
        assert_eq!(license_json["license2"].as_str(), Some("MIT"));

        #[derive(Deserialize)]
        struct Licenses {
            license1: LicenseExpression,
            license2: LicenseExpression,
        }

        let license_deser = serde_json::from_value::<Licenses>(license_json)?;

        assert_eq!(license_deser.license1, LicenseExpression::Proprietary);
        assert_eq!(license_deser.license2, "MIT".parse::<LicenseExpression>()?);

        let license_deser_single = serde_json::from_str::<LicenseExpression>("\"Proprietary\"")?;

        assert_eq!(license_deser_single, LicenseExpression::Proprietary);

        Ok(())
    }
}

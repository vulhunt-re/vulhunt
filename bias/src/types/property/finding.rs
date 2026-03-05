use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::common::{Fingerprint, FingerprintBuilder, Note, Reference};
use crate::types::property::{Evidence, Severity};
use crate::types::standards::{
    FindingClassification, FindingClassificationError, FindingIdentifier, FindingIdentifierError,
    FindingMetric, FindingMetricError,
};

use super::EvidenceError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    severity: Severity,
    identifiers: BTreeSet<FindingIdentifier>,
    classifications: BTreeSet<FindingClassification>,
    metrics: BTreeSet<FindingMetric>,
    description: Option<Cow<'static, str>>,
    evidence: Vec<Evidence>,
    references: Vec<Reference>,
    notes: Vec<Note>,
    variants: BTreeMap<Cow<'static, str>, FindingVariant>,
}

#[derive(Deserialize, Serialize)]
struct FindingRepr<'a> {
    severity: Severity,
    #[serde(default)]
    identifiers: Cow<'a, BTreeSet<FindingIdentifier>>,
    #[serde(default)]
    classifications: Cow<'a, BTreeSet<FindingClassification>>,
    #[serde(default)]
    metrics: Cow<'a, BTreeSet<FindingMetric>>,
    #[serde(default)]
    description: Cow<'a, Option<Cow<'static, str>>>,
    evidence: Cow<'a, Vec<Evidence>>,
    #[serde(default)]
    references: Cow<'a, Vec<Reference>>,
    #[serde(default)]
    notes: Cow<'a, Vec<Note>>,
    #[serde(default)]
    variants: Cow<'a, BTreeMap<Cow<'static, str>, FindingVariant>>,
    #[serde(default)]
    fingerprint: Fingerprint,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct FindingVariant {
    #[serde(default)]
    severity: Option<Severity>,
    #[serde(default)]
    identifiers: BTreeSet<String>,
    #[serde(default)]
    classifications: BTreeSet<FindingClassification>,
    #[serde(default)]
    metrics: BTreeSet<FindingMetric>,
    #[serde(default)]
    description: Option<Cow<'static, str>>,
    #[serde(default)]
    notes: Vec<Note>,
    #[serde(default)]
    references: Vec<Reference>,
    #[serde(default)]
    source: Option<String>,
}

impl<'de> Deserialize<'de> for Finding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let FindingRepr {
            severity,
            identifiers,
            classifications,
            metrics,
            description,
            evidence,
            references,
            notes,
            variants,
            ..
        } = FindingRepr::deserialize(deserializer)?;

        Ok(Self {
            severity,
            identifiers: identifiers.into_owned(),
            classifications: classifications.into_owned(),
            metrics: metrics.into_owned(),
            description: description.into_owned(),
            evidence: evidence.into_owned(),
            references: references.into_owned(),
            notes: notes.into_owned(),
            variants: variants.into_owned(),
        })
    }
}

impl Serialize for Finding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let repr = FindingRepr {
            severity: self.severity,
            identifiers: Cow::Borrowed(&self.identifiers),
            classifications: Cow::Borrowed(&self.classifications),
            metrics: Cow::Borrowed(&self.metrics),
            description: Cow::Borrowed(&self.description),
            evidence: Cow::Borrowed(&self.evidence),
            references: Cow::Borrowed(&self.references),
            notes: Cow::Borrowed(&self.notes),
            variants: Cow::Borrowed(&self.variants),
            fingerprint: self.fingerprint(),
        };

        repr.serialize(serializer)
    }
}

#[derive(Debug, Error)]
pub enum FindingError {
    #[error(transparent)]
    InvalidIdentifier(#[from] FindingIdentifierError),
    #[error(transparent)]
    InvalidClassification(#[from] FindingClassificationError),
    #[error(transparent)]
    InvalidMetric(#[from] FindingMetricError),
    #[error(transparent)]
    InvalidEvidence(#[from] EvidenceError),
    #[error("unsupported severity")]
    UnsupportedSeverity,
}

impl FindingVariant {
    // Variant is Binarly-specific, e.g., for use when we disagree with an
    // "official" source for vulnerability information, e.g., the vendor,
    // or NVD.
    pub const BINARLY: &'static str = "Binarly";

    // Variant information is from a specific package ecosystem,
    // e.g., Rocky Linux, Ubuntu, etc.
    pub const ECOSYSTEM: &'static str = "Ecosystem";

    // Variant information is from the original developer, manufacturer,
    // or vendor, e.g., OpenSSL, Intel, Supermicro, Insyde, etc.
    pub const VENDOR: &'static str = "Vendor";

    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with(source: impl Into<String>) -> Self {
        Self {
            source: Some(source.into()),
            ..Self::default()
        }
    }

    pub fn set_description(&mut self, description: impl Into<Cow<'static, str>>) {
        self.description = Some(description.into());
    }

    pub fn with_description(mut self, description: impl Into<Cow<'static, str>>) -> Self {
        self.set_description(description);
        self
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    pub fn clear_description(&mut self) {
        self.description = None;
    }

    pub fn set_severity(&mut self, severity: impl Into<Severity>) {
        self.severity = Some(severity.into());
    }

    pub fn with_severity(mut self, severity: impl Into<Severity>) -> Self {
        self.set_severity(severity);
        self
    }

    pub fn severity(&self) -> Option<Severity> {
        self.severity
    }

    pub fn clear_severity(&mut self) {
        self.severity = None;
    }

    pub fn add_identifier(&mut self, identifier: impl Into<String>) {
        self.identifiers.insert(identifier.into());
    }

    pub fn with_identifier(mut self, identifier: impl Into<String>) -> Self {
        self.add_identifier(identifier);
        self
    }

    pub fn add_identifiers<T>(&mut self, identifiers: impl IntoIterator<Item = T>)
    where
        T: Into<String>,
    {
        for identifier in identifiers.into_iter() {
            self.add_identifier(identifier);
        }
    }

    pub fn with_identifiers<T>(mut self, identifiers: impl IntoIterator<Item = T>) -> Self
    where
        T: Into<String>,
    {
        self.add_identifiers(identifiers);
        self
    }

    pub fn identifiers(&self) -> &BTreeSet<String> {
        &self.identifiers
    }

    pub fn identifiers_mut(&mut self) -> &mut BTreeSet<String> {
        &mut self.identifiers
    }

    pub fn add_classification(&mut self, classification: impl Into<FindingClassification>) {
        self.classifications.insert(classification.into());
    }

    pub fn with_classification(mut self, classification: impl Into<FindingClassification>) -> Self {
        self.add_classification(classification);
        self
    }

    pub fn add_classifications<T>(&mut self, classifications: impl IntoIterator<Item = T>)
    where
        T: Into<FindingClassification>,
    {
        for classification in classifications.into_iter() {
            self.add_classification(classification);
        }
    }

    pub fn with_classifications<T>(mut self, classifications: impl IntoIterator<Item = T>) -> Self
    where
        T: Into<FindingClassification>,
    {
        self.add_classifications(classifications);
        self
    }

    pub fn classifications(&self) -> &BTreeSet<FindingClassification> {
        &self.classifications
    }

    pub fn classifications_mut(&mut self) -> &mut BTreeSet<FindingClassification> {
        &mut self.classifications
    }

    pub fn has_classifications(&self) -> bool {
        !self.classifications.is_empty()
    }

    pub fn add_metric(&mut self, metric: impl Into<FindingMetric>) {
        self.metrics.insert(metric.into());
    }

    pub fn with_metric(mut self, metric: impl Into<FindingMetric>) -> Self {
        self.add_metric(metric);
        self
    }

    pub fn add_metrics<T>(&mut self, metrics: impl IntoIterator<Item = T>)
    where
        T: Into<FindingMetric>,
    {
        for metric in metrics.into_iter() {
            self.add_metric(metric);
        }
    }

    pub fn with_metrics<T>(mut self, metrics: impl IntoIterator<Item = T>) -> Self
    where
        T: Into<FindingMetric>,
    {
        self.add_metrics(metrics);
        self
    }

    pub fn metrics(&self) -> &BTreeSet<FindingMetric> {
        &self.metrics
    }

    pub fn metrics_mut(&mut self) -> &mut BTreeSet<FindingMetric> {
        &mut self.metrics
    }

    pub fn has_metrics(&self) -> bool {
        !self.metrics.is_empty()
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

    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    pub fn set_source(&mut self, source: impl Into<String>) {
        self.source = Some(source.into());
    }

    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.set_source(source);
        self
    }

    pub fn clear_source(&mut self) {
        self.source = None;
    }
}

impl Finding {
    pub fn new() -> Self {
        Self::new_with(Severity::None)
    }

    pub fn new_with(severity: impl Into<Severity>) -> Self {
        Self {
            severity: severity.into(),
            identifiers: BTreeSet::new(),
            classifications: BTreeSet::new(),
            metrics: BTreeSet::new(),
            description: None,
            evidence: Vec::new(),
            references: Vec::new(),
            notes: Vec::new(),
            variants: BTreeMap::new(),
        }
    }

    pub fn set_description(&mut self, description: impl Into<Cow<'static, str>>) {
        self.description = Some(description.into());
    }

    pub fn with_description(mut self, description: impl Into<Cow<'static, str>>) -> Self {
        self.set_description(description);
        self
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    pub fn set_severity(&mut self, severity: impl Into<Severity>) {
        self.severity = severity.into();
    }

    pub fn with_severity(mut self, severity: impl Into<Severity>) -> Self {
        self.set_severity(severity);
        self
    }

    pub fn severity(&self) -> Severity {
        self.severity
    }

    pub fn add_identifier(&mut self, identifier: impl Into<FindingIdentifier>) {
        self.identifiers.insert(identifier.into());
    }

    pub fn with_identifier(mut self, identifier: impl Into<FindingIdentifier>) -> Self {
        self.add_identifier(identifier);
        self
    }

    pub fn add_identifiers<T>(&mut self, identifiers: impl IntoIterator<Item = T>)
    where
        T: Into<FindingIdentifier>,
    {
        for identifier in identifiers.into_iter() {
            self.add_identifier(identifier);
        }
    }

    pub fn with_identifiers<T>(mut self, identifiers: impl IntoIterator<Item = T>) -> Self
    where
        T: Into<FindingIdentifier>,
    {
        self.add_identifiers(identifiers);
        self
    }

    pub fn identifiers(&self) -> &BTreeSet<FindingIdentifier> {
        &self.identifiers
    }

    pub fn identifiers_mut(&mut self) -> &mut BTreeSet<FindingIdentifier> {
        &mut self.identifiers
    }

    pub fn has_identifiers(&self) -> bool {
        !self.identifiers.is_empty()
    }

    pub fn add_classification(&mut self, classification: impl Into<FindingClassification>) {
        self.classifications.insert(classification.into());
    }

    pub fn with_classification(mut self, classification: impl Into<FindingClassification>) -> Self {
        self.add_classification(classification);
        self
    }

    pub fn add_classifications<T>(&mut self, classifications: impl IntoIterator<Item = T>)
    where
        T: Into<FindingClassification>,
    {
        for classification in classifications.into_iter() {
            self.add_classification(classification);
        }
    }

    pub fn with_classifications<T>(mut self, classifications: impl IntoIterator<Item = T>) -> Self
    where
        T: Into<FindingClassification>,
    {
        self.add_classifications(classifications);
        self
    }

    pub fn classifications(&self) -> &BTreeSet<FindingClassification> {
        &self.classifications
    }

    pub fn classifications_mut(&mut self) -> &mut BTreeSet<FindingClassification> {
        &mut self.classifications
    }

    pub fn has_classifications(&self) -> bool {
        !self.classifications.is_empty()
    }

    pub fn add_metric(&mut self, metric: impl Into<FindingMetric>) {
        self.metrics.insert(metric.into());
    }

    pub fn with_metric(mut self, metric: impl Into<FindingMetric>) -> Self {
        self.add_metric(metric);
        self
    }

    pub fn add_metrics<T>(&mut self, metrics: impl IntoIterator<Item = T>)
    where
        T: Into<FindingMetric>,
    {
        for metric in metrics.into_iter() {
            self.add_metric(metric);
        }
    }

    pub fn with_metrics<T>(mut self, metrics: impl IntoIterator<Item = T>) -> Self
    where
        T: Into<FindingMetric>,
    {
        self.add_metrics(metrics);
        self
    }

    pub fn metrics(&self) -> &BTreeSet<FindingMetric> {
        &self.metrics
    }

    pub fn metrics_mut(&mut self) -> &mut BTreeSet<FindingMetric> {
        &mut self.metrics
    }

    pub fn has_metrics(&self) -> bool {
        !self.metrics.is_empty()
    }

    pub fn add_evidence(&mut self, evidence: impl Into<Evidence>) {
        self.evidence.push(evidence.into());
    }

    pub fn with_evidence(mut self, evidence: impl Into<Evidence>) -> Self {
        self.add_evidence(evidence);
        self
    }

    pub fn evidence(&self) -> &[Evidence] {
        &self.evidence
    }

    pub fn evidence_mut(&mut self) -> &mut Vec<Evidence> {
        &mut self.evidence
    }

    pub fn has_evidence(&self) -> bool {
        !self.evidence.is_empty()
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

    pub fn variants(&self) -> &BTreeMap<Cow<'static, str>, FindingVariant> {
        &self.variants
    }

    pub fn variants_mut(&mut self) -> &mut BTreeMap<Cow<'static, str>, FindingVariant> {
        &mut self.variants
    }

    pub fn add_variant(
        &mut self,
        name: impl Into<Cow<'static, str>>,
        variant: impl Into<FindingVariant>,
    ) {
        self.variants.insert(name.into(), variant.into());
    }

    pub fn add_variants<K, V>(&mut self, variants: impl IntoIterator<Item = (K, V)>)
    where
        K: Into<Cow<'static, str>>,
        V: Into<FindingVariant>,
    {
        for (name, variant) in variants.into_iter() {
            self.add_variant(name, variant);
        }
    }

    pub fn with_variant(
        mut self,
        name: impl Into<Cow<'static, str>>,
        variant: impl Into<FindingVariant>,
    ) -> Self {
        self.add_variant(name, variant);
        self
    }

    pub fn with_variants<K, V>(mut self, variants: impl IntoIterator<Item = (K, V)>) -> Self
    where
        K: Into<Cow<'static, str>>,
        V: Into<FindingVariant>,
    {
        self.add_variants(variants);
        self
    }

    pub fn fingerprint(&self) -> Fingerprint {
        let mut builder = FingerprintBuilder::new();

        for evidence in self.evidence() {
            builder.push_fingerprint(evidence.fingerprint());
        }

        builder.build()
    }
}

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub enum ExternalAnalysisArtefactKind {
    #[serde(rename = "raw-data")]
    RawData,
    #[serde(rename = "code-listing")]
    CodeListing,
    #[serde(rename = "disassembly-listing")]
    DisassemblyListing,
    #[serde(rename = "ir-listing")]
    IRListing,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ExternalAnalysisArtefact {
    id: Uuid,
    kind: ExternalAnalysisArtefactKind,
    location: String,
    source: Option<String>,
    variant_of: Option<usize>,
}

impl ExternalAnalysisArtefact {
    pub fn new_data(id: impl Into<Uuid>, location: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            kind: ExternalAnalysisArtefactKind::RawData,
            location: location.into(),
            source: None,
            variant_of: None,
        }
    }

    pub fn new_code_listing(id: impl Into<Uuid>, location: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            kind: ExternalAnalysisArtefactKind::CodeListing,
            location: location.into(),
            source: None,
            variant_of: None,
        }
    }

    pub fn new_disassembly_listing(id: impl Into<Uuid>, location: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            kind: ExternalAnalysisArtefactKind::DisassemblyListing,
            location: location.into(),
            source: None,
            variant_of: None,
        }
    }

    pub fn new_ir_listing(id: impl Into<Uuid>, location: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            kind: ExternalAnalysisArtefactKind::IRListing,
            location: location.into(),
            source: None,
            variant_of: None,
        }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn kind(&self) -> ExternalAnalysisArtefactKind {
        self.kind
    }

    pub fn location(&self) -> &str {
        &self.location
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

    pub fn variant_of(&self) -> Option<usize> {
        self.variant_of
    }

    pub fn set_variant_of(&mut self, index: usize) {
        self.variant_of = Some(index);
    }

    pub fn with_variant_of(mut self, index: usize) -> Self {
        self.set_variant_of(index);
        self
    }
}

#[derive(Debug, Error)]
pub enum ExternalAnalysisArtefactError {
    #[error("invalid artefact variant index")]
    InvalidVariantIndex,
    #[error("missing ID")]
    NoId,
    #[error("unsupported artefact kind")]
    UnsupportedKind,
}

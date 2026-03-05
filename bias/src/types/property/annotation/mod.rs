use std::borrow::Cow;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::artefact::{
    AddressRange, AddressRangeError, Artefact, CodeRange, CodeRangeError, LocationRange,
    LocationRangeError, OffsetRange, OffsetRangeError,
};
use crate::types::common::AttributeMap;

pub mod function;
pub use function::{
    FunctionAnalysisLocation, FunctionMetadata, FunctionMetadataError, FunctionSourceLocation,
};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind")]
pub enum AnnotationSpan {
    #[serde(rename = "all")]
    All,
    #[serde(rename = "offset-range")]
    OffsetRange { value: OffsetRange },
    #[serde(rename = "address-range")]
    AddressRange { value: AddressRange },
    #[serde(rename = "location-range")]
    LocationRange { value: LocationRange },
    #[serde(rename = "code-range")]
    CodeRange { value: CodeRange },
}

#[derive(Debug, Error)]
pub enum AnnotationSpanError {
    #[error(transparent)]
    InvalidAddressRange(#[from] AddressRangeError),
    #[error(transparent)]
    InvalidCodeRange(#[from] CodeRangeError),
    #[error(transparent)]
    InvalidLocationRange(#[from] LocationRangeError),
    #[error(transparent)]
    InvalidOffsetRange(#[from] OffsetRangeError),
}

impl Default for AnnotationSpan {
    fn default() -> Self {
        Self::All
    }
}

impl From<OffsetRange> for AnnotationSpan {
    fn from(value: OffsetRange) -> Self {
        Self::OffsetRange { value }
    }
}

impl From<AddressRange> for AnnotationSpan {
    fn from(value: AddressRange) -> Self {
        Self::AddressRange { value }
    }
}

impl From<LocationRange> for AnnotationSpan {
    fn from(value: LocationRange) -> Self {
        Self::LocationRange { value }
    }
}

impl From<CodeRange> for AnnotationSpan {
    fn from(value: CodeRange) -> Self {
        Self::CodeRange { value }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind")]
pub enum AnnotationKind {
    #[default]
    #[serde(rename = "basic")]
    Basic,
    #[serde(rename = "function-metadata")]
    FunctionMetadata(function::FunctionMetadata),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Annotation {
    annotation: String,
    artefact_index: usize,
    span: AnnotationSpan,
    kind: AnnotationKind,
    attributes: AttributeMap,
}

#[derive(Debug, Error)]
pub enum AnnotationError {
    #[error("annotation has no span information")]
    NoSpan,
    #[error(transparent)]
    Span(#[from] AnnotationSpanError),
    #[error(transparent)]
    Kind(#[from] AnnotationKindError),
}

impl Annotation {
    pub fn new(annotation: impl Into<String>) -> Self {
        Self::new_with(annotation, 0, AnnotationSpan::default())
    }

    pub fn new_with(
        annotation: impl Into<String>,
        index: usize,
        span: impl Into<AnnotationSpan>,
    ) -> Self {
        Self {
            annotation: annotation.into(),
            artefact_index: index,
            span: span.into(),
            kind: AnnotationKind::default(),
            attributes: AttributeMap::new(),
        }
    }

    pub fn new_function_metadata(
        annotation: impl Into<String>,
        span: impl Into<AnnotationSpan>,
        meta: FunctionMetadata,
    ) -> Self {
        Self::new_function_metadata_with(annotation, 0, span, meta)
    }

    pub fn new_function_metadata_with(
        annotation: impl Into<String>,
        index: usize,
        span: impl Into<AnnotationSpan>,
        meta: FunctionMetadata,
    ) -> Self {
        Self {
            annotation: annotation.into(),
            artefact_index: index,
            span: span.into(),
            kind: AnnotationKind::FunctionMetadata(meta),
            attributes: AttributeMap::new(),
        }
    }

    pub(crate) fn is_valid_for(&self, artefact: &Artefact) -> bool {
        match (&self.span, artefact) {
            (AnnotationSpan::All, _)
            | (_, Artefact::ArtefactRef { .. })
            | (_, Artefact::ComponentRef { .. })
            | (AnnotationSpan::OffsetRange { .. }, Artefact::RawData { .. })
            | (AnnotationSpan::AddressRange { .. }, Artefact::DisassemblyListing { .. })
            | (AnnotationSpan::LocationRange { .. }, Artefact::IRListing { .. })
            | (AnnotationSpan::CodeRange { .. }, Artefact::CodeListing { .. }) => true,
            _ => false,
        }
    }

    pub fn set_annotation(&mut self, annotation: impl Into<String>) {
        self.annotation = annotation.into();
    }

    pub fn with_annotation(mut self, annotation: impl Into<String>) -> Self {
        self.set_annotation(annotation);
        self
    }

    pub fn annotation(&self) -> &str {
        &self.annotation
    }

    pub fn set_artefact_index(&mut self, artefact_index: usize) {
        self.artefact_index = artefact_index;
    }

    pub fn with_artefact_index(mut self, artefact_index: usize) -> Self {
        self.set_artefact_index(artefact_index);
        self
    }

    pub fn artefact_index(&self) -> usize {
        self.artefact_index
    }

    pub fn set_kind(&mut self, kind: impl Into<AnnotationKind>) {
        self.kind = kind.into();
    }

    pub fn with_kind(mut self, kind: impl Into<AnnotationKind>) -> Self {
        self.set_kind(kind);
        self
    }

    pub fn kind(&self) -> &AnnotationKind {
        &self.kind
    }

    pub fn set_span(&mut self, span: impl Into<AnnotationSpan>) {
        self.span = span.into();
    }

    pub fn with_span(mut self, span: impl Into<AnnotationSpan>) -> Self {
        self.set_span(span);
        self
    }

    pub fn span(&self) -> &AnnotationSpan {
        &self.span
    }

    pub fn offset_range(&self) -> Option<&OffsetRange> {
        if let AnnotationSpan::OffsetRange { ref value } = self.span {
            Some(value)
        } else {
            None
        }
    }

    pub fn address_range(&self) -> Option<&AddressRange> {
        if let AnnotationSpan::AddressRange { ref value } = self.span {
            Some(value)
        } else {
            None
        }
    }

    pub fn code_range(&self) -> Option<&CodeRange> {
        if let AnnotationSpan::CodeRange { ref value } = self.span {
            Some(value)
        } else {
            None
        }
    }

    pub fn location_range(&self) -> Option<&LocationRange> {
        if let AnnotationSpan::LocationRange { ref value } = self.span {
            Some(value)
        } else {
            None
        }
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
}

#[derive(Debug, Error)]
pub enum AnnotationKindError {
    #[error(transparent)]
    InvalidFunctionMetadata(#[from] FunctionMetadataError),
}

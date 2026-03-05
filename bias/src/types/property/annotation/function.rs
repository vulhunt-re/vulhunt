use std::borrow::Cow;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use thiserror::Error;

use crate::types::artefact::{
    AddressRange, AddressRangeError, CodeRange, CodeRangeError, OffsetRange, OffsetRangeError,
};
use crate::types::common::AttributeMap;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct FunctionMetadata {
    name: String,
    display_name: String,
    source_location: Option<FunctionSourceLocation>,
    analysis_location: FunctionAnalysisLocation,
    attributes: AttributeMap,
}

#[derive(Debug, Error)]
pub enum FunctionMetadataError {
    #[error(transparent)]
    InvalidAnalysisLocation(#[from] FunctionAnalysisLocationError),
    #[error(transparent)]
    InvalidSourceLocation(#[from] FunctionSourceLocationError),
    #[error("function metadata contains no analysis location")]
    NoAnalysisLocation,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct FunctionSourceLocation {
    path: Option<PathBuf>,
    location: FunctionSourceLocationKind,
}

#[derive(Debug, Error)]
pub enum FunctionSourceLocationError {
    #[error("function source location contains no location")]
    NoLocation,
    #[error(transparent)]
    InvalidLocation(#[from] CodeRangeError),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind")]
pub enum FunctionSourceLocationKind {
    #[serde(rename = "code-offset")]
    CodeOffset { value: u64 },
    #[serde(rename = "code-range")]
    CodeRange { value: CodeRange },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind")]
pub enum FunctionAnalysisLocation {
    #[serde(rename = "offset")]
    Offset { value: u64 },
    #[serde(rename = "offset-range")]
    OffsetRange { value: OffsetRange },
    #[serde(rename = "address")]
    Address { value: u64 },
    #[serde(rename = "address-range")]
    AddressRange { value: AddressRange },
    #[serde(rename = "code-offset")]
    CodeOffset { value: u64 },
    #[serde(rename = "code-range")]
    CodeRange { value: CodeRange },
}

#[derive(Debug, Error)]
pub enum FunctionAnalysisLocationError {
    #[error(transparent)]
    InvalidAddressRange(#[from] AddressRangeError),
    #[error(transparent)]
    InvalidCodeRange(#[from] CodeRangeError),
    #[error(transparent)]
    InvalidOffsetRange(#[from] OffsetRangeError),
}

impl FunctionMetadata {
    pub fn new(
        name: impl Into<String>,
        source_location: impl Into<Option<FunctionSourceLocation>>,
        analysis_location: impl Into<FunctionAnalysisLocation>,
    ) -> Self {
        let name = name.into();
        Self::new_with(name.clone(), name, source_location, analysis_location)
    }

    pub fn new_with(
        name: impl Into<String>,
        display_name: impl Into<String>,
        source_location: impl Into<Option<FunctionSourceLocation>>,
        analysis_location: impl Into<FunctionAnalysisLocation>,
    ) -> Self {
        Self {
            name: name.into(),
            display_name: display_name.into(),
            source_location: source_location.into(),
            analysis_location: analysis_location.into(),
            attributes: AttributeMap::default(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub fn source_location(&self) -> Option<&FunctionSourceLocation> {
        self.source_location.as_ref()
    }

    pub fn analysis_location(&self) -> &FunctionAnalysisLocation {
        &self.analysis_location
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

impl FunctionSourceLocation {
    pub fn new(location: impl Into<FunctionSourceLocationKind>) -> Self {
        Self {
            path: None,
            location: location.into(),
        }
    }

    pub fn new_with(
        path: impl Into<PathBuf>,
        location: impl Into<FunctionSourceLocationKind>,
    ) -> Self {
        Self {
            path: Some(path.into()),
            location: location.into(),
        }
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn location(&self) -> &FunctionSourceLocationKind {
        &self.location
    }
}

impl From<u64> for FunctionSourceLocationKind {
    fn from(value: u64) -> Self {
        Self::CodeOffset { value }
    }
}

impl From<CodeRange> for FunctionSourceLocationKind {
    fn from(value: CodeRange) -> Self {
        Self::CodeRange { value }
    }
}

impl FunctionSourceLocationKind {
    pub fn new_offset(value: impl Into<u64>) -> Self {
        Self::CodeOffset {
            value: value.into(),
        }
    }

    pub fn new_range(value: CodeRange) -> Self {
        Self::CodeRange {
            value: value.into(),
        }
    }

    pub fn start(&self) -> u64 {
        match self {
            Self::CodeOffset { value } => *value,
            Self::CodeRange { value } => value.start(),
        }
    }

    pub fn end(&self) -> Option<u64> {
        if let Self::CodeRange { value } = self {
            Some(value.end())
        } else {
            None
        }
    }
}

impl FunctionAnalysisLocation {
    pub fn new_offset(value: impl Into<u64>) -> Self {
        Self::Offset {
            value: value.into(),
        }
    }

    pub fn new_offset_range(value: impl Into<OffsetRange>) -> Self {
        Self::OffsetRange {
            value: value.into(),
        }
    }

    pub fn new_address(value: impl Into<u64>) -> Self {
        Self::Address {
            value: value.into(),
        }
    }

    pub fn new_address_range(value: impl Into<AddressRange>) -> Self {
        Self::AddressRange {
            value: value.into(),
        }
    }

    pub fn new_code_offset(value: impl Into<u64>) -> Self {
        Self::CodeOffset {
            value: value.into(),
        }
    }

    pub fn new_code_range(value: impl Into<CodeRange>) -> Self {
        Self::CodeRange {
            value: value.into(),
        }
    }

    pub fn offset(&self) -> Option<u64> {
        match self {
            Self::Offset { value } => Some(*value),
            _ => None,
        }
    }

    pub fn offset_range(&self) -> Option<&OffsetRange> {
        match self {
            Self::OffsetRange { value } => Some(value),
            _ => None,
        }
    }

    pub fn address(&self) -> Option<u64> {
        match self {
            Self::Address { value } => Some(*value),
            _ => None,
        }
    }

    pub fn address_range(&self) -> Option<&AddressRange> {
        match self {
            Self::AddressRange { value } => Some(value),
            _ => None,
        }
    }

    pub fn code_offset(&self) -> Option<u64> {
        match self {
            Self::CodeOffset { value } => Some(*value),
            _ => None,
        }
    }

    pub fn code_range(&self) -> Option<&CodeRange> {
        match self {
            Self::CodeRange { value } => Some(value),
            _ => None,
        }
    }
}

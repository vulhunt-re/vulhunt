use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::{uuid, Uuid};

pub mod analysis;
pub mod code;
pub mod data;
pub mod disassembly;
pub mod ir;
pub mod referenced;
pub mod structured;

pub use analysis::{ExternalAnalysisArtefact, ExternalAnalysisArtefactError};
pub use code::{CodeListing, CodeListingError, CodeRange, CodeRangeError};
pub use data::{OffsetRange, OffsetRangeError, RawData, RawDataError};
pub use disassembly::{
    AddressRange, AddressRangeError, DisassemblyListing, DisassemblyListingError,
};
pub use ir::{IRListing, IRListingError, LocationRange, LocationRangeError};
pub use referenced::{
    ReferencedArtefact, ReferencedArtefactError, ReferencedArtefactIdentity,
    ReferencedArtefactLinkage, ReferencedArtefactProvenance,
};
pub use structured::StructuredData;

use crate::types::common::Fingerprint;

pub const BIAS_ARTEFACT_NAMESPACE: Uuid = uuid!("DF4491BC-E494-4A9B-92DD-F2476C7E0DDA");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind")]
pub enum Artefact {
    #[serde(rename = "artefact-ref")]
    ArtefactRef { value: Uuid },
    #[serde(rename = "component-ref")]
    ComponentRef { value: Uuid },
    #[serde(rename = "raw-data")]
    RawData { value: RawData },
    #[serde(rename = "code-listing")]
    CodeListing { value: CodeListing },
    #[serde(rename = "disassembly-listing")]
    DisassemblyListing { value: DisassemblyListing },
    #[serde(rename = "ir-listing")]
    IRListing { value: IRListing },
    #[serde(rename = "structured-data")]
    StructuredData { value: StructuredData },
}

#[derive(Debug, Error)]
pub enum ArtefactError {
    #[error(transparent)]
    InvalidRawData(#[from] RawDataError),
    #[error(transparent)]
    InvalidCodeListing(#[from] CodeListingError),
    #[error(transparent)]
    InvalidDisassemblyListing(#[from] DisassemblyListingError),
    #[error(transparent)]
    InvalidIRListing(#[from] IRListingError),
    #[error("no artefact")]
    NoArtefact,
    #[error("unsupported artefact kind")]
    Unsupported,
}

impl Artefact {
    pub fn new_artefact_ref(uuid: impl Into<Uuid>) -> Self {
        Self::ArtefactRef { value: uuid.into() }
    }

    pub fn artefact_ref(&self) -> Option<Uuid> {
        if let Self::ArtefactRef { value } = self {
            Some(*value)
        } else {
            None
        }
    }

    pub fn is_artefact_ref(&self) -> bool {
        matches!(self, Self::ArtefactRef { .. })
    }

    pub fn new_component_ref(uuid: impl Into<Uuid>) -> Self {
        Self::ComponentRef { value: uuid.into() }
    }

    pub fn component_ref(&self) -> Option<Uuid> {
        if let Self::ComponentRef { value } = self {
            Some(*value)
        } else {
            None
        }
    }

    pub fn is_component_ref(&self) -> bool {
        matches!(self, Self::ComponentRef { .. })
    }

    pub fn new_data(data: impl Into<RawData>) -> Self {
        Self::RawData { value: data.into() }
    }

    pub fn data(&self) -> Option<&RawData> {
        if let Self::RawData { ref value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn into_data(self) -> Option<RawData> {
        if let Self::RawData { value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn is_data(&self) -> bool {
        matches!(self, Self::RawData { .. })
    }

    pub fn new_code_listing(listing: impl Into<CodeListing>) -> Self {
        Self::CodeListing {
            value: listing.into(),
        }
    }

    pub fn code_listing(&self) -> Option<&CodeListing> {
        if let Self::CodeListing { ref value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn into_code_listing(self) -> Option<CodeListing> {
        if let Self::CodeListing { value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn is_code_listing(&self) -> bool {
        matches!(self, Self::CodeListing { .. })
    }

    pub fn new_disassembly_listing(listing: impl Into<DisassemblyListing>) -> Self {
        Self::DisassemblyListing {
            value: listing.into(),
        }
    }

    pub fn disassembly_listing(&self) -> Option<&DisassemblyListing> {
        if let Self::DisassemblyListing { ref value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn into_disassembly_listing(self) -> Option<DisassemblyListing> {
        if let Self::DisassemblyListing { value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn is_disassembly_listing(&self) -> bool {
        matches!(self, Self::DisassemblyListing { .. })
    }

    pub fn new_ir_listing(listing: impl Into<IRListing>) -> Self {
        Self::IRListing {
            value: listing.into(),
        }
    }

    pub fn ir_listing(&self) -> Option<&IRListing> {
        if let Self::IRListing { ref value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn is_ir_listing(&self) -> bool {
        matches!(self, Self::IRListing { .. })
    }

    pub fn into_ir_listing(self) -> Option<IRListing> {
        if let Self::IRListing { value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn new_structured_data(data: impl Into<StructuredData>) -> Self {
        Self::StructuredData { value: data.into() }
    }

    pub fn structured_data(&self) -> Option<&StructuredData> {
        if let Self::StructuredData { ref value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn into_structured_data(self) -> Option<StructuredData> {
        if let Self::StructuredData { value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn is_structured_data(&self) -> bool {
        matches!(self, Self::StructuredData { .. })
    }

    pub fn fingerprint(&self) -> Option<Fingerprint> {
        match self {
            Self::RawData { value } => value.fingerprint(),
            Self::CodeListing { value } => value.fingerprint(),
            Self::DisassemblyListing { value } => value.fingerprint(),
            Self::IRListing { value } => value.fingerprint(),
            Self::StructuredData { value } => value.fingerprint(),
            _ => None,
        }
    }
}

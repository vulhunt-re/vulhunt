use std::str::FromStr;

use serde::{Deserialize, Serialize};
use strum::VariantNames;
use strum_macros::VariantNames;
use thiserror::Error;

pub mod cpe;
pub use cpe::{CPEError, CPEv22, CPEv23, CPE};

pub mod cvss;
pub use cvss::{CVSSError, CVSSv2, CVSSv3, CVSSv4, CVSS};

pub mod cwe;

pub mod environment_reachability;
pub use environment_reachability::{
    EnvironmentKind, EnvironmentReachability, EnvironmentReachabilityError,
    EnvironmentReachabilityKind,
};

pub mod mbc;

pub mod purl;
pub use purl::{PURLError, PackageType, PURL};

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize, VariantNames,
)]
#[serde(tag = "kind")]
#[non_exhaustive]
pub enum FindingClassification {
    #[serde(rename = "cwe")]
    #[strum(serialize = "cwe")]
    CWE { value: String },
    #[serde(rename = "att&ck")]
    #[strum(serialize = "att&ck")]
    ATTCK { value: String },
    #[serde(rename = "mbc")]
    #[strum(serialize = "mbc")]
    MBC { value: String },
}

impl FindingClassification {
    pub const KINDS: &'static [&'static str] = Self::VARIANTS;

    pub fn new_cwe(value: impl Into<String>) -> Self {
        Self::CWE {
            value: value.into(),
        }
    }

    pub fn cwe(&self) -> Option<&str> {
        if let Self::CWE { ref value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn new_mitre_attck(value: impl Into<String>) -> Self {
        Self::ATTCK {
            value: value.into(),
        }
    }

    pub fn mitre_attck(&self) -> Option<&str> {
        if let Self::ATTCK { ref value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn new_mbc(value: impl Into<String>) -> Self {
        Self::MBC {
            value: value.into(),
        }
    }

    pub fn mbc(&self) -> Option<&str> {
        if let Self::MBC { ref value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::CWE { value } | Self::ATTCK { value } | Self::MBC { value } => value,
        }
    }
}

#[derive(Debug, Error)]
#[error("missing classification value")]
pub struct FindingClassificationError;

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize, VariantNames,
)]
#[serde(tag = "kind")]
#[strum(serialize_all = "UPPERCASE")]
#[non_exhaustive]
pub enum FindingIdentifier {
    #[serde(rename = "brly")]
    BRLY { value: String },
    #[serde(rename = "cve")]
    CVE { value: String },
    #[serde(rename = "ghsa")]
    GHSA { value: String },
    #[serde(rename = "gsd")]
    GSD { value: String },
    #[serde(rename = "osv")]
    OSV { value: String },
}

impl FindingIdentifier {
    pub const KINDS: &'static [&'static str] = Self::VARIANTS;

    pub fn new_brly(value: impl Into<String>) -> Self {
        Self::BRLY {
            value: value.into(),
        }
    }

    pub fn brly(&self) -> Option<&str> {
        if let Self::BRLY { ref value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn new_cve(value: impl Into<String>) -> Self {
        Self::CVE {
            value: value.into(),
        }
    }

    pub fn cve(&self) -> Option<&str> {
        if let Self::CVE { ref value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn new_ghsa(value: impl Into<String>) -> Self {
        Self::GHSA {
            value: value.into(),
        }
    }

    pub fn ghsa(&self) -> Option<&str> {
        if let Self::GHSA { ref value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn new_gsd(value: impl Into<String>) -> Self {
        Self::GSD {
            value: value.into(),
        }
    }

    pub fn gsd(&self) -> Option<&str> {
        if let Self::GSD { ref value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn new_osv(value: impl Into<String>) -> Self {
        Self::OSV {
            value: value.into(),
        }
    }

    pub fn osv(&self) -> Option<&str> {
        if let Self::OSV { ref value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::BRLY { value }
            | Self::CVE { value }
            | Self::GHSA { value }
            | Self::GSD { value }
            | Self::OSV { value } => value,
        }
    }
}

#[derive(Debug, Error)]
pub enum FindingIdentifierError {
    #[error("missing identifier value")]
    NoIdentifier,
    #[error("unsupported identifier tag")]
    UnsupportedIdentifierTag,
}

impl FromStr for FindingIdentifier {
    type Err = FindingIdentifierError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((prefix, _)) = s.split_once("-") else {
            return Err(FindingIdentifierError::UnsupportedIdentifierTag);
        };

        Ok(match prefix {
            "BRLY" => Self::new_brly(s),
            "CVE" => Self::new_cve(s),
            "GHSA" => Self::new_ghsa(s),
            "GSD" => Self::new_gsd(s),
            "OSV" => Self::new_osv(s),
            _ => return Err(FindingIdentifierError::UnsupportedIdentifierTag),
        })
    }
}

#[derive(Debug, Error)]
pub enum FindingMetricError {
    #[error(transparent)]
    CVSS(#[from] CVSSError),
    #[error(transparent)]
    EnvironmentReachability(#[from] EnvironmentReachabilityError),
    #[error("missing metric value")]
    Missing,
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize, VariantNames,
)]
#[serde(tag = "kind")]
#[non_exhaustive]
pub enum FindingMetric {
    #[serde(rename = "cvss")]
    #[strum(serialize = "cvss")]
    CVSS { value: CVSS },
}

impl FindingMetric {
    pub const KINDS: &'static [&'static str] = Self::VARIANTS;

    pub fn new_cvss(cvss: CVSS) -> Self {
        Self::CVSS { value: cvss }
    }

    #[allow(irrefutable_let_patterns)]
    pub fn cvss(&self) -> Option<&CVSS> {
    
        if let Self::CVSS { ref value } = self {
            Some(value)
        } else {
            None
        }
    }
}

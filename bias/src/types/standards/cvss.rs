use serde::{Deserialize, Serialize};
use strum::VariantNames;
use strum_macros::{Display, VariantNames};
use thiserror::Error;

use crate::types::property::Severity;

#[derive(Debug, Error)]
pub enum CVSSError {
    #[error("invalid CVSS base score")]
    BaseScore,
    #[error("invalid CVSS exploitability score")]
    ExploitabilityScore,
    #[error("invalid CVSS impact score")]
    ImpactScore,
    #[error("invalid CVSS vector")]
    Vector,
    #[error("invalid CVSS version string")]
    Version,
    #[error("invalid CVSS metric")]
    Undefined,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct CVSS {
    v2: Option<CVSSv2>,
    v3: Option<CVSSv3>,
    v4: Option<CVSSv4>,
}

impl CVSS {
    pub fn new_v2(
        base_score: impl Into<String>,
        exploitability_score: impl Into<String>,
        impact_score: impl Into<String>,
        vector: impl Into<String>,
    ) -> Self {
        Self {
            v2: Some(CVSSv2 {
                version: CVSSVersion::V2.to_string(),
                base_score: base_score.into(),
                exploitability_score: exploitability_score.into(),
                impact_score: impact_score.into(),
                vector: vector.into(),
            }),
            v3: None,
            v4: None,
        }
    }

    pub fn new_v3(
        base_score: impl Into<String>,
        exploitability_score: impl Into<String>,
        impact_score: impl Into<String>,
        vector: impl Into<String>,
    ) -> Self {
        Self {
            v2: None,
            v3: Some(CVSSv3 {
                version: CVSSVersion::V3.to_string(),
                base_score: base_score.into(),
                exploitability_score: exploitability_score.into(),
                impact_score: impact_score.into(),
                vector: vector.into(),
            }),
            v4: None,
        }
    }

    pub fn new_v3_1(
        base_score: impl Into<String>,
        exploitability_score: impl Into<String>,
        impact_score: impl Into<String>,
        vector: impl Into<String>,
    ) -> Self {
        Self {
            v2: None,
            v3: Some(CVSSv3 {
                version: CVSSVersion::V3_1.to_string(),
                base_score: base_score.into(),
                exploitability_score: exploitability_score.into(),
                impact_score: impact_score.into(),
                vector: vector.into(),
            }),
            v4: None,
        }
    }

    pub fn new_v4(
        base_score: impl Into<String>,
        exploitability_score: impl Into<String>,
        impact_score: impl Into<String>,
        vector: impl Into<String>,
    ) -> Self {
        Self {
            v2: None,
            v3: None,
            v4: Some(CVSSv4 {
                version: CVSSVersion::V4.to_string(),
                base_score: base_score.into(),
                exploitability_score: exploitability_score.into(),
                impact_score: impact_score.into(),
                vector: vector.into(),
            }),
        }
    }

    pub fn v2(&self) -> Option<&CVSSv2> {
        self.v2.as_ref()
    }

    pub fn v3(&self) -> Option<&CVSSv3> {
        self.v3.as_ref()
    }

    pub fn v4(&self) -> Option<&CVSSv4> {
        self.v4.as_ref()
    }

    pub fn with(mut self, other: CVSS) -> CVSS {
        self.v2 = other.v2.or(self.v2);
        self.v3 = other.v3.or(self.v3);
        self.v4 = other.v4.or(self.v4);
        self
    }

    pub fn is_valid(&self) -> bool {
        self.v2.is_some() || self.v3.is_some() || self.v4.is_some()
    }

    pub fn severity(&self) -> Option<Severity> {
        if let Some(v4) = self.v4().and_then(|v4| v4.base_score().parse::<f64>().ok()) {
            return if v4 >= 9.0 {
                Some(Severity::Critical)
            } else if v4 >= 7.0 {
                Some(Severity::High)
            } else if v4 >= 4.0 {
                Some(Severity::Medium)
            } else if v4 >= 0.1 {
                Some(Severity::Low)
            } else {
                None
            };
        }

        if let Some(v3) = self.v3().and_then(|v3| v3.base_score().parse::<f64>().ok()) {
            return if v3 >= 9.0 {
                Some(Severity::Critical)
            } else if v3 >= 7.0 {
                Some(Severity::High)
            } else if v3 >= 4.0 {
                Some(Severity::Medium)
            } else if v3 >= 0.1 {
                Some(Severity::Low)
            } else {
                None
            };
        }

        if let Some(v2) = self.v2().and_then(|v2| v2.base_score().parse::<f64>().ok()) {
            return Some(if v2 >= 7.0 {
                Severity::High
            } else if v2 >= 4.0 {
                Severity::Medium
            } else {
                Severity::Low
            });
        }

        None
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize,
    Display,
    VariantNames,
)]
pub enum CVSSVersion {
    #[serde(rename = "2.0")]
    #[strum(serialize = "2.0")]
    V2,
    #[serde(rename = "3.0")]
    #[strum(serialize = "3.0")]
    V3,
    #[serde(rename = "3.1")]
    #[strum(serialize = "3.1")]
    V3_1,
    #[serde(rename = "4.0")]
    #[strum(serialize = "4.0")]
    V4,
}

impl CVSSVersion {
    pub const KINDS: &'static [&'static str] = Self::VARIANTS;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct CVSSBuilder {
    version: CVSSVersion,
    base_score: Option<String>,
    exploitability_score: Option<String>,
    impact_score: Option<String>,
    vector: Option<String>,
}

impl CVSSBuilder {
    pub fn new(version: CVSSVersion) -> Self {
        Self {
            version,
            base_score: None,
            exploitability_score: None,
            impact_score: None,
            vector: None,
        }
    }

    pub fn set_version(&mut self, version: CVSSVersion) {
        self.version = version;
    }

    pub fn version(mut self, version: CVSSVersion) -> Self {
        self.version = version;
        self
    }

    pub fn set_base_score(&mut self, score: impl Into<String>) {
        self.base_score = Some(score.into());
    }

    pub fn base_score(mut self, score: impl Into<String>) -> Self {
        self.set_base_score(score);
        self
    }

    pub fn set_impact_score(&mut self, score: impl Into<String>) {
        self.impact_score = Some(score.into());
    }

    pub fn impact_score(mut self, score: impl Into<String>) -> Self {
        self.set_impact_score(score);
        self
    }

    pub fn set_exploitability_score(&mut self, score: impl Into<String>) {
        self.exploitability_score = Some(score.into());
    }

    pub fn exploitability_score(mut self, score: impl Into<String>) -> Self {
        self.set_exploitability_score(score);
        self
    }

    pub fn set_vector(&mut self, score: impl Into<String>) {
        self.vector = Some(score.into());
    }

    pub fn vector(mut self, vector: impl Into<String>) -> Self {
        self.set_vector(vector);
        self
    }

    pub fn build(self) -> Result<CVSS, CVSSError> {
        let Some(base_score) = self.base_score else {
            return Err(CVSSError::BaseScore);
        };

        if !matches!(base_score.parse::<f32>(), Ok(value) if value >= 0f32 && value <= 10f32) {
            return Err(CVSSError::BaseScore);
        }

        let Some(exploitability_score) = self.exploitability_score else {
            return Err(CVSSError::ExploitabilityScore);
        };

        if !matches!(exploitability_score.parse::<f32>(), Ok(value) if value >= 0f32 && value <= 10f32)
        {
            return Err(CVSSError::ExploitabilityScore);
        }

        let Some(impact_score) = self.impact_score else {
            return Err(CVSSError::ImpactScore);
        };

        if !matches!(impact_score.parse::<f32>(), Ok(value) if value >= 0f32 && value <= 10f32) {
            return Err(CVSSError::ImpactScore);
        }

        let Some(vector) = self.vector else {
            return Err(CVSSError::Vector);
        };

        Ok(match self.version {
            CVSSVersion::V2 => CVSS::new_v2(base_score, exploitability_score, impact_score, vector),
            CVSSVersion::V3 => CVSS::new_v3(base_score, exploitability_score, impact_score, vector),
            CVSSVersion::V3_1 => {
                CVSS::new_v3_1(base_score, exploitability_score, impact_score, vector)
            }
            CVSSVersion::V4 => CVSS::new_v4(base_score, exploitability_score, impact_score, vector),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct CVSSv2 {
    version: String,
    base_score: String,
    exploitability_score: String,
    impact_score: String,
    vector: String,
}

impl CVSSv2 {
    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn base_score(&self) -> &str {
        &self.base_score
    }

    pub fn exploitability_score(&self) -> &str {
        &self.exploitability_score
    }

    pub fn impact_score(&self) -> &str {
        &self.impact_score
    }

    pub fn vector(&self) -> &str {
        &self.vector
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct CVSSv3 {
    version: String,
    base_score: String,
    exploitability_score: String,
    impact_score: String,
    vector: String,
}

impl CVSSv3 {
    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn base_score(&self) -> &str {
        &self.base_score
    }

    pub fn exploitability_score(&self) -> &str {
        &self.exploitability_score
    }

    pub fn impact_score(&self) -> &str {
        &self.impact_score
    }

    pub fn vector(&self) -> &str {
        &self.vector
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct CVSSv4 {
    version: String,
    base_score: String,
    exploitability_score: String,
    impact_score: String,
    vector: String,
}

impl CVSSv4 {
    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn base_score(&self) -> &str {
        &self.base_score
    }

    pub fn exploitability_score(&self) -> &str {
        &self.exploitability_score
    }

    pub fn impact_score(&self) -> &str {
        &self.impact_score
    }

    pub fn vector(&self) -> &str {
        &self.vector
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_cvss_builder() -> Result<(), Box<dyn std::error::Error>> {
        let _cvss = CVSSBuilder::new(CVSSVersion::V3_1)
            .base_score("5.3")
            .exploitability_score("3.9")
            .impact_score("1.4")
            .vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
            .build()?;

        let _cvss = CVSSBuilder::new(CVSSVersion::V3_1)
            .base_score("5")
            .exploitability_score("3")
            .impact_score("1")
            .vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
            .build()?;

        Ok(())
    }
}

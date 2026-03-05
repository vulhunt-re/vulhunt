use std::borrow::Cow;
use std::str::FromStr;

use ordered_float::OrderedFloat;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use strum::VariantNames;
use strum_macros::VariantNames;
use thiserror::Error;
use uuid::Uuid;

use crate::types::artefact::{
    ExternalAnalysisArtefact, ExternalAnalysisArtefactError, ReferencedArtefact,
    ReferencedArtefactError,
};
use crate::types::common::Fingerprint;
use crate::types::component::{ReferencedComponent, ReferencedComponentError};

mod constants;
pub use constants::*;

pub mod annotation;
pub use annotation::{Annotation, AnnotationError};

pub mod evidence;
pub use evidence::{Evidence, EvidenceBuilder, EvidenceError};

pub mod finding;
pub use finding::{Finding, FindingError, FindingVariant};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Property {
    entity_id: EntityIdentity,
    name: Cow<'static, str>,
    confidence: PropertyConfidence,
    kind: PropertyKind,
}

#[derive(Debug, Error)]
pub enum PropertyError {
    #[error(transparent)]
    InvalidEntityId(#[from] EntityIdentityError),
    #[error(transparent)]
    InvalidKind(#[from] PropertyKindError),
    #[error(transparent)]
    InvalidTarget(#[from] PropertyTargetError),
    #[error("property contains no component ID")]
    NoComponentId,
    #[error("property contains no entity ID")]
    NoEntityId,
    #[error("property contains no kind")]
    NoKind,
}

impl Property {
    pub fn new(
        component_id: Uuid,
        name: impl Into<Cow<'static, str>>,
        confidence: impl Into<PropertyConfidence>,
        kind: impl Into<PropertyKind>,
    ) -> Self {
        Self::new_with(component_id, name, confidence, kind)
    }

    pub fn new_for_artefact(
        component_id: Uuid,
        artefact_id: Uuid,
        name: impl Into<Cow<'static, str>>,
        confidence: impl Into<PropertyConfidence>,
        kind: impl Into<PropertyKind>,
    ) -> Self {
        Self::new_with(
            EntityIdentity::new_artefact_for_component(artefact_id, component_id),
            name,
            confidence,
            kind,
        )
    }

    pub fn new_for_artefact_with(
        owner: PropertyOwner,
        artefact_id: Uuid,
        name: impl Into<Cow<'static, str>>,
        confidence: impl Into<PropertyConfidence>,
        kind: impl Into<PropertyKind>,
    ) -> Self {
        Self::new_with(
            EntityIdentity::new_artefact_with(artefact_id, owner),
            name,
            confidence,
            kind,
        )
    }

    pub fn new_for_package(
        package_id: Uuid,
        name: impl Into<Cow<'static, str>>,
        confidence: impl Into<PropertyConfidence>,
        kind: impl Into<PropertyKind>,
    ) -> Self {
        Self::new_with(
            EntityIdentity::new_package(package_id),
            name,
            confidence,
            kind,
        )
    }

    pub fn new_with(
        entity_id: impl Into<EntityIdentity>,
        name: impl Into<Cow<'static, str>>,
        confidence: impl Into<PropertyConfidence>,
        kind: impl Into<PropertyKind>,
    ) -> Self {
        Self {
            entity_id: entity_id.into(),
            name: name.into(),
            confidence: confidence.into(),
            kind: kind.into(),
        }
    }

    pub fn new_metadata(
        component_id: Uuid,
        name: impl Into<Cow<'static, str>>,
        value: impl Serialize,
    ) -> Self {
        Self::new_metadata_with(component_id, name, PropertyConfidence::certain(), value)
    }

    pub fn new_metadata_with(
        component_id: impl Into<EntityIdentity>,
        name: impl Into<Cow<'static, str>>,
        confidence: impl Into<PropertyConfidence>,
        value: impl Serialize,
    ) -> Self {
        Self::new_with(
            component_id,
            name,
            confidence,
            PropertyKind::new_metadata(value),
        )
    }

    pub fn new_metadata_for_artefact(
        component_id: Uuid,
        artefact_id: Uuid,
        name: impl Into<Cow<'static, str>>,
        value: impl Serialize,
    ) -> Self {
        Self::new_metadata_for_artefact_with(
            PropertyOwner::new_component(component_id),
            artefact_id,
            name,
            PropertyConfidence::certain(),
            value,
        )
    }

    pub fn new_metadata_for_artefact_with(
        owner: PropertyOwner,
        artefact_id: Uuid,
        name: impl Into<Cow<'static, str>>,
        confidence: impl Into<PropertyConfidence>,
        value: impl Serialize,
    ) -> Self {
        Self::new_for_artefact_with(
            owner,
            artefact_id,
            name,
            confidence,
            PropertyKind::new_metadata(value),
        )
    }

    pub fn new_metadata_for_package(
        package_id: Uuid,
        name: impl Into<Cow<'static, str>>,
        value: impl Serialize,
    ) -> Self {
        Self::new_metadata_for_package_with(package_id, name, PropertyConfidence::certain(), value)
    }

    pub fn new_metadata_for_package_with(
        package_id: Uuid,
        name: impl Into<Cow<'static, str>>,
        confidence: impl Into<PropertyConfidence>,
        value: impl Serialize,
    ) -> Self {
        Self::new_for_package(
            package_id,
            name,
            confidence,
            PropertyKind::new_metadata(value),
        )
    }

    pub fn new_finding(
        component_id: Uuid,
        name: impl Into<Cow<'static, str>>,
        finding: impl Into<Finding>,
    ) -> Self {
        Self::new_finding_with(component_id, name, PropertyConfidence::certain(), finding)
    }

    pub fn new_finding_with(
        component_id: Uuid,
        name: impl Into<Cow<'static, str>>,
        confidence: impl Into<PropertyConfidence>,
        finding: impl Into<Finding>,
    ) -> Self {
        Self::new(
            component_id,
            name,
            confidence,
            PropertyKind::new_finding(finding),
        )
    }

    pub fn new_finding_for_artefact(
        component_id: Uuid,
        artefact_id: Uuid,
        name: impl Into<Cow<'static, str>>,
        finding: impl Into<Finding>,
    ) -> Self {
        Self::new_finding_for_artefact_with(
            PropertyOwner::new_component(component_id),
            artefact_id,
            name,
            PropertyConfidence::certain(),
            finding,
        )
    }

    pub fn new_finding_for_artefact_with(
        owner: PropertyOwner,
        artefact_id: Uuid,
        name: impl Into<Cow<'static, str>>,
        confidence: impl Into<PropertyConfidence>,
        finding: impl Into<Finding>,
    ) -> Self {
        Self::new_for_artefact_with(
            owner,
            artefact_id,
            name,
            confidence,
            PropertyKind::new_finding(finding),
        )
    }

    pub fn new_finding_for_package(
        package_id: Uuid,
        name: impl Into<Cow<'static, str>>,
        finding: impl Into<Finding>,
    ) -> Self {
        Self::new_finding_for_package_with(package_id, name, PropertyConfidence::certain(), finding)
    }

    pub fn new_finding_for_package_with(
        package_id: Uuid,
        name: impl Into<Cow<'static, str>>,
        confidence: impl Into<PropertyConfidence>,
        finding: impl Into<Finding>,
    ) -> Self {
        Self::new_for_package(
            package_id,
            name,
            confidence,
            PropertyKind::new_finding(finding),
        )
    }

    pub fn new_artefact_ref(
        component_id: Uuid,
        name: impl Into<Cow<'static, str>>,
        artefact: impl Into<ReferencedArtefact>,
    ) -> Self {
        Self::new(
            component_id,
            name,
            PropertyConfidence::certain(),
            PropertyKind::new_artefact_ref(artefact),
        )
    }

    pub fn new_artefact_ref_for_artefact(
        component_id: Uuid,
        artefact_id: Uuid,
        name: impl Into<Cow<'static, str>>,
        artefact: impl Into<ReferencedArtefact>,
    ) -> Self {
        Self::new_for_artefact(
            component_id,
            artefact_id,
            name,
            PropertyConfidence::certain(),
            PropertyKind::new_artefact_ref(artefact),
        )
    }

    pub fn new_artefact_ref_for_artefact_with(
        owner: PropertyOwner,
        artefact_id: Uuid,
        name: impl Into<Cow<'static, str>>,
        artefact: impl Into<ReferencedArtefact>,
    ) -> Self {
        Self::new_for_artefact_with(
            owner,
            artefact_id,
            name,
            PropertyConfidence::certain(),
            PropertyKind::new_artefact_ref(artefact),
        )
    }

    pub fn new_component_ref(
        component_id: Uuid,
        name: impl Into<Cow<'static, str>>,
        reference: impl Into<ReferencedComponent>,
    ) -> Self {
        Self::new(
            component_id,
            name,
            PropertyConfidence::certain(),
            PropertyKind::new_component_ref(reference),
        )
    }

    pub fn new_component_ref_for_artefact(
        component_id: Uuid,
        artefact_id: Uuid,
        name: impl Into<Cow<'static, str>>,
        reference: impl Into<ReferencedComponent>,
    ) -> Self {
        Self::new_for_artefact(
            component_id,
            artefact_id,
            name,
            PropertyConfidence::certain(),
            PropertyKind::new_component_ref(reference),
        )
    }

    pub fn new_component_ref_for_artefact_with(
        owner: PropertyOwner,
        artefact_id: Uuid,
        name: impl Into<Cow<'static, str>>,
        reference: impl Into<ReferencedComponent>,
    ) -> Self {
        Self::new_for_artefact_with(
            owner,
            artefact_id,
            name,
            PropertyConfidence::certain(),
            PropertyKind::new_component_ref(reference),
        )
    }

    pub fn new_external_analysis_artefact(
        component_id: Uuid,
        name: impl Into<Cow<'static, str>>,
        artefact: impl Into<ExternalAnalysisArtefact>,
    ) -> Self {
        Self::new(
            component_id,
            name,
            PropertyConfidence::certain(),
            PropertyKind::new_external_analysis_artefact(artefact),
        )
    }

    #[deprecated(since = "2.0.123", note = "deprecated in favour of `entity_id`")]
    pub fn component(&self) -> Uuid {
        self.entity_id.id()
    }

    #[deprecated(since = "2.0.123", note = "deprecated in favour of `with_entity`")]
    pub fn with_component(mut self, component: Uuid) -> Self {
        self.set_entity(component);
        self
    }

    #[deprecated(since = "2.0.123", note = "deprecated in favour of `set_entity`")]
    pub fn set_component(&mut self, component: Uuid) {
        self.set_entity(component)
    }

    pub fn entity_id(&self) -> Uuid {
        self.entity_id.id()
    }

    pub fn entity(&self) -> &EntityIdentity {
        &self.entity_id
    }

    pub fn with_entity(mut self, entity: impl Into<EntityIdentity>) -> Self {
        self.set_entity(entity);
        self
    }

    pub fn set_entity(&mut self, entity: impl Into<EntityIdentity>) {
        self.entity_id = entity.into();
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn with_name(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        self.set_name(name);
        self
    }

    pub fn set_name(&mut self, name: impl Into<Cow<'static, str>>) {
        self.name = name.into();
    }

    pub fn confidence(&self) -> PropertyConfidence {
        self.confidence
    }

    pub fn with_confidence(mut self, confidence: impl Into<PropertyConfidence>) -> Self {
        self.set_confidence(confidence);
        self
    }

    pub fn set_confidence(&mut self, confidence: impl Into<PropertyConfidence>) {
        self.confidence = confidence.into();
    }

    pub fn metadata(&self) -> Option<&Value> {
        if let PropertyKind::Metadata { ref value } = self.kind {
            Some(value)
        } else {
            None
        }
    }

    pub fn metadata_mut(&mut self) -> Option<&mut Value> {
        if let PropertyKind::Metadata { ref mut value } = self.kind {
            Some(value)
        } else {
            None
        }
    }

    pub fn into_metadata(self) -> Option<Value> {
        if let PropertyKind::Metadata { value } = self.kind {
            Some(value)
        } else {
            None
        }
    }

    pub fn metadata_as<T>(&self) -> Option<T>
    where
        T: DeserializeOwned,
    {
        if let PropertyKind::Metadata { ref value } = self.kind {
            serde_json::from_value(value.to_owned()).ok()
        } else {
            None
        }
    }

    pub fn into_metadata_as<T>(self) -> Option<T>
    where
        T: DeserializeOwned,
    {
        if let PropertyKind::Metadata { value } = self.kind {
            serde_json::from_value(value).ok()
        } else {
            None
        }
    }

    pub fn artefact_ref(&self) -> Option<&ReferencedArtefact> {
        if let PropertyKind::ReferencedArtefact { ref value } = self.kind {
            Some(value)
        } else {
            None
        }
    }

    pub fn artefact_ref_mut(&mut self) -> Option<&mut ReferencedArtefact> {
        if let PropertyKind::ReferencedArtefact { ref mut value } = self.kind {
            Some(value)
        } else {
            None
        }
    }

    pub fn into_artefact_ref(self) -> Option<ReferencedArtefact> {
        if let PropertyKind::ReferencedArtefact { value } = self.kind {
            Some(value)
        } else {
            None
        }
    }

    pub fn component_ref(&self) -> Option<&ReferencedComponent> {
        if let PropertyKind::ReferencedComponent { ref value } = self.kind {
            Some(value)
        } else {
            None
        }
    }

    pub fn component_ref_mut(&mut self) -> Option<&mut ReferencedComponent> {
        if let PropertyKind::ReferencedComponent { ref mut value } = self.kind {
            Some(value)
        } else {
            None
        }
    }

    pub fn into_component_ref(self) -> Option<ReferencedComponent> {
        if let PropertyKind::ReferencedComponent { value } = self.kind {
            Some(value)
        } else {
            None
        }
    }

    pub fn finding(&self) -> Option<&Finding> {
        if let PropertyKind::Finding { ref value } = self.kind {
            Some(value)
        } else {
            None
        }
    }

    pub fn finding_mut(&mut self) -> Option<&mut Finding> {
        if let PropertyKind::Finding { ref mut value } = self.kind {
            Some(value)
        } else {
            None
        }
    }

    pub fn into_finding(self) -> Option<Finding> {
        if let PropertyKind::Finding { value } = self.kind {
            Some(value)
        } else {
            None
        }
    }

    pub fn fingerprint(&self) -> Option<Fingerprint> {
        self.finding().map(Finding::fingerprint)
    }
}

impl<'de> Deserialize<'de> for Property {
    fn deserialize<D>(deserialiser: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct PropertyT {
            #[serde(default)]
            entity_id: Option<EntityIdentity>,
            name: Cow<'static, str>,
            confidence: PropertyConfidence,
            kind: PropertyKind,
            #[serde(default)]
            component_id: Option<Uuid>,
            #[serde(default)]
            target: Option<PropertyTarget>,
        }

        let property = PropertyT::deserialize(deserialiser)?;

        let entity_id = if let Some(entity_id) = property.entity_id {
            entity_id
        } else {
            let Some(component_id) = property.component_id else {
                return Err(serde::de::Error::missing_field("entity_id or component_id"));
            };

            let Some(target) = property.target else {
                return Err(serde::de::Error::missing_field("target"));
            };

            EntityIdentity::new_with_target(component_id.into(), target)
        };

        Ok(Self {
            entity_id,
            name: property.name,
            confidence: property.confidence,
            kind: property.kind,
        })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[repr(transparent)]
pub struct PropertyConfidence(OrderedFloat<f64>);

impl Default for PropertyConfidence {
    fn default() -> Self {
        Self::certain()
    }
}

impl From<f64> for PropertyConfidence {
    fn from(value: f64) -> Self {
        Self::new(value)
    }
}

impl From<PropertyConfidence> for f64 {
    fn from(value: PropertyConfidence) -> Self {
        value.0 .0
    }
}

impl PropertyConfidence {
    pub fn new(value: f64) -> Self {
        Self(OrderedFloat(value.clamp(0f64, 1f64)))
    }

    pub fn certain() -> Self {
        Self::new(1f64)
    }

    pub fn somewhat_certain() -> Self {
        Self::new(0.8f64)
    }

    pub fn somewhat_uncertain() -> Self {
        Self::new(0.6f64)
    }

    pub fn uncertain() -> Self {
        Self::new(0.4f64)
    }

    pub fn very_uncertain() -> Self {
        Self::new(0.2f64)
    }
}

impl<'de> Deserialize<'de> for PropertyConfidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Confidence {
            Float(f64),
            String(ConfidenceKinds),
        }

        #[derive(Deserialize)]
        enum ConfidenceKinds {
            #[serde(rename = "certain", alias = "very high")]
            Certain,
            #[serde(rename = "somewhat certain", alias = "high")]
            SomewhatCertain,
            #[serde(rename = "somewhat uncertain", alias = "medium")]
            SomewhatUncertain,
            #[serde(rename = "uncertain", alias = "low")]
            Uncertain,
            #[serde(rename = "very uncertain", alias = "very low")]
            VeryUncertain,
        }

        let value = Confidence::deserialize(deserializer)?;

        match value {
            Confidence::Float(value) => {
                if (0f64..=1f64).contains(&value) {
                    Ok(Self(value.into()))
                } else {
                    Err(serde::de::Error::custom(format!(
                        "property confidence must be between 0 and 1; got {value}",
                    )))
                }
            }
            Confidence::String(value) => match value {
                ConfidenceKinds::Certain => Ok(Self::certain()),
                ConfidenceKinds::SomewhatCertain => Ok(Self::somewhat_certain()),
                ConfidenceKinds::SomewhatUncertain => Ok(Self::somewhat_uncertain()),
                ConfidenceKinds::Uncertain => Ok(Self::uncertain()),
                ConfidenceKinds::VeryUncertain => Ok(Self::very_uncertain()),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[non_exhaustive]
#[serde(tag = "kind")]
pub enum PropertyKind {
    #[serde(rename = "metadata")]
    Metadata { value: Value },
    #[serde(rename = "finding")]
    Finding { value: Finding },
    #[serde(rename = "external-analysis-artefact")]
    ExternalAnalysisArtefact { value: ExternalAnalysisArtefact },
    #[serde(rename = "referenced-artefact")]
    ReferencedArtefact { value: ReferencedArtefact },
    #[serde(rename = "referenced-component")]
    ReferencedComponent { value: ReferencedComponent },
}

#[derive(Debug, Error)]
pub enum PropertyKindError {
    #[error(transparent)]
    InvalidFinding(#[from] FindingError),
    #[error(transparent)]
    InvalidExternalAnalysisArtefact(#[from] ExternalAnalysisArtefactError),
    #[error(transparent)]
    InvalidReferencedArtefact(#[from] ReferencedArtefactError),
    #[error(transparent)]
    InvalidReferencedComponent(#[from] ReferencedComponentError),
}

impl PropertyKind {
    pub fn new_metadata(value: impl Serialize) -> Self {
        Self::Metadata {
            value: serde_json::json!(value),
        }
    }

    pub fn metadata(&self) -> Option<&Value> {
        if let Self::Metadata { ref value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn into_metadata(self) -> Option<Value> {
        if let Self::Metadata { value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn new_finding(finding: impl Into<Finding>) -> Self {
        Self::Finding {
            value: finding.into(),
        }
    }

    pub fn finding(&self) -> Option<&Finding> {
        if let Self::Finding { ref value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn into_finding(self) -> Option<Finding> {
        if let Self::Finding { value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn new_external_analysis_artefact(artefact: impl Into<ExternalAnalysisArtefact>) -> Self {
        Self::ExternalAnalysisArtefact {
            value: artefact.into(),
        }
    }

    pub fn external_analysis_artefact(&self) -> Option<&ExternalAnalysisArtefact> {
        if let Self::ExternalAnalysisArtefact { ref value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn into_external_analysis_artefact(self) -> Option<ExternalAnalysisArtefact> {
        if let Self::ExternalAnalysisArtefact { value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn new_artefact_ref(artefact: impl Into<ReferencedArtefact>) -> Self {
        Self::ReferencedArtefact {
            value: artefact.into(),
        }
    }

    pub fn artefact_ref(&self) -> Option<&ReferencedArtefact> {
        if let Self::ReferencedArtefact { ref value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn into_artefact_ref(self) -> Option<ReferencedArtefact> {
        if let Self::ReferencedArtefact { value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn new_component_ref(component: impl Into<ReferencedComponent>) -> Self {
        Self::ReferencedComponent {
            value: component.into(),
        }
    }

    pub fn component_ref(&self) -> Option<&ReferencedComponent> {
        if let Self::ReferencedComponent { ref value } = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn into_component_ref(self) -> Option<ReferencedComponent> {
        if let Self::ReferencedComponent { value } = self {
            Some(value)
        } else {
            None
        }
    }
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize, VariantNames,
)]
pub enum Severity {
    #[serde(rename = "none", alias = "unspecified")]
    #[strum(serialize = "none")]
    None,
    #[serde(rename = "low")]
    #[strum(serialize = "low")]
    Low,
    #[serde(rename = "medium")]
    #[strum(serialize = "medium")]
    Medium,
    #[serde(rename = "high")]
    #[strum(serialize = "high")]
    High,
    #[serde(rename = "critical")]
    #[strum(serialize = "critical")]
    Critical,
}

impl Severity {
    pub const KINDS: &'static [&'static str] = Self::VARIANTS;
}

#[derive(Debug, Error)]
#[error("cannot parse severity from string")]
pub struct ParseSeverityError;

impl FromStr for Severity {
    type Err = ParseSeverityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_lowercase().as_str() {
            "none" | "unspecified" => Ok(Self::None),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(ParseSeverityError),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(tag = "kind", content = "value")]
pub enum EntityIdentity {
    #[serde(rename = "component")]
    Component(Uuid),
    #[serde(rename = "package")]
    Package(Uuid),
    #[serde(rename = "artefact")]
    Artefact(LinkedArtefact),
}

impl From<Uuid> for EntityIdentity {
    fn from(id: Uuid) -> Self {
        Self::Component(id)
    }
}

impl EntityIdentity {
    pub fn new_component(id: Uuid) -> Self {
        Self::Component(id)
    }

    pub fn new_package(id: Uuid) -> Self {
        Self::Package(id)
    }

    pub fn new_artefact_with(id: Uuid, owner: PropertyOwner) -> Self {
        Self::Artefact(LinkedArtefact::new_with(id, owner))
    }

    pub fn new_artefact_for_component(id: Uuid, component_id: Uuid) -> Self {
        Self::Artefact(LinkedArtefact::new_for_component(id, component_id))
    }

    pub fn new_artefact_for_package(id: Uuid, package_id: Uuid) -> Self {
        Self::Artefact(LinkedArtefact::new_for_package(id, package_id))
    }

    pub fn new_with_target(id: Uuid, target: PropertyTarget) -> Self {
        match target {
            PropertyTarget::Component => id.into(),
            PropertyTarget::Artefact(artefact_id) => {
                Self::new_artefact_for_component(artefact_id, id)
            }
        }
    }

    pub fn id(&self) -> Uuid {
        match self {
            Self::Component(id) => *id,
            Self::Package(id) => *id,
            Self::Artefact(entity) => entity.id(),
        }
    }

    pub fn owner_id(&self) -> Uuid {
        match self {
            Self::Component(id) => *id,
            Self::Package(id) => *id,
            Self::Artefact(artefact) => artefact.owner_id(),
        }
    }

    pub fn is_component(&self) -> bool {
        matches!(self, Self::Component(_))
    }

    pub fn is_package(&self) -> bool {
        matches!(self, Self::Package(_))
    }

    pub fn is_artefact(&self) -> bool {
        matches!(self, Self::Artefact(_))
    }

    pub fn artefact_id(&self) -> Option<Uuid> {
        if let Self::Artefact(entity) = self {
            Some(entity.id())
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct LinkedArtefact {
    id: Uuid,
    owner: PropertyOwner,
}

impl LinkedArtefact {
    pub fn new_with(id: Uuid, owner: PropertyOwner) -> Self {
        Self { id, owner }
    }

    pub fn new_for_component(id: Uuid, component_id: Uuid) -> Self {
        Self::new_with(id, PropertyOwner::new_component(component_id))
    }

    pub fn new_for_package(id: Uuid, package_id: Uuid) -> Self {
        Self::new_with(id, PropertyOwner::new_package(package_id))
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn owner(&self) -> &PropertyOwner {
        &self.owner
    }

    pub fn owner_id(&self) -> Uuid {
        self.owner.id()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(tag = "kind", content = "value")]
pub enum PropertyOwner {
    #[serde(rename = "component")]
    Component(Uuid),
    #[serde(rename = "package")]
    Package(Uuid),
}

impl PropertyOwner {
    pub fn new_component(component_id: Uuid) -> Self {
        Self::Component(component_id)
    }

    pub fn new_package(package_id: Uuid) -> Self {
        Self::Package(package_id)
    }

    pub fn is_component(&self) -> bool {
        matches!(self, Self::Component(_))
    }

    pub fn is_package(&self) -> bool {
        matches!(self, Self::Package(_))
    }

    pub fn component(&self) -> Option<Uuid> {
        match self {
            Self::Component(id) => Some(*id),
            Self::Package(_) => None,
        }
    }

    pub fn package(&self) -> Option<Uuid> {
        match self {
            Self::Package(id) => Some(*id),
            Self::Component(_) => None,
        }
    }

    pub fn id(&self) -> Uuid {
        match self {
            Self::Component(id) | Self::Package(id) => *id,
        }
    }
}

#[derive(Debug, Error)]
#[error("invalid property owner")]
pub struct PropertyOwnerError;

#[derive(Debug, Error)]
pub enum LinkedArtefactError {
    #[error(transparent)]
    InvalidPropertyOwner(#[from] PropertyOwnerError),
    #[error("artefact entity contains no ID")]
    NoArtefactId,
    #[error("artefact entity contains no owner")]
    NoPropertyOwner,
}

#[derive(Debug, Error)]
pub enum EntityIdentityError {
    #[error(transparent)]
    InvalidArtefacEntity(#[from] LinkedArtefactError),
    #[error("entity contains no entity ID")]
    NoEntityId,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Deserialize, Serialize)]
pub enum PropertyTarget {
    #[default]
    #[serde(rename = "component")]
    Component,
    #[serde(rename = "artefact")]
    Artefact(Uuid),
}

impl From<Option<Uuid>> for PropertyTarget {
    fn from(value: Option<Uuid>) -> Self {
        match value {
            None => Self::Component,
            Some(id) => Self::Artefact(id),
        }
    }
}

impl PropertyTarget {
    pub fn is_component(&self) -> bool {
        matches!(self, Self::Component)
    }

    pub fn is_artefact(&self) -> bool {
        matches!(self, Self::Artefact(_))
    }

    pub fn artefact(&self) -> Option<Uuid> {
        if let Self::Artefact(id) = self {
            Some(*id)
        } else {
            None
        }
    }
}

#[derive(Debug, Error)]
#[error("invalid property target")]
pub struct PropertyTargetError;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_confidence_deserialise() -> Result<(), Box<dyn std::error::Error>> {
        let s1 = r#""somewhat certain""#;
        let s2 = r#""somewhat uncertain""#;
        let s3 = r#""certain""#;
        let s4 = r#""very uncertain""#;
        let s5 = r#""very high""#;
        let s6 = r#""high""#;
        let s7 = r#""medium""#;

        let f1 = r#"0.2"#;
        let f2 = r#"0.4"#;

        assert_eq!(
            serde_json::from_str::<PropertyConfidence>(s1)?,
            PropertyConfidence::somewhat_certain()
        );
        assert_eq!(
            serde_json::from_str::<PropertyConfidence>(s2)?,
            PropertyConfidence::somewhat_uncertain()
        );
        assert_eq!(
            serde_json::from_str::<PropertyConfidence>(s3)?,
            PropertyConfidence::certain()
        );
        assert_eq!(
            serde_json::from_str::<PropertyConfidence>(s4)?,
            PropertyConfidence::very_uncertain()
        );
        assert_eq!(
            serde_json::from_str::<PropertyConfidence>(s5)?,
            PropertyConfidence::certain()
        );
        assert_eq!(
            serde_json::from_str::<PropertyConfidence>(s6)?,
            PropertyConfidence::somewhat_certain()
        );
        assert_eq!(
            serde_json::from_str::<PropertyConfidence>(s7)?,
            PropertyConfidence::somewhat_uncertain()
        );
        assert_eq!(
            serde_json::from_str::<PropertyConfidence>(f1)?,
            PropertyConfidence::very_uncertain()
        );
        assert_eq!(
            serde_json::from_str::<PropertyConfidence>(f2)?,
            PropertyConfidence::uncertain()
        );

        Ok(())
    }
}

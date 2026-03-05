use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::types::property::PropertyConfidence;

#[derive(Debug, Error)]
pub enum EnvironmentReachabilityError {
    #[error("missing reachability information")]
    MissingReachability,
    #[error("unsupported environment kind")]
    UnsupportedEnvironmentKind,
    #[error("unsupported environment reachability")]
    Unsupported,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
pub enum EnvironmentKind {
    #[default]
    #[serde(rename = "undetermined")]
    Undetermined,
    #[serde(rename = "container")]
    Container,
    #[serde(rename = "system-image")]
    SystemImage,
    #[serde(rename = "firmware-image")]
    FirmwareImage,
}

impl EnvironmentKind {
    pub fn undetermined() -> Self {
        Self::Undetermined
    }

    pub fn container() -> Self {
        Self::Container
    }

    pub fn system_image() -> Self {
        Self::SystemImage
    }

    pub fn firmware_image() -> Self {
        Self::FirmwareImage
    }

    pub fn is_undetermined(&self) -> bool {
        matches!(self, Self::Undetermined)
    }

    pub fn is_container(&self) -> bool {
        matches!(self, Self::Container)
    }

    pub fn is_system_image(&self) -> bool {
        matches!(self, Self::SystemImage)
    }

    pub fn is_firmware_image(&self) -> bool {
        matches!(self, Self::FirmwareImage)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(tag = "kind")]
pub enum EnvironmentReachabilityKind {
    #[serde(rename = "undetermined")]
    Undetermined,
    #[serde(rename = "entrypoint")]
    Entrypoint,
    #[serde(rename = "runtime-invocation")]
    RuntimeInvocation { referent: Uuid },
    #[serde(rename = "runtime-dependency")]
    RuntimeDependency { referent: Uuid },
}

impl EnvironmentReachabilityKind {
    pub fn undetermined() -> Self {
        Self::Undetermined
    }

    pub fn entrypoint() -> Self {
        Self::Entrypoint
    }

    pub fn runtime_invocation(referent: impl Into<Uuid>) -> Self {
        Self::RuntimeInvocation {
            referent: referent.into(),
        }
    }

    pub fn runtime_dependency(referent: impl Into<Uuid>) -> Self {
        Self::RuntimeDependency {
            referent: referent.into(),
        }
    }

    pub fn referent(&self) -> Option<Uuid> {
        match self {
            Self::RuntimeInvocation { referent } | Self::RuntimeDependency { referent } => {
                Some(*referent)
            }
            _ => None,
        }
    }

    pub fn is_undetermined(&self) -> bool {
        matches!(self, Self::Undetermined)
    }

    pub fn is_entrypoint(&self) -> bool {
        matches!(self, Self::Entrypoint)
    }

    pub fn is_runtime_invocation(&self) -> bool {
        matches!(self, Self::RuntimeInvocation { .. })
    }

    pub fn is_runtime_dependency(&self) -> bool {
        matches!(self, Self::RuntimeDependency { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct EnvironmentReachability {
    environment: EnvironmentKind,
    kind: EnvironmentReachabilityKind,
    confidence: PropertyConfidence,
}

impl EnvironmentReachability {
    pub fn new(environment: EnvironmentKind, kind: EnvironmentReachabilityKind) -> Self {
        Self::new_with(environment, kind, PropertyConfidence::default())
    }

    pub fn new_with(
        environment: EnvironmentKind,
        kind: EnvironmentReachabilityKind,
        confidence: PropertyConfidence,
    ) -> Self {
        Self {
            environment,
            kind,
            confidence,
        }
    }

    pub fn new_entrypoint(environment: EnvironmentKind) -> Self {
        Self::new(environment, EnvironmentReachabilityKind::entrypoint())
    }

    pub fn new_runtime_invocation(environment: EnvironmentKind, referent: impl Into<Uuid>) -> Self {
        Self::new(
            environment,
            EnvironmentReachabilityKind::runtime_invocation(referent),
        )
    }

    pub fn new_runtime_dependency(environment: EnvironmentKind, referent: impl Into<Uuid>) -> Self {
        Self::new(
            environment,
            EnvironmentReachabilityKind::runtime_dependency(referent),
        )
    }

    pub fn environment(&self) -> EnvironmentKind {
        self.environment
    }

    pub fn set_environment(&mut self, environment: EnvironmentKind) {
        self.environment = environment;
    }

    pub fn with_environment(mut self, environment: EnvironmentKind) -> Self {
        self.set_environment(environment);
        self
    }

    pub fn kind(&self) -> &EnvironmentReachabilityKind {
        &self.kind
    }

    pub fn set_kind(&mut self, kind: EnvironmentReachabilityKind) {
        self.kind = kind;
    }

    pub fn with_kind(mut self, kind: EnvironmentReachabilityKind) -> Self {
        self.set_kind(kind);
        self
    }

    pub fn confidence(&self) -> PropertyConfidence {
        self.confidence
    }

    pub fn set_confidence(&mut self, confidence: PropertyConfidence) {
        self.confidence = confidence;
    }

    pub fn with_confidence(mut self, confidence: PropertyConfidence) -> Self {
        self.set_confidence(confidence);
        self
    }

    pub fn referent(&self) -> Option<Uuid> {
        self.kind.referent()
    }
}

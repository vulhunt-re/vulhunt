use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
pub use serde_json::Value as BTPScanFindings;
use ulid::Ulid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BTPScanStateType {
    New,
    Running,
    Failed,
    Done,
    Cancelled,
}

impl BTPScanStateType {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Done | Self::Failed | Self::Cancelled)
    }

    pub fn is_success(&self) -> bool {
        matches!(self, Self::Done)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BTPScanState {
    id: Ulid,
    #[serde(rename = "type")]
    state_type: BTPScanStateType,
    #[serde(rename = "createTime")]
    create_time: DateTime<Utc>,
    #[serde(default)]
    parent: Option<String>,
}

impl BTPScanState {
    pub fn id(&self) -> Ulid {
        self.id
    }

    pub fn state_type(&self) -> BTPScanStateType {
        self.state_type
    }

    pub fn create_time(&self) -> DateTime<Utc> {
        self.create_time
    }

    pub fn parent(&self) -> Option<&str> {
        self.parent.as_deref()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BTPScan {
    id: Ulid,
    #[serde(rename = "createTime")]
    create_time: DateTime<Utc>,
    #[serde(default)]
    parent: Option<String>,
    #[serde(rename = "latestScanState")]
    latest_scan_state: Option<BTPScanState>,
}

impl BTPScan {
    pub fn id(&self) -> Ulid {
        self.id
    }

    pub fn create_time(&self) -> DateTime<Utc> {
        self.create_time
    }

    pub fn parent(&self) -> Option<&str> {
        self.parent.as_deref()
    }

    pub fn latest_state(&self) -> Option<&BTPScanState> {
        self.latest_scan_state.as_ref()
    }

    pub fn state_type(&self) -> Option<BTPScanStateType> {
        self.latest_scan_state.as_ref().map(|s| s.state_type)
    }

    pub fn is_terminal(&self) -> bool {
        self.state_type().is_some_and(|s| s.is_terminal())
    }

    pub fn is_success(&self) -> bool {
        self.state_type().is_some_and(|s| s.is_success())
    }
}

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

#[derive(Debug, Deserialize, Serialize)]
pub struct BTPImage {
    id: Ulid,
    name: String,
    version: String,
    #[serde(rename = "createTime")]
    create_time: DateTime<Utc>,
    #[serde(default)]
    parent: Option<String>,
}

impl BTPImage {
    pub fn id(&self) -> Ulid {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn create_time(&self) -> DateTime<Utc> {
        self.create_time
    }

    pub fn parent(&self) -> Option<&str> {
        self.parent.as_deref()
    }
}

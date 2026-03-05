use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

#[derive(Debug, Deserialize, Serialize)]
pub struct BTPOrg {
    id: Ulid,
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(rename = "createTime")]
    create_time: DateTime<Utc>,
}

impl BTPOrg {
    pub fn id(&self) -> Ulid {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    pub fn create_time(&self) -> DateTime<Utc> {
        self.create_time
    }
}

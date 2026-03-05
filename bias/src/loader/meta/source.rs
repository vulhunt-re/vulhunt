use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SourceCodeAttributes {
    #[serde(default)]
    magic_string: String,
    #[serde(default)]
    extension: String,
}

impl SourceCodeAttributes {
    pub fn new(magic_string: impl Into<String>, extension: impl Into<String>) -> Self {
        Self {
            magic_string: magic_string.into(),
            extension: extension.into(),
        }
    }

    pub fn magic_string(&self) -> &str {
        &self.magic_string
    }

    pub fn extension(&self) -> &str {
        &self.extension
    }
}

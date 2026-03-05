use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GitDiffAttributes {
    #[serde(default)]
    magic_string: String,
    #[serde(default)]
    extension: String,
    #[serde(default)]
    commit_lhs: Option<String>,
    #[serde(default)]
    commit_rhs: String,
}

impl GitDiffAttributes {
    pub fn new(
        magic_string: impl Into<String>,
        extension: impl Into<String>,
        commit_rhs: impl Into<String>,
    ) -> Self {
        Self::new_with(magic_string, extension, None, commit_rhs)
    }

    pub fn new_with(
        magic_string: impl Into<String>,
        extension: impl Into<String>,
        commit_lhs: impl Into<Option<String>>,
        commit_rhs: impl Into<String>,
    ) -> Self {
        Self {
            magic_string: magic_string.into(),
            extension: extension.into(),
            commit_lhs: commit_lhs.into(),
            commit_rhs: commit_rhs.into(),
        }
    }

    pub fn magic_string(&self) -> &str {
        &self.magic_string
    }

    pub fn extension(&self) -> &str {
        &self.extension
    }

    pub fn commit_lhs(&self) -> Option<&str> {
        self.commit_lhs.as_deref()
    }

    pub fn set_commit_lhs(&mut self, commit_lhs: impl Into<Option<String>>) {
        self.commit_lhs = commit_lhs.into()
    }

    pub fn with_commit_lhs(mut self, commit_lhs: impl Into<Option<String>>) -> Self {
        self.set_commit_lhs(commit_lhs);
        self
    }

    pub fn commit_rhs(&self) -> &str {
        &self.commit_rhs
    }
}

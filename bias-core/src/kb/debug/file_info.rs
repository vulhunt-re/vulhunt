use std::path::{Path, PathBuf};

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct SourceFileInfo {
    file: PathBuf,
    line: u32,
}

impl SourceFileInfo {
    pub fn new<P>(file: P, line: u32) -> Self
    where
        P: Into<PathBuf>,
    {
        Self {
            file: file.into(),
            line: line,
        }
    }
    pub fn file(&self) -> &Path {
        &self.file
    }

    pub fn line(&self) -> usize {
        self.line as usize
    }
}

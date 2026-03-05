use std::fmt::Display;
use std::fs::File;
use std::io;
use std::path::Path;

use hex_display::HexDisplayExt;
use memmap2::Mmap;
use semver::BuildMetadata;
use sha2::{Digest, Sha256};
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TagBuilder {
    parts: Vec<BlobTag>,
}

#[derive(Debug, Error)]
pub enum TagBuilderError {
    #[error(transparent)]
    Directory(#[from] walkdir::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
#[repr(transparent)]
pub struct BlobTag(#[serde(with = "hex::serde")] [u8; 32]);

impl AsRef<[u8]> for BlobTag {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq<BuildMetadata> for BlobTag {
    fn eq(&self, other: &BuildMetadata) -> bool {
        self.to_string() == other.as_str()
    }
}

impl Default for BlobTag {
    fn default() -> Self {
        TagBuilder::from_none()
    }
}

impl Display for BlobTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.hex().fmt(f)
    }
}

impl From<[u8; 32]> for BlobTag {
    fn from(inner: [u8; 32]) -> Self {
        Self(inner)
    }
}

impl BlobTag {
    pub fn new(bytes: impl AsRef<[u8]>) -> Self {
        Self(Sha256::digest(bytes).into())
    }
}

impl TagBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_none() -> BlobTag {
        Self::new().build()
    }

    pub fn from_single(tag: BlobTag) -> BlobTag {
        let mut slf = Self::new();
        slf.insert(tag);
        slf.build()
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<BlobTag, TagBuilderError> {
        let mmap = unsafe { Mmap::map(&File::open(path)?)? };
        Ok(Self::from_single(BlobTag::new(mmap)))
    }

    pub fn from_directory(path: impl AsRef<Path>) -> Result<BlobTag, TagBuilderError> {
        Self::from_directory_with(path, |_| true)
    }

    pub fn from_directory_with(
        path: impl AsRef<Path>,
        filter: impl Fn(&Path) -> bool,
    ) -> Result<BlobTag, TagBuilderError> {
        let walker = WalkDir::new(path).follow_links(true);
        let mut slf = Self::new();

        for entry in walker.into_iter() {
            let Ok(entry) = entry else { continue };
            if !entry.file_type().is_file() {
                continue;
            }

            if !filter(entry.path()) {
                continue;
            }

            let mmap = unsafe { Mmap::map(&File::open(entry.path())?)? };

            slf.insert(BlobTag::new(mmap));
        }

        Ok(slf.build())
    }

    pub fn insert(&mut self, tag: BlobTag) {
        self.parts.push(tag);
    }

    pub fn build(mut self) -> BlobTag {
        let mut hasher = Sha256::new();

        self.parts.sort();

        let init = u64::to_le_bytes(self.parts.len() as u64);

        hasher.update(init.as_ref());

        for hash in self.parts {
            hasher.update(hash.as_ref());
        }

        BlobTag(hasher.finalize().into())
    }
}

use std::borrow::Cow;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::types::common::AttributeMap;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Package {
    id: Uuid,
    name: String,
    path: Option<String>,
    #[serde(with = "hex")]
    md5: [u8; 16],
    #[serde(with = "hex")]
    sha1: [u8; 20],
    #[serde(with = "hex")]
    sha256: [u8; 32],
    attributes: AttributeMap,
}

impl Package {
    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    pub fn md5(&self) -> &[u8; 16] {
        &self.md5
    }

    pub fn sha1(&self) -> &[u8; 20] {
        &self.sha1
    }

    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    pub fn set_id(&mut self, id: Uuid) {
        self.id = id;
    }

    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    pub fn set_path(&mut self, path: impl Into<String>) {
        self.path = Some(path.into());
    }

    pub fn set_attr(&mut self, name: impl Into<Cow<'static, str>>, value: impl Serialize) {
        self.attributes
            .insert(name.into(), serde_json::json!(value));
    }

    pub fn get_attr<V: DeserializeOwned>(&self, name: impl AsRef<str>) -> Option<V> {
        self.attributes
            .get(name.as_ref())
            .and_then(|v| serde_json::from_value(v.to_owned()).ok())
    }

    pub fn set_attrs(&mut self, values: impl Serialize) {
        let serde_json::Value::Object(object) = serde_json::json!(values) else {
            return;
        };

        self.attributes
            .extend(object.into_iter().map(|(k, v)| (Cow::Owned(k), v)));
    }

    pub fn get_attrs<V: DeserializeOwned>(&self) -> Option<V> {
        let object = serde_json::Value::Object(
            self.attributes
                .iter()
                .map(|(k, v)| (k.as_ref().to_owned(), v.to_owned()))
                .collect(),
        );

        serde_json::from_value(object).ok()
    }
}

#[derive(Debug, Clone)]
pub struct PackageHashes {
    md5: [u8; 16],
    sha1: [u8; 20],
    sha256: [u8; 32],
}

impl PackageHashes {
    const CHUNK_SIZE: usize = 4096;

    pub fn from_parts(
        md5: impl Into<[u8; 16]>,
        sha1: impl Into<[u8; 20]>,
        sha256: impl Into<[u8; 32]>,
    ) -> Self {
        Self {
            md5: md5.into(),
            sha1: sha1.into(),
            sha256: sha256.into(),
        }
    }

    pub fn new(bytes: impl AsRef<[u8]>) -> Self {
        use md5::Digest as _;

        let bytes = bytes.as_ref();

        let mut md5_ctx = md5::Md5::new();
        let mut sha1_ctx = sha1::Sha1::new();
        let mut sha2_ctx = sha2::Sha256::new();

        for chunk in bytes.chunks(Self::CHUNK_SIZE) {
            md5_ctx.update(chunk);
            sha1_ctx.update(chunk);
            sha2_ctx.update(chunk);
        }

        Self::from_parts(md5_ctx.finalize(), sha1_ctx.finalize(), sha2_ctx.finalize())
    }

    pub fn md5(&self) -> &[u8; 16] {
        &self.md5
    }

    pub fn sha1(&self) -> &[u8; 20] {
        &self.sha1
    }

    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

#[derive(Debug, Clone)]
pub struct PackageBuilder {
    id: Option<Uuid>,
    name: Option<String>,
    path: Option<String>,
    hashes: Option<PackageHashes>,
    attributes: AttributeMap,
}

impl PackageBuilder {
    pub fn new() -> Self {
        Self {
            id: None,
            name: None,
            path: None,
            hashes: None,
            attributes: AttributeMap::new(),
        }
    }

    pub fn set_id(&mut self, id: impl Into<Uuid>) {
        self.id = Some(id.into());
    }

    pub fn with_id(mut self, id: impl Into<Uuid>) -> Self {
        self.set_id(id);
        self
    }

    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = Some(name.into());
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.set_name(name);
        self
    }

    pub fn set_path(&mut self, path: impl Into<String>) {
        self.path = Some(path.into());
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.set_path(path);
        self
    }

    pub fn set_hashes(&mut self, hashes: impl Into<PackageHashes>) {
        self.hashes = Some(hashes.into());
    }

    pub fn with_hashes(mut self, hashes: impl Into<PackageHashes>) -> Self {
        self.set_hashes(hashes);
        self
    }

    pub fn with_attrs(mut self, values: impl Serialize) -> Self {
        self.set_attrs(values);
        self
    }

    pub fn set_attr(&mut self, name: impl Into<Cow<'static, str>>, value: impl Serialize) {
        self.attributes
            .insert(name.into(), serde_json::json!(value));
    }

    pub fn set_attrs(&mut self, values: impl Serialize) {
        let serde_json::Value::Object(object) = serde_json::json!(values) else {
            return;
        };

        self.attributes
            .extend(object.into_iter().map(|(k, v)| (Cow::Owned(k), v)));
    }

    pub fn get_attr<V: DeserializeOwned>(&self, name: impl AsRef<str>) -> Option<V> {
        self.attributes
            .get(name.as_ref())
            .and_then(|v| serde_json::from_value(v.to_owned()).ok())
    }

    pub fn get_attrs<V: DeserializeOwned>(&self) -> Option<V> {
        let object = serde_json::Value::Object(
            self.attributes
                .iter()
                .map(|(k, v)| (k.as_ref().to_owned(), v.to_owned()))
                .collect(),
        );

        serde_json::from_value(object).ok()
    }

    pub fn build(self) -> Result<Package, PackageError> {
        let Some(id) = self.id else {
            return Err(PackageError::NoId);
        };

        // NOTE: no name -- use path or ID
        let name = self
            .name
            .or_else(|| self.path.as_ref().map(ToOwned::to_owned))
            .unwrap_or_else(|| id.as_hyphenated().to_string());

        let Some(PackageHashes { md5, sha1, sha256 }) = self.hashes else {
            return Err(PackageError::NoHashes);
        };

        Ok(Package {
            id,
            name,
            path: self.path,
            md5,
            sha1,
            sha256,
            attributes: self.attributes,
        })
    }
}

#[derive(Debug, Error)]
pub enum PackageError {
    #[error("invalid md5 digest")]
    InvalidMd5,
    #[error("invalid sha-1 digest")]
    InvalidSha1,
    #[error("invalid sha-256 digest")]
    InvalidSha256,
    #[error("package has no ID")]
    NoId,
    #[error("package has no name")]
    NoName,
    #[error("package has no hashes")]
    NoHashes,
}

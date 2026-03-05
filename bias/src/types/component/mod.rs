use std::borrow::Cow;
use std::fmt::{self, Display};
use std::str::FromStr;

use hex_display::HexDisplayExt;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::types::common::AttributeMap;

pub mod linkage;
use linkage::{Exports, ExportsError, ImportedDependency, Imports, ImportsError};

#[derive(Debug, Error)]
#[error("invalid component identity: {0}")]
pub struct InvalidComponentIdentity(hex::FromHexError);

impl FromStr for ComponentIdentity {
    type Err = InvalidComponentIdentity;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(s, &mut bytes).map_err(InvalidComponentIdentity)?;
        Ok(Self(bytes))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct ComponentIdentity(#[serde(with = "hex::serde")] [u8; 32]);

impl From<[u8; 32]> for ComponentIdentity {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<blake3::Hash> for ComponentIdentity {
    fn from(value: blake3::Hash) -> Self {
        Self(value.into())
    }
}

impl From<ComponentIdentity> for [u8; 32] {
    fn from(value: ComponentIdentity) -> Self {
        value.0
    }
}

impl AsRef<[u8]> for ComponentIdentity {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Display for ComponentIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.hex().fmt(f)
    }
}

#[derive(Default)]
#[repr(transparent)]
pub struct ComponentIdentityBuilder {
    state: blake3::Hasher,
}

impl ComponentIdentityBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, bytes: impl AsRef<[u8]>) {
        self.state.update(bytes.as_ref());
    }

    pub fn build(&mut self) -> ComponentIdentity {
        let id = self.state.finalize();
        self.state.reset();
        id.into()
    }
}

pub trait HasComponentIdentity {
    fn compute_identity_with(&self, builder: &mut ComponentIdentityBuilder) -> ComponentIdentity;

    fn compute_identity(&self) -> ComponentIdentity {
        self.compute_identity_with(&mut Default::default())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Component {
    id: Uuid,
    #[serde(default)]
    package_id: Option<Uuid>,
    #[serde(default)]
    partition_id: Option<u32>,
    name: String,
    kind: Cow<'static, str>,
    path: String,
    #[serde(default)]
    container_path: Option<String>,
    #[serde(default)]
    virtual_path: Option<String>,
    #[serde(default)]
    primary_component_id: Option<Uuid>,
    #[serde(default)]
    global_component_id: Option<ComponentIdentity>,
    #[serde(with = "hex")]
    md5: [u8; 16],
    #[serde(with = "hex")]
    sha1: [u8; 20],
    #[serde(with = "hex")]
    sha256: [u8; 32],
    attributes: AttributeMap,
}

impl Component {
    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn package_id(&self) -> Option<Uuid> {
        self.package_id
    }

    pub fn set_package_id(&mut self, id: impl Into<Uuid>) {
        self.package_id = Some(id.into());
    }

    pub fn with_package_id(mut self, id: impl Into<Uuid>) -> Self {
        self.set_package_id(id);
        self
    }

    pub fn partition_id(&self) -> Option<u32> {
        self.partition_id
    }

    pub fn set_partition_id(&mut self, id: u32) {
        self.partition_id = Some(id);
    }

    pub fn with_partition_id(mut self, id: u32) -> Self {
        self.set_partition_id(id);
        self
    }

    pub fn primary_component_id(&self) -> Option<Uuid> {
        self.primary_component_id
    }

    pub fn set_primary_component_id(&mut self, id: impl Into<Uuid>) {
        self.primary_component_id = Some(id.into());
    }

    pub fn with_primary_component_id(mut self, id: impl Into<Uuid>) -> Self {
        self.set_primary_component_id(id);
        self
    }

    pub fn global_component_id(&self) -> Option<ComponentIdentity> {
        self.global_component_id
    }

    pub fn set_global_component_id(&mut self, id: impl Into<ComponentIdentity>) {
        self.global_component_id = Some(id.into());
    }

    pub fn with_global_component_id(mut self, id: impl Into<ComponentIdentity>) -> Self {
        self.set_global_component_id(id);
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn container_path(&self) -> Option<&str> {
        self.container_path.as_deref()
    }

    pub fn virtual_path(&self) -> Option<&str> {
        self.virtual_path.as_deref()
    }

    pub fn set_virtual_path(&mut self, virtual_path: Option<impl Into<String>>) {
        self.virtual_path = virtual_path.map(Into::into);
    }

    pub fn with_virtual_path(mut self, virtual_path: Option<impl Into<String>>) -> Self {
        self.set_virtual_path(virtual_path);
        self
    }

    pub fn is_meta(&self) -> bool {
        self.container_path.is_none()
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
pub struct ComponentHashes {
    md5: [u8; 16],
    sha1: [u8; 20],
    sha256: [u8; 32],
}

impl ComponentHashes {
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
pub struct ComponentBuilder {
    id: Option<Uuid>,
    package_id: Option<Uuid>,
    partition_id: Option<u32>,
    primary_component_id: Option<Uuid>,
    global_component_id: Option<ComponentIdentity>,
    name: Option<String>,
    kind: Cow<'static, str>,
    path: Option<String>,
    container_path: Option<String>,
    virtual_path: Option<String>,
    hashes: Option<ComponentHashes>,
    attributes: AttributeMap,
}

impl ComponentBuilder {
    pub fn new(kind: impl Into<Cow<'static, str>>) -> Self {
        Self {
            id: None,
            package_id: None,
            partition_id: None,
            primary_component_id: None,
            global_component_id: None,
            name: None,
            kind: kind.into(),
            path: None,
            container_path: None,
            virtual_path: None,
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

    pub fn set_package_id(&mut self, id: impl Into<Uuid>) {
        self.package_id = Some(id.into());
    }

    pub fn with_package_id(mut self, id: impl Into<Uuid>) -> Self {
        self.set_package_id(id);
        self
    }

    pub fn set_partition_id(&mut self, id: u32) {
        self.partition_id = Some(id);
    }

    pub fn with_partition_id(mut self, id: u32) -> Self {
        self.set_partition_id(id);
        self
    }

    pub fn set_primary_component_id(&mut self, id: impl Into<Uuid>) {
        self.primary_component_id = Some(id.into());
    }

    pub fn with_primary_component_id(mut self, id: impl Into<Uuid>) -> Self {
        self.set_primary_component_id(id);
        self
    }

    pub fn set_global_component_id(&mut self, id: impl Into<ComponentIdentity>) {
        self.global_component_id = Some(id.into());
    }

    pub fn with_global_component_id(mut self, id: impl Into<ComponentIdentity>) -> Self {
        self.set_global_component_id(id);
        self
    }

    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = Some(name.into());
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.set_name(name);
        self
    }

    pub fn set_kind(&mut self, kind: impl Into<Cow<'static, str>>) {
        self.kind = kind.into();
    }

    pub fn with_kind(mut self, kind: impl Into<Cow<'static, str>>) -> Self {
        self.set_kind(kind);
        self
    }

    pub fn set_path(&mut self, path: impl Into<String>) {
        self.path = Some(path.into());
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.set_path(path);
        self
    }

    pub fn set_container_path(&mut self, container_path: Option<impl Into<String>>) {
        self.container_path = container_path.map(Into::into);
    }

    pub fn with_container_path(mut self, container_path: Option<impl Into<String>>) -> Self {
        self.set_container_path(container_path);
        self
    }

    pub fn set_virtual_path(&mut self, virtual_path: Option<impl Into<String>>) {
        self.virtual_path = virtual_path.map(Into::into);
    }

    pub fn with_virtual_path(mut self, virtual_path: Option<impl Into<String>>) -> Self {
        self.set_virtual_path(virtual_path);
        self
    }

    pub fn set_hashes(&mut self, hashes: impl Into<ComponentHashes>) {
        self.hashes = Some(hashes.into());
    }

    pub fn with_hashes(mut self, hashes: impl Into<ComponentHashes>) -> Self {
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

    pub fn build(self) -> Result<Component, ComponentError> {
        let Some(id) = self.id else {
            return Err(ComponentError::NoId);
        };

        let Some(name) = self.name else {
            return Err(ComponentError::NoName);
        };

        let Some(path) = self.path else {
            return Err(ComponentError::NoPath);
        };

        let Some(ComponentHashes { md5, sha1, sha256 }) = self.hashes else {
            return Err(ComponentError::NoHashes);
        };

        Ok(Component {
            id,
            package_id: self.package_id,
            partition_id: self.partition_id,
            primary_component_id: self.primary_component_id,
            global_component_id: self.global_component_id,
            name,
            kind: self.kind,
            path,
            container_path: self.container_path,
            virtual_path: self.virtual_path,
            md5,
            sha1,
            sha256,
            attributes: self.attributes,
        })
    }
}

#[derive(Debug, Error)]
pub enum ComponentError {
    #[error(transparent)]
    InvalidGlobalId(#[from] InvalidComponentIdentity),
    #[error("invalid md5 digest")]
    InvalidMd5,
    #[error("invalid sha-1 digest")]
    InvalidSha1,
    #[error("invalid sha-256 digest")]
    InvalidSha256,
    #[error("component metadata is invalid: {0}")]
    MetadataParse(#[from] serde_json::Error),
    #[error("component has no ID")]
    NoId,
    #[error("component has no name")]
    NoName,
    #[error("component has no path")]
    NoPath,
    #[error("component has no hashes")]
    NoHashes,
    #[error("could not identify platform from component bytes")]
    UnknownFormat,
    #[error("component of type not supported")]
    UnsupportedFormat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferencedComponent {
    id: Uuid,
    metadata: Option<ReferencedComponentMetadata>,
}

#[derive(Debug, Error)]
pub enum ReferencedComponentError {
    #[error(transparent)]
    InvalidMetadata(#[from] ReferencedComponentMetadataError),
    #[error("referenced component has no ID")]
    NoId,
}

impl From<ExportsError> for ReferencedComponentError {
    fn from(value: ExportsError) -> Self {
        Self::InvalidMetadata(ReferencedComponentMetadataError::Exports(value))
    }
}

impl From<ImportsError> for ReferencedComponentError {
    fn from(value: ImportsError) -> Self {
        Self::InvalidMetadata(ReferencedComponentMetadataError::Imports(value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum ReferencedComponentMetadata {
    Imports(Imports),
    Exports(Exports),
    UnresolvedImports(Imports),
    UnresolvedDependency(ImportedDependency),
}

#[derive(Debug, Error)]
pub enum ReferencedComponentMetadataError {
    #[error(transparent)]
    Imports(#[from] ImportsError),
    #[error(transparent)]
    Exports(#[from] ExportsError),
    #[error(transparent)]
    UnresolvedImports(ImportsError),
}

impl From<Imports> for ReferencedComponentMetadata {
    fn from(value: Imports) -> Self {
        Self::Imports(value)
    }
}

impl From<Exports> for ReferencedComponentMetadata {
    fn from(value: Exports) -> Self {
        Self::Exports(value)
    }
}

impl From<&'_ Uuid> for ReferencedComponent {
    fn from(value: &Uuid) -> Self {
        Self::new(*value)
    }
}

impl From<Uuid> for ReferencedComponent {
    fn from(value: Uuid) -> Self {
        Self::new(value)
    }
}

impl ReferencedComponent {
    pub fn new(id: impl Into<Uuid>) -> Self {
        Self {
            id: id.into(),
            metadata: None,
        }
    }

    pub fn new_with(id: impl Into<Uuid>, metadata: impl Into<ReferencedComponentMetadata>) -> Self {
        Self {
            id: id.into(),
            metadata: Some(metadata.into()),
        }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn has_metadata(&self) -> bool {
        self.metadata.is_some()
    }

    pub fn metadata(&self) -> Option<&ReferencedComponentMetadata> {
        self.metadata.as_ref()
    }

    pub fn set_metadata(&mut self, metadata: impl Into<ReferencedComponentMetadata>) {
        self.metadata = Some(metadata.into());
    }

    pub fn with_metadata(mut self, metadata: impl Into<ReferencedComponentMetadata>) -> Self {
        self.set_metadata(metadata);
        self
    }

    pub fn imports(&self) -> Option<&Imports> {
        if let Some(ReferencedComponentMetadata::Imports(imports)) = &self.metadata {
            Some(imports)
        } else {
            None
        }
    }

    pub fn set_imports(&mut self, imports: impl Into<Imports>) {
        self.metadata = Some(ReferencedComponentMetadata::Imports(imports.into()));
    }

    pub fn with_imports(mut self, imports: impl Into<Imports>) -> Self {
        self.set_imports(imports);
        self
    }

    pub fn exports(&self) -> Option<&Exports> {
        if let Some(ReferencedComponentMetadata::Exports(exports)) = &self.metadata {
            Some(exports)
        } else {
            None
        }
    }

    pub fn set_exports(&mut self, exports: impl Into<Exports>) {
        self.metadata = Some(ReferencedComponentMetadata::Exports(exports.into()));
    }

    pub fn with_exports(mut self, exports: impl Into<Exports>) -> Self {
        self.set_exports(exports);
        self
    }

    pub fn unresolved_imports(&self) -> Option<&Imports> {
        if let Some(ReferencedComponentMetadata::UnresolvedImports(imports)) = &self.metadata {
            Some(imports)
        } else {
            None
        }
    }

    pub fn set_unresolved_imports(&mut self, imports: impl Into<Imports>) {
        self.metadata = Some(ReferencedComponentMetadata::UnresolvedImports(
            imports.into(),
        ));
    }

    pub fn with_unresolved_imports(mut self, imports: impl Into<Imports>) -> Self {
        self.set_unresolved_imports(imports);
        self
    }

    pub fn unresolved_dependency(&self) -> Option<&ImportedDependency> {
        if let Some(ReferencedComponentMetadata::UnresolvedDependency(dep)) = &self.metadata {
            Some(dep)
        } else {
            None
        }
    }

    pub fn set_unresolved_dependency(&mut self, dep: impl Into<ImportedDependency>) {
        self.metadata = Some(ReferencedComponentMetadata::UnresolvedDependency(
            dep.into(),
        ));
    }

    pub fn with_unresolved_dependency(mut self, dep: impl Into<ImportedDependency>) -> Self {
        self.set_unresolved_dependency(dep);
        self
    }
}

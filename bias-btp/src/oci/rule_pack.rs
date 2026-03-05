use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use async_compression::tokio::write::GzipEncoder;
use chrono::Utc;
use oci_client::client::ClientProtocol;
use oci_client::manifest::{OciDescriptor, OciImageManifest, OciManifest};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio_tar::{Builder, EntryType, Header};

use crate::auth::BTPCredentials;
use crate::client::BTPClient;
use crate::error::{BTPError, BTPRulePackError};

const MEDIA_TYPE_VULHUNT_RULEPACK: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const MEDIA_TYPE_EMPTY_JSON: &str = "application/vnd.oci.empty.v1+json";

fn registry_auth(credentials: &BTPCredentials) -> Result<RegistryAuth, BTPError> {
    match credentials {
        BTPCredentials::User { username, password } => Ok(RegistryAuth::Basic(
            username.clone(),
            password.expose_secret().to_owned(),
        )),
        _ => Err(BTPError::Authentication(
            "unsupported credentials type for registry authentication".to_owned(),
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BTPRulePlatform {
    Posix,
    Uefi,
}

impl std::fmt::Display for BTPRulePlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Posix => write!(f, "posix"),
            Self::Uefi => write!(f, "uefi"),
        }
    }
}

impl std::str::FromStr for BTPRulePlatform {
    type Err = BTPRulePackError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "posix" => Ok(Self::Posix),
            "uefi" => Ok(Self::Uefi),
            _ => Err(BTPRulePackError::InvalidPlatform(s.to_owned())),
        }
    }
}

pub struct BTPRulePackBuilder {
    repository: String,
    tag: String,
    tar: Builder<Vec<u8>>,
    file_count: usize,
    annotations: BTreeMap<String, String>,
    created_dirs: BTreeSet<PathBuf>,
}

impl BTPRulePackBuilder {
    pub fn new(repository: impl Into<String>, tag: impl Into<String>) -> Self {
        Self {
            repository: repository.into(),
            tag: tag.into(),
            tar: Builder::new(Vec::new()),
            file_count: 0,
            annotations: BTreeMap::new(),
            created_dirs: BTreeSet::new(),
        }
    }

    pub fn add_annotation(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.annotations.insert(key.into(), value.into());
    }

    pub fn with_annotation(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.add_annotation(key, value);
        self
    }

    pub async fn add_rule(
        &mut self,
        platform: BTPRulePlatform,
        name: impl AsRef<str>,
        data: impl AsRef<[u8]>,
    ) -> Result<(), BTPError> {
        let name = name.as_ref();
        let data = data.as_ref();

        if !name.ends_with(".vh") {
            return Err(BTPRulePackError::InvalidExtension {
                path: name.to_owned(),
                expected: ".vh",
            }
            .into());
        }

        let path = format!("vulhunt/{platform}/{name}");
        self.append_file(&path, data).await?;
        self.file_count += 1;

        Ok(())
    }

    pub async fn with_rule(
        mut self,
        platform: BTPRulePlatform,
        name: impl AsRef<str>,
        data: impl AsRef<[u8]>,
    ) -> Result<Self, BTPError> {
        self.add_rule(platform, name, data).await?;
        Ok(self)
    }

    pub async fn add_rule_from_file(
        &mut self,
        platform: BTPRulePlatform,
        path: impl AsRef<Path>,
    ) -> Result<(), BTPError> {
        let path = path.as_ref();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| BTPRulePackError::InvalidPath(path.display().to_string()))?;

        let data = tokio::fs::read(path).await?;
        self.add_rule(platform, name, &data).await
    }

    pub async fn with_rule_from_file(
        mut self,
        platform: BTPRulePlatform,
        path: impl AsRef<Path>,
    ) -> Result<Self, BTPError> {
        self.add_rule_from_file(platform, path).await?;
        Ok(self)
    }

    pub async fn add_rules_from_directory(
        &mut self,
        platform: BTPRulePlatform,
        dir: impl AsRef<Path>,
    ) -> Result<(), BTPError> {
        let dir = dir.as_ref();
        let mut entries = tokio::fs::read_dir(dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("vh") {
                self.add_rule_from_file(platform, &path).await?;
            }
        }

        Ok(())
    }

    pub async fn with_rules_from_directory(
        mut self,
        platform: BTPRulePlatform,
        dir: impl AsRef<Path>,
    ) -> Result<Self, BTPError> {
        self.add_rules_from_directory(platform, dir).await?;
        Ok(self)
    }

    pub async fn add_module(
        &mut self,
        name: impl AsRef<str>,
        data: impl AsRef<[u8]>,
    ) -> Result<(), BTPError> {
        let name = name.as_ref();
        let data = data.as_ref();

        if !name.ends_with(".vhm") {
            return Err(BTPRulePackError::InvalidExtension {
                path: name.to_owned(),
                expected: ".vhm",
            }
            .into());
        }

        let path = format!("vulhunt/modules/{name}");
        self.append_file(&path, data).await?;
        self.file_count += 1;

        Ok(())
    }

    pub async fn with_module(
        mut self,
        name: impl AsRef<str>,
        data: impl AsRef<[u8]>,
    ) -> Result<Self, BTPError> {
        self.add_module(name, data).await?;
        Ok(self)
    }

    pub async fn add_module_from_file(&mut self, path: impl AsRef<Path>) -> Result<(), BTPError> {
        let path = path.as_ref();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| BTPRulePackError::InvalidPath(path.display().to_string()))?;

        let data = tokio::fs::read(path).await?;
        self.add_module(name, &data).await
    }

    pub async fn with_module_from_file(mut self, path: impl AsRef<Path>) -> Result<Self, BTPError> {
        self.add_module_from_file(path).await?;
        Ok(self)
    }

    pub async fn add_modules_from_directory(
        &mut self,
        dir: impl AsRef<Path>,
    ) -> Result<(), BTPError> {
        let dir = dir.as_ref();
        let mut entries = tokio::fs::read_dir(dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("vhm") {
                self.add_module_from_file(&path).await?;
            }
        }

        Ok(())
    }

    pub async fn with_modules_from_directory(
        mut self,
        dir: impl AsRef<Path>,
    ) -> Result<Self, BTPError> {
        self.add_modules_from_directory(dir).await?;
        Ok(self)
    }

    pub async fn push(mut self, client: &BTPClient) -> Result<String, BTPError> {
        if self.file_count == 0 {
            return Err(BTPRulePackError::EmptyRulePack.into());
        }

        let tar_data = self.tar.into_inner().await?;

        let mut encoder = GzipEncoder::new(Vec::new());

        encoder.write_all(&tar_data).await?;
        encoder.shutdown().await?;

        let tar_data = encoder.into_inner();

        let credentials = client.credentials().await?;
        let auth = registry_auth(&credentials)?;

        let oci_client = Client::new(oci_client::client::ClientConfig {
            protocol: ClientProtocol::Https,
            ..Default::default()
        });

        let reference = format!("{}/{}:{}", client.registry_url(), self.repository, self.tag)
            .parse::<Reference>()
            .map_err(|e: oci_client::ParseError| {
                BTPRulePackError::InvalidReference(e.to_string())
            })?;

        oci_client
            .store_auth_if_needed(reference.registry(), &auth)
            .await;

        let layer_digest = format!("sha256:{}", hex::encode(Sha256::digest(&tar_data)));
        let layer_descriptor = OciDescriptor {
            media_type: MEDIA_TYPE_VULHUNT_RULEPACK.to_owned(),
            digest: layer_digest.clone(),
            size: tar_data.len() as i64,
            annotations: Some({
                let mut map = BTreeMap::new();
                map.insert("org.opencontainers.image.title".to_owned(), ".".to_owned());
                map.insert("io.deis.oras.content.unpack".to_owned(), "true".to_owned());
                map
            }),
            ..Default::default()
        };

        let config_data = b"{}".to_vec();
        let config_digest = format!("sha256:{}", hex::encode(Sha256::digest(&config_data)));
        let config_descriptor = OciDescriptor {
            media_type: MEDIA_TYPE_EMPTY_JSON.to_owned(),
            digest: config_digest.clone(),
            size: config_data.len() as i64,
            ..Default::default()
        };

        self.annotations.insert(
            "org.opencontainers.image.created".to_owned(),
            Utc::now().to_rfc3339(),
        );

        let manifest = OciImageManifest {
            schema_version: 2,
            media_type: Some("application/vnd.oci.image.manifest.v1+json".to_owned()),
            config: config_descriptor,
            layers: vec![layer_descriptor],
            annotations: Some(self.annotations),
            ..Default::default()
        };

        oci_client
            .push_blob(&reference, tar_data, &layer_digest)
            .await
            .map_err(BTPRulePackError::PushLayer)?;

        oci_client
            .push_blob(&reference, config_data, &config_digest)
            .await
            .map_err(BTPRulePackError::PushConfig)?;

        let manifest_url = oci_client
            .push_manifest(&reference, &OciManifest::Image(manifest))
            .await
            .map_err(BTPRulePackError::PushManifest)?;

        tracing::info!(
            "pushed rule pack to {} ({} files)",
            reference,
            self.file_count
        );

        Ok(manifest_url)
    }

    async fn append_dir(&mut self, path: impl AsRef<Path>) -> Result<(), BTPError> {
        let path = path.as_ref();
        let dir_path = format!("{}/", path.display());

        let mut header = Header::new_gnu();
        header
            .set_path(&dir_path)
            .map_err(|source| BTPRulePackError::TarPath {
                path: dir_path,
                source,
            })?;
        header.set_size(0);
        header.set_mode(0o755);
        header.set_mtime(0);
        header.set_entry_type(EntryType::Directory);
        header.set_cksum();

        self.tar.append(&header, &[] as &[u8]).await?;
        Ok(())
    }

    async fn ensure_parent_dirs(&mut self, file_path: impl AsRef<Path>) -> Result<(), BTPError> {
        let path = file_path.as_ref();
        let Some(parent) = path.parent() else {
            return Ok(());
        };

        let mut current = PathBuf::new();
        for component in parent.components() {
            if let Component::Normal(name) = component {
                current.push(name);
                if self.created_dirs.insert(current.clone()) {
                    self.append_dir(&current).await?;
                }
            }
        }
        Ok(())
    }

    async fn append_file(&mut self, path: &str, data: &[u8]) -> Result<(), BTPError> {
        self.ensure_parent_dirs(path).await?;

        let mut header = Header::new_gnu();
        header
            .set_path(path)
            .map_err(|source| BTPRulePackError::TarPath {
                path: path.to_owned(),
                source,
            })?;
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();

        self.tar.append(&header, data).await?;

        Ok(())
    }
}

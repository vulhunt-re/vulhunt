use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::models::{BTPImage, BTPOrg, BTPProduct, BTPScan};

#[derive(Debug, Deserialize)]
pub(crate) struct TokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: String,
    expires_in: u64,
}

impl TokenResponse {
    pub(crate) fn access_token(&self) -> &str {
        &self.access_token
    }

    pub(crate) fn expires_in(&self) -> u64 {
        self.expires_in
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct DownloadUrlResponse {
    #[serde(rename = "downloadUrl")]
    download_url: String,
}

impl DownloadUrlResponse {
    pub(crate) fn download_url(&self) -> &str {
        &self.download_url
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct TempFileResponse {
    #[serde(rename = "uploadUrl")]
    upload_url: String,
    id: Ulid,
}

impl TempFileResponse {
    pub(crate) fn upload_url(&self) -> &str {
        &self.upload_url
    }

    pub(crate) fn id(&self) -> Ulid {
        self.id
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct CreateProductRequest {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

impl CreateProductRequest {
    pub(crate) fn new(name: String, description: Option<String>) -> Self {
        Self { name, description }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct ProductsResponse {
    products: Vec<BTPProduct>,
}

impl ProductsResponse {
    pub(crate) fn into_products(self) -> Vec<BTPProduct> {
        self.products
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct ImagesResponse {
    images: Vec<BTPImage>,
}

impl ImagesResponse {
    pub(crate) fn into_images(self) -> Vec<BTPImage> {
        self.images
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct ScansResponse {
    scans: Vec<BTPScan>,
}

impl ScansResponse {
    pub(crate) fn into_scans(self) -> Vec<BTPScan> {
        self.scans
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct ImageUploadResponse {
    #[serde(flatten)]
    image: BTPImage,
    #[serde(default)]
    scans: Vec<BTPScan>,
}

impl ImageUploadResponse {
    pub(crate) fn into_parts(self) -> (BTPImage, Option<BTPScan>) {
        (self.image, self.scans.into_iter().next())
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RulesDeploymentRequest {
    package_name: String,
    artifact_ref: String,
    is_enabled: bool,
}

impl RulesDeploymentRequest {
    pub(crate) fn new(
        package_name: impl Into<String>,
        artifact_ref: impl Into<String>,
        is_enabled: bool,
    ) -> Self {
        Self {
            package_name: package_name.into(),
            artifact_ref: artifact_ref.into(),
            is_enabled,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct OrgsResponse {
    orgs: Vec<BTPOrg>,
}

impl OrgsResponse {
    pub(crate) fn into_orgs(self) -> Vec<BTPOrg> {
        self.orgs
    }
}

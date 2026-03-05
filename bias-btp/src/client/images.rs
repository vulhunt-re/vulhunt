use reqwest::Body;
use tokio::io::AsyncRead;
use tokio_util::io::ReaderStream;
use ulid::Ulid;

use super::BTPClient;
use super::util::{check_response, json_response};
use crate::error::BTPError;
use crate::internal::{ImageUploadResponse, ImagesResponse, TempFileResponse};
use crate::models::{BTPImage, BTPProduct};

impl BTPClient {
    pub async fn list_images(&self, product: &BTPProduct) -> Result<Vec<BTPImage>, BTPError> {
        self.list_images_by_id(product.id()).await
    }

    pub async fn list_images_by_id(&self, product_id: Ulid) -> Result<Vec<BTPImage>, BTPError> {
        let path = format!("api/v4/products/{product_id}/images");
        let url = self.base_url.join(&path)?;

        let request = self
            .http
            .get(url)
            .header("Authorization", self.bearer_token().await?)
            .header("Accept", "application/json");

        let resp = json_response::<ImagesResponse>(request).await?;
        Ok(resp.into_images())
    }

    pub async fn upload_image<R>(
        &self,
        product: &BTPProduct,
        name: impl Into<String>,
        version: impl Into<String>,
        filename: impl Into<String>,
        reader: R,
    ) -> Result<BTPImage, BTPError>
    where
        R: AsyncRead + Send + Sync + Unpin + 'static,
    {
        self.upload_image_by_id(product.id(), name, version, filename, reader)
            .await
    }

    pub async fn upload_image_by_id<R>(
        &self,
        product_id: Ulid,
        name: impl Into<String>,
        version: impl Into<String>,
        filename: impl Into<String>,
        reader: R,
    ) -> Result<BTPImage, BTPError>
    where
        R: AsyncRead + Send + Sync + Unpin + 'static,
    {
        let (image, _) = self
            .upload_image_aux_by_id(product_id, name, version, filename, false, reader)
            .await?;
        Ok(image)
    }

    pub async fn upload_and_scan_image<R>(
        &self,
        product: &BTPProduct,
        name: impl Into<String>,
        version: impl Into<String>,
        filename: impl Into<String>,
        reader: R,
    ) -> Result<(BTPImage, Ulid), BTPError>
    where
        R: AsyncRead + Send + Sync + Unpin + 'static,
    {
        self.upload_and_scan_image_by_id(product.id(), name, version, filename, reader)
            .await
    }

    pub async fn upload_and_scan_image_by_id<R>(
        &self,
        product_id: Ulid,
        name: impl Into<String>,
        version: impl Into<String>,
        filename: impl Into<String>,
        reader: R,
    ) -> Result<(BTPImage, Ulid), BTPError>
    where
        R: AsyncRead + Send + Sync + Unpin + 'static,
    {
        let (image, scan_id) = self
            .upload_image_aux_by_id(product_id, name, version, filename, true, reader)
            .await?;
        let scan_id = scan_id
            .ok_or_else(|| BTPError::ScanFailed("no scan ID returned from upload".to_owned()))?;
        Ok((image, scan_id))
    }

    async fn upload_image_aux_by_id<R>(
        &self,
        product_id: Ulid,
        name: impl Into<String>,
        version: impl Into<String>,
        filename: impl Into<String>,
        create_scan: bool,
        reader: R,
    ) -> Result<(BTPImage, Option<Ulid>), BTPError>
    where
        R: AsyncRead + Send + Sync + Unpin + 'static,
    {
        let name = name.into();
        let version = version.into();
        let filename = filename.into();

        let temp_file = self.generate_temp_upload_url_by_id(product_id).await?;
        tracing::debug!(temp_file_id = %temp_file.id(), "generated temp upload URL");

        self.upload_to_temp_url(temp_file.upload_url(), reader)
            .await?;
        tracing::debug!(temp_file_id = %temp_file.id(), "uploaded file to temp URL");

        let path = format!("api/v4/products/{product_id}/images:upload");
        let mut url = self.base_url.join(&path)?;

        url.query_pairs_mut()
            .append_pair("tempFileId", &temp_file.id().to_string())
            .append_pair("imageName", &name)
            .append_pair("version", &version)
            .append_pair("filename", &filename)
            .append_pair("createScan", &create_scan.to_string());

        let form = reqwest::multipart::Form::new();
        let request = self
            .http
            .post(url)
            .header("Authorization", self.bearer_token().await?)
            .header("Accept", "application/json")
            .multipart(form);

        let resp = json_response::<ImageUploadResponse>(request).await?;
        let (image, latest_scan) = resp.into_parts();
        let scan_id = latest_scan.as_ref().map(|s| s.id());

        tracing::info!(
            image_id = %image.id(),
            name = %image.name(),
            version = %image.version(),
            scan_id = ?scan_id,
            "uploaded image"
        );

        Ok((image, scan_id))
    }

    async fn generate_temp_upload_url_by_id(
        &self,
        product_id: Ulid,
    ) -> Result<TempFileResponse, BTPError> {
        let path = format!("api/v4/products/{product_id}/tempFiles:generateUploadUrl");
        let url = self.base_url.join(&path)?;

        let request = self
            .http
            .get(url)
            .header("Authorization", self.bearer_token().await?)
            .header("Accept", "application/json");

        let temp_file = json_response::<TempFileResponse>(request).await?;
        Ok(temp_file)
    }

    async fn upload_to_temp_url<R>(&self, upload_url: &str, reader: R) -> Result<(), BTPError>
    where
        R: AsyncRead + Send + Sync + Unpin + 'static,
    {
        let stream = ReaderStream::new(reader);
        let body = Body::wrap_stream(stream);

        let response = self
            .http
            .put(upload_url)
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .send()
            .await?;

        check_response(response).await?;
        Ok(())
    }
}

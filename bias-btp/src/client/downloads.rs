use std::path::{Path, PathBuf};

use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio_stream::StreamExt;
use url::Url;

use super::BTPClient;
use super::util::{check_response, json_response};
use crate::error::BTPError;
use crate::internal::DownloadUrlResponse;

impl BTPClient {
    pub async fn generate_download_url(
        &self,
        product_id: impl AsRef<str>,
        image_id: impl Into<Option<&str>>,
        scan_id: impl Into<Option<&str>>,
    ) -> Result<Url, BTPError> {
        let product_id = product_id.as_ref();
        let image = image_id.into().unwrap_or("-");
        let scan = scan_id.into().unwrap_or("-");

        let path = format!(
            "api/v4/products/{product_id}/images/{image}/scans/{scan}/ba2/downloadUrl:generate"
        );
        let url = self.base_url.join(&path)?;

        let request = self
            .http
            .post(url)
            .header("Authorization", self.bearer_token().await?)
            .header("Accept", "application/json");

        let resp = json_response::<DownloadUrlResponse>(request).await?;
        let download_url = Url::parse(resp.download_url())?;

        tracing::debug!(url = %download_url, "generated download URL");

        Ok(download_url)
    }

    pub async fn download_ba2_to_file(
        &self,
        download_url: &Url,
        path: impl AsRef<Path>,
    ) -> Result<u64, BTPError> {
        let path = path.as_ref();
        let response = self.http.get(download_url.clone()).send().await?;
        let response = check_response(response).await?;

        let mut file = File::create(path).await?;
        let mut stream = response.bytes_stream();
        let mut total = 0u64;

        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            total += chunk.len() as u64;
            file.write_all(&chunk).await?;
        }

        tracing::info!(path = %path.display(), size = total, "saved BA2 file");
        Ok(total)
    }

    pub fn extract_filename_from_url(download_url: &Url) -> Option<PathBuf> {
        download_url
            .query_pairs()
            .find(|(k, _)| k == "response-content-disposition")
            .and_then(|(_, v)| {
                v.split("filename=")
                    .nth(1)
                    .map(|s| PathBuf::from(s.trim_matches('"')))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_filename() {
        let url = Url::parse("https://example.com/file?response-content-disposition=attachment%3B+filename%3D%22test_file.ba2%22").unwrap();
        let filename = BTPClient::extract_filename_from_url(&url);
        assert_eq!(filename.as_deref(), Some(Path::new("test_file.ba2")))
    }

    #[test]
    fn test_extract_filename_no_disposition() {
        let url = Url::parse("https://example.com/file").unwrap();
        let filename = BTPClient::extract_filename_from_url(&url);
        assert_eq!(filename, None);
    }
}

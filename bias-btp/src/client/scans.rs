use std::time::Duration;

use ulid::Ulid;

use super::BTPClient;
use super::util::json_response;
use crate::error::BTPError;
use crate::internal::ScansResponse;
use crate::models::{BTPScan, BTPScanFindings, BTPScanStateType};

impl BTPClient {
    pub async fn list_scans(
        &self,
        product_id: Ulid,
        image_id: Ulid,
    ) -> Result<Vec<BTPScan>, BTPError> {
        let path = format!("api/v4/products/{product_id}/images/{image_id}/scans");
        let url = self.base_url.join(&path)?;

        let request = self
            .http
            .get(url)
            .header("Authorization", self.bearer_token().await?)
            .header("Accept", "application/json");

        let resp = json_response::<ScansResponse>(request).await?;
        Ok(resp.into_scans())
    }

    pub async fn create_scan(&self, product_id: Ulid, image_id: Ulid) -> Result<BTPScan, BTPError> {
        let path = format!("api/v4/products/{product_id}/images/{image_id}/scans");
        let url = self.base_url.join(&path)?;

        let request = self
            .http
            .post(url)
            .header("Authorization", self.bearer_token().await?)
            .header("Accept", "application/json");

        let scan = json_response::<BTPScan>(request).await?;
        Ok(scan)
    }

    pub async fn get_scan(
        &self,
        product_id: Ulid,
        image_id: Ulid,
        scan_id: Ulid,
    ) -> Result<BTPScan, BTPError> {
        let path = format!("api/v4/products/{product_id}/images/{image_id}/scans/{scan_id}");
        let url = self.base_url.join(&path)?;

        let request = self
            .http
            .get(url)
            .header("Authorization", self.bearer_token().await?)
            .header("Accept", "application/json");

        let scan = json_response::<BTPScan>(request).await?;
        Ok(scan)
    }

    pub async fn poll_scan_until_complete(
        &self,
        product_id: Ulid,
        image_id: Ulid,
        scan_id: Ulid,
        poll_interval: Duration,
    ) -> Result<BTPScan, BTPError> {
        loop {
            let scan = self.get_scan(product_id, image_id, scan_id).await?;

            match scan.state_type() {
                Some(BTPScanStateType::Done) => return Ok(scan),
                Some(BTPScanStateType::Failed) => {
                    return Err(BTPError::ScanFailed(format!("scan {scan_id} failed")));
                }
                Some(BTPScanStateType::Cancelled) => {
                    return Err(BTPError::ScanCancelled);
                }
                _ => {
                    tracing::debug!(
                        %scan_id,
                        state = ?scan.state_type(),
                        "scan not complete, polling again"
                    );
                    tokio::time::sleep(poll_interval).await;
                }
            }
        }
    }

    pub async fn get_findings_report(
        &self,
        product_id: Ulid,
        image_id: Ulid,
    ) -> Result<BTPScanFindings, BTPError> {
        let path = format!("api/v4/products/{product_id}/images/{image_id}/findingsReport:json");
        let url = self.base_url.join(&path)?;

        let request = self
            .http
            .post(url)
            .header("Authorization", self.bearer_token().await?)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .body("{}");

        let findings = json_response::<BTPScanFindings>(request).await?;
        Ok(findings)
    }
}

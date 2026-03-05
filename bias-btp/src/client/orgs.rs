use super::BTPClient;
use super::util::json_response;
use crate::error::BTPError;
use crate::internal::OrgsResponse;
use crate::models::BTPOrg;

impl BTPClient {
    pub async fn list_orgs(&self) -> Result<Vec<BTPOrg>, BTPError> {
        let url = self.base_url.join("api/v4/orgs")?;
        let request = self
            .http
            .get(url)
            .header("Authorization", self.bearer_token().await?)
            .header("Accept", "application/json");

        let resp = json_response::<OrgsResponse>(request).await?;
        Ok(resp.into_orgs())
    }
}

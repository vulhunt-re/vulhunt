use ulid::Ulid;

use super::BTPClient;
use super::util::check_response;
use crate::error::BTPError;
use crate::internal::RulesDeploymentRequest;

impl BTPClient {
    pub async fn update_product_rules_deployment(
        &self,
        product_id: Ulid,
        package_name: impl Into<String>,
        artifact_ref: impl Into<String>,
        is_enabled: bool,
    ) -> Result<(), BTPError> {
        let path = format!("api/v4/products/{product_id}/rulesetDeployments");
        let url = self.base_url.join(&path)?;
        let body = RulesDeploymentRequest::new(package_name, artifact_ref, is_enabled);

        let request = self
            .http
            .post(url)
            .header("Authorization", self.bearer_token().await?)
            .header("Accept", "application/json")
            .json(&body);

        let response = request.send().await?;
        check_response(response).await?;
        Ok(())
    }

    pub async fn update_org_rules_deployment(
        &self,
        org_id: Ulid,
        package_name: impl Into<String>,
        artifact_ref: impl Into<String>,
        is_enabled: bool,
    ) -> Result<(), BTPError> {
        let path = format!("api/v4/orgs/{org_id}/rulesetDeployments");
        let url = self.base_url.join(&path)?;
        let body = RulesDeploymentRequest::new(package_name, artifact_ref, is_enabled);

        let request = self
            .http
            .post(url)
            .header("Authorization", self.bearer_token().await?)
            .header("Accept", "application/json")
            .json(&body);

        let response = request.send().await?;
        check_response(response).await?;
        Ok(())
    }
}

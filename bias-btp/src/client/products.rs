use super::BTPClient;
use super::util::json_response;
use crate::error::BTPError;
use crate::internal::{CreateProductRequest, ProductsResponse};
use crate::models::BTPProduct;

impl BTPClient {
    pub async fn list_products(&self) -> Result<Vec<BTPProduct>, BTPError> {
        let url = self.base_url.join("api/v4/products")?;
        let request = self
            .http
            .get(url)
            .header("Authorization", self.bearer_token().await?)
            .header("Accept", "application/json");

        let resp = json_response::<ProductsResponse>(request).await?;
        Ok(resp.into_products())
    }

    pub async fn create_product(
        &self,
        name: impl Into<String>,
        description: Option<impl Into<String>>,
    ) -> Result<BTPProduct, BTPError> {
        let url = self.base_url.join("api/v4/products")?;
        let body = CreateProductRequest::new(name.into(), description.map(Into::into));

        let request = self
            .http
            .post(url)
            .header("Authorization", self.bearer_token().await?)
            .header("Accept", "application/json")
            .json(&body);

        let product = json_response::<BTPProduct>(request).await?;
        Ok(product)
    }
}

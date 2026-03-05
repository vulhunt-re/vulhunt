use reqwest::{RequestBuilder, Response};
use serde::de::DeserializeOwned;

use crate::error::BTPError;

pub(crate) async fn check_response(response: Response) -> Result<Response, BTPError> {
    if response.status().is_success() {
        Ok(response)
    } else {
        let status = response.status().as_u16();
        let message = response.text().await.unwrap_or_default();
        Err(BTPError::Api { status, message })
    }
}

pub(crate) async fn json_response<T: DeserializeOwned>(
    request: RequestBuilder,
) -> Result<T, BTPError> {
    let response = request.send().await?;
    let response = check_response(response).await?;
    Ok(response.json::<T>().await?)
}

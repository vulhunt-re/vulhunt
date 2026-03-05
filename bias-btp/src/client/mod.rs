use std::sync::Arc;
use std::time::{Duration, Instant};

use secrecy::{ExposeSecret, SecretString};
use tokio::sync::RwLock;
use url::Url;

use crate::auth::{BTPCredentials, TokenState};
use crate::error::BTPError;
use crate::internal::TokenResponse;

mod deployments;
mod downloads;
mod images;
mod orgs;
mod products;
mod scans;
mod util;

pub struct BTPClient {
    http: reqwest::Client,
    base_url: Url,
    slug: String,
    registry_url: String,
    state: Arc<RwLock<TokenState>>,
}

impl BTPClient {
    pub fn new(slug: impl AsRef<str>) -> Result<Self, BTPError> {
        let slug = slug.as_ref();
        let base_url = format!("https://dashboard-{slug}.binarly.cloud");
        let registry_url = format!("registry-{slug}.binarly.cloud");

        Ok(Self {
            http: reqwest::Client::new(),
            base_url: Url::parse(&base_url)?,
            slug: slug.to_owned(),
            registry_url,
            state: Arc::new(RwLock::new(TokenState::new())),
        })
    }

    pub(crate) fn registry_url(&self) -> &str {
        &self.registry_url
    }

    pub async fn authenticate(&self, credentials: &BTPCredentials) -> Result<(), BTPError> {
        let params = match credentials {
            BTPCredentials::User { username, password } => vec![
                ("grant_type", "password"),
                ("scope", "openid"),
                ("client_id", "BinarlyClient"),
                ("username", username.as_str()),
                ("password", password.expose_secret()),
            ],
            BTPCredentials::Machine2Machine {
                client_id,
                client_secret,
            } => vec![
                ("grant_type", "client_credentials"),
                ("scope", "openid"),
                ("client_id", client_id.as_str()),
                ("client_secret", client_secret.expose_secret()),
            ],
        };

        let auth_url = format!(
            "https://auth-{}.binarly.cloud/realms/BinarlyRealm/protocol/openid-connect/token",
            self.slug
        );
        let request = self.http.post(&auth_url).form(&params);
        let result = util::json_response::<TokenResponse>(request).await;

        let token_response = match result {
            Err(BTPError::Api { status: 404, .. }) => {
                tracing::debug!("auth- endpoint returned 404, trying kc- endpoint");

                let kc_url = format!(
                    "https://kc-{}.binarly.cloud/realms/BinarlyRealm/protocol/openid-connect/token",
                    self.slug
                );
                let request = self.http.post(&kc_url).form(&params);
                util::json_response::<TokenResponse>(request).await
            }
            other => other,
        }
        .map_err(|e| {
            if let BTPError::Api { status, message } = e {
                BTPError::Authentication(format!("status {status}: {message}"))
            } else {
                e
            }
        })?;

        let buffer = Duration::from_secs(60);
        let expires_in = Duration::from_secs(token_response.expires_in());
        let expiry = Instant::now() + expires_in - buffer;

        let mut state = self.state.write().await;
        state.set_token(
            SecretString::from(token_response.access_token().to_owned()),
            expiry,
        );
        state.set_credentials(credentials.clone());

        tracing::info!("successfully authenticated");

        Ok(())
    }

    async fn refresh_if_needed(&self) -> Result<(), BTPError> {
        let credentials = {
            let state = self.state.read().await;
            if state.is_valid() {
                return Ok(());
            }
            state.credentials().cloned()
        };

        if let Some(ref creds) = credentials {
            tracing::info!("refreshing expired token");
            self.authenticate(creds).await?;
        } else {
            return Err(BTPError::Authentication(
                "no credentials stored for refresh".to_owned(),
            ));
        }

        Ok(())
    }

    pub(crate) async fn bearer_token(&self) -> Result<String, BTPError> {
        self.refresh_if_needed().await?;

        let state = self.state.read().await;
        state
            .access_token()
            .map(|t| format!("Bearer {}", t.expose_secret()))
            .ok_or_else(|| BTPError::Authentication("not authenticated".to_owned()))
    }

    pub(crate) async fn credentials(&self) -> Result<BTPCredentials, BTPError> {
        let state = self.state.read().await;
        state
            .credentials()
            .cloned()
            .ok_or_else(|| BTPError::Authentication("not authenticated".to_owned()))
    }
}

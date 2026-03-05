use std::time::Instant;

use secrecy::SecretString;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub enum BTPCredentials {
    User {
        username: String,
        password: SecretString,
    },
    Machine2Machine {
        client_id: String,
        client_secret: SecretString,
    },
}

impl BTPCredentials {
    pub fn new_user(username: impl Into<String>, password: impl Into<SecretString>) -> Self {
        Self::User {
            username: username.into(),
            password: password.into(),
        }
    }

    pub fn new_m2m(client_id: impl Into<String>, client_secret: impl Into<SecretString>) -> Self {
        Self::Machine2Machine {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
        }
    }
}

pub(crate) struct TokenState {
    access_token: Option<SecretString>,
    expiry: Option<Instant>,
    credentials: Option<BTPCredentials>,
}

impl TokenState {
    pub(crate) fn new() -> Self {
        Self {
            access_token: None,
            expiry: None,
            credentials: None,
        }
    }

    pub(crate) fn is_valid(&self) -> bool {
        match (&self.access_token, self.expiry) {
            (Some(_), Some(expiry)) => Instant::now() < expiry,
            _ => false,
        }
    }

    pub(crate) fn access_token(&self) -> Option<&SecretString> {
        self.access_token.as_ref()
    }

    pub(crate) fn credentials(&self) -> Option<&BTPCredentials> {
        self.credentials.as_ref()
    }

    pub(crate) fn set_token(&mut self, token: SecretString, expiry: Instant) {
        self.access_token = Some(token);
        self.expiry = Some(expiry);
    }

    pub(crate) fn set_credentials(&mut self, credentials: BTPCredentials) {
        self.credentials = Some(credentials);
    }
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum BTPError {
    #[error("API error: ({status}) {message}")]
    Api { status: u16, message: String },
    #[error("authentication failed: {0}")]
    Authentication(String),
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    RulePack(#[from] BTPRulePackError),
    #[error("scan failed: {0}")]
    ScanFailed(String),
    #[error("scan cancelled")]
    ScanCancelled,
}

#[derive(Debug, Error)]
pub enum BTPRulePackError {
    #[error("invalid platform: {0}, expected `posix` or `uefi`")]
    InvalidPlatform(String),
    #[error("invalid file extension for {path}: expected {expected}")]
    InvalidExtension {
        path: String,
        expected: &'static str,
    },
    #[error("invalid path: {0}")]
    InvalidPath(String),
    #[error("empty rule pack")]
    EmptyRulePack,
    #[error("invalid OCI reference: {0}")]
    InvalidReference(String),
    #[error("failed to set tar path {path}: {source}")]
    TarPath {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to push layer: {0}")]
    PushLayer(#[source] OCIClientError),
    #[error("failed to push config: {0}")]
    PushConfig(#[source] OCIClientError),
    #[error("failed to push manifest: {0}")]
    PushManifest(#[source] OCIClientError),
}

pub use oci_client::errors::OciDistributionError as OCIClientError;

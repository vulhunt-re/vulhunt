use std::io;
use std::path::PathBuf;

use bias::component::ComponentError;
use bias::component::ComponentLoaderError;
use bias::package::PackageError;
use bias::platform::PlatformError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BNDBSourceError {
    #[error("failed to load component: {0}")]
    ComponentLoad(#[from] ComponentLoaderError),
    #[error("failed to load BNDB from file: {0}: {1}")]
    Io(PathBuf, #[source] io::Error),
    #[error("failed to initialise Binary Ninja")]
    Init(#[source] binaryninja::headless::InitializationError),
    #[error("failed to load view from: {0}")]
    ViewLoad(PathBuf),
    #[error("failed to obtain raw view from: {0}")]
    RawView(PathBuf),
    #[error("failed to read bytes from view: {0}")]
    BytesRead(PathBuf),
    #[error("failed to build component metadata: {0}")]
    Metadata(#[from] ComponentError),
    #[error("failed to build package metadata: {0}")]
    Package(#[from] PackageError),
    #[error(transparent)]
    Unsupported(#[from] PlatformError),
    #[error("unsupported binary format for guided loading")]
    UnsupportedFormat,
}

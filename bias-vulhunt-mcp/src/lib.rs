use bias::platform::common::data::PlatformDataProviderBuilderError;

use thiserror::Error;

mod project;
mod server;
mod session;
mod tools;

pub use project::{VulHuntProject, VulHuntProjectError, VulHuntProjectErrorKind};
pub use server::{VulHuntHttpServerOptions, VulHuntServer};
pub use session::VulHuntHandler;

pub use rust_mcp_sdk as mcp;
pub use rust_mcp_sdk::TransportError;
pub use rust_mcp_sdk::error::McpSdkError;

#[derive(Debug, Error)]
pub enum VulHuntServerError {
    #[error("component loader could not be initialised: {0}")]
    ComponentLoader(#[from] bias::component::ComponentLoaderError),
    #[error("platform data could not be loaded: {0}")]
    PlatformDataProvider(#[from] PlatformDataProviderBuilderError),
    #[error("MCP runtime error: {0}")]
    Runtime(McpSdkError),
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
}

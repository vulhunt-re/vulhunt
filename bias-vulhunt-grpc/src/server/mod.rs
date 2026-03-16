mod service;
pub(crate) mod session;

use std::net::SocketAddr;
use std::time::Duration;

use bias::component::ComponentLoaderError;
use bias::platform::common::data::PlatformDataProviderBuilderError;
use thiserror::Error;
use tonic::transport::Server;

use crate::proto::vul_hunt_server::VulHuntServer as VulHuntGrpcService;

pub use self::session::{VulHuntHandler, VulHuntHandlerError, VulHuntSessionInfo};

const SESSION_REAP_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Default)]
pub struct VulHuntServerOptions {
    pub session_ttl: Option<Duration>,
}

pub struct VulHuntServer {
    handler: VulHuntHandler,
    options: VulHuntServerOptions,
}

#[derive(Debug, Error)]
pub enum VulHuntServerError {
    #[error("component loader could not be initialised: {0}")]
    ComponentLoader(#[from] ComponentLoaderError),
    #[error("platform data could not be loaded: {0}")]
    PlatformDataProvider(#[from] PlatformDataProviderBuilderError),
    #[error("transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
}

impl VulHuntServer {
    pub fn new() -> Result<Self, VulHuntServerError> {
        Ok(Self {
            handler: VulHuntHandler::new()?,
            options: VulHuntServerOptions::default(),
        })
    }

    pub fn new_with(handler: VulHuntHandler, options: VulHuntServerOptions) -> Self {
        Self { handler, options }
    }

    pub async fn serve(self, addr: SocketAddr) -> Result<(), VulHuntServerError> {
        if let Some(ttl) = self.options.session_ttl {
            let sessions = self.handler.sessions_handle();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(SESSION_REAP_INTERVAL);
                loop {
                    interval.tick().await;
                    session::reap_expired(&sessions, ttl).await;
                }
            });
        }

        tracing::info!("starting gRPC server on {addr}");

        let svc = VulHuntGrpcService::new(self.handler);

        Server::builder().add_service(svc).serve(addr).await?;

        Ok(())
    }
}

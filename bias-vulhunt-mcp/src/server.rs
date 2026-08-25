use std::sync::Arc;

use rust_mcp_sdk::event_store::InMemoryEventStore;
use rust_mcp_sdk::mcp_server::hyper_server::create_server as create_streaming_http_mcp_server;
use rust_mcp_sdk::mcp_server::server_runtime::create_server as create_stdio_mcp_server;
use rust_mcp_sdk::mcp_server::{HyperServer, McpServerOptions};
use rust_mcp_sdk::schema::{
    Implementation, InitializeResult, ProtocolVersion, ServerCapabilities, ServerCapabilitiesTools,
    ServerTaskRequest, ServerTaskTools, ServerTasks, ToolExecutionTaskSupport,
};
use rust_mcp_sdk::task_store::InMemoryTaskStore;
use rust_mcp_sdk::{McpServer, StdioTransport, ToMcpServerHandler, TransportOptions};
use serde_json::Value;

use crate::VulHuntServerError;
use crate::session::VulHuntHandler;
use crate::tools::TOOLS;

pub use rust_mcp_sdk::mcp_server::HyperServerOptions as VulHuntHttpServerOptions;

pub enum VulHuntServer {
    Stdio(Arc<dyn McpServer>),
    StreamingHttp(Box<HyperServer>),
}

impl VulHuntServer {
    pub fn new_stdio_with(handler: VulHuntHandler) -> Result<Self, VulHuntServerError> {
        let transport = StdioTransport::new(TransportOptions::default())?;
        let server_details = Self::server_details();

        Ok(Self::Stdio(create_stdio_mcp_server(McpServerOptions {
            transport,
            handler: handler.to_mcp_server_handler(),
            server_details,
            client_task_store: Some(Arc::new(InMemoryTaskStore::new(None))),
            task_store: Some(Arc::new(InMemoryTaskStore::new(None))),
        })))
    }

    pub fn new_stdio() -> Result<Self, VulHuntServerError> {
        Self::new_stdio_with(VulHuntHandler::new()?)
    }

    pub fn new_streaming_http_with(
        mut options: VulHuntHttpServerOptions,
        handler: VulHuntHandler,
    ) -> Result<Self, VulHuntServerError> {
        let handler = handler.to_mcp_server_handler();
        let server_details = Self::server_details();

        if options.client_task_store.is_none() {
            options.client_task_store = Some(Arc::new(InMemoryTaskStore::new(None)));
        }

        if options.task_store.is_none() {
            options.task_store = Some(Arc::new(InMemoryTaskStore::new(None)));
        }

        if options.event_store.is_none() {
            options.event_store = Some(Arc::new(InMemoryEventStore::new(None)));
        }

        let server = create_streaming_http_mcp_server(server_details, handler, options);

        Ok(Self::StreamingHttp(Box::new(server)))
    }

    pub fn new_streaming_http(
        options: VulHuntHttpServerOptions,
    ) -> Result<Self, VulHuntServerError> {
        Self::new_streaming_http_with(options, VulHuntHandler::new()?)
    }

    fn server_details() -> InitializeResult {
        let tools_with_call_support = ServerTaskTools {
            call: Some(
                TOOLS
                    .iter()
                    .map(|(name, tool)| {
                        let supported = tool
                            .execution
                            .as_ref()
                            .map(|exec| {
                                !matches!(
                                    exec.task_support,
                                    None | Some(ToolExecutionTaskSupport::Forbidden)
                                )
                            })
                            .unwrap_or_default();
                        (name.to_owned(), Value::Bool(supported))
                    })
                    .collect(),
            ),
        };

        InitializeResult {
            capabilities: ServerCapabilities {
                tasks: Some(ServerTasks {
                    cancel: None,
                    list: Some(Default::default()),
                    requests: Some(ServerTaskRequest {
                        tools: Some(tools_with_call_support),
                    }),
                }),
                tools: Some(ServerCapabilitiesTools { list_changed: None }),
                ..Default::default()
            },
            instructions: None,
            meta: None,
            protocol_version: ProtocolVersion::latest().to_string(),
            server_info: Implementation {
                description: Some(
                    "A MCP server supporting binary analysis and vulnerabiliy hunting capabilities"
                        .to_owned(),
                ),
                icons: Vec::default(),
                name: "vulhunt-mcp-server".to_owned(),
                title: Some("VulHunt MCP server".to_owned()),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                website_url: Some("https://vulhunt.re".to_owned()),
            },
        }
    }

    pub async fn start(self) -> Result<(), VulHuntServerError> {
        match self {
            Self::Stdio(server) => server.start().await.map_err(VulHuntServerError::Runtime),
            Self::StreamingHttp(server) => {
                let runtime = (*server)
                    .start_runtime()
                    .await
                    .map_err(VulHuntServerError::Runtime)?;

                runtime
                    .await_server()
                    .await
                    .map_err(VulHuntServerError::Runtime)
            }
        }
    }
}

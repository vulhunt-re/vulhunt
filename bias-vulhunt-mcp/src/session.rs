use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Once};

use bias::component::ComponentLoader;
use bias::platform::common::data::{PlatformDataProviderBuilder, PlatformDataProviderBuilderError};

use bias_core::decompiler;

use rust_mcp_sdk::McpServer;
use rust_mcp_sdk::mcp_server::ServerHandler;
use rust_mcp_sdk::schema::{
    CallToolError, CallToolRequestParams, CallToolResult, CreateTaskResult, GetTaskParams,
    GetTaskPayloadParams, GetTaskPayloadResult, GetTaskResult, ListTasksResult, ListToolsResult,
    PaginatedRequestParams, RpcError, TaskStatus, TextContent, Tool, ToolExecutionTaskSupport,
};
use rust_mcp_sdk::task_store::{CreateTaskOptions, ServerTaskCreator};

use serde_json::Value;
use tokio::sync::{Mutex, RwLock};

use crate::VulHuntServerError;
use crate::project::VulHuntProject;
use crate::tools::*;

static INIT_PLATFORM_DATA: Once = Once::new();

#[derive(Clone)]
struct VulHuntSession {
    data_provider: PlatformDataProviderBuilder,
    modules: Option<PathBuf>,
    loader: Arc<ComponentLoader<'static>>,
    state: Arc<RwLock<VulHuntSessionState>>,
}

#[derive(Default)]
pub(crate) struct VulHuntSessionState {
    project: Option<VulHuntProject>,
}

impl VulHuntSessionState {
    pub(crate) fn set_project(&mut self, project: VulHuntProject) {
        self.project = Some(project);
    }

    pub(crate) fn project(&self) -> Option<&VulHuntProject> {
        self.project.as_ref()
    }

    pub(crate) fn project_mut(&mut self) -> Option<&mut VulHuntProject> {
        self.project.as_mut()
    }
}

impl VulHuntSession {
    pub fn new(
        data_provider: PlatformDataProviderBuilder,
        modules: impl Into<Option<PathBuf>>,
        loader: Arc<ComponentLoader<'static>>,
    ) -> Self {
        Self {
            data_provider,
            modules: modules.into(),
            loader,
            state: Arc::new(RwLock::new(VulHuntSessionState::default())),
        }
    }

    pub async fn process_call(
        self,
        req: CallToolRequestParams,
    ) -> Result<CallToolResult, CallToolError> {
        let name = req.name;
        let args = req.arguments.map(Value::Object).unwrap_or(Value::Null);

        match &*name {
            "open_project" => {
                let tool =
                    serde_json::from_value::<VulHuntOpenProject>(args).map_err(|e| {
                        tracing::error!("failed to deserialise arguments for `{name}`: {e}");
                        CallToolError::new(RpcError::invalid_request().with_message(format!(
                            "failed to deserialise arguments for `{name}`: {e}"
                        )))
                    })?;

                let state = self.state.clone();
                let data_provider = self.data_provider.clone();
                let modules = self.modules.clone();
                let loader = self.loader.clone();

                let handle = tokio::task::spawn_blocking(move || {
                    tool.execute(data_provider, modules, loader, state)
                });

                let result = match handle
                    .await
                    .map_err(|e| {
                        tracing::error!("failed to execute `open_project`: {e}");
                        CallToolError::new(
                            RpcError::internal_error()
                                .with_message(format!("failed to execute `open_project`: {e}")),
                        )
                    })?
                    .map_err(CallToolError::from_message)
                {
                    Ok(res) => res,
                    Err(e) => {
                        tracing::warn!("error executing `query_project`: {e}");
                        return Ok(CallToolResult::with_error(e));
                    }
                };

                let text = serde_json::to_string(&result).map_err(|e| {
                    tracing::error!("failed to serialise result for `open_project`: {e}");
                    CallToolError::new(RpcError::internal_error().with_message(format!(
                        "failed to serialise result for `open_project`: {e}"
                    )))
                })?;

                let mut tool_result =
                    CallToolResult::text_content(vec![TextContent::new(text, None, None)]);

                if let Value::Object(map) = result {
                    tool_result = tool_result.with_structured_content(map);
                }

                Ok(tool_result)
            }
            "query_project" => {
                let tool =
                    serde_json::from_value::<VulHuntQueryProject>(args).map_err(|e| {
                        tracing::error!("failed to deserialise arguments for `{name}`: {e}");
                        CallToolError::new(RpcError::invalid_request().with_message(format!(
                            "failed to deserialise arguments for `{name}`: {e}"
                        )))
                    })?;

                let state = self.state.clone();

                let handle = tokio::task::spawn_blocking(move || tool.execute(state));

                let result = match handle
                    .await
                    .map_err(|e| {
                        tracing::error!("failed to execute `query_project`: {e}");
                        CallToolError::new(
                            RpcError::internal_error()
                                .with_message(format!("failed to execute `query_project`: {e}")),
                        )
                    })?
                    .map_err(CallToolError::from_message)
                {
                    Ok(res) => res,
                    Err(e) => {
                        tracing::warn!("error executing `query_project`: {e}");
                        return Ok(CallToolResult::with_error(e));
                    }
                };

                let text = serde_json::to_string(&result).map_err(|e| {
                    tracing::error!("failed to serialise result for `query_project`: {e}");
                    CallToolError::new(RpcError::internal_error().with_message(format!(
                        "failed to serialise result for `query_project`: {e}"
                    )))
                })?;

                let mut tool_result =
                    CallToolResult::text_content(vec![TextContent::new(text, None, None)]);

                if let Value::Object(map) = result {
                    tool_result = tool_result.with_structured_content(map);
                }

                Ok(tool_result)
            }
            "update_function_name" => {
                let tool =
                    serde_json::from_value::<VulHuntUpdateFunctionName>(args).map_err(|e| {
                        tracing::error!("failed to deserialise arguments for `{name}`: {e}");
                        CallToolError::new(RpcError::invalid_request().with_message(format!(
                            "failed to deserialise arguments for `{name}`: {e}"
                        )))
                    })?;

                let state = self.state.clone();

                let handle = tokio::task::spawn_blocking(move || tool.execute(state));

                let result =
                    match handle
                        .await
                        .map_err(|e| {
                            tracing::error!("failed to execute `update_function_name`: {e}");
                            CallToolError::new(RpcError::internal_error().with_message(format!(
                                "failed to execute `update_function_name`: {e}"
                            )))
                        })?
                        .map_err(CallToolError::from_message)
                    {
                        Ok(res) => res,
                        Err(e) => {
                            tracing::warn!("error executing `update_function_name`: {e}");
                            return Ok(CallToolResult::with_error(e));
                        }
                    };

                let text = serde_json::to_string(&result).map_err(|e| {
                    tracing::error!("failed to serialise result for `update_function_name`: {e}");
                    CallToolError::new(RpcError::internal_error().with_message(format!(
                        "failed to serialise result for `update_function_name`: {e}"
                    )))
                })?;

                let mut tool_result =
                    CallToolResult::text_content(vec![TextContent::new(text, None, None)]);

                if let Value::Object(map) = result {
                    tool_result = tool_result.with_structured_content(map);
                }

                Ok(tool_result)
            }
            "set_function_notes" => {
                let tool =
                    serde_json::from_value::<VulHuntSetFunctionNotes>(args).map_err(|e| {
                        tracing::error!("failed to deserialise arguments for `{name}`: {e}");
                        CallToolError::new(RpcError::invalid_request().with_message(format!(
                            "failed to deserialise arguments for `{name}`: {e}"
                        )))
                    })?;

                let state = self.state.clone();

                let handle = tokio::task::spawn_blocking(move || tool.execute(state));

                let result =
                    match handle
                        .await
                        .map_err(|e| {
                            tracing::error!("failed to execute `set_function_notes`: {e}");
                            CallToolError::new(RpcError::internal_error().with_message(format!(
                                "failed to execute `set_function_notes`: {e}"
                            )))
                        })?
                        .map_err(CallToolError::from_message)
                    {
                        Ok(res) => res,
                        Err(e) => {
                            tracing::warn!("error executing `set_function_notes`: {e}");
                            return Ok(CallToolResult::with_error(e));
                        }
                    };

                let text = serde_json::to_string(&result).map_err(|e| {
                    tracing::error!("failed to serialise result for `set_function_notes`: {e}");
                    CallToolError::new(RpcError::internal_error().with_message(format!(
                        "failed to serialise result for `set_function_notes`: {e}"
                    )))
                })?;

                let mut tool_result =
                    CallToolResult::text_content(vec![TextContent::new(text, None, None)]);

                if let Value::Object(map) = result {
                    tool_result = tool_result.with_structured_content(map);
                }

                Ok(tool_result)
            }
            "get_function_notes" => {
                let tool =
                    serde_json::from_value::<VulHuntGetFunctionNotes>(args).map_err(|e| {
                        tracing::error!("failed to deserialise arguments for `{name}`: {e}");
                        CallToolError::new(RpcError::invalid_request().with_message(format!(
                            "failed to deserialise arguments for `{name}`: {e}"
                        )))
                    })?;

                let state = self.state.clone();

                let handle = tokio::task::spawn_blocking(move || tool.execute(state));

                let result =
                    match handle
                        .await
                        .map_err(|e| {
                            tracing::error!("failed to execute `get_function_notes`: {e}");
                            CallToolError::new(RpcError::internal_error().with_message(format!(
                                "failed to execute `get_function_notes`: {e}"
                            )))
                        })?
                        .map_err(CallToolError::from_message)
                    {
                        Ok(res) => res,
                        Err(e) => {
                            tracing::warn!("error executing `get_function_notes`: {e}");
                            return Ok(CallToolResult::with_error(e));
                        }
                    };

                let text = serde_json::to_string(&result).map_err(|e| {
                    tracing::error!("failed to serialise result for `get_function_notes`: {e}");
                    CallToolError::new(RpcError::internal_error().with_message(format!(
                        "failed to serialise result for `get_function_notes`: {e}"
                    )))
                })?;

                let mut tool_result =
                    CallToolResult::text_content(vec![TextContent::new(text, None, None)]);

                if let Value::Object(map) = result {
                    tool_result = tool_result.with_structured_content(map);
                }

                Ok(tool_result)
            }
            "load_signatures" => {
                let tool =
                    serde_json::from_value::<VulHuntLoadSignatures>(args).map_err(|e| {
                        tracing::error!("failed to deserialise arguments for `{name}`: {e}");
                        CallToolError::new(RpcError::invalid_request().with_message(format!(
                            "failed to deserialise arguments for `{name}`: {e}"
                        )))
                    })?;

                let state = self.state.clone();

                let handle = tokio::task::spawn_blocking(move || tool.execute(state));

                let result = match handle
                    .await
                    .map_err(|e| {
                        tracing::error!("failed to execute `load_signatures`: {e}");
                        CallToolError::new(
                            RpcError::internal_error()
                                .with_message(format!("failed to execute `load_signatures`: {e}")),
                        )
                    })?
                    .map_err(CallToolError::from_message)
                {
                    Ok(res) => res,
                    Err(e) => {
                        tracing::warn!("error executing `load_signatures`: {e}");
                        return Ok(CallToolResult::with_error(e));
                    }
                };

                let text = serde_json::to_string(&result).map_err(|e| {
                    tracing::error!("failed to serialise result for `load_signatures`: {e}");
                    CallToolError::new(RpcError::internal_error().with_message(format!(
                        "failed to serialise result for `load_signatures`: {e}"
                    )))
                })?;

                let mut tool_result =
                    CallToolResult::text_content(vec![TextContent::new(text, None, None)]);

                if let Value::Object(map) = result {
                    tool_result = tool_result.with_structured_content(map);
                }

                Ok(tool_result)
            }
            "load_types" => {
                let tool =
                    serde_json::from_value::<VulHuntLoadTypes>(args).map_err(|e| {
                        tracing::error!("failed to deserialise arguments for `{name}`: {e}");
                        CallToolError::new(RpcError::invalid_request().with_message(format!(
                            "failed to deserialise arguments for `{name}`: {e}"
                        )))
                    })?;

                let state = self.state.clone();

                let handle = tokio::task::spawn_blocking(move || tool.execute(state));

                let result = match handle
                    .await
                    .map_err(|e| {
                        tracing::error!("failed to execute `load_types`: {e}");
                        CallToolError::new(
                            RpcError::internal_error()
                                .with_message(format!("failed to execute `load_types`: {e}")),
                        )
                    })?
                    .map_err(CallToolError::from_message)
                {
                    Ok(res) => res,
                    Err(e) => {
                        tracing::warn!("error executing `load_types`: {e}");
                        return Ok(CallToolResult::with_error(e));
                    }
                };

                let text =
                    serde_json::to_string(&result).map_err(|e| {
                        tracing::error!("failed to serialise result for `load_types`: {e}");
                        CallToolError::new(RpcError::internal_error().with_message(format!(
                            "failed to serialise result for `load_types`: {e}"
                        )))
                    })?;

                let mut tool_result =
                    CallToolResult::text_content(vec![TextContent::new(text, None, None)]);

                if let Value::Object(map) = result {
                    tool_result = tool_result.with_structured_content(map);
                }

                Ok(tool_result)
            }
            _ => Err(CallToolError::unknown_tool(name)),
        }
    }
}

pub struct VulHuntHandler {
    loader: Arc<ComponentLoader<'static>>,
    data_provider: PlatformDataProviderBuilder,
    modules: Option<PathBuf>,
    sessions: Arc<Mutex<HashMap<String, VulHuntSession>>>,
}

impl VulHuntHandler {
    pub fn new() -> Result<Self, VulHuntServerError> {
        let platform_data = env::var("BIAS_PLATFORM_DATA_DIR").map_err(|_| {
            VulHuntServerError::PlatformDataProvider(PlatformDataProviderBuilderError::NoValidPaths)
        })?;

        let data_provider = platform_data.parse::<PlatformDataProviderBuilder>()?;

        INIT_PLATFORM_DATA.call_once(|| {
            let root = data_provider.root_dir();
            tracing::info!(
                "initialising decompiler with platform data from `{}`",
                root.display()
            );
            if let Err(e) = decompiler::add_search_paths(root) {
                tracing::error!("failed to initialise decompiler with platform data: {e}");
            }
        });

        Self::new_with(data_provider)
    }

    pub fn new_with(
        data_provider: PlatformDataProviderBuilder,
    ) -> Result<Self, VulHuntServerError> {
        let root = data_provider.root_dir();
        Ok(Self {
            loader: Arc::new(ComponentLoader::new_with(root)?),
            data_provider,
            modules: None,
            sessions: Default::default(),
        })
    }

    pub fn set_module_directory(&mut self, modules: impl AsRef<Path>) {
        self.modules = Some(modules.as_ref().to_path_buf());
    }

    fn tool_by_name(name: &str) -> Option<Tool> {
        TOOLS.get(name).cloned()
    }
}

#[async_trait::async_trait]
impl ServerHandler for VulHuntHandler {
    async fn handle_list_tools_request(
        &self,
        _req: Option<PaginatedRequestParams>,
        _rt: Arc<dyn McpServer>,
    ) -> Result<ListToolsResult, RpcError> {
        Ok(ListToolsResult {
            tools: TOOLS.values().cloned().collect(),
            meta: None,
            next_cursor: None,
        })
    }

    async fn handle_call_tool_request(
        &self,
        req: CallToolRequestParams,
        rt: Arc<dyn McpServer>,
    ) -> Result<CallToolResult, CallToolError> {
        let session_id = rt.session_id().unwrap_or_default();
        let state = self
            .sessions
            .lock()
            .await
            .entry(session_id)
            .or_insert_with(|| {
                VulHuntSession::new(
                    self.data_provider.clone(),
                    self.modules.clone(),
                    self.loader.clone(),
                )
            })
            .clone();

        state.process_call(req).await
    }

    async fn handle_task_augmented_tool_call(
        &self,
        req: CallToolRequestParams,
        task_creator: ServerTaskCreator,
        rt: Arc<dyn McpServer>,
    ) -> Result<CreateTaskResult, CallToolError> {
        let name = &req.name;
        let tool = Self::tool_by_name(&name).ok_or_else(|| CallToolError::unknown_tool(name))?;

        let task_support = tool
            .execution
            .as_ref()
            .and_then(|e| e.task_support)
            .unwrap_or(ToolExecutionTaskSupport::Forbidden);

        if task_support == ToolExecutionTaskSupport::Forbidden {
            return Err(CallToolError::new(
                RpcError::invalid_request()
                    .with_message(format!("tool `{name}` does not support task execution")),
            ));
        }

        let session_id = rt.session_id().unwrap_or_default();
        let state = self
            .sessions
            .lock()
            .await
            .entry(session_id)
            .or_insert_with(|| {
                VulHuntSession::new(
                    self.data_provider.clone(),
                    self.modules.clone(),
                    self.loader.clone(),
                )
            })
            .clone();

        let task = task_creator
            .create_task(CreateTaskOptions {
                ttl: None,
                poll_interval: Some(500),
                meta: None,
            })
            .await;

        let task_id = task.task_id.clone();

        let task_store = rt
            .task_store()
            .expect("task store must be configured for task-augmented tool calls");

        let session_id = rt.session_id();

        tokio::spawn(async move {
            task_store
                .update_task_status(&task_id, TaskStatus::Working, None, session_id.clone())
                .await;

            let name = req.name.clone();
            let (status, result) = match state.process_call(req).await {
                Ok(tool_result) => (TaskStatus::Completed, tool_result.into()),
                Err(e) => {
                    let error_message = e.to_string();
                    tracing::warn!(task_id = %task_id, "failed to execute tool `{name}`: {error_message}");
                    let mut error_result = CallToolResult::text_content(vec![TextContent::new(
                        error_message,
                        None,
                        None,
                    )]);
                    error_result.is_error = Some(true);
                    (TaskStatus::Failed, error_result.into())
                }
            };

            task_store
                .store_task_result(&task_id, status, result, session_id.as_ref())
                .await;
        });

        Ok(CreateTaskResult { meta: None, task })
    }

    async fn handle_get_task_request(
        &self,
        params: GetTaskParams,
        rt: Arc<dyn McpServer>,
    ) -> Result<GetTaskResult, RpcError> {
        let task_store = rt.task_store().expect("task store is always configured");

        let task = task_store
            .get_task(&params.task_id, rt.session_id())
            .await
            .ok_or_else(|| {
                let task_id = &params.task_id;
                RpcError::invalid_request().with_message(format!("task `{task_id}` not found"))
            })?;

        Ok(GetTaskResult {
            task_id: task.task_id,
            status: task.status,
            status_message: task.status_message,
            created_at: task.created_at,
            last_updated_at: task.last_updated_at,
            poll_interval: task.poll_interval,
            ttl: task.ttl.unwrap_or(0),
            meta: None,
            extra: None,
        })
    }

    async fn handle_get_task_payload_request(
        &self,
        params: GetTaskPayloadParams,
        rt: Arc<dyn McpServer>,
    ) -> Result<GetTaskPayloadResult, RpcError> {
        let task_store = rt.task_store().expect("task store is always configured");

        let task_id = &params.task_id;
        let result = task_store
            .get_task_result(task_id, rt.session_id())
            .await
            .ok_or_else(|| {
                RpcError::invalid_request()
                    .with_message(format!("result for task `{task_id}` not found"))
            })?;

        let Value::Object(extra) = serde_json::to_value(&result).map_err(|e| {
            RpcError::internal_error().with_message(format!("failed to serialise result: {e}"))
        })?
        else {
            return Err(
                RpcError::internal_error().with_message("result is not an object".to_owned())
            );
        };

        Ok(GetTaskPayloadResult {
            meta: None,
            extra: Some(extra),
        })
    }

    async fn handle_list_task_request(
        &self,
        params: Option<PaginatedRequestParams>,
        rt: Arc<dyn McpServer>,
    ) -> Result<ListTasksResult, RpcError> {
        let task_store = rt.task_store().expect("task store is always configured");

        let cursor = params.and_then(|p| p.cursor);

        Ok(task_store.list_tasks(cursor, rt.session_id()).await)
    }
}

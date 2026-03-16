use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};

use bias::component::ComponentLoader;
use bias::platform::common::PlatformAttributeMap;
use bias::platform::common::data::PlatformDataProviderBuilder;

use bias_vulhunt_engine::{SignatureEntry, SignatureRange, SignatureVersion};

use rust_mcp_sdk::macros::{JsonSchema, mcp_tool};
use rust_mcp_sdk::schema::Tool;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;

use bias_vulhunt_engine::project::VulHuntProject;
use crate::session::VulHuntSessionState;

pub(crate) static TOOLS: LazyLock<HashMap<String, Tool>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert(VulHuntOpenProject::tool_name(), VulHuntOpenProject::tool());
    m.insert(
        VulHuntQueryProject::tool_name(),
        VulHuntQueryProject::tool(),
    );
    m.insert(
        VulHuntLoadSignatures::tool_name(),
        VulHuntLoadSignatures::tool(),
    );
    m.insert(VulHuntLoadTypes::tool_name(), VulHuntLoadTypes::tool());
    m.insert(
        VulHuntUpdateFunctionName::tool_name(),
        VulHuntUpdateFunctionName::tool(),
    );
    m.insert(
        VulHuntSetFunctionNotes::tool_name(),
        VulHuntSetFunctionNotes::tool(),
    );
    m.insert(
        VulHuntGetFunctionNotes::tool_name(),
        VulHuntGetFunctionNotes::tool(),
    );
    m
});

#[mcp_tool(
    name = "open_project",
    title = "Open Project",
    description = "Open a project from a given path, with optional platform attributes.",
    execution(task_support = "optional")
)]
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct VulHuntOpenProject {
    #[json_schema(description = "The path to the project to open.")]
    path: String,
    #[json_schema(description = r#"
Optional platform attributes to use when opening the project; if provided, this will be an
object where the keys are attribute names and the values are attribute values. Example:

UEFI module:
{ "guid": "...", "kind": "DxeDriver" }"#)]
    #[serde(default)]
    attributes: Option<HashMap<String, String>>,
}

impl VulHuntOpenProject {
    pub fn execute(
        self,
        provider: PlatformDataProviderBuilder,
        modules: Option<PathBuf>,
        loader: Arc<ComponentLoader<'static>>,
        state: Arc<RwLock<VulHuntSessionState>>,
    ) -> Result<Value, String> {
        let mut state = state.blocking_write();

        let mut attributes = PlatformAttributeMap::from_iter(self.attributes.unwrap_or_default());

        if !attributes.contains("modules")
            && let Some(modules) = modules
        {
            attributes.set_attr("modules", modules);
        }

        let project = VulHuntProject::new(&provider, &loader, self.path, attributes)
            .map_err(|e| e.to_string())?;

        state.set_project(project);

        Ok(Value::Null)
    }
}

#[mcp_tool(
    name = "query_project",
    title = "Query Project",
    description = "Execute a Lua script against the currently open project and return the result as JSON.",
    execution(task_support = "optional")
)]
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct VulHuntQueryProject {
    #[json_schema(
        description = "The Lua script to execute. The script has access to a `project` global variable."
    )]
    script: String,
}

impl VulHuntQueryProject {
    pub fn execute(self, state: Arc<RwLock<VulHuntSessionState>>) -> Result<Value, String> {
        let mut state = state.blocking_write();

        let project = state
            .project_mut()
            .ok_or_else(|| "no project is currently open".to_owned())?;

        project.query(&self.script).map_err(|e| e.to_string())
    }
}

#[mcp_tool(
    name = "update_function_name",
    title = "Update Function Name",
    description = "Update the name of a function in the currently open project."
)]
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct VulHuntUpdateFunctionName {
    #[json_schema(
        description = "The current function identifier (symbol or address, for example, `sub_1234` or `0x1234`)."
    )]
    function: String,
    #[json_schema(description = "The new name for the function.")]
    new_name: String,
}

impl VulHuntUpdateFunctionName {
    pub fn execute(self, state: Arc<RwLock<VulHuntSessionState>>) -> Result<Value, String> {
        let mut state = state.blocking_write();

        let project = state
            .project_mut()
            .ok_or_else(|| "no project is currently open".to_owned())?;

        project
            .update_function_name(&self.function, &self.new_name)
            .map_err(|e| e.to_string())?;

        Ok(Value::Null)
    }
}

#[mcp_tool(
    name = "set_function_notes",
    title = "Set Function Notes",
    description = "Set notes for a function in the currently open project."
)]
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct VulHuntSetFunctionNotes {
    #[json_schema(
        description = "The function identifier (symbol or address, for example, `sub_1234` or `0x1234`)."
    )]
    function: String,
    #[json_schema(description = "The notes to set for the function.")]
    notes: String,
}

impl VulHuntSetFunctionNotes {
    pub fn execute(self, state: Arc<RwLock<VulHuntSessionState>>) -> Result<Value, String> {
        let mut state = state.blocking_write();

        let project = state
            .project_mut()
            .ok_or_else(|| "no project is currently open".to_owned())?;

        project
            .set_function_notes(&self.function, self.notes)
            .map_err(|e| e.to_string())?;

        Ok(Value::Null)
    }
}

#[mcp_tool(
    name = "get_function_notes",
    title = "Get Function Notes",
    description = "Get the notes for a function in the currently open project."
)]
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct VulHuntGetFunctionNotes {
    #[json_schema(
        description = "The function identifier (symbol or address, for example, `sub_1234` or `0x1234`)."
    )]
    function: String,
}

impl VulHuntGetFunctionNotes {
    pub fn execute(self, state: Arc<RwLock<VulHuntSessionState>>) -> Result<Value, String> {
        let state = state.blocking_read();

        let project = state
            .project()
            .ok_or_else(|| "no project is currently open".to_owned())?;

        let notes = project.function_notes(&self.function);

        Ok(notes.into())
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum SignatureSpec {
    Single(SignatureEntrySpec),
    Multiple(Vec<SignatureEntrySpec>),
}

impl SignatureSpec {
    pub fn into_entries(self) -> Vec<SignatureEntrySpec> {
        match self {
            Self::Single(e) => vec![e],
            Self::Multiple(v) => v,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum SignatureEntrySpec {
    Range {
        project: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        from: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        to: Option<String>,
    },
    Version {
        project: String,
        version: String,
    },
    File(String),
}

impl fmt::Display for SignatureEntrySpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Range { project, from, to } => {
                write!(f, "{project}")?;
                if let Some(from) = from {
                    write!(f, " from {from}")?;
                }
                if let Some(to) = to {
                    write!(f, " to {to}")?;
                }
                Ok(())
            }
            Self::Version { project, version } => write!(f, "{project}@{version}"),
            Self::File(path) => write!(f, "{path}"),
        }
    }
}

impl From<SignatureEntrySpec> for SignatureEntry {
    fn from(spec: SignatureEntrySpec) -> Self {
        match spec {
            SignatureEntrySpec::Range { project, from, to } => {
                SignatureEntry::Range(SignatureRange::new(project, from, to))
            }
            SignatureEntrySpec::Version { project, version } => {
                SignatureEntry::Version(SignatureVersion::new(project, version))
            }
            SignatureEntrySpec::File(path) => SignatureEntry::File(path),
        }
    }
}

#[mcp_tool(
    name = "load_signatures",
    title = "Load Signatures",
    description = "Load FLIRT signature databases for function identification.",
    execution(task_support = "optional")
)]
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct VulHuntLoadSignatures {
    #[json_schema(description = "Signature specification (single entry or array)")]
    signatures: SignatureSpec,
}

impl VulHuntLoadSignatures {
    pub fn execute(self, state: Arc<RwLock<VulHuntSessionState>>) -> Result<Value, String> {
        let mut state = state.blocking_write();

        let project = state
            .project_mut()
            .ok_or_else(|| "no project is currently open".to_owned())?;

        let entries = self.signatures.into_entries();
        let result = project
            .load_signatures(entries.into_iter().map(SignatureEntry::from))
            .map_err(|e| e.to_string())?;

        serde_json::to_value(&result).map_err(|e| e.to_string())
    }
}

#[mcp_tool(
    name = "load_types",
    title = "Load Type Library",
    description = "Load a type library for function type information.",
    execution(task_support = "optional")
)]
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct VulHuntLoadTypes {
    #[json_schema(description = "Type library in `project/version/library` format")]
    types: String,
}

impl VulHuntLoadTypes {
    pub fn execute(self, state: Arc<RwLock<VulHuntSessionState>>) -> Result<Value, String> {
        let mut state = state.blocking_write();

        let project = state
            .project_mut()
            .ok_or_else(|| "no project is currently open".to_owned())?;

        let result = project.load_types(&self.types).map_err(|e| e.to_string())?;

        serde_json::to_value(&result).map_err(|e| e.to_string())
    }
}

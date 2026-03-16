use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use bias::platform::common::data::PlatformDataProviderBuilder;
use bias_core::decompiler::add_search_paths;
use bias_vulhunt_engine::{SignatureEntry, SignatureRange, SignatureVersion};
use bias_vulhunt_grpc::{VulHuntClient, VulHuntHandler, VulHuntServer, VulHuntServerOptions};

use clap::{Arg, ArgMatches, Command};
use serde::Serialize;

#[derive(Serialize)]
#[serde(tag = "status")]
pub enum ServiceResponse<T>
where
    T: Serialize,
{
    #[serde(rename = "ok")]
    Ok { payload: T },
    #[serde(rename = "error")]
    Error { message: String },
}

impl<T> ServiceResponse<T>
where
    T: Serialize,
{
    pub fn ok(payload: T) -> Self {
        Self::Ok { payload }
    }
}

impl ServiceResponse<()> {
    pub fn error(message: impl Into<String>) -> Self {
        ServiceResponse::Error {
            message: message.into(),
        }
    }
}

fn common_args(cmd: Command) -> Command {
    cmd.arg(
        Arg::new("endpoint")
            .short('e')
            .long("endpoint")
            .env("BIAS_VULHUNT_ENDPOINT")
            .help("Service endpoint URL (e.g. http://127.0.0.1:50051)")
            .required(true),
    )
}

fn session_common_args(cmd: Command) -> Command {
    common_args(cmd).arg(
        Arg::new("session-id")
            .short('S')
            .long("session-id")
            .env("BIAS_VULHUNT_SESSION_ID")
            .help("Active session UUID")
            .required(true),
    )
}

fn start_command() -> Command {
    Command::new("start")
        .about("Start the VulHunt gRPC daemon")
        .arg(
            Arg::new("host")
                .long("host")
                .help("Host address to bind")
                .default_value("127.0.0.1"),
        )
        .arg(
            Arg::new("port")
                .long("port")
                .help("Port to listen on")
                .default_value("50051")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("data")
                .short('d')
                .long("data")
                .env("BIAS_DATA")
                .help("Directory containing auxiliary data (processor specifications, etc.)")
                .required(true)
                .value_parser(clap::value_parser!(PlatformDataProviderBuilder)),
        )
        .arg(
            Arg::new("modules")
                .short('m')
                .long("modules")
                .env("BIAS_VULHUNT_MODULES")
                .help("Directory containing VulHunt modules")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("session-ttl")
                .long("session-ttl")
                .help("Session time-to-live (since last activity) in seconds (0 = no expiry)")
                .value_parser(clap::value_parser!(u64)),
        )
}

fn open_project_command() -> Command {
    common_args(
        Command::new("open-project")
            .about("Open a project via the service and obtain a session ID"),
    )
    .arg(
        Arg::new("path")
            .long("path")
            .help("Path to the binary to open")
            .required(true)
            .value_parser(clap::value_parser!(PathBuf)),
    )
    .arg(
        Arg::new("attribute")
            .long("attribute")
            .value_name("KEY=VALUE")
            .help("Project attributes (repeatable)")
            .action(clap::ArgAction::Append),
    )
}

fn close_project_command() -> Command {
    session_common_args(Command::new("close-project").about("Close an active session"))
}

fn list_sessions_command() -> Command {
    common_args(Command::new("list-sessions").about("List active sessions"))
}

fn query_project_command() -> Command {
    session_common_args(
        Command::new("query-project").about("Run a Lua query against an active session"),
    )
    .arg(
        Arg::new("script")
            .long("script")
            .help("Lua script to execute")
            .required(true),
    )
}

fn update_function_name_command() -> Command {
    session_common_args(
        Command::new("update-function-name").about("Rename a function in an active session"),
    )
    .arg(
        Arg::new("function")
            .long("function")
            .help("Function identifier (name or 0x-prefixed address)")
            .required(true),
    )
    .arg(
        Arg::new("name")
            .long("name")
            .help("New function name")
            .required(true),
    )
}

fn set_function_notes_command() -> Command {
    session_common_args(
        Command::new("set-function-notes").about("Set notes on a function in an active session"),
    )
    .arg(
        Arg::new("function")
            .long("function")
            .help("Function identifier (name or 0x-prefixed address)")
            .required(true),
    )
    .arg(
        Arg::new("notes")
            .long("notes")
            .help("Notes to attach to the function")
            .required(true),
    )
}

fn get_function_notes_command() -> Command {
    session_common_args(
        Command::new("get-function-notes").about("Get notes for a function in an active session"),
    )
    .arg(
        Arg::new("function")
            .long("function")
            .help("Function identifier (name or 0x-prefixed address)")
            .required(true),
    )
}

fn load_signatures_command() -> Command {
    session_common_args(
        Command::new("load-signatures")
            .about("Load FLIRT signatures into an active session"),
    )
    .arg(
        Arg::new("signature")
            .long("signature")
            .help("Signature specification: file:<path>, range:<project>[:<from>][:<to>], version:<project>:<version>")
            .action(clap::ArgAction::Append)
            .required(true),
    )
}

fn load_types_command() -> Command {
    session_common_args(
        Command::new("load-types").about("Load a type library into an active session"),
    )
    .arg(
        Arg::new("types")
            .long("types")
            .help("Type library name or path")
            .required(true),
    )
}

pub fn command() -> Command {
    Command::new("service")
        .about("Start or interact with the VulHunt gRPC daemon")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(start_command())
        .subcommand(open_project_command())
        .subcommand(close_project_command())
        .subcommand(list_sessions_command())
        .subcommand(query_project_command())
        .subcommand(update_function_name_command())
        .subcommand(set_function_notes_command())
        .subcommand(get_function_notes_command())
        .subcommand(load_signatures_command())
        .subcommand(load_types_command())
}

pub async fn run(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let result = match opts.subcommand() {
        Some(("start", sub_m)) => return run_start(sub_m).await,
        Some(("open-project", sub_m)) => run_open_project(sub_m).await,
        Some(("close-project", sub_m)) => run_close_project(sub_m).await,
        Some(("list-sessions", sub_m)) => run_list_sessions(sub_m).await,
        Some(("query-project", sub_m)) => run_query_project(sub_m).await,
        Some(("update-function-name", sub_m)) => run_update_function_name(sub_m).await,
        Some(("set-function-notes", sub_m)) => run_set_function_notes(sub_m).await,
        Some(("get-function-notes", sub_m)) => run_get_function_notes(sub_m).await,
        Some(("load-signatures", sub_m)) => run_load_signatures(sub_m).await,
        Some(("load-types", sub_m)) => run_load_types(sub_m).await,
        _ => unreachable!(),
    };

    if let Err(e) = result {
        let response = ServiceResponse::error(e.to_string());
        serde_json::to_writer(std::io::stdout(), &response)?;
    }

    Ok(())
}

async fn connect_client(opts: &ArgMatches) -> Result<VulHuntClient, Box<dyn std::error::Error>> {
    let endpoint = opts.get_one::<String>("endpoint").unwrap();
    let client = VulHuntClient::new(endpoint.clone()).await?;
    Ok(client)
}

async fn connect_client_with_session(
    opts: &ArgMatches,
) -> Result<VulHuntClient, Box<dyn std::error::Error>> {
    let endpoint = opts.get_one::<String>("endpoint").unwrap();
    let session_id = opts.get_one::<String>("session-id").unwrap();
    let client = VulHuntClient::new_with(endpoint.clone(), Some(session_id.clone())).await?;
    Ok(client)
}

fn parse_attributes(
    opts: &ArgMatches,
) -> Result<Option<serde_json::Map<String, serde_json::Value>>, Box<dyn std::error::Error>> {
    let Some(attrs) = opts.get_many::<String>("attribute") else {
        return Ok(None);
    };

    let mut map = serde_json::Map::new();
    for kv in attrs {
        let (key, value) = kv
            .split_once('=')
            .ok_or_else(|| format!("invalid attribute format (expected KEY=VALUE): {kv}"))?;
        map.insert(key.to_owned(), serde_json::Value::String(value.to_owned()));
    }
    Ok(Some(map))
}

fn parse_signature_entry(s: &str) -> Result<SignatureEntry, Box<dyn std::error::Error>> {
    if let Some(path) = s.strip_prefix("file:") {
        return Ok(SignatureEntry::File(path.to_owned()));
    }

    if let Some(rest) = s.strip_prefix("range:") {
        let mut parts = rest.splitn(3, ':');
        let project = parts
            .next()
            .ok_or("range: requires at least a project name")?;
        let from = parts
            .next()
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned);
        let to = parts
            .next()
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned);
        return Ok(SignatureEntry::Range(SignatureRange::new(
            project, from, to,
        )));
    }

    if let Some(rest) = s.strip_prefix("version:") {
        let (project, version) = rest
            .split_once(':')
            .ok_or("version: requires project:version")?;
        return Ok(SignatureEntry::Version(SignatureVersion::new(
            project, version,
        )));
    }

    Err(format!("unrecognised signature spec: {s} (expected file:<path>, range:<project>[:<from>][:<to>], or version:<project>:<version>)").into())
}

async fn run_start(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let host = opts.get_one::<String>("host").unwrap();
    let port = *opts.get_one::<u16>("port").unwrap();
    let data = opts.get_one::<PlatformDataProviderBuilder>("data").unwrap();
    let modules = opts.get_one::<PathBuf>("modules");
    let session_ttl = opts.get_one::<u64>("session-ttl").copied();

    add_search_paths(data.root_dir())?;

    let mut handler = VulHuntHandler::new_with(data.to_owned())?;

    if let Some(modules) = modules {
        handler.set_module_directory(modules);
    }

    let options = VulHuntServerOptions {
        session_ttl: session_ttl.map(Duration::from_secs),
    };

    let server = VulHuntServer::new_with(handler, options);
    let addr = format!("{host}:{port}")
        .parse::<SocketAddr>()
        .map_err(|e| format!("invalid host or port: {e}"))?;

    server.serve(addr).await?;
    Ok(())
}

#[derive(Serialize)]
struct OpenProjectPayload {
    session_id: String,
}

async fn run_open_project(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = connect_client(opts).await?;
    let path = opts.get_one::<PathBuf>("path").unwrap();
    let attributes = parse_attributes(opts)?;

    let session_id = client.open_project(path, attributes).await?;

    let response = ServiceResponse::ok(OpenProjectPayload { session_id });
    serde_json::to_writer(std::io::stdout(), &response)?;
    Ok(())
}

async fn run_close_project(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = connect_client_with_session(opts).await?;
    client.close_project().await?;

    let response = ServiceResponse::ok(());
    serde_json::to_writer(std::io::stdout(), &response)?;
    Ok(())
}

#[derive(Serialize)]
struct SessionInfoPayload {
    session_id: String,
    path: String,
    created_at: Option<String>,
    last_accessed_at: Option<String>,
}

async fn run_list_sessions(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = connect_client(opts).await?;
    let sessions = client.list_sessions().await?;

    let payload = sessions
        .into_iter()
        .map(|s| SessionInfoPayload {
            session_id: s.session_id,
            path: s.path,
            created_at: s.created_at.as_ref().map(|ts| ts.to_string()),
            last_accessed_at: s.last_accessed_at.as_ref().map(|ts| ts.to_string()),
        })
        .collect::<Vec<_>>();

    let response = ServiceResponse::ok(payload);

    serde_json::to_writer(std::io::stdout(), &response)?;

    Ok(())
}

async fn run_query_project(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = connect_client_with_session(opts).await?;
    let script = opts.get_one::<String>("script").unwrap();

    let result = client.query_project(script.as_str()).await?;

    let response = ServiceResponse::ok(result);

    serde_json::to_writer(std::io::stdout(), &response)?;

    Ok(())
}

async fn run_update_function_name(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = connect_client_with_session(opts).await?;
    let function = opts.get_one::<String>("function").unwrap();
    let name = opts.get_one::<String>("name").unwrap();

    client
        .update_function_name(function.as_str(), name.as_str())
        .await?;

    let response = ServiceResponse::ok(());

    serde_json::to_writer(std::io::stdout(), &response)?;

    Ok(())
}

async fn run_set_function_notes(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = connect_client_with_session(opts).await?;
    let function = opts.get_one::<String>("function").unwrap();
    let notes = opts.get_one::<String>("notes").unwrap();

    client
        .set_function_notes(function.as_str(), notes.as_str())
        .await?;

    let response = ServiceResponse::ok(());

    serde_json::to_writer(std::io::stdout(), &response)?;

    Ok(())
}

#[derive(Serialize)]
struct GetFunctionNotesPayload {
    notes: Option<String>,
}

async fn run_get_function_notes(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = connect_client_with_session(opts).await?;
    let function = opts.get_one::<String>("function").unwrap();

    let notes = client.get_function_notes(function.as_str()).await?;

    let response = ServiceResponse::ok(GetFunctionNotesPayload { notes });

    serde_json::to_writer(std::io::stdout(), &response)?;

    Ok(())
}

#[derive(Serialize)]
struct LoadSignaturesPayload {
    loaded_files: Vec<String>,
    matched_functions: u64,
}

async fn run_load_signatures(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = connect_client_with_session(opts).await?;
    let specs = opts.get_many::<String>("signature").unwrap();

    let entries = specs
        .map(|s| parse_signature_entry(s))
        .collect::<Result<Vec<_>, _>>()?;

    let result = client.load_signatures(entries).await?;

    let response = ServiceResponse::ok(LoadSignaturesPayload {
        loaded_files: result.loaded_files,
        matched_functions: result.matched_functions,
    });

    serde_json::to_writer(std::io::stdout(), &response)?;

    Ok(())
}

#[derive(Serialize)]
struct LoadTypesPayload {
    type_library: String,
    imported_types: u64,
    matched_functions: u64,
}

async fn run_load_types(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = connect_client_with_session(opts).await?;
    let types = opts.get_one::<String>("types").unwrap();

    let result = client.load_types(types.as_str()).await?;

    let response = ServiceResponse::ok(LoadTypesPayload {
        type_library: result.type_library,
        imported_types: result.imported_types,
        matched_functions: result.matched_functions,
    });

    serde_json::to_writer(std::io::stdout(), &response)?;

    Ok(())
}

use std::path::PathBuf;

use bias::platform::common::data::PlatformDataProviderBuilder;
use bias_core::decompiler::add_search_paths;
use bias_vulhunt_mcp::{VulHuntHandler, VulHuntHttpServerOptions, VulHuntServer};

use clap::{Arg, ArgMatches, Command};

pub fn command() -> Command {
    Command::new("mcp")
        .about("Start MCP server")
        .arg(
            Arg::new("host")
                .long("host")
                .help("Host address to bind")
                .num_args(1)
                .default_value("127.0.0.1")
                .conflicts_with("stdio"),
        )
        .arg(
            Arg::new("port")
                .long("port")
                .help("Port to listen on")
                .num_args(1)
                .value_parser(clap::value_parser!(u16))
                .default_value("8080")
                .conflicts_with("stdio"),
        )
        .arg(
            Arg::new("stdio")
                .long("stdio")
                .help("Use stdio transport instead of HTTP")
                .num_args(0)
                .action(clap::ArgAction::SetTrue)
                .conflicts_with_all(["host", "port"]),
        )
        .arg(
            Arg::new("data")
                .short('d')
                .long("data")
                .env("BIAS_DATA")
                .num_args(1)
                .help("Directory containing auxiliary data (processor specifications, etc.)")
                .required(true)
                .value_parser(clap::value_parser!(PlatformDataProviderBuilder)),
        )
        .arg(
            Arg::new("modules")
                .short('m')
                .long("modules")
                .env("BIAS_VULHUNT_MODULES")
                .num_args(1)
                .help("Directory containing VulHunt modules")
                .required(false)
                .value_parser(clap::value_parser!(PathBuf)),
        )
}

pub async fn run(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let data = opts.get_one::<PlatformDataProviderBuilder>("data").unwrap();
    let modules = opts.get_one::<PathBuf>("modules");

    add_search_paths(data.root_dir())?;

    let mut handler = VulHuntHandler::new_with(data.to_owned())?;

    if let Some(modules) = modules {
        handler.set_module_directory(modules);
    }

    let server = if opts.get_flag("stdio") {
        tracing::info!("starting VulHunt MCP server (stdio)");

        VulHuntServer::new_stdio_with(handler)?
    } else {
        let host = opts.get_one::<String>("host").unwrap().clone();
        let port = *opts.get_one::<u16>("port").unwrap();

        tracing::info!("starting VulHunt MCP server on http://{host}:{port}");

        VulHuntServer::new_streaming_http_with(
            VulHuntHttpServerOptions {
                host,
                port,
                ..Default::default()
            },
            handler,
        )?
    };

    server.start().await?;
    Ok(())
}

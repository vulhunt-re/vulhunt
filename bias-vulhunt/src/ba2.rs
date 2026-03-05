use std::path::{Path, PathBuf};

use bias::loader::meta::BA2ComponentMetadata;
use bias::loader::BA2Loader;
use bias::types::common::Uuid;

use clap::{Arg, ArgMatches, Command};
use serde::Serialize;
use tokio::fs::File;

#[derive(Serialize)]
struct ExtractComponentPayload<'a> {
    component: &'a BA2ComponentMetadata,
    output_path: &'a Path,
    output_size: usize,
}

fn list_components_command() -> Command {
    Command::new("list-components")
        .about("List all components in a BA2")
        .arg(
            Arg::new("INPUT")
                .help("Path to input BA2")
                .required(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
}

fn extract_component_command() -> Command {
    Command::new("extract-component")
        .about("Extract component from a BA2")
        .arg(
            Arg::new("INPUT")
                .help("Path to input BA2")
                .required(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("OUTPUT")
                .short('o')
                .long("output")
                .help("Output path")
                .required(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("component-id")
                .long("component-id")
                .help("Component ID (UUID)")
                .required(true)
                .value_parser(clap::value_parser!(Uuid)),
        )
}

pub fn command() -> Command {
    Command::new("ba2")
        .about("Query Binarly Analysis Archives (BA2s)")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(list_components_command())
        .subcommand(extract_component_command())
}

pub async fn run(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    match opts.subcommand() {
        Some(("extract-component", sub_m)) => run_extract_component(sub_m).await,
        Some(("list-components", sub_m)) => run_list_components(sub_m).await,
        _ => unreachable!(),
    }
}

async fn run_list_components(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let ba2_path = opts.get_one::<PathBuf>("INPUT").unwrap();
    let loader = BA2Loader::from_file(ba2_path)?;

    let components = loader.meta().components().collect::<Vec<_>>();
    serde_json::to_writer(std::io::stdout(), &components)?;

    Ok(())
}

async fn run_extract_component(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::AsyncWriteExt;

    let ba2_path = opts.get_one::<PathBuf>("INPUT").unwrap();
    let output_path = opts.get_one::<PathBuf>("OUTPUT").unwrap();
    let component_id = *opts.get_one::<Uuid>("component-id").unwrap();

    let loader = BA2Loader::from_file(ba2_path)?;
    let component = loader
        .meta()
        .by_uuid(&component_id)
        .ok_or_else(|| format!("component {component_id} not found"))?;

    let data = loader.get_by_uuid(component_id)?;
    let bytes = data.bytes();

    let mut file = File::create(output_path).await?;
    file.write_all(bytes).await?;

    let payload = ExtractComponentPayload {
        component,
        output_path,
        output_size: bytes.len(),
    };

    serde_json::to_writer(std::io::stdout(), &payload)?;

    Ok(())
}

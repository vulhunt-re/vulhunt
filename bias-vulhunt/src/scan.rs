use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::Arc;

use bias::component::ComponentLoader;
use bias::loader::BA2LoaderConfig;
use bias::pipeline::analysis::AnalysisGroupForCode;
use bias::pipeline::types::property::FINDING_KNOWN_VULNERABILITY_PATCH;
use bias::pipeline::{Pipeline, Source};
use bias::platform::common::data::PlatformDataProviderBuilder;
use bias::platform::common::KeyValue;
use bias::platform::efi::analysis::EFIModuleAnalysis;
use bias::platform::efi::{EFIModule, EFIStandalone};
use bias::platform::posix::analysis::PosixBinaryAnalysis;
use bias::platform::posix::PosixBinary;
use bias::reporting::{BasicReportSink, JSONLEntityStream, ProgressMonitorSink};
use bias::types::common::AttributeMap;

use bias_core::decompiler::add_search_paths;

use bias_vulhunt_engine::analysis::efi::{VulHuntEFIAnalyser, VulHuntEFIAnalyserConfig};
use bias_vulhunt_engine::analysis::posix::{VulHuntPosixAnalyser, VulHuntPosixAnalyserConfig};

use clap::{Arg, ArgMatches, Command};
use owo_colors::OwoColorize as _;

use crate::loader::VulHuntLoader;

pub fn command() -> Command {
    Command::new("scan")
        .about("Scan binaries and firmware for vulnerabilities")
        .arg(
            Arg::new("INPUT")
                .num_args(1)
                .help("Path to the binary or firmware to scan")
                .required(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("OUTPUT")
                .short('o')
                .long("output")
                .num_args(1)
                .help("Path to write output JSON")
                .required(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("loader")
                .long("loader")
                .help("Configure the loader to use for the input source")
                .num_args(1)
                .value_parser(clap::value_parser!(VulHuntLoader))
                .default_value("component"),
        )
        .arg(
            Arg::new("component-attribute")
                .long("component-attribute")
                .aliases(["component-attr", "attribute", "attr"])
                .value_name("key=value")
                .help("Component attributes (repeatable), used as additional metadata during loading analysis, e.g., --component-attribute kind=SmmModule, --component-attribute guid=FEAB1234-5678-90AB-CDEF-1234567890AB")
                .num_args(1)
                .action(clap::ArgAction::Append)
                .value_parser(clap::value_parser!(KeyValue))
                .required(false),
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
            Arg::new("rules")
                .short('r')
                .short_alias('r')
                .long("rules")
                .alias("rules")
                .env("BIAS_VULHUNT_RULES")
                .num_args(1)
                .help("Directory containing VulHunt rules")
                .required(true)
                .value_parser(clap::value_parser!(PathBuf)),
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
        .arg(
            Arg::new("pretty")
                .long("pretty")
                .help("Format output report for human consumption and render each issue to stdout")
                .conflicts_with("stream")
                .num_args(0)
                .action(clap::ArgAction::SetTrue)
                .required(false),
        )
        .arg(
            Arg::new("stream")
                .long("stream")
                .help("Format output report for machine consumption as a stream of JSONL messages")
                .conflicts_with("pretty")
                .num_args(0)
                .action(clap::ArgAction::SetTrue)
                .required(false),
        )
        .arg(
            Arg::new("compress")
                .long("compress")
                .help("Compress output JSONL stream with Zstandard")
                .conflicts_with("pretty")
                .num_args(0)
                .action(clap::ArgAction::SetTrue)
                .required(false),
        )
}

pub async fn run(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let input = opts.get_one::<PathBuf>("INPUT").unwrap();
    let output = opts.get_one::<PathBuf>("OUTPUT").unwrap();
    let loader = opts
        .get_one::<VulHuntLoader>("loader")
        .copied()
        .unwrap_or_default();

    let pretty = opts.get_flag("pretty");
    let stream = opts.get_flag("stream");
    let compress = opts.get_flag("compress");

    let data = opts.get_one::<PlatformDataProviderBuilder>("data").unwrap();
    let rules = opts.get_one::<PathBuf>("rules").unwrap();
    let modules = opts.get_one::<PathBuf>("modules");

    let attributes = opts.get_many::<KeyValue>("component-attribute");

    if !loader.has_attributes() && attributes.is_some() {
        eprintln!("component attributes are not supported by the selected loader");
        exit(1);
    }

    let attributes = attributes
        .unwrap_or_default()
        .cloned()
        .collect::<AttributeMap>();

    let config = BA2LoaderConfig {
        attributes,
        ..Default::default()
    };

    add_search_paths(data.root_dir())?;

    let mut pipeline = Pipeline::new(ComponentLoader::new_with(data.root_dir())?);

    let efi_config = VulHuntEFIAnalyserConfig::new().with_render(pretty);

    let efi_config = if let Some(modules) = &modules {
        efi_config.with_module_directory(modules)
    } else {
        efi_config
    };

    let efi_modules = AnalysisGroupForCode::new(VulHuntEFIAnalyser::new_with(
        rules,
        EFIModuleAnalysis::new(data)?,
        efi_config.clone(),
    )?);

    let efi_standalone = AnalysisGroupForCode::new(VulHuntEFIAnalyser::new_with(
        rules,
        EFIModuleAnalysis::new(data)?,
        efi_config,
    )?);

    let posix_config = VulHuntPosixAnalyserConfig::new().with_render(pretty);

    let posix_binaries = AnalysisGroupForCode::new(VulHuntPosixAnalyser::new_with(
        rules,
        PosixBinaryAnalysis::new(data)?,
        if let Some(modules) = &modules {
            posix_config.with_module_directory(modules)
        } else {
            posix_config
        },
    )?);

    pipeline.register_group_for_code::<EFIModule>(efi_modules)?;
    pipeline.register_group_for_code::<EFIStandalone>(efi_standalone)?;
    pipeline.register_group_for_code::<PosixBinary>(posix_binaries)?;

    let source = loader.source_with(input, config)?;

    run_pipeline(pipeline, source, pretty, stream, compress, input, output).await
}

async fn run_pipeline(
    pipeline: Pipeline,
    source: Arc<dyn Source>,
    pretty: bool,
    stream: bool,
    compress: bool,
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let output = output.as_ref();
    let sink = Arc::new(BasicReportSink::new());

    if pretty && !input.as_ref().is_dir() {
        ProgressMonitorSink::run_pipeline(source.clone(), sink.clone(), &pipeline).await?;

        let results = Arc::try_unwrap(sink)
            .map_err(|_| "failed to unwrap sink")?
            .into_results()?;
        let file = BufWriter::new(File::create(output)?);

        for component in results.components() {
            for (finding, name) in results.properties().filter_map(|property| {
                if property.entity_id() == component.id() {
                    Some((property.finding()?, property.name()))
                } else {
                    None
                }
            }) {
                let mut to_render = finding
                    .evidence()
                    .iter()
                    .filter_map(|evidence| evidence.get_attr::<String>("rendered"));

                let Some(p0) = to_render.next() else { continue };

                let prefix = if name == FINDING_KNOWN_VULNERABILITY_PATCH {
                    "Patch"
                } else {
                    "Issues"
                };

                println!(
                    "{prefix} for {} ({})",
                    component.name().bold().underline(),
                    component.path(),
                );
                println!("{p0}");
                for pi in to_render {
                    println!("{pi}");
                }
            }
        }

        serde_json::to_writer_pretty(file, &results)?;
    } else if pretty {
        ProgressMonitorSink::run_pipeline(source.clone(), sink.clone(), &pipeline).await?;

        let results = Arc::try_unwrap(sink)
            .map_err(|_| "failed to unwrap sink")?
            .into_results()?;
        let file = BufWriter::new(File::create(output)?);

        serde_json::to_writer_pretty(file, &results)?;
    } else if stream {
        let file = BufWriter::new(File::create(output)?);
        let sink = Arc::new(JSONLEntityStream::unbounded_with(file, compress)?);

        ProgressMonitorSink::run_pipeline(source.clone(), sink, &pipeline).await?;
    } else {
        let sink = Arc::new(BasicReportSink::new());

        pipeline.run(source, sink.clone()).await?;

        Arc::try_unwrap(sink)
            .map_err(|_| "failed to unwrap sink")?
            .into_results()?
            .properties_to_json_file(output)?;
    }

    Ok(())
}

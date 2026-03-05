use std::collections::HashSet;
use std::path::Path;
use std::process::exit;

use bias_core::caches;
use bias_core::decompiler::compiler::SleighCompiler;
use bias_core::fugue::ir::LanguageDB;

use clap::{Arg, Command};
use tracing_subscriber::EnvFilter;

fn compile_sleigh_languages(data: impl AsRef<Path>) -> Result<(), Box<dyn std::error::Error>> {
    let data = data.as_ref();

    let language_db = LanguageDB::from_directory_with(data, true)?;
    let compiler = SleighCompiler::new()?;

    let mut compiled = HashSet::new();

    for builder in language_db.iter() {
        let sla_path = builder.language().sla_file();

        if !compiled.insert(sla_path.to_path_buf()) {
            continue;
        }

        let slaspec_path = sla_path.with_extension("slaspec");

        if !slaspec_path.exists() {
            tracing::warn!(path = %slaspec_path.display(), "slaspec not found, skipping");
            continue;
        }

        tracing::debug!(
            slaspec = %slaspec_path.display(),
            sla = %sla_path.display(),
            "compiling SLEIGH specification"
        );
        compiler.build_with(&slaspec_path, &sla_path)?;
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("off"))
        .add_directive("bias_core::lifter=debug".parse().unwrap())
        .add_directive("fugue_ir=warn".parse().unwrap())
        .add_directive("lutil=debug".parse().unwrap());

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    let command = Command::new("lutil")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Utility for compiling lifters from SLEIGH language specifications")
        .arg(
            Arg::new("data")
                .help("Path to auxiliary data directory")
                .short('d')
                .long("data")
                .num_args(1)
                .required(true),
        );

    let matches = match command.try_get_matches() {
        Ok(matches) => matches,
        Err(e) => {
            e.print()?;
            exit(-1);
        }
    };

    let data = matches.get_one::<String>("data").unwrap();

    if let Err(e) = compile_sleigh_languages(data) {
        tracing::error!(error = %e, "failed to compile SLEIGH languages");
        exit(-1);
    }

    if let Err(e) = caches::CacheBuilder::new(data).build_caches() {
        tracing::error!(error = %e, "failed to build caches");
        exit(-1);
    }

    Ok(())
}

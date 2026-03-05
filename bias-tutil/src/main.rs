use std::borrow::Cow;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::process::exit;

use anyhow::anyhow;

use bias_core::cio::{TypeDB, TypeDBConfig, TypeInfoDB};
use bias_core::ir::types::TypeDisplay;
use bias_core::ir::{Term, Type};

use clap::{value_parser, Arg, ArgAction, ArgMatches, Command, ValueEnum};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum TypeBits {
    #[default]
    Any,
    M32,
    M64,
}

pub enum TypeQuery<'a> {
    None,
    Prefix(&'a str),
    Exact(&'a str),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct BuildConfig<'a> {
    #[serde(default)]
    no_defaults: bool,
    #[serde(default)]
    no_mxx: bool,
    #[serde(rename = "common arguments", alias = "args", default)]
    args: Vec<Cow<'a, str>>,
    #[serde(rename = "32-bit arguments", alias = "args32", default)]
    args32: Vec<Cow<'a, str>>,
    #[serde(rename = "64-bit arguments", alias = "args64", default)]
    args64: Vec<Cow<'a, str>>,
}

fn dump_types(
    input: impl AsRef<Path>,
    query: TypeQuery,
    bits: TypeBits,
    depth: usize,
    config: BuildConfig,
) -> anyhow::Result<()> {
    let input = input.as_ref();

    if !input.exists() {
        return Err(anyhow!("cannot find header: {}", input.display()));
    }

    let config = if config.no_defaults {
        TypeDBConfig::new(true)
    } else {
        TypeDBConfig::default().with_header(false)
    }
    .with_mxx(!config.no_mxx)
    .with_args(config.args.iter().map(|s| s.as_ref()))
    .with_args32(config.args32.iter().map(|s| s.as_ref()))
    .with_args64(config.args64.iter().map(|s| s.as_ref()));

    let tdb = TypeDB::from_file_with_config(input, &config)?;

    match query {
        TypeQuery::None => match bits {
            TypeBits::Any => {
                for (name, t) in tdb.type_iter().chain(tdb.prototype_iter()) {
                    println!(
                        "{name} (32-bit): {}",
                        TypeDisplay::new_with(&t.to_32(), &tdb, depth)
                    );
                    println!(
                        "{name} (64-bit): {}",
                        TypeDisplay::new_with(&t.to_64(), &tdb, depth)
                    );
                }
            }
            TypeBits::M32 => {
                for (name, t) in tdb.type_iter().chain(tdb.prototype_iter()) {
                    println!("{name}: {}", TypeDisplay::new_with(&t.to_32(), &tdb, depth));
                }
            }
            TypeBits::M64 => {
                for (name, t) in tdb.type_iter().chain(tdb.prototype_iter()) {
                    println!("{name}: {}", TypeDisplay::new_with(&t.to_64(), &tdb, depth));
                }
            }
        },
        TypeQuery::Prefix(m) => match bits {
            TypeBits::Any => {
                for (name, t) in tdb
                    .type_iter()
                    .chain(tdb.prototype_iter())
                    .filter(|(name, _)| name.starts_with(m))
                {
                    println!(
                        "{name} (32-bit): {}",
                        TypeDisplay::new_with(&t.to_32(), &tdb, depth)
                    );
                    println!(
                        "{name} (64-bit): {}",
                        TypeDisplay::new_with(&t.to_64(), &tdb, depth)
                    );
                }
            }
            TypeBits::M32 => {
                for (name, t) in tdb
                    .type_iter()
                    .chain(tdb.prototype_iter())
                    .filter(|(name, _)| name.starts_with(m))
                {
                    println!("{name}: {}", TypeDisplay::new_with(&t.to_32(), &tdb, depth));
                }
            }
            TypeBits::M64 => {
                for (name, t) in tdb
                    .type_iter()
                    .chain(tdb.prototype_iter())
                    .filter(|(name, _)| name.starts_with(m))
                {
                    println!("{name}: {}", TypeDisplay::new_with(&t.to_64(), &tdb, depth));
                }
            }
        },
        TypeQuery::Exact(m) => {
            if !(exact_for(&tdb, m, bits, |tdb, m, bits| tdb.get_type_for(m, bits))
                || exact_for(&tdb, m, bits, |tdb, m, bits| tdb.get_prototype_for(m, bits)))
            {
                return Err(anyhow!("type `{m}` not found"));
            }
        }
    }

    Ok(())
}

fn exact_for(
    tdb: &TypeDB,
    m: &str,
    bits: TypeBits,
    f: impl Fn(&TypeDB, &str, u32) -> Option<Term<Type>>,
) -> bool {
    match bits {
        TypeBits::Any => {
            if let Some(t) = f(tdb, m, 32) {
                println!("{m} (32-bit): {}", TypeDisplay::new_with(&t, tdb, 1));
            } else {
                return false;
            }

            let t = f(tdb, m, 64).unwrap();
            println!("{m} (64-bit): {}", TypeDisplay::new_with(&t, tdb, 1));
        }
        TypeBits::M32 => {
            if let Some(t) = f(tdb, m, 32) {
                println!("{m}: {}", TypeDisplay::new_with(&t, tdb, 1));
            } else {
                return false;
            }
        }
        TypeBits::M64 => {
            if let Some(t) = f(tdb, m, 64) {
                println!("{m}: {}", TypeDisplay::new_with(&t, tdb, 1));
            } else {
                return false;
            }
        }
    }

    true
}

fn build_type_file(
    input: impl AsRef<Path>,
    output: Option<&String>,
    config: BuildConfig,
) -> anyhow::Result<()> {
    let input = input.as_ref();

    if !input.exists() {
        return Err(anyhow!("cannot find header: {}", input.display()));
    }

    let config = if config.no_defaults {
        TypeDBConfig::new(true)
    } else {
        TypeDBConfig::default().with_header(true)
    }
    .with_mxx(!config.no_mxx)
    .with_args(config.args.iter().map(|s| s.as_ref()))
    .with_args32(config.args32.iter().map(|s| s.as_ref()))
    .with_args64(config.args64.iter().map(|s| s.as_ref()));

    let tdb = TypeInfoDB::from_file_with_config(input, &config)?;
    let output = output
        .map(|path| Cow::Borrowed(Path::new(path)))
        .unwrap_or_else(|| Cow::Owned(input.with_extension("bin")));

    tdb.cache(output)?;

    Ok(())
}

fn build_type_directory(root: impl AsRef<Path>, config: BuildConfig) -> anyhow::Result<()> {
    let config = if config.no_defaults {
        TypeDBConfig::new(true)
    } else {
        TypeDBConfig::default().with_header(true)
    }
    .with_mxx(!config.no_mxx)
    .with_args(config.args.iter().map(|s| s.as_ref()))
    .with_args32(config.args32.iter().map(|s| s.as_ref()))
    .with_args64(config.args64.iter().map(|s| s.as_ref()));

    let walker = WalkDir::new(root.as_ref()).into_iter();

    for entry in walker
        .filter_entry(|e| {
            !e.file_type().is_file()
                || e.file_name()
                    .to_str()
                    .map(|s| {
                        s.ends_with(".h")
                            || s.ends_with(".H")
                            || s.ends_with(".hh")
                            || s.ends_with(".hpp")
                    })
                    .unwrap_or(false)
        })
        .filter_map(|entry| entry.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }

        let tdb = TypeInfoDB::from_file_with_config(entry.path(), &config)?;
        let cached = entry.path().with_extension("bin");
        tdb.cache(cached)?;
    }

    Ok(())
}

fn build_config<'a>(matches: &'a ArgMatches) -> anyhow::Result<BuildConfig<'a>> {
    if let Some(config) = matches.get_one::<String>("CONFIG") {
        let f = BufReader::new(File::open(config)?);
        return serde_yaml::from_reader::<_, BuildConfig>(f).map_err(anyhow::Error::from);
    }

    let args = matches
        .get_many::<String>("ARGS")
        .unwrap_or_default()
        .map(|s| Cow::Borrowed(s.as_ref()))
        .collect::<Vec<_>>();

    let args32 = matches
        .get_many::<String>("ARGS-32")
        .unwrap_or_default()
        .map(|s| Cow::Borrowed(s.as_ref()))
        .collect::<Vec<_>>();

    let args64 = matches
        .get_many::<String>("ARGS-64")
        .unwrap_or_default()
        .map(|s| Cow::Borrowed(s.as_ref()))
        .collect::<Vec<_>>();

    let no_defaults = matches.get_flag("ARG-NO-DEFAULTS");
    let no_mxx = matches.get_flag("ARG-NO-MXX");

    Ok(BuildConfig {
        no_mxx,
        no_defaults,
        args,
        args32,
        args64,
    })
}

fn main() -> anyhow::Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .with_line_number(true)
        .with_file(true)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .finish();

    let _guard = tracing::subscriber::set_default(subscriber);

    if let Err(e) = run() {
        eprintln!("{e}");
        exit(-1);
    }

    Ok(())
}

fn run() -> anyhow::Result<()> {
    let command = Command::new("tutil")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Utilities for working with headers and type databases")
        .subcommand_required(true)
        .subcommands([
            Command::new("build")
                .about("Build a type library from a file or directory")
                .arg(
                    Arg::new("CONFIG")
                        .long("config")
                        .num_args(1)
                        .required(false),
                )
                .arg(
                    Arg::new("ARG-NO-DEFAULTS")
                        .long("no-clang-defaults")
                        .action(ArgAction::SetTrue)
                        .num_args(0)
                        .conflicts_with("CONFIG"),
                )
                .arg(
                    Arg::new("ARG-NO-MXX")
                        .long("no-clang-mxx")
                        .action(ArgAction::SetTrue)
                        .num_args(0)
                        .conflicts_with("CONFIG"),
                )
                .arg(
                    Arg::new("ARGS")
                        .long("clang-arg")
                        .allow_hyphen_values(true)
                        .value_delimiter(',')
                        .num_args(1)
                        .required(false)
                        .conflicts_with("CONFIG"),
                )
                .arg(
                    Arg::new("ARGS-32")
                        .long("clang-arg32")
                        .allow_hyphen_values(true)
                        .value_delimiter(',')
                        .num_args(1)
                        .required(false)
                        .conflicts_with("CONFIG"),
                )
                .arg(
                    Arg::new("ARGS-64")
                        .long("clang-arg64")
                        .allow_hyphen_values(true)
                        .value_delimiter(',')
                        .num_args(1)
                        .required(false)
                        .conflicts_with("CONFIG"),
                )
                .arg(Arg::new("INPUT").required(true))
                .arg(Arg::new("OUTPUT").required(false)),
            Command::new("query")
                .about("Query a header or type library")
                .arg(
                    Arg::new("BITS")
                        .long("bits")
                        .num_args(1)
                        .value_parser(value_parser!(TypeBits))
                        .default_value("any")
                        .required(false),
                )
                .arg(
                    Arg::new("EXACT")
                        .long("exact")
                        .conflicts_with("PREFIX")
                        .num_args(1)
                        .required(false),
                )
                .arg(
                    Arg::new("PREFIX")
                        .long("prefix")
                        .conflicts_with("EXACT")
                        .num_args(1)
                        .required(false),
                )
                .arg(
                    Arg::new("DEPTH")
                        .long("depth")
                        .num_args(1)
                        .default_value("1")
                        .value_parser(value_parser!(usize))
                        .required(false),
                )
                .arg(
                    Arg::new("CONFIG")
                        .long("config")
                        .num_args(1)
                        .required(false),
                )
                .arg(
                    Arg::new("ARG-NO-DEFAULTS")
                        .long("no-clang-defaults")
                        .action(ArgAction::SetTrue)
                        .num_args(0)
                        .conflicts_with("CONFIG"),
                )
                .arg(
                    Arg::new("ARG-NO-MXX")
                        .long("no-clang-mxx")
                        .action(ArgAction::SetTrue)
                        .num_args(0)
                        .conflicts_with("CONFIG"),
                )
                .arg(
                    Arg::new("ARGS")
                        .long("clang-arg")
                        .allow_hyphen_values(true)
                        .value_delimiter(',')
                        .num_args(1)
                        .required(false)
                        .conflicts_with("CONFIG"),
                )
                .arg(
                    Arg::new("ARGS-32")
                        .long("clang-arg32")
                        .allow_hyphen_values(true)
                        .value_delimiter(',')
                        .num_args(1)
                        .required(false)
                        .conflicts_with("CONFIG"),
                )
                .arg(
                    Arg::new("ARGS-64")
                        .long("clang-arg64")
                        .allow_hyphen_values(true)
                        .value_delimiter(',')
                        .num_args(1)
                        .required(false)
                        .conflicts_with("CONFIG"),
                )
                .arg(Arg::new("INPUT").required(true)),
        ]);

    let matches = match command.try_get_matches() {
        Ok(matches) => matches,
        Err(e) => {
            e.print()?;
            exit(-1);
        }
    };

    match matches.subcommand() {
        Some(("build", matches)) => {
            let config = build_config(&matches)?;

            let input = matches.get_one::<String>("INPUT").unwrap();
            let output = matches.get_one::<String>("OUTPUT");

            if Path::new(input).is_dir() {
                if output.is_some() {
                    println!("ignoring `OUTPUT` parameter; INPUT is a directory");
                }
                build_type_directory(input, config)?;
            } else {
                build_type_file(input, output, config)?;
            }
        }
        Some(("query", matches)) => {
            let config = build_config(&matches)?;

            let input = matches.get_one::<String>("INPUT").unwrap();

            let bits = matches.get_one::<TypeBits>("BITS").copied().unwrap();
            let depth = matches.get_one::<usize>("DEPTH").copied().unwrap();

            let query = if let Some(exact) = matches.get_one::<String>("EXACT") {
                TypeQuery::Exact(exact)
            } else if let Some(prefix) = matches.get_one::<String>("PREFIX") {
                TypeQuery::Prefix(prefix)
            } else {
                TypeQuery::None
            };

            dump_types(input, query, bits, depth, config)?;
        }
        _ => {}
    }

    Ok(())
}

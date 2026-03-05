use std::process::exit;

use clap::{ArgMatches, Command};
use mimalloc::MiMalloc;

mod ba2;
mod btp;
mod loader;
mod mcp;
mod scan;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_line_number(true)
        .with_file(true)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .finish();

    let _guard = tracing::subscriber::set_default(subscriber);

    let opts = Command::new("vulhunt")
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(scan::command())
        .subcommand(mcp::command())
        .subcommand(btp::command())
        .subcommand(ba2::command())
        .get_matches();

    if let Err(e) = run_command(&opts).await {
        tracing::error!("{e}");
        exit(1);
    }
}

async fn run_command(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    match opts.subcommand() {
        Some(("scan", sub_m)) => scan::run(sub_m).await,
        Some(("mcp", sub_m)) => mcp::run(sub_m).await,
        Some(("btp", sub_m)) => btp::run(sub_m).await,
        Some(("ba2", sub_m)) => ba2::run(sub_m).await,
        _ => unreachable!(),
    }
}

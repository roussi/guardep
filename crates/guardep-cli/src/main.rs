mod commands;
mod report;
mod shim;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
}

impl From<OutputFormat> for commands::audit::Format {
    fn from(f: OutputFormat) -> Self {
        match f {
            OutputFormat::Table => commands::audit::Format::Table,
            OutputFormat::Json => commands::audit::Format::Json,
        }
    }
}

#[derive(Parser)]
#[command(name = "guardep", version, about = "Block compromised dependencies before they install")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Audit a project against advisory DB without running install.
    Audit {
        #[arg(long, default_value = ".")]
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
        format: OutputFormat,
        /// Group findings by package@version, joining advisory IDs with commas.
        #[arg(long)]
        collapse: bool,
        /// Surface single-maintainer-only findings as Info. Off by
        /// default because most npm packages have one maintainer and
        /// reporting all of them is noise.
        #[arg(long)]
        report_single_maintainer: bool,
    },
    /// Install symlinks (npm/mvn/gradle) into ~/.guardep/bin.
    InstallShims {
        #[arg(long)]
        force: bool,
    },
    /// Run as the underlying tool's shim (auto-dispatched via argv0).
    Shim {
        /// Tool name (npm, mvn, gradle). Required when invoked directly.
        tool: String,
        /// Forwarded args.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Print resolved cache + config locations.
    Info,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_env("GUARDEP_LOG").unwrap_or_else(|_| EnvFilter::new("warn")))
        .with_writer(std::io::stderr)
        .init();

    // Argv0 dispatch — busybox pattern.
    if let Some(tool) = shim::detect_invocation() {
        let args: Vec<String> = std::env::args().skip(1).collect();
        return shim::run(&tool, &args).await;
    }

    let cli = Cli::parse();
    match cli.command {
        Cmd::Audit { path, format, collapse, report_single_maintainer } => {
            commands::audit::run(&path, format.into(), collapse, report_single_maintainer).await
        }
        Cmd::InstallShims { force } => commands::install_shims::run(force),
        Cmd::Shim { tool, args } => shim::run(&tool, &args).await,
        Cmd::Info => commands::info::run(),
    }
}

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

#[derive(Copy, Clone, Debug, ValueEnum)]
enum FailOnArg {
    Never,
    Warn,
    Block,
}

impl From<FailOnArg> for commands::audit::FailOn {
    fn from(f: FailOnArg) -> Self {
        match f {
            FailOnArg::Never => commands::audit::FailOn::Never,
            FailOnArg::Warn => commands::audit::FailOn::Warn,
            FailOnArg::Block => commands::audit::FailOn::Block,
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum FixTargetArg {
    /// Smallest in-major bump that clears every finding (default).
    Safe,
    /// Cheapest in-major bump that clears at least one finding.
    Min,
}

impl From<FixTargetArg> for commands::fix::FixTarget {
    fn from(f: FixTargetArg) -> Self {
        match f {
            FixTargetArg::Safe => commands::fix::FixTarget::Safe,
            FixTargetArg::Min => commands::fix::FixTarget::Min,
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
enum CacheCmd {
    /// Drop entries older than `--days` (default 30) and VACUUM.
    Prune {
        #[arg(long, default_value_t = 30)]
        days: i64,
    },
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
        /// Show every finding the evaluators emitted, including those
        /// the policy would normally Allow-filter (Low CVEs, etc.).
        /// Use when you want the full picture instead of just
        /// warn/block-tier results.
        #[arg(long, alias = "report-single-maintainer")]
        info: bool,
        /// Threshold above which the audit exits non-zero. `block`
        /// (default): exit 2 on blocks. `warn`: exit 1 on warnings,
        /// 2 on blocks. `never`: always exit 0 (informational).
        #[arg(long, value_enum, default_value_t = FailOnArg::Block)]
        fail_on: FailOnArg,
        /// Force a specific lockfile when more than one is present
        /// (`package-lock.json` | `pnpm-lock.yaml` | `yarn.lock` |
        /// `pom.xml`). Default: auto-detect.
        #[arg(long)]
        lockfile: Option<String>,
    },
    /// Generate (and optionally apply) the upgrade commands that
    /// resolve fix-able findings in the current project.
    Fix {
        #[arg(long, default_value = ".")]
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = FixTargetArg::Safe)]
        target: FixTargetArg,
        /// Actually run the install commands instead of just printing them.
        #[arg(long)]
        apply: bool,
        /// Skip the confirmation prompt before `--apply`. Use in CI.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Install symlinks (npm/pnpm/yarn) into ~/.guardep/bin and wire
    /// PATH in the user's shell rc files (zsh/bash/fish on Unix,
    /// PowerShell `$PROFILE` on Windows). Pass --no-wire-path to
    /// skip rc file edits.
    InstallShims {
        #[arg(long)]
        force: bool,
        /// Skip editing shell rc files. Symlinks are created either way;
        /// you'll need to add `~/.guardep/bin` to PATH manually.
        #[arg(long)]
        no_wire_path: bool,
        /// Skip the interactive confirmation before editing rc files.
        /// Use in CI or scripted installs.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Remove guardep shim symlinks from ~/.guardep/bin and strip the
    /// guardep PATH block from shell rc files.
    UninstallShims {
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
    /// Cache management subcommands.
    #[command(subcommand)]
    Cache(CacheCmd),
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
        Cmd::Audit { path, format, collapse, info, fail_on, lockfile } => {
            commands::audit::run(
                &path,
                format.into(),
                collapse,
                info,
                fail_on.into(),
                lockfile.as_deref(),
            )
            .await
        }
        Cmd::Fix { path, target, apply, yes } => {
            commands::fix::run(&path, target.into(), apply, yes).await
        }
        Cmd::InstallShims { force, no_wire_path, yes } => {
            commands::install_shims::run(force, !no_wire_path, yes)
        }
        Cmd::UninstallShims { force } => commands::install_shims::uninstall(force),
        Cmd::Shim { tool, args } => shim::run(&tool, &args).await,
        Cmd::Info => commands::info::run(),
        Cmd::Cache(CacheCmd::Prune { days }) => commands::cache::prune(days),
    }
}

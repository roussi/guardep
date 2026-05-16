mod commands;
mod report;
mod sarif;
mod sbom;
mod shim;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
    Cyclonedx,
    Sarif,
}

impl From<OutputFormat> for commands::audit::Format {
    fn from(f: OutputFormat) -> Self {
        match f {
            OutputFormat::Table => commands::audit::Format::Table,
            OutputFormat::Json => commands::audit::Format::Json,
            OutputFormat::Cyclonedx => commands::audit::Format::CycloneDx,
            OutputFormat::Sarif => commands::audit::Format::Sarif,
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

#[derive(Copy, Clone, Debug, ValueEnum)]
enum SeverityArg {
    /// Show everything, including informational signals (single-maintainer alone, etc.).
    Info,
    /// Show Low and above (default). Hides Info-tier rows.
    Low,
    /// Show Medium and above.
    Medium,
    /// Show High and above.
    High,
    /// Show only Critical findings.
    Critical,
}

impl From<SeverityArg> for guardep_core::FindingSeverity {
    fn from(s: SeverityArg) -> Self {
        match s {
            SeverityArg::Info => guardep_core::FindingSeverity::Info,
            SeverityArg::Low => guardep_core::FindingSeverity::Low,
            SeverityArg::Medium => guardep_core::FindingSeverity::Medium,
            SeverityArg::High => guardep_core::FindingSeverity::High,
            SeverityArg::Critical => guardep_core::FindingSeverity::Critical,
        }
    }
}

#[derive(Parser)]
#[command(
    name = "guardep",
    version,
    about = "Block compromised dependencies before they install",
    long_about = None,
    after_help = HELP_AFTER,
    disable_help_subcommand = true,
)]
struct Cli {
    /// Verbose logging (HTTP calls, evaluator timings, cache hits).
    /// Affects diagnostics only — does NOT change which findings are
    /// shown. Use `--severity` to control finding visibility.
    #[arg(short = 'v', long, global = true)]
    verbose: bool,
    /// Hide the banner. Auto-enabled in CI / when stdout is piped.
    #[arg(long, global = true)]
    no_banner: bool,
    #[command(subcommand)]
    command: Cmd,
}

const HELP_AFTER: &str = "\
Examples:
  $ guardep audit                           # audit current dir, default Low+ severity
  $ guardep audit --severity high           # only High + Critical
  $ guardep audit --collapse --format json  # one row per package, JSON for CI
  $ guardep fix --apply                     # bump vulnerable deps, after y/N preview
  $ guardep shims install                   # wire npm/pnpm/yarn/mvn/cargo (interactive)
  $ guardep shims install --tools npm,cargo # wire only those, skip the prompt
  $ guardep shims list                      # show which shims are active
  $ guardep shims enable cargo              # turn one shim on without re-wiring PATH

Environment variables:
  NO_COLOR              Disable ANSI colors
  CLICOLOR_FORCE        Force ANSI colors even when stdout is piped
  GUARDEP_LOG           Override tracing filter (e.g. `guardep=debug,reqwest=info`)
  GUARDEP_STRICT=1      Fail closed when shim audit errors (default: fail open)
  GUARDEP_BYPASS=1      Bypass the shim audit once, unless GUARDEP_STRICT=1

Exit codes:
  0   clean (or `--fail-on never`)
  1   warnings present (only when `--fail-on warn`)
  2   blocks present (default `--fail-on block`)
  >2  underlying tool error passed through (shim mode)

For per-command help: `guardep <command> --help`.
";

#[derive(Subcommand)]
enum CacheCmd {
    /// Drop entries older than `--days` (default 30) and VACUUM.
    Prune {
        #[arg(long, default_value_t = 30)]
        days: i64,
    },
}

#[derive(Subcommand)]
enum ShimsCmd {
    /// Install symlinks (npm/pnpm/yarn/mvn/cargo) into
    /// `~/.guardep/bin` and wire PATH in the user's shell rc files
    /// (zsh/bash/fish on Unix, PowerShell `$PROFILE` on Windows). Pass
    /// `--no-wire-path` to skip rc file edits. When stdout is a TTY
    /// and `--tools` is omitted, presents an interactive selection
    /// seeded by detected lockfiles in the current directory.
    Install {
        #[arg(long)]
        force: bool,
        /// Skip editing shell rc files. Symlinks are created either
        /// way; you'll need to add `~/.guardep/bin` to PATH manually.
        #[arg(long)]
        no_wire_path: bool,
        /// Skip the interactive confirmation before editing rc files.
        /// Use in CI or scripted installs.
        #[arg(long, short = 'y')]
        yes: bool,
        /// Comma-separated list of tools to wire (`npm,pnpm,yarn,mvn,cargo`).
        /// Use `all` for the full set. When omitted, interactive
        /// selection runs in a TTY; in CI the detected lockfiles drive
        /// the choice, falling back to all tools if none are present.
        #[arg(long, value_delimiter = ',')]
        tools: Option<Vec<String>>,
    },
    /// Remove guardep shim symlinks from `~/.guardep/bin` and strip
    /// the guardep PATH block from shell rc files.
    Uninstall {
        #[arg(long)]
        force: bool,
    },
    /// Show which package-manager shims are currently active.
    List,
    /// Enable one or more shims by adding their symlink under
    /// `~/.guardep/bin/`. Requires `shims install` to have run.
    Enable {
        #[arg(required = true)]
        tools: Vec<String>,
    },
    /// Disable one or more shims by removing the symlink. PATH wiring
    /// is left in place — re-enable later with `shims enable`.
    Disable {
        #[arg(required = true)]
        tools: Vec<String>,
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
        /// Minimum severity to display in the report. Findings below
        /// this threshold are dropped from the table/JSON entirely
        /// (policy still scores them; only display is filtered).
        /// `info` shows everything, `low` (default) hides Info-tier
        /// rows, `critical` shows only the most urgent findings.
        #[arg(long, value_enum, default_value_t = SeverityArg::Low)]
        severity: SeverityArg,
        /// Threshold above which the audit exits non-zero. `block`
        /// (default): exit 2 on blocks. `warn`: exit 1 on warnings,
        /// 2 on blocks. `never`: always exit 0 (informational).
        #[arg(long, value_enum, default_value_t = FailOnArg::Block)]
        fail_on: FailOnArg,
        /// Force a specific lockfile when more than one is present
        /// (`package-lock.json` | `pnpm-lock.yaml` | `yarn.lock` |
        /// `Cargo.lock` | `pom.xml` | `build.gradle` | `build.gradle.kts`).
        /// Default: auto-detect.
        #[arg(long)]
        lockfile: Option<String>,
        /// Emit one source-behavior finding per call-site instead of
        /// aggregating per (package, behavior). Useful for downstream
        /// tooling that wants byte-range granularity. Off by default.
        #[arg(long)]
        granular: bool,
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
    /// Manage package-manager shims: install, uninstall, list,
    /// enable, disable. `shims install` wires symlinks + PATH;
    /// `shims uninstall` reverses it. List/enable/disable adjust the
    /// active set without re-wiring PATH.
    #[command(subcommand)]
    Shims(ShimsCmd),
    /// Forward a single tool invocation to the real binary, skipping
    /// the audit. Public, supported escape hatch — equivalent to
    /// `$(which -a npm | grep -v guardep | head -1) install` but
    /// discoverable, greppable in CI logs, and refused under
    /// GUARDEP_STRICT=1. Prints a stderr warning on every use so the
    /// bypass shows up in build output.
    Skip {
        /// Tool name (npm, pnpm, yarn, mvn, cargo).
        tool: String,
        /// Forwarded args (use `--` to pass flags to the tool).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Run as the underlying tool's shim (auto-dispatched via argv0).
    /// For `cargo` the shim audits both the post-lock graph
    /// (`build/check/test/run/...`) and the future graph for the
    /// lock-mutating commands (`add/install/update`) via a temp-dir
    /// dry-run resolver.
    Shim {
        /// Tool name (npm, mvn, cargo, gradle). Required when invoked directly.
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
    /// Diff two project states and report only the NEW findings.
    /// Useful for PR-aware audits: compare the merge-base lockfile
    /// against the head lockfile and surface only what the PR adds.
    Diff {
        /// Baseline project root (typically `git worktree` of main).
        #[arg(long)]
        base: PathBuf,
        /// Head project root (the proposed change).
        #[arg(long)]
        head: PathBuf,
        #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
        format: OutputFormat,
        /// Minimum severity for findings shown in the diff.
        #[arg(long, value_enum, default_value_t = SeverityArg::Low)]
        severity: SeverityArg,
        /// Threshold above which the diff exits non-zero. Same semantics
        /// as `audit --fail-on`. Default: exit 2 when the PR adds blocks.
        #[arg(long, value_enum, default_value_t = FailOnArg::Block)]
        fail_on: FailOnArg,
        /// Emit one source-behavior finding per call-site (see
        /// `audit --granular`). Off by default.
        #[arg(long)]
        granular: bool,
    },
}

// Banner shown above `--help` / `--version` output. Modeled on
// Socket's compact 4-line ASCII header: name + version on the left,
// runtime context (shim status, cwd) on the right. Skipped under
// `--no-banner`, when stdout is non-tty (CI / piped), or under
// the conventional `NO_COLOR` / `CI` env vars to keep CI logs
// clean. Always written to stderr so it doesn't pollute pipes
// even when the tty heuristic is wrong.
fn maybe_print_banner() {
    use std::io::IsTerminal;

    let args: Vec<String> = std::env::args().collect();
    let wants_meta_output = args
        .iter()
        .any(|a| matches!(a.as_str(), "-h" | "--help" | "-V" | "--version"));
    if !wants_meta_output {
        return;
    }
    if args.iter().any(|a| a == "--no-banner") {
        return;
    }
    if std::env::var_os("NO_COLOR").is_some() || std::env::var_os("CI").is_some() {
        return;
    }
    if !std::io::stderr().is_terminal() {
        return;
    }

    let version = env!("CARGO_PKG_VERSION");
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|p| {
            // Display ~ for $HOME so the banner stays narrow.
            let home = std::env::var_os("HOME")?;
            let home = std::path::PathBuf::from(home);
            p.strip_prefix(&home)
                .ok()
                .map(|rel| format!("~/{}", rel.display()))
                .or_else(|| Some(p.display().to_string()))
        })
        .unwrap_or_else(|| ".".to_string());
    let shim_status = match commands::install_shims::shim_dir() {
        Ok(dir) if dir.join("npm").exists() => "active",
        _ => "not installed",
    };

    // Five-line ASCII logo, padded to a constant width so the
    // right-side context column stays aligned. Width chosen to match
    // the widest logo line (line 3, 41 cols).
    let logo = [
        "   __ _ _   _  __ _ _ __ __| | ___ _ __  ",
        "  / _` | | | |/ _` | '__/ _` |/ _ \\ '_ \\ ",
        " | (_| | |_| | (_| | | | (_| |  __/ |_) |",
        "  \\__, |\\__,_|\\__,_|_|  \\__,_|\\___| .__/ ",
        "  |___/                           |_|.dev",
    ];
    let context = [
        format!("guardep v{version}"),
        format!("shims: {shim_status}"),
        format!("cwd:   {cwd}"),
        String::new(),
        String::new(),
    ];
    for (l, c) in logo.iter().zip(context.iter()) {
        if c.is_empty() {
            eprintln!("  {l}  |");
        } else {
            eprintln!("  {l}  | {c}");
        }
    }
    eprintln!();
}

// Configure log level. `--verbose` bumps the default from `warn` to
// `debug` so HTTP calls / cache hits / evaluator timings surface in
// stderr. `GUARDEP_LOG` env var overrides both.
fn init_tracing(verbose: bool) {
    let default = if verbose { "debug" } else { "warn" };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("GUARDEP_LOG").unwrap_or_else(|_| EnvFilter::new(default)),
        )
        .with_writer(std::io::stderr)
        .init();
}

// Honour NO_COLOR / CLICOLOR_FORCE / non-tty stdout. Without this we
// emit ANSI escapes into pipes (`guardep audit | tee log.txt`) and
// non-color terminals.
fn init_color_support() {
    if std::env::var_os("NO_COLOR").is_some() {
        owo_colors::set_override(false);
        return;
    }
    if std::env::var_os("CLICOLOR_FORCE").is_some() {
        owo_colors::set_override(true);
        return;
    }
    let on = supports_color::on(supports_color::Stream::Stdout)
        .map(|level| level.has_basic)
        .unwrap_or(false);
    owo_colors::set_override(on);
}

#[tokio::main]
async fn main() -> Result<()> {
    init_color_support();

    // Argv0 dispatch — busybox pattern. Shim-mode never sees `--verbose`
    // since it forwards args to the underlying tool unchanged, so init
    // tracing at the default level here.
    if let Some(tool) = shim::detect_invocation() {
        init_tracing(false);
        let args: Vec<String> = std::env::args().skip(1).collect();
        return shim::run(&tool, &args).await;
    }

    maybe_print_banner();

    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match cli.command {
        Cmd::Audit {
            path,
            format,
            collapse,
            severity,
            fail_on,
            lockfile,
            granular,
        } => {
            commands::audit::run(
                &path,
                format.into(),
                collapse,
                severity.into(),
                fail_on.into(),
                lockfile.as_deref(),
                granular,
            )
            .await
        }
        Cmd::Fix {
            path,
            target,
            apply,
            yes,
        } => commands::fix::run(&path, target.into(), apply, yes).await,
        Cmd::Shims(ShimsCmd::Install {
            force,
            no_wire_path,
            yes,
            tools,
        }) => commands::install_shims::run(force, !no_wire_path, yes, tools),
        Cmd::Shims(ShimsCmd::Uninstall { force }) => commands::install_shims::uninstall(force),
        Cmd::Shims(ShimsCmd::List) => commands::shims::list(),
        Cmd::Shims(ShimsCmd::Enable { tools }) => commands::shims::enable(&tools),
        Cmd::Shims(ShimsCmd::Disable { tools }) => commands::shims::disable(&tools),
        Cmd::Skip { tool, args } => commands::skip::run(&tool, &args).await,
        Cmd::Shim { tool, args } => shim::run(&tool, &args).await,
        Cmd::Info => commands::info::run(),
        Cmd::Cache(CacheCmd::Prune { days }) => commands::cache::prune(days),
        Cmd::Diff {
            base,
            head,
            format,
            severity,
            fail_on,
            granular,
        } => {
            commands::diff::run(
                &base,
                &head,
                format.into(),
                severity.into(),
                fail_on.into(),
                granular,
            )
            .await
        }
    }
}

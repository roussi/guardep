use crate::commands::audit;
use crate::shim::{locate_real_binary, passthrough};
use anyhow::Result;
use guardep_core::resolver::{NpmDryRunResolver, Resolver};
use owo_colors::OwoColorize;
use std::path::PathBuf;

const INTERCEPTED: &[&str] = &["install", "i", "add", "ci", "update", "upgrade"];

/// Subcommands for which a dry-run is required to capture packages
/// not yet in the lockfile (e.g. `npm install foo`). For `npm ci`
/// the lockfile is authoritative by definition.
const NEEDS_DRY_RUN: &[&str] = &["install", "i", "add", "update", "upgrade"];

pub async fn dispatch(tool: &str, args: &[String]) -> Result<()> {
    let subcommand = args.iter().find(|a| !a.starts_with('-')).map(|s| s.as_str());

    let should_intercept = subcommand
        .map(|s| INTERCEPTED.contains(&s))
        .unwrap_or(false);

    if !should_intercept {
        return passthrough(tool, args);
    }

    eprintln!(
        "{} guardep: pre-install audit ({tool} {})",
        ">".cyan(),
        subcommand.unwrap_or("")
    );

    let project_root = std::env::current_dir()?;
    let lock_path = project_root.join("package-lock.json");

    // Detect explicit --no-package-lock flag (npm) — refuse to gate.
    // Exit 1 (general error) per Unix convention; the message on
    // stderr explains what specifically failed.
    if args.iter().any(|a| a == "--no-package-lock") {
        eprintln!(
            "{} --no-package-lock disables guardep's gate. Refusing to proceed.",
            "X".red()
        );
        std::process::exit(1);
    }

    // For `npm install foo`, the existing lockfile is stale w.r.t. the
    // new package. Use a dry-run resolution that includes the intended
    // additions. For `npm ci` the lockfile is authoritative.
    let needs_dry_run = subcommand
        .map(|s| NEEDS_DRY_RUN.contains(&s))
        .unwrap_or(false);

    let resolved = if needs_dry_run && tool == "npm" {
        eprintln!(
            "{} resolving via `npm install --dry-run` (captures intended additions)",
            ">".cyan()
        );
        match NpmDryRunResolver::new(args.to_vec()).resolve(&project_root) {
            Ok(pkgs) => Some(pkgs),
            Err(e) => {
                eprintln!("{} dry-run resolution failed: {e}", "!".yellow());
                eprintln!(
                    "{} falling back to existing lockfile audit (may miss new packages)",
                    "i".cyan()
                );
                None
            }
        }
    } else {
        None
    };

    if resolved.is_none() && !lock_path.exists() && !project_root.join("pnpm-lock.yaml").exists()
        && !project_root.join("yarn.lock").exists()
    {
        eprintln!(
            "{} no lockfile found in {}",
            "X".red(),
            project_root.display()
        );
        eprintln!(
            "{} guardep requires a lockfile to pre-audit. Run:",
            "i".cyan()
        );
        eprintln!("    npm install --package-lock-only");
        std::process::exit(1);
    }

    let verdict_result = match resolved {
        Some(packages) => {
            audit::evaluate_packages(
                &project_root,
                packages,
                guardep_core::FindingSeverity::Low,
            )
            .await
        }
        None => {
            audit::evaluate_project(
                &project_root,
                guardep_core::FindingSeverity::Low,
                None,
            )
            .await
        }
    };

    let verdict = match verdict_result {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} guardep audit failed: {e}", "!".yellow());
            eprintln!(
                "{} proceeding with install (fail-open). Set GUARDEP_STRICT=1 to fail closed.",
                "i".cyan()
            );
            if std::env::var("GUARDEP_STRICT").ok().as_deref() == Some("1") {
                std::process::exit(1);
            }
            return run_real(tool, args);
        }
    };

    if verdict.should_block() {
        crate::report::print_verdict(&verdict, false);
        eprintln!(
            "\n{} {} install blocked by guardep policy",
            "X".red().bold(),
            tool.bold()
        );
        std::process::exit(2);
    }
    if verdict.has_warnings() {
        crate::report::print_verdict(&verdict, false);
    }

    run_real(tool, args)
}

fn run_real(tool: &str, args: &[String]) -> Result<()> {
    let real: PathBuf = locate_real_binary(tool)?;
    let status = std::process::Command::new(real).args(args).status()?;
    std::process::exit(status.code().unwrap_or(1));
}

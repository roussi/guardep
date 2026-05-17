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
    let subcommand = npm_subcommand(args);

    if !npm_should_intercept(args) {
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
    if npm_disables_lock(args) {
        eprintln!(
            "{} --no-package-lock disables guardep's gate. Refusing to proceed.",
            "X".red()
        );
        std::process::exit(1);
    }

    // For `npm install foo`, the existing lockfile is stale w.r.t. the
    // new package. Use a dry-run resolution that includes the intended
    // additions. For `npm ci` the lockfile is authoritative.
    let resolved = if npm_needs_dry_run(args) && tool == "npm" {
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

    if resolved.is_none()
        && !lock_path.exists()
        && !project_root.join("pnpm-lock.yaml").exists()
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
                false,
            )
            .await
        }
        None => {
            audit::evaluate_project(&project_root, guardep_core::FindingSeverity::Low, None).await
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

/// First positional arg that doesn't start with `-`. Treats every flag
/// (long or short) as a global option; npm itself doesn't accept
/// option-with-arg in the way cargo does, so we don't need cargo's
/// `consumes-next-arg` heuristic.
fn npm_subcommand(args: &[String]) -> Option<&str> {
    args.iter()
        .find(|a| !a.starts_with('-'))
        .map(|s| s.as_str())
}

fn npm_should_intercept(args: &[String]) -> bool {
    npm_subcommand(args)
        .map(|s| INTERCEPTED.contains(&s))
        .unwrap_or(false)
}

fn npm_needs_dry_run(args: &[String]) -> bool {
    npm_subcommand(args)
        .map(|s| NEEDS_DRY_RUN.contains(&s))
        .unwrap_or(false)
}

fn npm_disables_lock(args: &[String]) -> bool {
    args.iter().any(|a| a == "--no-package-lock")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn detects_plain_install_subcommand() {
        assert_eq!(npm_subcommand(&args(&["install"])), Some("install"));
        assert_eq!(
            npm_subcommand(&args(&["install", "lodash"])),
            Some("install")
        );
    }

    #[test]
    fn skips_leading_flags_before_subcommand() {
        // Equals-style global options are common in scripted npm
        // invocations; the parser must skip them and land on the
        // first positional.
        let values = args(&["--silent", "--prefix=/tmp/x", "install", "express"]);
        assert_eq!(npm_subcommand(&values), Some("install"));
    }

    #[test]
    fn space_separated_option_value_is_treated_as_subcommand() {
        // Known limitation: `--prefix /tmp/x install` resolves to
        // `/tmp/x` because the parser has no knowledge of which flags
        // consume the next arg. npm itself accepts `--prefix=/tmp/x`
        // and that's the path real users hit; we document the edge
        // here so a future refactor doesn't break it silently.
        let values = args(&["--prefix", "/tmp/x", "install"]);
        assert_eq!(npm_subcommand(&values), Some("/tmp/x"));
    }

    #[test]
    fn returns_none_for_flags_only() {
        assert_eq!(npm_subcommand(&args(&["--version"])), None);
        assert_eq!(npm_subcommand(&args(&["--help"])), None);
        assert_eq!(npm_subcommand(&args(&[])), None);
    }

    #[test]
    fn intercept_matches_install_family() {
        for sub in ["install", "i", "add", "ci", "update", "upgrade"] {
            assert!(
                npm_should_intercept(&args(&[sub])),
                "expected `{sub}` to be intercepted",
            );
        }
    }

    #[test]
    fn intercept_skips_read_only_subcommands() {
        for sub in ["audit", "ls", "outdated", "view", "run"] {
            assert!(
                !npm_should_intercept(&args(&[sub])),
                "did not expect `{sub}` to be intercepted",
            );
        }
    }

    #[test]
    fn dry_run_needed_for_lock_mutators_only() {
        // ci is intercepted but should not trigger a dry-run since the
        // lockfile is already authoritative.
        assert!(npm_needs_dry_run(&args(&["install", "lodash"])));
        assert!(npm_needs_dry_run(&args(&["add"])));
        assert!(npm_needs_dry_run(&args(&["update"])));
        assert!(!npm_needs_dry_run(&args(&["ci"])));
        assert!(!npm_needs_dry_run(&args(&["ls"])));
        assert!(!npm_needs_dry_run(&args(&[])));
    }

    #[test]
    fn disables_lock_detects_no_package_lock_flag() {
        assert!(npm_disables_lock(&args(&["install", "--no-package-lock"])));
        assert!(!npm_disables_lock(&args(&["install"])));
        // Substring/related-prefix flags must not match.
        assert!(!npm_disables_lock(&args(&[
            "install",
            "--package-lock-only"
        ])));
    }
}

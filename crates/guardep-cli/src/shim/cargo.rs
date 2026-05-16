//! Cargo build-side shim.
//!
//! Cargo does not run dependency lifecycle hooks during resolution the
//! way npm does, but compiling a dependency can execute its `build.rs`.
//! The shim therefore gates commands that resolve or build the locked
//! dependency graph. Lock-mutating and global install commands are
//! forwarded unchanged for now because pre-auditing their post-update
//! graph requires a separate dry-run resolver.

use crate::commands::audit;
use crate::shim::{locate_real_binary, passthrough};
use anyhow::Result;
use guardep_core::resolver::{CargoLockResolver, Resolver};
use owo_colors::OwoColorize;
use std::path::PathBuf;

const INTERCEPTED: &[&str] = &[
    "bench", "build", "check", "clippy", "doc", "fetch", "run", "test",
];

pub async fn dispatch(tool: &str, args: &[String]) -> Result<()> {
    let subcommand = cargo_subcommand(args);

    let should_intercept = subcommand
        .map(|s| INTERCEPTED.contains(&s))
        .unwrap_or(false);

    if !should_intercept {
        return passthrough(tool, args);
    }

    eprintln!(
        "{} guardep: pre-build audit (cargo {})",
        ">".cyan(),
        subcommand.unwrap_or("")
    );

    let project_root = std::env::current_dir()?;
    if !project_root.join("Cargo.lock").exists() {
        if project_root.join("Cargo.toml").exists() {
            eprintln!("{} no Cargo.lock in {}", "X".red(), project_root.display());
            eprintln!(
                "{} guardep requires Cargo.lock to pre-audit. Run:",
                "i".cyan()
            );
            eprintln!("    cargo generate-lockfile");
            std::process::exit(1);
        }
        eprintln!(
            "{} no Cargo.lock in {}; forwarding `{tool} {}` without audit",
            "!".yellow(),
            project_root.display(),
            args.join(" ")
        );
        return run_real(tool, args);
    }

    let packages = match CargoLockResolver.resolve(&project_root) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} Cargo.lock resolution failed: {e}", "!".yellow());
            eprintln!(
                "{} proceeding with cargo (fail-open). Set GUARDEP_STRICT=1 to fail closed.",
                "i".cyan()
            );
            if std::env::var("GUARDEP_STRICT").ok().as_deref() == Some("1") {
                std::process::exit(1);
            }
            return run_real(tool, args);
        }
    };

    let verdict_result = audit::evaluate_packages(
        &project_root,
        packages,
        guardep_core::FindingSeverity::Low,
        false,
    )
    .await;

    let verdict = match verdict_result {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} guardep audit failed: {e}", "!".yellow());
            eprintln!(
                "{} proceeding with cargo (fail-open). Set GUARDEP_STRICT=1 to fail closed.",
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
            "\n{} cargo invocation blocked by guardep policy",
            "X".red().bold()
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

fn cargo_subcommand(args: &[String]) -> Option<&str> {
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg.starts_with('+') {
            continue;
        }
        if cargo_option_consumes_next(arg) {
            skip_next = true;
            continue;
        }
        if cargo_option_has_inline_value(arg) {
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        return Some(arg.as_str());
    }
    None
}

fn cargo_option_consumes_next(arg: &str) -> bool {
    matches!(
        arg,
        "--color" | "--config" | "--manifest-path" | "--target-dir" | "-C" | "-Z"
    )
}

fn cargo_option_has_inline_value(arg: &str) -> bool {
    arg.starts_with("--color=")
        || arg.starts_with("--config=")
        || arg.starts_with("--manifest-path=")
        || arg.starts_with("--target-dir=")
        || (arg.starts_with("-C") && arg != "-C")
        || (arg.starts_with("-Z") && arg != "-Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn detects_plain_cargo_subcommand() {
        assert_eq!(
            cargo_subcommand(&args(&["build", "--locked"])),
            Some("build")
        );
    }

    #[test]
    fn skips_toolchain_selector_and_global_options() {
        let values = args(&[
            "+nightly",
            "--config",
            "net.git-fetch-with-cli=true",
            "check",
        ]);
        assert_eq!(cargo_subcommand(&values), Some("check"));
    }

    #[test]
    fn skips_equals_style_global_options() {
        let values = args(&[
            "--color=always",
            "--manifest-path=crates/x/Cargo.toml",
            "test",
        ]);
        assert_eq!(cargo_subcommand(&values), Some("test"));
    }

    #[test]
    fn returns_none_for_metadata_flags() {
        assert_eq!(cargo_subcommand(&args(&["--version"])), None);
    }

    #[test]
    fn does_not_skip_after_inline_short_option() {
        assert_eq!(
            cargo_subcommand(&args(&["-Zunstable-options", "build"])),
            Some("build")
        );
    }
}

//! Cargo shim.
//!
//! Two gate flavours:
//!
//! 1. Post-lock: `build/check/test/run/doc/bench/fetch/clippy` audit the
//!    already-resolved `Cargo.lock`. By the time we see these, the user
//!    has accepted the locked graph; we only need to refuse to compile
//!    or run anything malicious in it.
//!
//! 2. Pre-install: `add/install/update` mutate the lock. Auditing only
//!    on the next `build` lets a compromised crate land in the user's
//!    `Cargo.lock` first. For these we resolve the future graph via a
//!    temp-dir cargo invocation (see `CargoDryRunResolver`), audit it,
//!    and only then forward to real cargo on the user's workspace.
//!
//! Off-registry deps (`--path`, `--git`, `--registry`) bypass the
//! pre-install audit with a stderr warning: OSV has no advisory keys
//! for those sources, so the audit would be a no-op anyway. Strict-mode
//! users can still set `GUARDEP_STRICT=1` to fail-closed on any
//! resolver / spawn errors.

use crate::commands::audit;
use crate::shim::{locate_real_binary, passthrough};
use anyhow::Result;
use guardep_core::resolver::{CargoDryRunAction, CargoDryRunResolver, CargoLockResolver, Resolver};
use owo_colors::OwoColorize;
use std::path::PathBuf;

const INTERCEPTED: &[&str] = &[
    "add", "bench", "build", "check", "clippy", "doc", "fetch", "install", "run", "test", "update",
];

pub async fn dispatch(tool: &str, args: &[String]) -> Result<()> {
    let subcommand = cargo_subcommand(args);
    let Some(sub) = subcommand else {
        return passthrough(tool, args);
    };
    if !INTERCEPTED.contains(&sub) {
        return passthrough(tool, args);
    }

    match sub {
        "add" => audit_pre_install(tool, args, CargoDryRunAction::Add, "add").await,
        "install" => audit_pre_install(tool, args, CargoDryRunAction::Install, "install").await,
        "update" => audit_pre_install(tool, args, CargoDryRunAction::Update, "update").await,
        other => audit_post_lock(tool, args, other).await,
    }
}

async fn audit_post_lock(tool: &str, args: &[String], subcommand: &str) -> Result<()> {
    eprintln!(
        "{} guardep: pre-build audit (cargo {})",
        ">".cyan(),
        subcommand
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

    finish_audit(tool, args, &project_root, packages).await
}

async fn audit_pre_install(
    tool: &str,
    args: &[String],
    action: CargoDryRunAction,
    subcommand: &str,
) -> Result<()> {
    eprintln!(
        "{} guardep: pre-install audit (cargo {})",
        ">".cyan(),
        subcommand
    );

    // OSV has no keys for path/git/alternate-registry sources. Auditing
    // them yields nothing actionable, so warn loudly and forward — the
    // user still gets the package, but knows guardep didn't gate it.
    if cargo_uses_off_registry(args) {
        eprintln!(
            "{} off-registry dep (--path/--git/--registry), skipping audit",
            "!".yellow()
        );
        return run_real(tool, args);
    }

    let project_root = std::env::current_dir()?;
    eprintln!(
        "{} resolving via temp-dir `cargo {subcommand}` (captures intended graph)",
        ">".cyan()
    );

    let resolver = CargoDryRunResolver::new(action, args.to_vec());
    let packages = match resolver.resolve(&project_root) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} pre-install resolution failed: {e}", "!".yellow());
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

    finish_audit(tool, args, &project_root, packages).await
}

async fn finish_audit(
    tool: &str,
    args: &[String],
    project_root: &std::path::Path,
    packages: Vec<guardep_core::ecosystem::PackageRef>,
) -> Result<()> {
    let verdict_result = audit::evaluate_packages(
        project_root,
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

/// True if the args pin an off-registry source. We never want to claim
/// we gated such installs: OSV / cargo-audit have no advisory keys for
/// path / git / alternate-registry sources.
fn cargo_uses_off_registry(args: &[String]) -> bool {
    args.iter().any(|a| {
        a == "--path"
            || a.starts_with("--path=")
            || a == "--git"
            || a.starts_with("--git=")
            || a == "--registry"
            || a.starts_with("--registry=")
    })
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

    #[test]
    fn detects_add_install_update_subcommands() {
        assert_eq!(cargo_subcommand(&args(&["add", "serde"])), Some("add"));
        assert_eq!(
            cargo_subcommand(&args(&["install", "ripgrep"])),
            Some("install")
        );
        assert_eq!(
            cargo_subcommand(&args(&["update", "-p", "serde"])),
            Some("update")
        );
    }

    #[test]
    fn detects_add_after_global_options() {
        let values = args(&[
            "--color=always",
            "+stable",
            "--manifest-path",
            "x",
            "add",
            "serde",
        ]);
        assert_eq!(cargo_subcommand(&values), Some("add"));
    }

    #[test]
    fn off_registry_detects_path() {
        assert!(cargo_uses_off_registry(&args(&["add", "--path", "../foo"])));
        assert!(cargo_uses_off_registry(&args(&["add", "--path=../foo"])));
    }

    #[test]
    fn off_registry_detects_git() {
        assert!(cargo_uses_off_registry(&args(&[
            "add",
            "--git",
            "https://example.com/x.git"
        ])));
        assert!(cargo_uses_off_registry(&args(&[
            "add",
            "--git=https://example.com/x.git"
        ])));
    }

    #[test]
    fn off_registry_detects_alt_registry() {
        assert!(cargo_uses_off_registry(&args(&[
            "add",
            "serde",
            "--registry",
            "internal"
        ])));
        assert!(cargo_uses_off_registry(&args(&[
            "add",
            "serde",
            "--registry=internal"
        ])));
    }

    #[test]
    fn off_registry_false_for_plain_add() {
        assert!(!cargo_uses_off_registry(&args(&["add", "serde"])));
        assert!(!cargo_uses_off_registry(&args(&[
            "add",
            "serde",
            "--features",
            "derive"
        ])));
    }

    #[test]
    fn off_registry_false_for_plain_install() {
        assert!(!cargo_uses_off_registry(&args(&["install", "ripgrep"])));
    }
}

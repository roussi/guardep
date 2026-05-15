//! Maven install-side shim.
//!
//! Intercepts `mvn install`, `mvn package`, and `mvn verify` — the
//! lifecycle phases that resolve transitive dependencies and trigger
//! plugin downloads. Other phases (`compile`, `test`, `clean`) are
//! forwarded unchanged because they don't pull new artifacts unless
//! they implicitly depend on a resolution-triggering phase, and we
//! avoid auditing on every command for cost reasons.
//!
//! Maven's threat model differs from npm's in a key way: there is no
//! `postinstall` hook on a downloaded jar. Plugins can run arbitrary
//! code, but only when explicitly invoked. So the gate here is more
//! about supply-chain hygiene (CVE / malware in resolved deps) than
//! about blocking install-time code execution.

use crate::commands::audit;
use crate::shim::{locate_real_binary, passthrough};
use anyhow::Result;
use guardep_core::resolver::{MavenTreeResolver, Resolver};
use owo_colors::OwoColorize;
use std::path::PathBuf;

/// Maven phases that trigger transitive dependency resolution. Any
/// invocation containing one of these as a positional arg is gated.
const INTERCEPTED_PHASES: &[&str] = &["install", "package", "verify"];

pub async fn dispatch(tool: &str, args: &[String]) -> Result<()> {
    // Maven goals can be chained: `mvn clean install -DskipTests`.
    // Walk every positional arg; if any matches an intercepted phase
    // we audit before forwarding.
    let triggers: Vec<&str> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .filter(|a| INTERCEPTED_PHASES.contains(&a.as_str()))
        .map(|s| s.as_str())
        .collect();

    if triggers.is_empty() {
        return passthrough(tool, args);
    }

    eprintln!(
        "{} guardep: pre-install audit (mvn {})",
        ">".cyan(),
        triggers.join(" ")
    );

    let project_root = std::env::current_dir()?;
    if !project_root.join("pom.xml").exists() {
        eprintln!("{} no pom.xml in {}", "X".red(), project_root.display());
        std::process::exit(1);
    }

    let packages = match MavenTreeResolver.resolve(&project_root) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "{} maven dependency:tree resolution failed: {e}",
                "!".yellow()
            );
            eprintln!(
                "{} proceeding with mvn (fail-open). Set GUARDEP_STRICT=1 to fail closed.",
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
                "{} proceeding with mvn (fail-open). Set GUARDEP_STRICT=1 to fail closed.",
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
            "\n{} mvn invocation blocked by guardep policy",
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

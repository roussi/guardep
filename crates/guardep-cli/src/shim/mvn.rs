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
    let triggers = mvn_triggers(args);

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

/// Lifecycle phases in the invocation that should trigger an audit.
/// Empty when none of `install`/`package`/`verify` is present.
fn mvn_triggers(args: &[String]) -> Vec<&str> {
    args.iter()
        .filter(|a| !a.starts_with('-'))
        .filter(|a| INTERCEPTED_PHASES.contains(&a.as_str()))
        .map(|s| s.as_str())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_triggers_for_read_only_goals() {
        assert!(mvn_triggers(&args(&["compile"])).is_empty());
        assert!(mvn_triggers(&args(&["test"])).is_empty());
        assert!(mvn_triggers(&args(&["clean"])).is_empty());
        assert!(mvn_triggers(&args(&[])).is_empty());
    }

    #[test]
    fn detects_install_phase() {
        assert_eq!(mvn_triggers(&args(&["install"])), vec!["install"]);
    }

    #[test]
    fn detects_chained_phases_in_order() {
        // `mvn clean install` should produce only the lifecycle hit.
        assert_eq!(mvn_triggers(&args(&["clean", "install"])), vec!["install"]);
        // `mvn package verify` yields both, in encounter order.
        assert_eq!(
            mvn_triggers(&args(&["package", "verify"])),
            vec!["package", "verify"],
        );
    }

    #[test]
    fn ignores_system_properties_and_profile_flags() {
        let values = args(&["-DskipTests", "-Pprod", "install"]);
        assert_eq!(mvn_triggers(&values), vec!["install"]);
    }

    #[test]
    fn ignores_phase_in_property_value() {
        // `-Dfoo=install` must not be treated as the install phase.
        let values = args(&["-Dfoo=install", "test"]);
        assert!(mvn_triggers(&values).is_empty());
    }

    #[test]
    fn ignores_unrelated_positional_args() {
        // Goals like `dependency:tree` are passthrough.
        assert!(mvn_triggers(&args(&["dependency:tree"])).is_empty());
        // Mixed: `install` is positional, plugin invocation is not.
        assert_eq!(
            mvn_triggers(&args(&["dependency:tree", "install"])),
            vec!["install"],
        );
    }
}

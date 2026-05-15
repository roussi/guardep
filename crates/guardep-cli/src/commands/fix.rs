//! `guardep fix` — generate (and optionally run) the upgrade commands
//! that resolve as many findings as possible for a project.
//!
//! Strategy:
//!   - Re-run the audit to get a fresh `FindingsReport`.
//!   - Group findings by `(name, version)`.
//!   - Compute `FixTargets` per group; pick `min` or `safe` per the
//!     `--target` flag (default `safe` — full coverage).
//!   - Translate to package-manager-specific install commands.
//!   - With `--apply`: spawn the commands. Otherwise just print them.
//!
//! Note: this only handles findings that have a fix version
//! (vulnerabilities). Postinstall, risk, and provenance findings have
//! no version-bump remedy and are reported separately so the user
//! knows they still need attention.

use anyhow::Result;
use guardep_core::{FindingKind, FindingSeverity, FindingsReport, ScoredFinding};
use owo_colors::OwoColorize;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use crate::commands::audit;
use crate::report::fix_targets;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixTarget {
    /// Cheapest in-major bump that clears at least one finding.
    Min,
    /// Smallest bump that clears every finding (default).
    Safe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageManager {
    Npm,
    Pnpm,
    Yarn,
}

impl PackageManager {
    fn detect(project_root: &Path) -> Self {
        if project_root.join("pnpm-lock.yaml").exists() {
            Self::Pnpm
        } else if project_root.join("yarn.lock").exists() {
            Self::Yarn
        } else {
            Self::Npm
        }
    }

    fn install_cmd(self, name: &str, version: &str) -> Vec<String> {
        match self {
            // npm install pkg@^x.y.z saves to package.json AND updates
            // the lockfile to that exact range.
            Self::Npm => vec![
                "npm".into(),
                "install".into(),
                format!("{name}@^{version}"),
            ],
            Self::Pnpm => vec![
                "pnpm".into(),
                "add".into(),
                format!("{name}@^{version}"),
            ],
            Self::Yarn => vec![
                "yarn".into(),
                "add".into(),
                format!("{name}@^{version}"),
            ],
        }
    }
}

pub async fn run(path: &Path, target: FixTarget, apply: bool, yes: bool) -> Result<()> {
    let report = audit::evaluate_project(path, false).await?;
    let plan = build_plan(&report, target);
    print_plan(&plan, target);

    if apply {
        if plan.upgrades.is_empty() {
            eprintln!("{} nothing to apply.", "i".cyan());
            return Ok(());
        }
        let pm = PackageManager::detect(path);
        // Confirmation: --apply without --yes asks before mutating
        // package.json + lockfile. CI users opt out via --yes.
        if !yes && !confirm(plan.upgrades.len(), pm)? {
            eprintln!("{} aborted by user.", "i".cyan());
            return Ok(());
        }
        eprintln!(
            "\n{} applying {} upgrade(s) via {:?}",
            ">".cyan(),
            plan.upgrades.len(),
            pm
        );
        for upg in &plan.upgrades {
            let cmd = pm.install_cmd(&upg.name, &upg.target_version);
            run_command(path, &cmd)?;
        }
        eprintln!("\n{} done.", "OK".green().bold());
    } else if !plan.upgrades.is_empty() {
        eprintln!(
            "\n{} run with `--apply` to execute these commands.",
            "i".cyan()
        );
    }
    Ok(())
}

fn confirm(upgrade_count: usize, pm: PackageManager) -> Result<bool> {
    use std::io::{self, BufRead, Write};
    eprint!(
        "\n{} apply {} upgrade(s) via {:?}? This will modify package.json + lockfile. [y/N] ",
        "?".yellow().bold(),
        upgrade_count,
        pm
    );
    io::stderr().flush().ok();
    let mut line = String::new();
    let stdin = io::stdin();
    stdin.lock().read_line(&mut line)?;
    let answer = line.trim().to_ascii_lowercase();
    Ok(matches!(answer.as_str(), "y" | "yes"))
}

#[derive(Debug)]
pub struct Plan {
    pub upgrades: Vec<Upgrade>,
    /// Findings that the audit surfaced but cannot be fixed by a
    /// version bump (postinstall scripts, risk score, missing
    /// provenance, etc.). Reported so the user knows they remain.
    pub manual: Vec<ManualItem>,
    /// Packages that need a major-version bump (breaking change).
    pub breaking: Vec<Upgrade>,
}

#[derive(Debug, Clone)]
pub struct Upgrade {
    pub name: String,
    pub current_version: String,
    pub target_version: String,
    /// `n / total` findings cleared at this target.
    pub clears: String,
}

#[derive(Debug, Clone)]
pub struct ManualItem {
    pub name: String,
    pub version: String,
    pub kind: FindingKind,
    pub summary: String,
}

fn build_plan(report: &FindingsReport, target: FixTarget) -> Plan {
    let mut by_package: BTreeMap<(String, String), Vec<&ScoredFinding>> = BTreeMap::new();
    let mut manual: Vec<ManualItem> = Vec::new();

    for s in &report.items {
        // Skip Info-tier rows — they aren't actionable.
        if s.finding.severity == FindingSeverity::Info {
            continue;
        }
        match s.finding.kind {
            FindingKind::Vulnerability | FindingKind::Malware => {
                by_package
                    .entry((s.finding.package.name.clone(), s.finding.package.version.clone()))
                    .or_default()
                    .push(s);
            }
            // No version-bump remedy — surface as manual to-do.
            FindingKind::PostinstallScript
            | FindingKind::RiskScore
            | FindingKind::MissingProvenance
            | FindingKind::ProvenanceMismatch => {
                manual.push(ManualItem {
                    name: s.finding.package.name.clone(),
                    version: s.finding.package.version.clone(),
                    kind: s.finding.kind,
                    summary: s.finding.summary.clone(),
                });
            }
        }
    }

    let mut upgrades: Vec<Upgrade> = Vec::new();
    let mut breaking: Vec<Upgrade> = Vec::new();

    for ((name, current), items) in by_package {
        let targets = fix_targets(&items);
        let chosen = match target {
            FixTarget::Min => targets.min.clone(),
            FixTarget::Safe => targets.safe.clone().or_else(|| targets.min.clone()),
        };
        let Some(target_version) = chosen else {
            // No in-major fix available; check for cross-major fallback.
            if let Some(v) = targets.cross_major_fallback.clone() {
                breaking.push(Upgrade {
                    name,
                    current_version: current,
                    target_version: v,
                    clears: "breaking".into(),
                });
            }
            continue;
        };
        let clears = match target {
            FixTarget::Min => format!("{}/{}", targets.cleared_at_min, targets.total),
            FixTarget::Safe => format!("{}/{}", targets.total, targets.total),
        };
        let upg = Upgrade {
            name,
            current_version: current,
            target_version,
            clears,
        };
        if targets.breaking {
            breaking.push(upg);
        } else {
            upgrades.push(upg);
        }
    }

    Plan {
        upgrades,
        manual,
        breaking,
    }
}

fn print_plan(plan: &Plan, target: FixTarget) {
    if !plan.upgrades.is_empty() {
        println!(
            "{} {} upgrade(s) ({}):",
            ">".cyan(),
            plan.upgrades.len(),
            match target {
                FixTarget::Min => "min, cheapest patch",
                FixTarget::Safe => "safe, clears all findings in package",
            }
        );
        for u in &plan.upgrades {
            println!(
                "  {} {} -> {}  ({})",
                u.name.bold(),
                u.current_version.dimmed(),
                u.target_version.green(),
                u.clears.dimmed()
            );
        }
    } else {
        println!("{} no in-major upgrades available", "i".cyan());
    }

    if !plan.breaking.is_empty() {
        println!(
            "\n{} {} breaking upgrade(s) — major version bump required:",
            "!".yellow(),
            plan.breaking.len()
        );
        for u in &plan.breaking {
            println!(
                "  {} {} -> {}  ({})",
                u.name.bold(),
                u.current_version.dimmed(),
                u.target_version.yellow(),
                u.clears.dimmed()
            );
        }
    }

    if !plan.manual.is_empty() {
        println!(
            "\n{} {} finding(s) cannot be fixed by version bump — manual review:",
            "i".cyan(),
            plan.manual.len()
        );
        let mut by_kind: BTreeMap<&'static str, Vec<&ManualItem>> = BTreeMap::new();
        for m in &plan.manual {
            by_kind.entry(kind_label(m.kind)).or_default().push(m);
        }
        for (kind, items) in by_kind {
            println!("  [{}]", kind.cyan());
            for it in items {
                println!("    {}@{}  {}", it.name, it.version, it.summary);
            }
        }
    }
}

fn kind_label(k: FindingKind) -> &'static str {
    match k {
        FindingKind::PostinstallScript => "postinstall script",
        FindingKind::RiskScore => "risk score",
        FindingKind::MissingProvenance => "missing provenance",
        FindingKind::ProvenanceMismatch => "provenance mismatch",
        FindingKind::Malware | FindingKind::Vulnerability => "advisory",
    }
}

fn run_command(cwd: &Path, parts: &[String]) -> Result<()> {
    eprintln!("  {} {}", "$".dimmed(), parts.join(" "));
    let status = Command::new(&parts[0])
        .args(&parts[1..])
        .current_dir(cwd)
        .status()?;
    if !status.success() {
        anyhow::bail!("`{}` exited {}", parts.join(" "), status);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardep_core::ecosystem::{Ecosystem, PackageRef};
    use guardep_core::finding::Finding;
    use guardep_core::policy::Policy;

    fn vuln(name: &str, version: &str, fixes: &[&str]) -> Finding {
        Finding {
            package: PackageRef::new(Ecosystem::Npm, name, version),
            kind: FindingKind::Vulnerability,
            id: format!("GHSA-{name}"),
            aliases: vec![],
            summary: String::new(),
            severity: FindingSeverity::High,
            fixed_versions: fixes.iter().map(|s| s.to_string()).collect(),
            references: vec![],
            details: serde_json::Value::Null,
        }
    }

    #[test]
    fn safe_target_picks_full_coverage() {
        let report = FindingsReport::from_findings(
            vec![
                vuln("axios", "1.0.0", &["1.0.5"]),
                vuln("axios", "1.0.0", &["1.0.7"]),
            ],
            &Policy::default(),
        );
        let plan = build_plan(&report, FixTarget::Safe);
        assert_eq!(plan.upgrades.len(), 1);
        assert_eq!(plan.upgrades[0].target_version, "1.0.7");
        assert_eq!(plan.upgrades[0].clears, "2/2");
    }

    #[test]
    fn min_target_picks_cheapest_patch() {
        let report = FindingsReport::from_findings(
            vec![
                vuln("axios", "1.0.0", &["1.0.5"]),
                vuln("axios", "1.0.0", &["1.0.7"]),
            ],
            &Policy::default(),
        );
        let plan = build_plan(&report, FixTarget::Min);
        assert_eq!(plan.upgrades[0].target_version, "1.0.5");
        assert_eq!(plan.upgrades[0].clears, "1/2");
    }

    #[test]
    fn cross_major_routes_to_breaking() {
        let report = FindingsReport::from_findings(
            vec![vuln("tar", "6.2.1", &["7.5.4"])],
            &Policy::default(),
        );
        let plan = build_plan(&report, FixTarget::Safe);
        assert!(plan.upgrades.is_empty());
        assert_eq!(plan.breaking.len(), 1);
        assert_eq!(plan.breaking[0].target_version, "7.5.4");
    }

    #[test]
    fn non_vulnerability_findings_go_to_manual_bucket() {
        let mut postinstall = vuln("evil", "1.0.0", &[]);
        postinstall.kind = FindingKind::PostinstallScript;
        postinstall.id = "script:postinstall:abc".into();
        postinstall.severity = FindingSeverity::Critical;
        postinstall.summary = "exfil postinstall".into();

        let report = FindingsReport::from_findings(vec![postinstall], &Policy::default());
        let plan = build_plan(&report, FixTarget::Safe);
        assert!(plan.upgrades.is_empty());
        assert_eq!(plan.manual.len(), 1);
        assert_eq!(plan.manual[0].kind, FindingKind::PostinstallScript);
    }

    #[test]
    fn npm_install_command_is_caret_prefixed() {
        let cmd = PackageManager::Npm.install_cmd("axios", "1.15.2");
        assert_eq!(cmd, vec!["npm", "install", "axios@^1.15.2"]);
    }

    #[test]
    fn pnpm_install_command() {
        let cmd = PackageManager::Pnpm.install_cmd("axios", "1.15.2");
        assert_eq!(cmd, vec!["pnpm", "add", "axios@^1.15.2"]);
    }
}

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

    /// Build a single install command that applies every upgrade in
    /// one transaction. npm/pnpm/yarn all support multiple specs in
    /// one invocation. Either all bumps land or the package manager
    /// fails atomically — no half-applied state, no divergent
    /// lockfile.
    fn install_all_cmd(self, upgrades: &[Upgrade]) -> Vec<String> {
        let specs: Vec<String> = upgrades
            .iter()
            .map(|u| format!("{}@^{}", u.name, u.target_version))
            .collect();
        let (bin, sub) = match self {
            Self::Npm => ("npm", "install"),
            Self::Pnpm => ("pnpm", "add"),
            Self::Yarn => ("yarn", "add"),
        };
        let mut cmd = vec![bin.to_string(), sub.to_string()];
        cmd.extend(specs);
        cmd
    }
}

pub async fn run(path: &Path, target: FixTarget, apply: bool, yes: bool) -> Result<()> {
    // Fix planning needs every actionable finding regardless of CLI
    // display preference, so override threshold to Low (default minus
    // Info-only signals like single-maintainer-alone, which carry no
    // version-bump remedy anyway).
    let report =
        audit::evaluate_project(path, guardep_core::FindingSeverity::Low, None).await?;
    let plan = build_plan(&report, target);
    print_plan(&plan, target);

    if apply {
        if plan.upgrades.is_empty() {
            eprintln!("{} nothing to apply.", "i".cyan());
            return Ok(());
        }
        let pm = PackageManager::detect(path);
        if !yes {
            print_manifest_diff(path, &plan.upgrades);
        }
        // Confirmation: --apply without --yes asks before mutating
        // package.json + lockfile. CI users opt out via --yes.
        if !yes && !confirm(plan.upgrades.len(), pm)? {
            eprintln!("{} aborted by user.", "i".cyan());
            return Ok(());
        }
        eprintln!(
            "\n{} applying {} upgrade(s) atomically via {:?}",
            ">".cyan(),
            plan.upgrades.len(),
            pm
        );
        // Single invocation for all upgrades. Either every spec lands
        // or the package manager fails atomically and the lockfile is
        // unchanged. No half-applied state to recover from.
        let cmd = pm.install_all_cmd(&plan.upgrades);
        run_command(path, &cmd)?;
        eprintln!("\n{} done.", "OK".green().bold());
    } else if !plan.upgrades.is_empty() {
        eprintln!(
            "\n{} run with `--apply` to execute these commands.",
            "i".cyan()
        );
    }
    Ok(())
}

// Show a unified diff of how `package.json` will look after the
// upgrades. The actual change is performed by the package manager so
// the projection is approximate (it only swaps existing version
// strings; transitive bumps and lockfile detail still come from npm).
// Good enough to confirm "yes I want to bump these specific deps".
fn print_manifest_diff(project_root: &Path, upgrades: &[Upgrade]) {
    if upgrades.is_empty() {
        return;
    }
    let manifest = project_root.join("package.json");
    let Ok(current) = std::fs::read_to_string(&manifest) else {
        return;
    };
    let projected = project_manifest(&current, upgrades);
    if projected == current {
        return;
    }
    eprintln!("\n{} package.json diff preview:", ">".cyan());
    let diff = similar::TextDiff::from_lines(&current, &projected);
    for change in diff.iter_all_changes() {
        match change.tag() {
            similar::ChangeTag::Delete => {
                eprint!("  {}", format!("-{change}").red());
            }
            similar::ChangeTag::Insert => {
                eprint!("  {}", format!("+{change}").green());
            }
            similar::ChangeTag::Equal => {}
        }
    }
}

fn project_manifest(original: &str, upgrades: &[Upgrade]) -> String {
    // Line-level swap: for each upgrade, replace any line that pins the
    // current version with the new `^target` spec. Conservative: only
    // touches lines where both the package name and current version
    // match, leaving comments / unrelated keys alone.
    let mut out = String::with_capacity(original.len());
    'lines: for line in original.split_inclusive('\n') {
        for u in upgrades {
            let needle_quoted = format!("\"{}\"", u.name);
            if !line.contains(&needle_quoted) {
                continue;
            }
            let current_pat = format!("\"{}\"", u.current_version);
            let current_caret = format!("\"^{}\"", u.current_version);
            let current_tilde = format!("\"~{}\"", u.current_version);
            let target = format!("\"^{}\"", u.target_version);
            for from in [&current_pat, &current_caret, &current_tilde] {
                if line.contains(from.as_str()) {
                    out.push_str(&line.replacen(from.as_str(), &target, 1));
                    continue 'lines;
                }
            }
        }
        out.push_str(line);
    }
    out
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

    fn upg(name: &str, version: &str) -> Upgrade {
        Upgrade {
            name: name.into(),
            current_version: "0.0.0".into(),
            target_version: version.into(),
            clears: "1/1".into(),
        }
    }

    #[test]
    fn npm_install_all_is_atomic_single_invocation() {
        let cmd = PackageManager::Npm.install_all_cmd(&[
            upg("axios", "1.15.2"),
            upg("lodash", "4.18.0"),
        ]);
        assert_eq!(
            cmd,
            vec![
                "npm",
                "install",
                "axios@^1.15.2",
                "lodash@^4.18.0",
            ]
        );
    }

    #[test]
    fn pnpm_install_all_is_atomic_single_invocation() {
        let cmd = PackageManager::Pnpm.install_all_cmd(&[upg("axios", "1.15.2")]);
        assert_eq!(cmd, vec!["pnpm", "add", "axios@^1.15.2"]);
    }

    #[test]
    fn install_all_handles_empty_upgrades() {
        let cmd = PackageManager::Yarn.install_all_cmd(&[]);
        assert_eq!(cmd, vec!["yarn", "add"]);
        // Caller is responsible for not invoking when empty; this just
        // verifies the function doesn't panic.
    }

    fn upg_with_current(name: &str, current: &str, target: &str) -> Upgrade {
        Upgrade {
            name: name.into(),
            current_version: current.into(),
            target_version: target.into(),
            clears: "1/1".into(),
        }
    }

    #[test]
    fn project_manifest_swaps_exact_version() {
        let manifest = "{\n  \"dependencies\": {\n    \"axios\": \"1.0.0\"\n  }\n}\n";
        let out = project_manifest(manifest, &[upg_with_current("axios", "1.0.0", "1.0.5")]);
        assert!(out.contains("\"^1.0.5\""));
        assert!(!out.contains("\"1.0.0\""));
    }

    #[test]
    fn project_manifest_swaps_caret_range() {
        let manifest = "{\n  \"dependencies\": {\n    \"axios\": \"^1.0.0\"\n  }\n}\n";
        let out = project_manifest(manifest, &[upg_with_current("axios", "1.0.0", "1.0.5")]);
        assert!(out.contains("\"^1.0.5\""));
        assert!(!out.contains("\"^1.0.0\""));
    }

    #[test]
    fn project_manifest_leaves_unrelated_lines_alone() {
        let manifest = "{\n  \"name\": \"foo\",\n  \"dependencies\": {\n    \"axios\": \"1.0.0\",\n    \"lodash\": \"4.17.20\"\n  }\n}\n";
        let out = project_manifest(manifest, &[upg_with_current("axios", "1.0.0", "1.0.5")]);
        assert!(out.contains("\"^1.0.5\""));
        assert!(out.contains("\"4.17.20\""));
        assert!(out.contains("\"name\": \"foo\""));
    }
}

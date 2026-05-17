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
use guardep_core::ecosystem::Ecosystem;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PackageManager {
    Npm,
    Pnpm,
    Yarn,
    Cargo,
    Maven,
}

impl PackageManager {
    /// Detect the package manager that owns the upgrade. Order matters:
    /// for an Npm upgrade we prefer pnpm > yarn > npm based on which
    /// lockfile is present. Cargo/Maven map 1:1 to their ecosystem.
    /// PyPI maps to Maven's manual-only path for now — there's no pip
    /// resolver in guardep yet, but if a finding ever leaks into the
    /// fix planner we'd rather print "manual review" than spawn the
    /// wrong tool.
    fn for_upgrade(upg: &Upgrade, project_root: &Path) -> Self {
        match upg.ecosystem {
            Ecosystem::Cargo => Self::Cargo,
            Ecosystem::Maven | Ecosystem::PyPI => Self::Maven,
            Ecosystem::Npm => {
                if project_root.join("pnpm-lock.yaml").exists() {
                    Self::Pnpm
                } else if project_root.join("yarn.lock").exists() {
                    Self::Yarn
                } else {
                    Self::Npm
                }
            }
        }
    }

    /// True iff `guardep fix --apply` can drive this PM end-to-end.
    /// Cargo: yes (`cargo update -p X --precise V`). Maven: no — there's
    /// no surgical "bump this transitive" CLI; users must add an
    /// explicit override. Returning false here makes apply skip the
    /// group and print manual guidance instead of running a wrong cmd.
    fn supports_apply(self) -> bool {
        !matches!(self, Self::Maven)
    }

    /// Build a single install command that applies every upgrade in
    /// the group in one transaction. npm/pnpm/yarn/cargo all accept
    /// multiple specs in one invocation. Either all bumps land or the
    /// package manager fails atomically — no half-applied state, no
    /// divergent lockfile.
    fn install_all_cmd(self, upgrades: &[Upgrade]) -> Vec<String> {
        match self {
            Self::Npm | Self::Pnpm | Self::Yarn => {
                let specs: Vec<String> = upgrades
                    .iter()
                    .map(|u| format!("{}@^{}", u.name, u.target_version))
                    .collect();
                let (bin, sub) = match self {
                    Self::Npm => ("npm", "install"),
                    Self::Pnpm => ("pnpm", "add"),
                    Self::Yarn => ("yarn", "add"),
                    _ => unreachable!(),
                };
                let mut cmd = vec![bin.to_string(), sub.to_string()];
                cmd.extend(specs);
                cmd
            }
            Self::Cargo => {
                // `cargo update --package X --precise V` pins exactly
                // one transitive in the lockfile without touching
                // Cargo.toml. Multiple `-p X --precise V` pairs work
                // in one invocation and resolve atomically.
                let mut cmd = vec!["cargo".to_string(), "update".to_string()];
                for u in upgrades {
                    cmd.push("--package".into());
                    cmd.push(u.name.clone());
                    cmd.push("--precise".into());
                    cmd.push(u.target_version.clone());
                }
                cmd
            }
            Self::Maven => {
                // Not invokable — gated by `supports_apply()`. Returned
                // so callers that misuse this path get a clear panic in
                // debug rather than silently spawning an empty cmd.
                vec!["mvn".into(), "--unsupported".into()]
            }
        }
    }
}

pub async fn run(path: &Path, target: FixTarget, apply: bool, yes: bool) -> Result<()> {
    // Fix planning needs every actionable finding regardless of CLI
    // display preference, so override threshold to Low (default minus
    // Info-only signals like single-maintainer-alone, which carry no
    // version-bump remedy anyway).
    let report = audit::evaluate_project(path, guardep_core::FindingSeverity::Low, None).await?;
    let mut plan = build_plan(&report, target);
    // Constraint-aware preflight: ask cargo whether each proposed
    // Cargo upgrade fits the workspace's manifest constraints. Any
    // rejection (e.g. `sigstore = "^0.13"` blocking tough@0.22.0)
    // gets demoted from `upgrades` to `breaking` with the upstream
    // diagnostic attached. Best-effort: missing cargo or IO errors
    // leave the plan unchanged.
    cargo_preflight(path, &mut plan);
    print_plan(&plan, target);

    if apply {
        if plan.upgrades.is_empty() {
            eprintln!("{} nothing to apply.", "i".cyan());
            return Ok(());
        }
        // Group upgrades by their target package manager. A single
        // project can only realistically yield one PM today (a Cargo
        // project's findings are all Ecosystem::Cargo) but the
        // grouping keeps the contract honest: each PM gets exactly
        // one atomic invocation, in a stable order.
        let mut by_pm: BTreeMap<PackageManager, Vec<Upgrade>> = BTreeMap::new();
        for u in &plan.upgrades {
            by_pm
                .entry(PackageManager::for_upgrade(u, path))
                .or_default()
                .push(u.clone());
        }

        // Show the npm-style manifest diff only when we're about to
        // touch package.json. Cargo apply only edits Cargo.lock.
        if !yes && by_pm.contains_key(&PackageManager::Npm) {
            print_manifest_diff(path, &plan.upgrades);
        }

        // Confirmation: --apply without --yes asks before any mutation.
        // CI users opt out via --yes.
        if !yes && !confirm_multi(&by_pm)? {
            eprintln!("{} aborted by user.", "i".cyan());
            return Ok(());
        }

        for (pm, upgrades) in &by_pm {
            if !pm.supports_apply() {
                eprintln!(
                    "\n{} {} upgrade(s) need manual review for {:?} — \
                     no surgical bump CLI exists",
                    "!".yellow(),
                    upgrades.len(),
                    pm
                );
                for u in upgrades {
                    eprintln!(
                        "  {} {} -> {}  (add an explicit override in pom.xml \
                         <dependencyManagement>, or run `mvn versions:use-dep-version \
                         -Dincludes={}` if you have versions-maven-plugin configured)",
                        u.name.bold(),
                        u.current_version.dimmed(),
                        u.target_version.green(),
                        u.name,
                    );
                }
                continue;
            }
            eprintln!(
                "\n{} applying {} upgrade(s) atomically via {:?}",
                ">".cyan(),
                upgrades.len(),
                pm
            );
            // Single invocation per PM. Either every spec lands or the
            // package manager fails atomically and the lockfile is
            // unchanged. No half-applied state to recover from.
            let cmd = pm.install_all_cmd(upgrades);
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

fn confirm_multi(by_pm: &BTreeMap<PackageManager, Vec<Upgrade>>) -> Result<bool> {
    use std::io::{self, BufRead, Write};
    let summary: Vec<String> = by_pm
        .iter()
        .map(|(pm, ups)| format!("{} via {:?}", ups.len(), pm))
        .collect();
    eprint!(
        "\n{} apply {}? This will modify lockfile(s) (and package.json for npm/pnpm/yarn). [y/N] ",
        "?".yellow().bold(),
        summary.join(" + "),
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
    pub ecosystem: Ecosystem,
    pub name: String,
    pub current_version: String,
    pub target_version: String,
    /// `n / total` findings cleared at this target.
    pub clears: String,
    /// Populated when the upgrade was demoted from `upgrades` to
    /// `breaking` by a constraint-aware preflight (e.g. a Cargo
    /// downstream pin that refuses the target version). Carries the
    /// upstream tool's diagnostic verbatim so the user sees the same
    /// reason cargo / npm / mvn would print.
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ManualItem {
    pub name: String,
    pub version: String,
    pub kind: FindingKind,
    pub summary: String,
}

fn build_plan(report: &FindingsReport, target: FixTarget) -> Plan {
    // Key is (ecosystem, name, version) so a Cargo `foo` never merges
    // with an Npm `foo` — they have separate fix targets and separate
    // package managers driving the apply.
    let mut by_package: BTreeMap<(Ecosystem, String, String), Vec<&ScoredFinding>> =
        BTreeMap::new();
    let mut manual: Vec<ManualItem> = Vec::new();

    for s in &report.items {
        // Skip Info-tier rows — they aren't actionable.
        if s.finding.severity == FindingSeverity::Info {
            continue;
        }
        match s.finding.kind {
            FindingKind::Vulnerability | FindingKind::Malware => {
                by_package
                    .entry((
                        s.finding.package.ecosystem,
                        s.finding.package.name.clone(),
                        s.finding.package.version.clone(),
                    ))
                    .or_default()
                    .push(s);
            }
            // No version-bump remedy — surface as manual to-do.
            FindingKind::PostinstallScript
            | FindingKind::RiskScore
            | FindingKind::MissingProvenance
            | FindingKind::ProvenanceMismatch
            | FindingKind::SourceBehavior
            | FindingKind::License => {
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

    for ((ecosystem, name, current), items) in by_package {
        let targets = fix_targets(&items);
        let chosen = match target {
            FixTarget::Min => targets.min.clone(),
            FixTarget::Safe => targets.safe.clone().or_else(|| targets.min.clone()),
        };
        let Some(target_version) = chosen else {
            // No in-major fix available; check for cross-major fallback.
            if let Some(v) = targets.cross_major_fallback.clone() {
                breaking.push(Upgrade {
                    ecosystem,
                    name,
                    current_version: current,
                    target_version: v,
                    clears: "breaking".into(),
                    note: None,
                });
            }
            continue;
        };
        let clears = match target {
            FixTarget::Min => format!("{}/{}", targets.cleared_at_min, targets.total),
            FixTarget::Safe => format!("{}/{}", targets.total, targets.total),
        };
        let upg = Upgrade {
            ecosystem,
            name,
            current_version: current,
            target_version,
            clears,
            note: None,
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
            "\n{} {} breaking upgrade(s) — manual intervention required:",
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
            if let Some(note) = &u.note {
                // Preflight-rejected: print the upstream tool's exact
                // constraint diagnostic so the user knows *why* this
                // bump isn't reachable (e.g. "sigstore = '^0.13'
                // requires tough = '^0.21'"). Indented to read as a
                // subordinate hint, not its own line item.
                println!("      {} {}", "↳".dimmed(), note.dimmed());
            }
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
        FindingKind::SourceBehavior => "source behavior",
        FindingKind::License => "license",
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

/// Ask cargo whether each proposed Cargo upgrade actually fits the
/// workspace's manifest constraints. Anything cargo refuses moves
/// from `plan.upgrades` to `plan.breaking` with the rejection message
/// attached as `note`. No-op when there are no Cargo upgrades or when
/// cargo isn't on PATH; failures are non-fatal — at worst the user
/// sees the same constraint error at `--apply` time instead of in the
/// plan.
fn cargo_preflight(project_root: &Path, plan: &mut Plan) {
    let cargo_count = plan
        .upgrades
        .iter()
        .filter(|u| u.ecosystem == Ecosystem::Cargo)
        .count();
    if cargo_count == 0 {
        return;
    }
    if !project_root.join("Cargo.toml").exists() {
        return;
    }

    // Test each Cargo candidate in isolation via
    // `cargo update -p X --precise V --dry-run`. We use --dry-run so
    // the user's real lockfile is never touched. Per-upgrade rather
    // than batched because a single rejection in a batched call would
    // taint the whole pass and we want one diagnostic per candidate.
    apply_preflight_outcomes(plan, |upg| {
        cargo_dry_run_precise(project_root, &upg.name, &upg.target_version)
    });
}

/// Apply per-upgrade preflight outcomes to a plan. Extracted so the
/// demotion logic is unit-testable without shelling out to cargo.
fn apply_preflight_outcomes<F>(plan: &mut Plan, mut check: F)
where
    F: FnMut(&Upgrade) -> PreflightOutcome,
{
    let mut accepted: Vec<Upgrade> = Vec::with_capacity(plan.upgrades.len());
    let mut newly_breaking: Vec<Upgrade> = Vec::new();
    let original = std::mem::take(&mut plan.upgrades);

    for upg in original {
        if upg.ecosystem != Ecosystem::Cargo {
            accepted.push(upg);
            continue;
        }
        match check(&upg) {
            PreflightOutcome::Accepted | PreflightOutcome::Unknown => accepted.push(upg),
            PreflightOutcome::Rejected(reason) => {
                let mut demoted = upg;
                demoted.clears = "breaking".into();
                demoted.note = Some(reason);
                newly_breaking.push(demoted);
            }
        }
    }

    plan.upgrades = accepted;
    plan.breaking.extend(newly_breaking);
}

enum PreflightOutcome {
    Accepted,
    /// Cargo refused the bump; payload is the upstream stderr excerpt.
    Rejected(String),
    /// Couldn't reach a verdict (cargo missing, IO error, etc.).
    /// Treated as Accepted upstream — fail-open at plan time.
    Unknown,
}

fn cargo_dry_run_precise(project_root: &Path, name: &str, version: &str) -> PreflightOutcome {
    // Scrub `~/.guardep/bin` from PATH so we don't re-enter our own
    // shim during the preflight — that would just call us back and
    // produce shim diagnostics instead of cargo's constraint chain.
    let output = Command::new("cargo")
        .arg("update")
        .arg("--package")
        .arg(name)
        .arg("--precise")
        .arg(version)
        .arg("--dry-run")
        .current_dir(project_root)
        .env("PATH", guardep_core::resolver::scrub_shim_from_path())
        .output();
    let output = match output {
        Ok(o) => o,
        Err(_) => return PreflightOutcome::Unknown,
    };
    if output.status.success() {
        return PreflightOutcome::Accepted;
    }
    // Cargo prints the constraint chain to stderr. Trim hard so the
    // plan stays readable; the full message is still available at
    // apply time.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let reason = stderr
        .lines()
        .filter(|l| !l.trim().is_empty())
        .take(3)
        .collect::<Vec<_>>()
        .join(" | ");
    if reason.is_empty() {
        PreflightOutcome::Unknown
    } else {
        PreflightOutcome::Rejected(reason)
    }
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
            ecosystem: Ecosystem::Npm,
            name: name.into(),
            current_version: "0.0.0".into(),
            target_version: version.into(),
            clears: "1/1".into(),
            note: None,
        }
    }

    fn upg_eco(eco: Ecosystem, name: &str, current: &str, target: &str) -> Upgrade {
        Upgrade {
            ecosystem: eco,
            name: name.into(),
            current_version: current.into(),
            target_version: target.into(),
            clears: "1/1".into(),
            note: None,
        }
    }

    #[test]
    fn npm_install_all_is_atomic_single_invocation() {
        let cmd =
            PackageManager::Npm.install_all_cmd(&[upg("axios", "1.15.2"), upg("lodash", "4.18.0")]);
        assert_eq!(
            cmd,
            vec!["npm", "install", "axios@^1.15.2", "lodash@^4.18.0",]
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

    #[test]
    fn cargo_apply_uses_update_precise_per_package() {
        let cmd = PackageManager::Cargo.install_all_cmd(&[
            upg_eco(Ecosystem::Cargo, "tough", "0.21.0", "0.22.0"),
            upg_eco(Ecosystem::Cargo, "rsa", "0.9.10", "0.9.11"),
        ]);
        assert_eq!(
            cmd,
            vec![
                "cargo",
                "update",
                "--package",
                "tough",
                "--precise",
                "0.22.0",
                "--package",
                "rsa",
                "--precise",
                "0.9.11",
            ]
        );
    }

    #[test]
    fn cargo_upgrade_routes_to_cargo_pm() {
        let upg = upg_eco(Ecosystem::Cargo, "tough", "0.21.0", "0.22.0");
        let pm = PackageManager::for_upgrade(&upg, std::path::Path::new("/tmp/does-not-exist"));
        assert_eq!(pm, PackageManager::Cargo);
    }

    #[test]
    fn maven_upgrade_routes_to_maven_pm_and_is_not_appliable() {
        let upg = upg_eco(
            Ecosystem::Maven,
            "org.apache.commons:commons-text",
            "1.9",
            "1.10.0",
        );
        let pm = PackageManager::for_upgrade(&upg, std::path::Path::new("/tmp/does-not-exist"));
        assert_eq!(pm, PackageManager::Maven);
        assert!(
            !pm.supports_apply(),
            "Maven has no surgical bump CLI; apply should refuse"
        );
    }

    #[test]
    fn npm_upgrade_prefers_pnpm_when_pnpm_lock_present() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("pnpm-lock.yaml"), "").unwrap();
        let upg = upg("axios", "1.15.2");
        assert_eq!(
            PackageManager::for_upgrade(&upg, dir.path()),
            PackageManager::Pnpm
        );
    }

    fn upg_with_current(name: &str, current: &str, target: &str) -> Upgrade {
        Upgrade {
            ecosystem: Ecosystem::Npm,
            name: name.into(),
            current_version: current.into(),
            target_version: target.into(),
            clears: "1/1".into(),
            note: None,
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

    fn plan_with(upgrades: Vec<Upgrade>) -> Plan {
        Plan {
            upgrades,
            manual: Vec::new(),
            breaking: Vec::new(),
        }
    }

    #[test]
    fn preflight_rejected_cargo_upgrade_moves_to_breaking_with_note() {
        let mut plan = plan_with(vec![upg_eco(Ecosystem::Cargo, "tough", "0.21.0", "0.22.0")]);
        apply_preflight_outcomes(&mut plan, |_| {
            PreflightOutcome::Rejected("required by sigstore = \"^0.13\"".into())
        });
        assert!(
            plan.upgrades.is_empty(),
            "rejected upgrade must leave the upgrades list"
        );
        assert_eq!(plan.breaking.len(), 1);
        assert_eq!(plan.breaking[0].name, "tough");
        assert_eq!(plan.breaking[0].clears, "breaking");
        assert_eq!(
            plan.breaking[0].note.as_deref(),
            Some("required by sigstore = \"^0.13\"")
        );
    }

    #[test]
    fn preflight_accepted_cargo_upgrade_stays_in_upgrades() {
        let mut plan = plan_with(vec![upg_eco(Ecosystem::Cargo, "tough", "0.21.0", "0.22.0")]);
        apply_preflight_outcomes(&mut plan, |_| PreflightOutcome::Accepted);
        assert_eq!(plan.upgrades.len(), 1);
        assert!(plan.breaking.is_empty());
        assert!(plan.upgrades[0].note.is_none());
    }

    #[test]
    fn preflight_unknown_outcome_is_fail_open() {
        // Cargo not on PATH / IO error: we keep the upgrade in
        // `upgrades` rather than silently dropping it. Worst case the
        // user sees the same error at `--apply` time.
        let mut plan = plan_with(vec![upg_eco(Ecosystem::Cargo, "tough", "0.21.0", "0.22.0")]);
        apply_preflight_outcomes(&mut plan, |_| PreflightOutcome::Unknown);
        assert_eq!(plan.upgrades.len(), 1);
        assert!(plan.breaking.is_empty());
    }

    #[test]
    fn preflight_skips_non_cargo_upgrades() {
        // Npm upgrades must pass through untouched even if the
        // checker would have rejected them — the cargo preflight is
        // not authoritative for other ecosystems.
        let mut plan = plan_with(vec![
            upg_eco(Ecosystem::Npm, "axios", "1.0.0", "1.0.5"),
            upg_eco(Ecosystem::Cargo, "tough", "0.21.0", "0.22.0"),
        ]);
        let mut calls = 0usize;
        apply_preflight_outcomes(&mut plan, |upg| {
            calls += 1;
            assert_eq!(upg.ecosystem, Ecosystem::Cargo);
            PreflightOutcome::Accepted
        });
        assert_eq!(calls, 1, "checker must only see Cargo upgrades");
        assert_eq!(plan.upgrades.len(), 2);
        assert!(plan.breaking.is_empty());
    }

    #[test]
    fn kind_label_covers_every_finding_kind() {
        // Pin the label-mapping so renderer output doesn't drift
        // silently when a new FindingKind variant is added.
        assert_eq!(
            kind_label(FindingKind::PostinstallScript),
            "postinstall script"
        );
        assert_eq!(kind_label(FindingKind::RiskScore), "risk score");
        assert_eq!(
            kind_label(FindingKind::MissingProvenance),
            "missing provenance"
        );
        assert_eq!(
            kind_label(FindingKind::ProvenanceMismatch),
            "provenance mismatch"
        );
        assert_eq!(kind_label(FindingKind::Malware), "advisory");
        assert_eq!(kind_label(FindingKind::Vulnerability), "advisory");
        assert_eq!(kind_label(FindingKind::SourceBehavior), "source behavior");
        assert_eq!(kind_label(FindingKind::License), "license");
    }

    #[test]
    fn for_upgrade_picks_pnpm_when_pnpm_lock_present() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("pnpm-lock.yaml"), b"").unwrap();
        let upg = upg_eco(Ecosystem::Npm, "axios", "1.0.0", "1.0.5");
        assert_eq!(
            PackageManager::for_upgrade(&upg, dir.path()),
            PackageManager::Pnpm
        );
    }

    #[test]
    fn for_upgrade_picks_yarn_when_yarn_lock_present() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("yarn.lock"), b"").unwrap();
        let upg = upg_eco(Ecosystem::Npm, "axios", "1.0.0", "1.0.5");
        assert_eq!(
            PackageManager::for_upgrade(&upg, dir.path()),
            PackageManager::Yarn
        );
    }

    #[test]
    fn for_upgrade_npm_defaults_to_npm() {
        // No pnpm/yarn lockfile in cwd; default falls through to npm
        // regardless of whether package-lock.json is present.
        let dir = tempfile::TempDir::new().unwrap();
        let upg = upg_eco(Ecosystem::Npm, "axios", "1.0.0", "1.0.5");
        assert_eq!(
            PackageManager::for_upgrade(&upg, dir.path()),
            PackageManager::Npm
        );
        std::fs::write(dir.path().join("package-lock.json"), b"").unwrap();
        assert_eq!(
            PackageManager::for_upgrade(&upg, dir.path()),
            PackageManager::Npm
        );
    }

    #[test]
    fn for_upgrade_pnpm_beats_yarn_when_both_lockfiles_present() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("pnpm-lock.yaml"), b"").unwrap();
        std::fs::write(dir.path().join("yarn.lock"), b"").unwrap();
        let upg = upg_eco(Ecosystem::Npm, "axios", "1.0.0", "1.0.5");
        assert_eq!(
            PackageManager::for_upgrade(&upg, dir.path()),
            PackageManager::Pnpm
        );
    }

    #[test]
    fn for_upgrade_cargo_maps_to_cargo() {
        let dir = tempfile::TempDir::new().unwrap();
        let upg = upg_eco(Ecosystem::Cargo, "tough", "0.21.0", "0.22.0");
        assert_eq!(
            PackageManager::for_upgrade(&upg, dir.path()),
            PackageManager::Cargo
        );
    }

    #[test]
    fn print_plan_with_empty_plan_does_not_panic() {
        // Empty plan: should print "no in-major upgrades available"
        // without touching the breaking or manual buckets.
        let plan = Plan {
            upgrades: vec![],
            manual: vec![],
            breaking: vec![],
        };
        print_plan(&plan, FixTarget::Safe);
        print_plan(&plan, FixTarget::Min);
    }

    #[test]
    fn print_plan_with_breaking_and_manual_does_not_panic() {
        let plan = Plan {
            upgrades: vec![Upgrade {
                ecosystem: Ecosystem::Npm,
                name: "axios".into(),
                current_version: "1.0.0".into(),
                target_version: "1.0.5".into(),
                clears: "1/1".into(),
                note: None,
            }],
            manual: vec![
                ManualItem {
                    name: "evil".into(),
                    version: "1.0.0".into(),
                    kind: FindingKind::PostinstallScript,
                    summary: "exfil".into(),
                },
                ManualItem {
                    name: "risky".into(),
                    version: "2.0.0".into(),
                    kind: FindingKind::RiskScore,
                    summary: "fresh publish".into(),
                },
            ],
            breaking: vec![Upgrade {
                ecosystem: Ecosystem::Npm,
                name: "tar".into(),
                current_version: "6.2.1".into(),
                target_version: "7.5.4".into(),
                clears: "1/1".into(),
                note: None,
            }],
        };
        print_plan(&plan, FixTarget::Safe);
    }
}

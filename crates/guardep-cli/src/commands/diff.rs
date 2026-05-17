//! `guardep diff` — PR-aware audit diff.
//!
//! Runs `evaluate_project_with_pkgs` against two project roots, then
//! reports only the findings present in `head` that were NOT in `base`.
//! Designed to slot into PR CI: clone the merge-base into a worktree,
//! point `--base` at it and `--head` at the working tree.
//!
//! Identity is `(package, version, kind, id)`. Findings whose
//! `pkg@version` already existed in base AND match the same finding ID
//! are filtered out; truly new findings (new pkg, new version of an
//! existing pkg, or new finding id on a previously-clean pkg) come
//! through.

use crate::commands::audit::{evaluate_project_with_pkgs, FailOn, Format};
use crate::sbom;
use anyhow::Result;
use guardep_core::{ecosystem::PackageRef, Finding, FindingSeverity, FindingsReport};
use owo_colors::OwoColorize;
use std::collections::HashSet;
use std::path::Path;

pub async fn run(
    base: &Path,
    head: &Path,
    format: Format,
    min_severity: FindingSeverity,
    fail_on: FailOn,
    granular: bool,
) -> Result<()> {
    eprintln!(
        "{} diffing {} → {}",
        ">".cyan(),
        base.display(),
        head.display()
    );

    let (base_pkgs, base_report) =
        evaluate_project_with_pkgs(base, min_severity, None, granular).await?;
    let (head_pkgs, head_report) =
        evaluate_project_with_pkgs(head, min_severity, None, granular).await?;

    let new_findings = findings_only_in_head(&base_report, &head_report);

    // Build a fresh report from just the new findings so the renderer
    // / SBOM emitter can use the same code path as `audit`.
    let policy = guardep_core::policy::Policy::default();
    let new_report = FindingsReport::from_findings(new_findings.clone(), &policy);

    eprintln!(
        "{} base={} pkgs / {} findings   head={} pkgs / {} findings   new={} findings",
        ">".cyan(),
        base_pkgs.len(),
        base_report.deduped().len(),
        head_pkgs.len(),
        head_report.deduped().len(),
        new_findings.len(),
    );

    match format {
        Format::Table => crate::report::print_verdict(&new_report, false),
        Format::Json => crate::report::print_json(&new_report, false)?,
        Format::CycloneDx => sbom::print_cyclonedx(&head_pkgs, &new_report)?,
        Format::Sarif => crate::sarif::print_sarif(&new_report)?,
    }

    let exit_code = crate::commands::audit::compute_exit_code(fail_on, &new_report);
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct FindingKey {
    pkg: String,
    version: String,
    kind: &'static str,
    id: String,
}

fn key_for(f: &Finding) -> FindingKey {
    FindingKey {
        pkg: f.package.name.clone(),
        version: f.package.version.clone(),
        kind: f.kind.as_str(),
        id: f.id.clone(),
    }
}

/// Return the deduped findings present in `head` but not in `base`.
/// Pulled out of `run` so the diff semantics are testable without
/// running the evaluator pipeline twice. Identity is the `FindingKey`
/// tuple `(pkg, version, kind, id)`.
fn findings_only_in_head(base: &FindingsReport, head: &FindingsReport) -> Vec<Finding> {
    let base_keys: HashSet<FindingKey> =
        base.deduped().iter().map(|s| key_for(&s.finding)).collect();
    head.deduped()
        .iter()
        .filter(|s| !base_keys.contains(&key_for(&s.finding)))
        .map(|s| s.finding.clone())
        .collect()
}

#[allow(dead_code)]
fn unused_marker(_pkgs: &[PackageRef]) {}

#[cfg(test)]
mod tests {
    use super::*;
    use guardep_core::{
        ecosystem::{Ecosystem, PackageRef as Pkg},
        finding::FindingKind,
    };

    fn finding(name: &str, version: &str, kind: FindingKind, id: &str) -> Finding {
        Finding {
            package: Pkg::new(Ecosystem::Npm, name, version),
            kind,
            id: id.into(),
            aliases: vec![],
            summary: String::new(),
            severity: FindingSeverity::Medium,
            fixed_versions: vec![],
            references: vec![],
            details: serde_json::Value::Null,
        }
    }

    #[test]
    fn key_distinguishes_by_package_name() {
        let a = key_for(&finding(
            "lodash",
            "4.17.20",
            FindingKind::Vulnerability,
            "GHSA-1",
        ));
        let b = key_for(&finding(
            "axios",
            "4.17.20",
            FindingKind::Vulnerability,
            "GHSA-1",
        ));
        assert_ne!(a, b);
    }

    #[test]
    fn key_distinguishes_by_version() {
        let a = key_for(&finding(
            "lodash",
            "4.17.20",
            FindingKind::Vulnerability,
            "GHSA-1",
        ));
        let b = key_for(&finding(
            "lodash",
            "4.17.21",
            FindingKind::Vulnerability,
            "GHSA-1",
        ));
        assert_ne!(a, b);
    }

    #[test]
    fn key_distinguishes_by_kind() {
        let a = key_for(&finding(
            "lodash",
            "4.17.20",
            FindingKind::Vulnerability,
            "X",
        ));
        let b = key_for(&finding("lodash", "4.17.20", FindingKind::Malware, "X"));
        assert_ne!(a, b);
    }

    #[test]
    fn key_distinguishes_by_id() {
        let a = key_for(&finding(
            "lodash",
            "4.17.20",
            FindingKind::Vulnerability,
            "GHSA-1",
        ));
        let b = key_for(&finding(
            "lodash",
            "4.17.20",
            FindingKind::Vulnerability,
            "GHSA-2",
        ));
        assert_ne!(a, b);
    }

    #[test]
    fn key_is_equal_for_identical_inputs() {
        let a = key_for(&finding(
            "lodash",
            "4.17.20",
            FindingKind::Vulnerability,
            "GHSA-1",
        ));
        let b = key_for(&finding(
            "lodash",
            "4.17.20",
            FindingKind::Vulnerability,
            "GHSA-1",
        ));
        assert_eq!(a, b);
    }

    #[test]
    fn key_works_as_hashset_member() {
        // Round-trip through a HashSet to confirm hash + eq agree;
        // this is exactly how `run` filters base findings out of head.
        let f = finding("lodash", "4.17.20", FindingKind::Vulnerability, "GHSA-1");
        let mut set: HashSet<FindingKey> = HashSet::new();
        set.insert(key_for(&f));
        assert!(set.contains(&key_for(&f)));

        let other = finding("axios", "1.0.0", FindingKind::Vulnerability, "GHSA-9");
        assert!(!set.contains(&key_for(&other)));
    }

    fn report_of(findings: Vec<Finding>) -> FindingsReport {
        let policy = guardep_core::policy::Policy::default();
        FindingsReport::from_findings(findings, &policy)
    }

    #[test]
    fn diff_returns_empty_when_base_and_head_match() {
        let f = finding("lodash", "4.17.20", FindingKind::Vulnerability, "GHSA-1");
        let base = report_of(vec![f.clone()]);
        let head = report_of(vec![f]);
        assert!(findings_only_in_head(&base, &head).is_empty());
    }

    #[test]
    fn diff_surfaces_new_findings_added_in_head() {
        let shared = finding("lodash", "4.17.20", FindingKind::Vulnerability, "GHSA-1");
        let added = finding("axios", "1.0.0", FindingKind::Vulnerability, "GHSA-9");

        let base = report_of(vec![shared.clone()]);
        let head = report_of(vec![shared, added.clone()]);

        let new = findings_only_in_head(&base, &head);
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].id, added.id);
    }

    #[test]
    fn diff_treats_version_bump_as_new() {
        let v1 = finding("lodash", "4.17.20", FindingKind::Vulnerability, "GHSA-1");
        let v2 = finding("lodash", "4.17.21", FindingKind::Vulnerability, "GHSA-1");
        let base = report_of(vec![v1]);
        let head = report_of(vec![v2.clone()]);

        let new = findings_only_in_head(&base, &head);
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].package.version, "4.17.21");
    }

    #[test]
    fn diff_drops_findings_removed_in_head() {
        // A finding that base has but head doesn't is not "new" — diff
        // is one-sided. (Removed findings would surface in a reverse
        // diff; here they should be silently dropped.)
        let removed = finding("lodash", "4.17.20", FindingKind::Vulnerability, "GHSA-1");
        let base = report_of(vec![removed]);
        let head = report_of(vec![]);
        assert!(findings_only_in_head(&base, &head).is_empty());
    }

    #[test]
    fn diff_against_empty_base_returns_all_head_findings() {
        let a = finding("axios", "1.0.0", FindingKind::Vulnerability, "GHSA-9");
        let b = finding("lodash", "4.17.20", FindingKind::Vulnerability, "GHSA-1");
        let base = report_of(vec![]);
        let head = report_of(vec![a, b]);
        assert_eq!(findings_only_in_head(&base, &head).len(), 2);
    }
}

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

    let base_keys: HashSet<FindingKey> = base_report
        .deduped()
        .iter()
        .map(|s| key_for(&s.finding))
        .collect();

    let new_findings: Vec<Finding> = head_report
        .deduped()
        .iter()
        .filter(|s| !base_keys.contains(&key_for(&s.finding)))
        .map(|s| s.finding.clone())
        .collect();

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

    let exit_code = match fail_on {
        FailOn::Never => 0,
        FailOn::Warn if new_report.should_block() => 2,
        FailOn::Warn if new_report.has_warnings() => 1,
        FailOn::Warn => 0,
        FailOn::Block if new_report.should_block() => 2,
        FailOn::Block => 0,
    };
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

#[derive(Hash, Eq, PartialEq, Clone)]
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

#[allow(dead_code)]
fn unused_marker(_pkgs: &[PackageRef]) {}

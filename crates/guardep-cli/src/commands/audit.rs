use anyhow::Result;
use guardep_core::{
    ecosystem::PackageRef,
    evaluator::EvaluatorRegistry,
    intel::IntelEvaluator,
    license::LicenseEvaluator,
    osv_evaluator::OsvEvaluator,
    policy::Policy,
    postinstall::PostinstallEvaluator,
    provenance::ProvenanceEvaluator,
    resolver::{auto_resolve, resolve_with},
    source_scan_evaluator::SourceScanEvaluator,
    FindingSeverity, FindingsReport,
};
use owo_colors::OwoColorize;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Table,
    Json,
    CycloneDx,
    Sarif,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailOn {
    Never,
    Warn,
    Block,
}

pub async fn run(
    path: &Path,
    format: Format,
    collapse: bool,
    min_severity: FindingSeverity,
    fail_on: FailOn,
    lockfile: Option<&str>,
    granular: bool,
) -> Result<()> {
    let (packages, report) =
        evaluate_project_with_pkgs(path, min_severity, lockfile, granular).await?;
    match format {
        Format::Table => crate::report::print_verdict(&report, collapse),
        Format::Json => crate::report::print_json(&report, collapse)?,
        Format::CycloneDx => crate::sbom::print_cyclonedx(&packages, &report)?,
        Format::Sarif => crate::sarif::print_sarif(&report)?,
    }
    let exit_code = compute_exit_code(fail_on, &report);
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

/// Translate `(fail_on, report)` into a Unix exit code. Pulled out of
/// `run` so the policy can be tested without spawning a process or
/// running the full evaluator stack. Same shape used by
/// `commands::diff::run`.
pub(crate) fn compute_exit_code(fail_on: FailOn, report: &FindingsReport) -> i32 {
    match fail_on {
        FailOn::Never => 0,
        FailOn::Warn if report.should_block() => 2,
        FailOn::Warn if report.has_warnings() => 1,
        FailOn::Warn => 0,
        FailOn::Block if report.should_block() => 2,
        FailOn::Block => 0,
    }
}

pub async fn evaluate_project(
    path: &Path,
    min_severity: FindingSeverity,
    lockfile: Option<&str>,
) -> Result<FindingsReport> {
    let (_, report) = evaluate_project_with_pkgs(path, min_severity, lockfile, false).await?;
    Ok(report)
}

/// Variant that returns the resolved package list alongside the report
/// so callers (CycloneDX export, SARIF, diff) can include the full
/// dependency graph, not just findings. `granular` opts source-behavior
/// findings into per-call-site emission.
pub async fn evaluate_project_with_pkgs(
    path: &Path,
    min_severity: FindingSeverity,
    lockfile: Option<&str>,
    granular: bool,
) -> Result<(Vec<PackageRef>, FindingsReport)> {
    let (packages, lockfile_kind) = match lockfile {
        Some(name) => (resolve_with(path, name)?, name),
        None => {
            let (pkgs, name) = auto_resolve(path)?;
            (pkgs, name)
        }
    };
    eprintln!(
        "{} resolved {} packages from {}",
        ">".cyan(),
        packages.len(),
        lockfile_kind
    );
    let report = evaluate_packages(path, packages.clone(), min_severity, granular).await?;
    Ok((packages, report))
}

pub async fn evaluate_packages(
    path: &Path,
    packages: Vec<PackageRef>,
    min_severity: FindingSeverity,
    granular: bool,
) -> Result<FindingsReport> {
    let dirs = directories::ProjectDirs::from("dev", "guardep", "guardep")
        .ok_or_else(|| anyhow::anyhow!("could not determine cache dir"))?;
    let cache_dir = dirs.cache_dir().to_path_buf();
    std::fs::create_dir_all(&cache_dir).ok();
    evaluate_packages_in(path, &cache_dir, packages, min_severity, granular).await
}

/// Variant taking an explicit cache directory so tests can isolate
/// evaluator state from the user's real `~/.cache/guardep`. Same wiring
/// as `evaluate_packages` — `evaluate_packages` is just this with the
/// platform default cache dir.
pub async fn evaluate_packages_in(
    path: &Path,
    cache_dir: &Path,
    packages: Vec<PackageRef>,
    min_severity: FindingSeverity,
    granular: bool,
) -> Result<FindingsReport> {
    let mut policy = Policy::load(&path.join("guardep.toml"))?;
    // CLI override: `--severity X` lowers/raises the display threshold
    // independently of `guardep.toml`. Useful for one-off debugging
    // ("show me everything") or strict CI ("only critical+").
    policy.min_display_severity = min_severity;
    // CLI override: `--granular` opts in to per-call-site source-behavior
    // findings without needing a `guardep.toml`.
    if granular {
        policy.source_scan_granular = true;
    }

    std::fs::create_dir_all(cache_dir).ok();
    // Single SQLite file shared by all evaluators (one schema, namespaced rows).
    let cache_db = cache_dir.join("cache.db");
    let mut registry = EvaluatorRegistry::new();
    registry.register(Arc::new(OsvEvaluator::new(cache_db.clone())?));
    registry.register(Arc::new(PostinstallEvaluator::new(path.to_path_buf())));
    registry.register(Arc::new(IntelEvaluator::new(cache_db.clone())?));
    registry.register(Arc::new(ProvenanceEvaluator::new(cache_db.clone())?));
    registry.register(Arc::new(SourceScanEvaluator::new(path.to_path_buf())));
    registry.register(Arc::new(LicenseEvaluator::new(path.to_path_buf())));
    registry.register(Arc::new(
        guardep_core::threat_feed::ThreatFeedEvaluator::new(cache_db)?,
    ));

    eprintln!(
        "{} running evaluators: {}",
        ">".cyan(),
        registry.names().join(", ")
    );

    let findings = registry.run(&packages, &policy).await?;
    Ok(FindingsReport::from_findings(findings, &policy))
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardep_core::{
        ecosystem::{Ecosystem, PackageRef},
        finding::{Finding, FindingKind},
        policy::Action,
        report_data::ScoredFinding,
    };

    fn scored(severity: FindingSeverity, action: Action) -> ScoredFinding {
        let finding = Finding {
            package: PackageRef::new(Ecosystem::Npm, "lodash", "4.17.20"),
            kind: FindingKind::Vulnerability,
            id: "GHSA-xxxx-yyyy-zzzz".into(),
            aliases: vec![],
            summary: "test fixture".into(),
            severity,
            fixed_versions: vec![],
            references: vec![],
            details: serde_json::Value::Null,
        };
        ScoredFinding { finding, action }
    }

    fn report(items: Vec<ScoredFinding>) -> FindingsReport {
        FindingsReport { items }
    }

    #[test]
    fn never_always_returns_zero() {
        let r = report(vec![scored(FindingSeverity::Critical, Action::Block)]);
        assert_eq!(compute_exit_code(FailOn::Never, &r), 0);
        let r = report(vec![scored(FindingSeverity::Medium, Action::Warn)]);
        assert_eq!(compute_exit_code(FailOn::Never, &r), 0);
        assert_eq!(compute_exit_code(FailOn::Never, &report(vec![])), 0);
    }

    #[test]
    fn block_returns_two_only_on_block_action() {
        let blockers = report(vec![scored(FindingSeverity::Critical, Action::Block)]);
        assert_eq!(compute_exit_code(FailOn::Block, &blockers), 2);
        // Warnings under `--fail-on block` do not raise the exit code.
        let warnings = report(vec![scored(FindingSeverity::Medium, Action::Warn)]);
        assert_eq!(compute_exit_code(FailOn::Block, &warnings), 0);
        // Clean report.
        assert_eq!(compute_exit_code(FailOn::Block, &report(vec![])), 0);
    }

    #[test]
    fn warn_returns_one_on_warning_and_two_on_block() {
        let warnings = report(vec![scored(FindingSeverity::Medium, Action::Warn)]);
        assert_eq!(compute_exit_code(FailOn::Warn, &warnings), 1);

        let blockers = report(vec![scored(FindingSeverity::Critical, Action::Block)]);
        assert_eq!(compute_exit_code(FailOn::Warn, &blockers), 2);

        // Mixed: a block dominates a warn.
        let mixed = report(vec![
            scored(FindingSeverity::Medium, Action::Warn),
            scored(FindingSeverity::Critical, Action::Block),
        ]);
        assert_eq!(compute_exit_code(FailOn::Warn, &mixed), 2);

        // Clean report.
        assert_eq!(compute_exit_code(FailOn::Warn, &report(vec![])), 0);
    }

    #[test]
    fn allow_only_findings_never_fail() {
        // `Action::Allow` should not trigger an exit-non-zero under
        // either threshold. Pre-allowlist allowlisted findings live in
        // the report but should not block CI.
        let r = report(vec![scored(FindingSeverity::High, Action::Allow)]);
        assert_eq!(compute_exit_code(FailOn::Warn, &r), 0);
        assert_eq!(compute_exit_code(FailOn::Block, &r), 0);
    }

    /// Empty packages → empty registry run → empty report. Exercises
    /// the evaluator wiring (constructors + names) without any network
    /// or filesystem fixtures beyond a tempdir cache. Most evaluators
    /// short-circuit on an empty package slice, so this is offline-safe.
    #[tokio::test]
    async fn evaluate_packages_in_with_empty_input_yields_empty_report() {
        let project = tempfile::TempDir::new().unwrap();
        let cache = tempfile::TempDir::new().unwrap();
        let report = evaluate_packages_in(
            project.path(),
            cache.path(),
            vec![],
            FindingSeverity::Low,
            false,
        )
        .await
        .expect("empty-package audit should succeed offline");
        assert!(report.items.is_empty());
        // cache.db is created by OsvEvaluator/IntelEvaluator wiring.
        assert!(cache.path().join("cache.db").exists());
    }
}

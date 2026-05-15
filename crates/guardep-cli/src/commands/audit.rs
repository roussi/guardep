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
    let exit_code = match fail_on {
        FailOn::Never => 0,
        FailOn::Warn if report.should_block() => 2,
        FailOn::Warn if report.has_warnings() => 1,
        FailOn::Warn => 0,
        FailOn::Block if report.should_block() => 2,
        FailOn::Block => 0,
    };
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
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

    let dirs = directories::ProjectDirs::from("dev", "guardep", "guardep")
        .ok_or_else(|| anyhow::anyhow!("could not determine cache dir"))?;
    let cache_dir = dirs.cache_dir().to_path_buf();
    std::fs::create_dir_all(&cache_dir).ok();

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

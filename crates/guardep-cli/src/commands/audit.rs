use anyhow::Result;
use guardep_core::{
    ecosystem::PackageRef,
    evaluator::EvaluatorRegistry,
    finding_adapter::findings_to_verdict,
    intel::IntelEvaluator,
    matcher::Verdict,
    osv_evaluator::OsvEvaluator,
    policy::Policy,
    postinstall::PostinstallEvaluator,
    provenance::ProvenanceEvaluator,
    resolver::auto_resolve,
};
use owo_colors::OwoColorize;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Table,
    Json,
}

/// Severity threshold above which the audit exits non-zero.
///
/// `Block` (default): only confirmed blocks fail the run. Warnings are
/// printed but exit code is 0.
/// `Warn`: warnings also fail (CI mode for stricter pipelines).
/// `Never`: always exit 0; the report is informational only.
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
    report_single_maintainer: bool,
    fail_on: FailOn,
) -> Result<()> {
    let verdict = evaluate_project(path, report_single_maintainer).await?;
    match format {
        Format::Table => crate::report::print_verdict(&verdict, collapse),
        Format::Json => crate::report::print_json(&verdict, collapse)?,
    }
    let exit_code = match fail_on {
        FailOn::Never => 0,
        FailOn::Warn if verdict.should_block() => 2,
        FailOn::Warn if verdict.has_warnings() => 1,
        FailOn::Warn => 0,
        FailOn::Block if verdict.should_block() => 2,
        FailOn::Block => 0,
    };
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

pub async fn evaluate_project(path: &Path, report_single_maintainer: bool) -> Result<Verdict> {
    let (packages, lockfile_kind) = auto_resolve(path)?;
    eprintln!(
        "{} resolved {} packages from {}",
        ">".cyan(),
        packages.len(),
        lockfile_kind
    );
    evaluate_packages(path, packages, report_single_maintainer).await
}

/// Audit a pre-resolved set of packages. Used by the npm shim when the
/// dry-run resolver has already produced the intended graph (so the
/// audit reflects what's about to be installed, not just what's
/// currently locked).
pub async fn evaluate_packages(
    path: &Path,
    packages: Vec<PackageRef>,
    report_single_maintainer: bool,
) -> Result<Verdict> {
    let mut policy = Policy::load(&path.join("guardep.toml"))?;
    if report_single_maintainer {
        policy.report_single_maintainer = true;
    }

    let dirs = directories::ProjectDirs::from("dev", "guardep", "guardep")
        .ok_or_else(|| anyhow::anyhow!("could not determine cache dir"))?;
    let cache_dir = dirs.cache_dir().to_path_buf();
    std::fs::create_dir_all(&cache_dir).ok();

    let mut registry = EvaluatorRegistry::new();
    registry.register(Arc::new(OsvEvaluator::new(
        cache_dir.join("advisories.db"),
    )?));
    registry.register(Arc::new(PostinstallEvaluator::new(path.to_path_buf())));
    registry.register(Arc::new(IntelEvaluator::new(
        cache_dir.join("intel.db"),
    )?));
    registry.register(Arc::new(ProvenanceEvaluator::new(
        cache_dir.join("provenance.db"),
    )?));

    eprintln!(
        "{} running evaluators: {}",
        ">".cyan(),
        registry.names().join(", ")
    );

    let findings = registry.run(&packages, &policy).await?;
    Ok(findings_to_verdict(findings, &policy))
}

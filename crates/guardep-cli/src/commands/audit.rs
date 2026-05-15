use anyhow::Result;
use guardep_core::{
    ecosystem::PackageRef,
    evaluator::EvaluatorRegistry,
    intel::IntelEvaluator,
    osv_evaluator::OsvEvaluator,
    policy::Policy,
    postinstall::PostinstallEvaluator,
    provenance::ProvenanceEvaluator,
    resolver::auto_resolve,
    FindingsReport,
};
use owo_colors::OwoColorize;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Table,
    Json,
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
    show_info: bool,
    fail_on: FailOn,
) -> Result<()> {
    let report = evaluate_project(path, show_info).await?;
    match format {
        Format::Table => crate::report::print_verdict(&report, collapse),
        Format::Json => crate::report::print_json(&report, collapse)?,
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
    show_info: bool,
) -> Result<FindingsReport> {
    let (packages, lockfile_kind) = auto_resolve(path)?;
    eprintln!(
        "{} resolved {} packages from {}",
        ">".cyan(),
        packages.len(),
        lockfile_kind
    );
    evaluate_packages(path, packages, show_info).await
}

pub async fn evaluate_packages(
    path: &Path,
    packages: Vec<PackageRef>,
    show_info: bool,
) -> Result<FindingsReport> {
    let mut policy = Policy::load(&path.join("guardep.toml"))?;
    if show_info {
        policy.show_info = true;
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
    registry.register(Arc::new(ProvenanceEvaluator::new(cache_db)?));

    eprintln!(
        "{} running evaluators: {}",
        ">".cyan(),
        registry.names().join(", ")
    );

    let findings = registry.run(&packages, &policy).await?;
    Ok(FindingsReport::from_findings(findings, &policy))
}

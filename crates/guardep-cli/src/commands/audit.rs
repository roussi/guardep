use anyhow::Result;
use guardep_core::{
    evaluator::EvaluatorRegistry,
    finding_adapter::findings_to_verdict,
    intel::IntelEvaluator,
    matcher::Verdict,
    osv_evaluator::OsvEvaluator,
    policy::Policy,
    postinstall::PostinstallEvaluator,
    provenance::ProvenanceEvaluator,
    resolver::{NpmLockResolver, Resolver},
};
use owo_colors::OwoColorize;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Table,
    Json,
}

pub async fn run(
    path: &Path,
    format: Format,
    collapse: bool,
    report_single_maintainer: bool,
) -> Result<()> {
    let verdict = evaluate_project(path, report_single_maintainer).await?;
    match format {
        Format::Table => crate::report::print_verdict(&verdict, collapse),
        Format::Json => crate::report::print_json(&verdict, collapse)?,
    }
    if verdict.should_block() {
        std::process::exit(2);
    }
    Ok(())
}

pub async fn evaluate_project(path: &Path, report_single_maintainer: bool) -> Result<Verdict> {
    let mut policy = Policy::load(&path.join("guardep.toml"))?;
    // CLI flag overrides config (only flips false -> true; setting it
    // in config has the same effect as the flag).
    if report_single_maintainer {
        policy.report_single_maintainer = true;
    }
    let packages = NpmLockResolver.resolve(path)?;
    eprintln!("{} resolved {} packages", ">".cyan(), packages.len());

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

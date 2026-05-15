use anyhow::Result;
use guardep_core::{
    cache::Cache,
    matcher::{evaluate, Verdict},
    osv::OsvClient,
    policy::Policy,
    resolver::{NpmLockResolver, Resolver},
    Advisory, PackageRef,
};
use owo_colors::OwoColorize;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Table,
    Json,
}

pub async fn run(path: &Path, format: Format, collapse: bool) -> Result<()> {
    let verdict = evaluate_project(path).await?;
    match format {
        Format::Table => crate::report::print_verdict(&verdict, collapse),
        Format::Json => crate::report::print_json(&verdict, collapse)?,
    }
    if verdict.should_block() {
        std::process::exit(2);
    }
    Ok(())
}

pub async fn evaluate_project(path: &Path) -> Result<Verdict> {
    let policy = Policy::load(&path.join("guardep.toml"))?;
    let packages = NpmLockResolver.resolve(path)?;
    eprintln!("{} resolved {} packages", "→".cyan(), packages.len());

    let dirs = directories::ProjectDirs::from("dev", "guardep", "guardep")
        .ok_or_else(|| anyhow::anyhow!("could not determine cache dir"))?;
    let cache = Cache::open(&dirs.cache_dir().join("advisories.db"), policy.cache_refresh_hours)?;
    let client = OsvClient::new()?;

    // Phase 1: cache lookup
    let mut all: Vec<Advisory> = Vec::new();
    let mut to_fetch: Vec<PackageRef> = Vec::new();
    for pkg in &packages {
        match cache.get(pkg)? {
            Some(hit) => all.extend(hit),
            None => to_fetch.push(pkg.clone()),
        }
    }

    // Phase 2: batch-fetch misses
    if !to_fetch.is_empty() {
        eprintln!(
            "{} fetching {} uncached package(s) from OSV (batched)",
            "→".cyan(),
            to_fetch.len()
        );
        match client.query_batch(&to_fetch).await {
            Ok(batched) => {
                for (pkg, advs) in to_fetch.iter().zip(batched.iter()) {
                    let _ = cache.put(pkg, advs);
                    all.extend(advs.clone());
                }
            }
            Err(e) => {
                eprintln!("{} batch query failed: {e} — falling back to per-package", "!".yellow());
                for pkg in &to_fetch {
                    let fetched = client.query(pkg).await.unwrap_or_else(|err| {
                        tracing::warn!("OSV query failed for {pkg}: {err}");
                        Vec::new()
                    });
                    let _ = cache.put(pkg, &fetched);
                    all.extend(fetched);
                }
            }
        }
    }

    Ok(evaluate(&packages, &all, &policy))
}

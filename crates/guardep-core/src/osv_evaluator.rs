//! Bridges the existing OSV client + cache into the unified Evaluator
//! interface. This lets the registry treat advisory matching as one
//! finding source among several (postinstall, risk, provenance).

use crate::advisory::{Advisory, ThreatClass as AdvClass};
use crate::cache::Cache;
use crate::ecosystem::PackageRef;
use crate::finding::{Evaluator, Finding, FindingKind, FindingSeverity};
use crate::matcher::evaluate as match_advisories;
use crate::osv::OsvClient;
use crate::policy::Policy;
use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;

pub struct OsvEvaluator {
    cache_path: PathBuf,
    client: OsvClient,
}

impl OsvEvaluator {
    pub fn new(cache_path: PathBuf) -> Result<Self> {
        Ok(Self {
            cache_path,
            client: OsvClient::new()?,
        })
    }
}

#[async_trait]
impl Evaluator for OsvEvaluator {
    fn name(&self) -> &'static str {
        "osv"
    }

    fn enabled(&self, _: &Policy) -> bool {
        true
    }

    async fn evaluate(&self, packages: &[PackageRef], policy: &Policy) -> Result<Vec<Finding>> {
        // Lazy-init cache (Cache isn't Send across await points easily; we
        // open it per call to keep the interface clean).
        let cache = Cache::open(&self.cache_path, policy.cache_refresh_hours)?;

        let mut all_advisories: Vec<Advisory> = Vec::new();
        let mut to_fetch: Vec<PackageRef> = Vec::new();
        for pkg in packages {
            match cache.get(pkg)? {
                Some(hit) => all_advisories.extend(hit),
                None => to_fetch.push(pkg.clone()),
            }
        }

        if !to_fetch.is_empty() {
            match self.client.query_batch(&to_fetch).await {
                Ok(batched) => {
                    for (pkg, advs) in to_fetch.iter().zip(batched.iter()) {
                        let _ = cache.put(pkg, advs);
                        all_advisories.extend(advs.clone());
                    }
                }
                Err(e) => {
                    tracing::warn!("OSV batch failed: {e} — per-package fallback");
                    for pkg in &to_fetch {
                        let advs = self.client.query(pkg).await.unwrap_or_default();
                        let _ = cache.put(pkg, &advs);
                        all_advisories.extend(advs);
                    }
                }
            }
        }

        // Keep the legacy matcher to reuse semver range logic, then translate.
        let verdict = match_advisories(packages, &all_advisories, policy);
        let findings: Vec<Finding> = verdict
            .matches
            .into_iter()
            .map(|m| Finding {
                package: m.package,
                kind: match m.advisory.class {
                    AdvClass::Malware => FindingKind::Malware,
                    AdvClass::Vulnerability => FindingKind::Vulnerability,
                },
                id: m.advisory.id,
                aliases: m.advisory.aliases,
                summary: m.advisory.summary,
                severity: legacy_severity(m.advisory.severity),
                fixed_versions: m.advisory.fixed_versions,
                references: m.advisory.references,
                details: serde_json::Value::Null,
            })
            .collect();

        Ok(findings)
    }
}

fn legacy_severity(s: crate::advisory::Severity) -> FindingSeverity {
    use crate::advisory::Severity::*;
    match s {
        Critical => FindingSeverity::Critical,
        High => FindingSeverity::High,
        Medium => FindingSeverity::Medium,
        Low => FindingSeverity::Low,
        Unknown => FindingSeverity::Unknown,
    }
}

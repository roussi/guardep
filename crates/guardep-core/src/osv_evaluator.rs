//! OSV.dev advisory evaluator.
//!
//! Wraps the existing OSV client + SQLite cache + semver matcher as an
//! `Evaluator`. Emits `Finding`s directly — no legacy `MatchResult`
//! intermediate step.

use crate::advisory::{Advisory, ThreatClass as AdvClass};
use crate::cache::{Cache, KvCache};
use crate::ecosystem::PackageRef;
use crate::finding::{Evaluator, Finding, FindingKind, FindingSeverity};
use crate::osv::OsvClient;
use crate::policy::Policy;
use crate::range::version_in_ranges;
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
        let kv = KvCache::open(&self.cache_path, policy.cache_refresh_hours)?;
        let cache = Cache::new(&kv);

        // Phase 1: per-package cache lookup. Misses go to a fetch list.
        let mut all_advisories: Vec<(PackageRef, Vec<Advisory>)> = Vec::new();
        let mut to_fetch: Vec<PackageRef> = Vec::new();
        for pkg in packages {
            match cache.get(pkg)? {
                Some(hit) => all_advisories.push((pkg.clone(), hit)),
                None => to_fetch.push(pkg.clone()),
            }
        }

        // Phase 2: batch-fetch misses through OSV's querybatch endpoint.
        if !to_fetch.is_empty() {
            match self.client.query_batch(&to_fetch).await {
                Ok(batched) => {
                    for (pkg, advs) in to_fetch.iter().zip(batched.iter()) {
                        let _ = cache.put(pkg, advs);
                        all_advisories.push((pkg.clone(), advs.clone()));
                    }
                }
                Err(e) => {
                    tracing::warn!("OSV batch failed: {e} — per-package fallback");
                    for pkg in &to_fetch {
                        let advs = self.client.query(pkg).await.unwrap_or_default();
                        let _ = cache.put(pkg, &advs);
                        all_advisories.push((pkg.clone(), advs));
                    }
                }
            }
        }

        // Phase 3: range-match each advisory against its package; emit
        // a `Finding` per match. The `decide_action` step happens later
        // in `FindingsReport::from_findings` so we don't need to touch
        // policy here beyond classification.
        let mut findings = Vec::new();
        for (pkg, advs) in all_advisories {
            for adv in advs {
                if adv.ecosystem != pkg.ecosystem || adv.package != pkg.name {
                    continue;
                }
                if !version_in_ranges(&pkg.version, pkg.ecosystem, &adv.ranges) {
                    continue;
                }
                findings.push(Finding {
                    package: pkg.clone(),
                    kind: match adv.class {
                        AdvClass::Malware => FindingKind::Malware,
                        AdvClass::Vulnerability => FindingKind::Vulnerability,
                    },
                    id: adv.id,
                    aliases: adv.aliases,
                    summary: adv.summary,
                    severity: legacy_severity(adv.severity),
                    fixed_versions: adv.fixed_versions,
                    references: adv.references,
                    details: serde_json::Value::Null,
                });
            }
        }
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
        Info => FindingSeverity::Info,
        Unknown => FindingSeverity::Unknown,
    }
}

//! OSV.dev advisory evaluator.
//!
//! Wraps the OSV client, KV cache, and version-range matcher as an
//! `Evaluator`. Emits `Finding`s directly into the unified pipeline.

use crate::advisory::{Advisory, ThreatClass as AdvClass};
use crate::cache::{Cache, KvCache};
use crate::ecosystem::PackageRef;
use crate::exploit::{ExploitClient, ExploitInfo};
use crate::finding::{Evaluator, Finding, FindingKind, FindingSeverity};
use crate::osv::OsvClient;
use crate::policy::Policy;
use crate::range::version_in_ranges;
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::PathBuf;

pub struct OsvEvaluator {
    cache_path: PathBuf,
    client: OsvClient,
    exploit: ExploitClient,
}

impl OsvEvaluator {
    pub fn new(cache_path: PathBuf) -> Result<Self> {
        Ok(Self {
            cache_path,
            client: OsvClient::new()?,
            exploit: ExploitClient::new()?,
        })
    }

    /// Test helper: inject an `ExploitClient` aimed at mock servers.
    pub fn with_exploit_client(cache_path: PathBuf, exploit: ExploitClient) -> Result<Self> {
        Ok(Self {
            cache_path,
            client: OsvClient::new()?,
            exploit,
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
                    tracing::warn!("OSV batch failed: {e}; per-package fallback");
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

        // Phase 4: enrich vulnerability findings with EPSS + KEV. Only
        // CVE-shaped IDs (id or alias starting with "CVE-") are
        // queryable; ghost ids and pure GHSA-only entries are skipped.
        // Promotion is policy-driven: KEV → Critical when configured,
        // EPSS >= threshold bumps one tier.
        let cves: Vec<String> = findings
            .iter()
            .filter(|f| f.kind == FindingKind::Vulnerability)
            .flat_map(|f| std::iter::once(&f.id).chain(f.aliases.iter()))
            .filter(|s| s.starts_with("CVE-"))
            .cloned()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        if !cves.is_empty() {
            let exploit_map: HashMap<String, ExploitInfo> =
                self.exploit.enrich(&cves, &kv).await.unwrap_or_else(|e| {
                    tracing::warn!("exploit enrichment failed: {e}");
                    HashMap::new()
                });
            for f in &mut findings {
                if f.kind != FindingKind::Vulnerability {
                    continue;
                }
                let mut hit: Option<&ExploitInfo> = None;
                if let Some(info) = exploit_map.get(&f.id) {
                    hit = Some(info);
                }
                if hit.is_none() {
                    for alias in &f.aliases {
                        if let Some(info) = exploit_map.get(alias) {
                            hit = Some(info);
                            break;
                        }
                    }
                }
                if let Some(info) = hit {
                    apply_exploit(f, info, policy);
                }
            }
        }

        Ok(findings)
    }
}

/// Mutate a finding in-place: attach EPSS/KEV details and bump severity
/// per policy. Idempotent: running twice produces the same result
/// because we set, not increment.
fn apply_exploit(f: &mut Finding, info: &ExploitInfo, policy: &Policy) {
    let mut details = match f.details.take() {
        serde_json::Value::Object(m) => m,
        _ => serde_json::Map::new(),
    };
    details.insert(
        "epss".into(),
        serde_json::json!({
            "score": info.epss_score,
            "percentile": info.epss_percentile,
        }),
    );
    details.insert("kev".into(), serde_json::Value::Bool(info.kev));
    f.details = serde_json::Value::Object(details);

    if info.kev && policy.kev_promote_to_critical {
        f.severity = FindingSeverity::Critical;
        return;
    }

    if let Some(score) = info.epss_score {
        if score >= policy.epss_promote_threshold {
            f.severity = bump_one_tier(f.severity);
        }
    }
}

fn bump_one_tier(s: FindingSeverity) -> FindingSeverity {
    match s {
        FindingSeverity::Unknown | FindingSeverity::Info | FindingSeverity::Low => {
            FindingSeverity::Medium
        }
        FindingSeverity::Medium => FindingSeverity::High,
        FindingSeverity::High | FindingSeverity::Critical => FindingSeverity::Critical,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::{Ecosystem, PackageRef};

    fn vuln(severity: FindingSeverity, id: &str, aliases: &[&str]) -> Finding {
        Finding {
            package: PackageRef::new(Ecosystem::Npm, "x", "1.0.0"),
            kind: FindingKind::Vulnerability,
            id: id.into(),
            aliases: aliases.iter().map(|s| (*s).into()).collect(),
            summary: String::new(),
            severity,
            fixed_versions: vec![],
            references: vec![],
            details: serde_json::Value::Null,
        }
    }

    #[test]
    fn kev_promotes_to_critical_regardless_of_starting_severity() {
        let policy = Policy::default();
        for start in [
            FindingSeverity::Low,
            FindingSeverity::Medium,
            FindingSeverity::High,
        ] {
            let mut f = vuln(start, "CVE-2024-1", &[]);
            let info = ExploitInfo {
                epss_score: Some(0.01),
                epss_percentile: Some(0.1),
                kev: true,
            };
            apply_exploit(&mut f, &info, &policy);
            assert_eq!(f.severity, FindingSeverity::Critical, "start={start:?}");
            assert_eq!(f.details["kev"].as_bool(), Some(true));
        }
    }

    #[test]
    fn epss_above_threshold_bumps_one_tier() {
        let policy = Policy::default(); // threshold 0.5
        let mut f = vuln(FindingSeverity::Medium, "CVE-2024-2", &[]);
        let info = ExploitInfo {
            epss_score: Some(0.8),
            epss_percentile: Some(0.99),
            kev: false,
        };
        apply_exploit(&mut f, &info, &policy);
        assert_eq!(f.severity, FindingSeverity::High);
    }

    #[test]
    fn epss_below_threshold_does_not_promote() {
        let policy = Policy::default();
        let mut f = vuln(FindingSeverity::Medium, "CVE-2024-3", &[]);
        let info = ExploitInfo {
            epss_score: Some(0.1),
            epss_percentile: Some(0.5),
            kev: false,
        };
        apply_exploit(&mut f, &info, &policy);
        assert_eq!(f.severity, FindingSeverity::Medium);
        assert!((f.details["epss"]["score"].as_f64().unwrap() - 0.1).abs() < 1e-5);
    }

    #[test]
    fn kev_promotion_disabled_by_policy() {
        let mut policy = Policy::default();
        policy.kev_promote_to_critical = false;
        let mut f = vuln(FindingSeverity::Low, "CVE-2024-4", &[]);
        let info = ExploitInfo {
            epss_score: None,
            epss_percentile: None,
            kev: true,
        };
        apply_exploit(&mut f, &info, &policy);
        // KEV recorded in details but severity unchanged.
        assert_eq!(f.severity, FindingSeverity::Low);
        assert_eq!(f.details["kev"].as_bool(), Some(true));
    }

    #[test]
    fn bump_one_tier_caps_at_critical() {
        assert_eq!(
            bump_one_tier(FindingSeverity::Critical),
            FindingSeverity::Critical
        );
        assert_eq!(
            bump_one_tier(FindingSeverity::High),
            FindingSeverity::Critical
        );
    }
}

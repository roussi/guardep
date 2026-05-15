//! Cross-file source-behavior evaluator.
//!
//! Wraps `source_scan::scan_package_dir` as an `Evaluator`. For each
//! installed npm package, scans every JS/TS file and aggregates behavior
//! hits into one `Finding` per (package, behavior) pair. Per-call-site
//! detail goes into `Finding.details.locations` so the renderer or JSON
//! consumers can surface byte-offset-style location info.

use crate::ecosystem::{Ecosystem, PackageRef};
use crate::finding::{Evaluator, Finding, FindingKind, FindingSeverity};
use crate::policy::Policy;
use crate::source_scan::{scan_package_dir, Behavior, BehaviorHit};
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::PathBuf;

pub struct SourceScanEvaluator {
    project_root: PathBuf,
}

impl SourceScanEvaluator {
    pub fn new(project_root: PathBuf) -> Self {
        Self { project_root }
    }

    fn pkg_dir(&self, name: &str) -> PathBuf {
        self.project_root.join("node_modules").join(name)
    }
}

#[async_trait]
impl Evaluator for SourceScanEvaluator {
    fn name(&self) -> &'static str {
        "source_scan"
    }

    fn enabled(&self, policy: &Policy) -> bool {
        policy.source_scan_enabled
    }

    async fn evaluate(&self, packages: &[PackageRef], _policy: &Policy) -> Result<Vec<Finding>> {
        // Source scanning is CPU-bound (parse + walk AST). Run packages
        // in parallel with bounded concurrency via tokio's blocking pool.
        use futures::stream::{self, StreamExt};
        const SCAN_CONCURRENCY: usize = 8;

        let project_root = self.project_root.clone();
        let pkg_list: Vec<PackageRef> = packages
            .iter()
            .filter(|p| p.ecosystem == Ecosystem::Npm)
            .cloned()
            .collect();

        let scans: Vec<(PackageRef, Vec<BehaviorHit>)> = stream::iter(pkg_list)
            .map(|pkg| {
                let dir = project_root.join("node_modules").join(&pkg.name);
                async move {
                    let pkg_for_task = pkg.clone();
                    let hits = tokio::task::spawn_blocking(move || {
                        if !dir.exists() {
                            return Vec::new();
                        }
                        scan_package_dir(&dir).unwrap_or_default()
                    })
                    .await
                    .unwrap_or_default();
                    (pkg_for_task, hits)
                }
            })
            .buffer_unordered(SCAN_CONCURRENCY)
            .collect()
            .await;
        // Use pkg_dir to keep the helper exercised by the type checker
        // even when no packages are present.
        let _ = self.pkg_dir("");

        let mut findings: Vec<Finding> = Vec::new();
        for (pkg, hits) in scans {
            if hits.is_empty() {
                continue;
            }
            // Group by behavior.
            let mut grouped: HashMap<Behavior, Vec<BehaviorHit>> = HashMap::new();
            for hit in hits {
                grouped.entry(hit.behavior).or_default().push(hit);
            }
            for (behavior, group) in grouped {
                let severity = severity_for(behavior, group.len());
                let locations: Vec<serde_json::Value> = group
                    .iter()
                    .take(20) // cap to keep JSON manageable
                    .map(|h| {
                        let mut entry = serde_json::json!({
                            "file": h.file,
                            "line": h.line,
                            "note": h.note,
                        });
                        if let Some((start, end)) = h.bytes {
                            entry["bytes"] = serde_json::json!({
                                "start": start,
                                "end": end,
                            });
                        }
                        entry
                    })
                    .collect();
                let details = serde_json::json!({
                    "behavior": behavior.as_str(),
                    "label": behavior.label(),
                    "occurrences": group.len(),
                    "locations": locations,
                });
                findings.push(Finding {
                    package: pkg.clone(),
                    kind: FindingKind::SourceBehavior,
                    id: format!("behavior:{}:{}", behavior.as_str(), pkg.name),
                    aliases: vec![],
                    summary: format!(
                        "{} ({} occurrences in {})",
                        behavior.label(),
                        group.len(),
                        pkg.name
                    ),
                    severity,
                    fixed_versions: vec![],
                    references: vec![],
                    details,
                });
            }
        }
        Ok(findings)
    }
}

/// Severity calibration. Most behaviors are Low (Socket emits these as
/// `severity: "low"` too). UsesEval and DynamicRequire are Medium because
/// they are the load-bearing primitives of dynamic-malware execution.
/// Three or more occurrences of the same behavior in one package
/// promotes one tier (clusters look more intentional than incidental).
fn severity_for(behavior: Behavior, count: usize) -> FindingSeverity {
    let base = match behavior {
        Behavior::UsesEval => FindingSeverity::Medium,
        Behavior::DynamicRequire => FindingSeverity::Medium,
        Behavior::HighEntropyString => FindingSeverity::Low,
        Behavior::MinifiedFile => FindingSeverity::Low,
        Behavior::NetworkAccess => FindingSeverity::Low,
        Behavior::FilesystemAccess => FindingSeverity::Low,
        Behavior::EnvVars => FindingSeverity::Low,
        Behavior::UrlStrings => FindingSeverity::Low,
    };
    if count >= 3 {
        match base {
            FindingSeverity::Low => FindingSeverity::Medium,
            FindingSeverity::Medium => FindingSeverity::High,
            other => other,
        }
    } else {
        base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_for_promotes_on_clusters() {
        assert_eq!(severity_for(Behavior::EnvVars, 1), FindingSeverity::Low);
        assert_eq!(severity_for(Behavior::EnvVars, 5), FindingSeverity::Medium);
        assert_eq!(severity_for(Behavior::UsesEval, 1), FindingSeverity::Medium);
        assert_eq!(severity_for(Behavior::UsesEval, 3), FindingSeverity::High);
    }
}

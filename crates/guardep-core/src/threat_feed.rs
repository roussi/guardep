//! OSSF malicious-packages threat feed.
//!
//! Pulls the OpenSSF `malicious-packages` repository tarball, extracts
//! the per-ecosystem index of known-malicious package names, and caches
//! the result. Used as a fast pre-screen for `Malware` findings that
//! does not depend on the OSV.dev indexer being up to date — community
//! reports often land in the OSSF repo hours before OSV reflects them.
//!
//! Source: https://github.com/ossf/malicious-packages
//!
//! ## Coverage
//!
//! As of 2026-Q2, the feed lists ~6000 npm entries plus PyPI / RubyGems
//! / crates.io. We index npm only for now (matches our resolver scope).
//!
//! ## Cost
//!
//! One tarball fetch per `cache_refresh_hours`. The tarball is ~3-5 MB
//! gzipped. We extract just the directory listing from
//! `osv/malicious/npm/` — entry names are the package names.
//!
//! Acts as a complement to OSV, not a replacement: OSV still gets
//! consulted for full advisory metadata (severity, references, etc.).

use crate::cache::KvCache;
use crate::ecosystem::{Ecosystem, PackageRef};
use crate::finding::{Evaluator, Finding, FindingKind, FindingSeverity};
use crate::policy::Policy;
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

/// GitHub Trees API for the `osv/malicious/npm/` directory. Returns up
/// to 100k entries in one call when `recursive=1`. Each entry name is a
/// package name (with URL-decoding for scoped packages).
const FEED_TREE_URL: &str =
    "https://api.github.com/repos/ossf/malicious-packages/git/trees/main?recursive=1";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct FeedSnapshot {
    /// Lowercased package names (npm normalises to lowercase).
    npm: HashSet<String>,
}

pub struct ThreatFeedEvaluator {
    cache_path: PathBuf,
    http: reqwest::Client,
    feed_url: String,
}

impl ThreatFeedEvaluator {
    pub fn new(cache_path: PathBuf) -> Result<Self> {
        Self::with_url(cache_path, FEED_TREE_URL.to_string())
    }

    pub fn with_url(cache_path: PathBuf, feed_url: String) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("guardep-threat-feed/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build reqwest client")?;
        Ok(Self {
            cache_path,
            http,
            feed_url,
        })
    }

    async fn load_snapshot(&self, cache: &KvCache) -> Result<FeedSnapshot> {
        if let Some(payload) = cache.get("threat_feed", "ossf")? {
            if let Ok(snap) = serde_json::from_str::<FeedSnapshot>(&payload) {
                return Ok(snap);
            }
        }
        let snap = self.fetch().await?;
        let _ = cache.put("threat_feed", "ossf", &serde_json::to_string(&snap)?);
        Ok(snap)
    }

    async fn fetch(&self) -> Result<FeedSnapshot> {
        let resp = self
            .http
            .get(&self.feed_url)
            .send()
            .await
            .with_context(|| format!("GET {}", self.feed_url))?;
        if !resp.status().is_success() {
            anyhow::bail!("threat feed returned {}", resp.status());
        }
        let body: GithubTree = resp.json().await.context("parse github trees response")?;
        let mut npm: HashSet<String> = HashSet::new();
        for entry in body.tree {
            // Path shape: osv/malicious/npm/<pkg>/<file>.json
            // We want the third path segment, dedup so each pkg counts once.
            let parts: Vec<&str> = entry.path.split('/').collect();
            if parts.len() >= 4 && parts[0] == "osv" && parts[1] == "malicious" && parts[2] == "npm"
            {
                let name = parts[3];
                if !name.is_empty() {
                    npm.insert(name.to_ascii_lowercase());
                }
            }
        }
        Ok(FeedSnapshot { npm })
    }
}

#[async_trait]
impl Evaluator for ThreatFeedEvaluator {
    fn name(&self) -> &'static str {
        "threat_feed"
    }

    fn enabled(&self, policy: &Policy) -> bool {
        policy.threat_feed_enabled
    }

    async fn evaluate(&self, packages: &[PackageRef], policy: &Policy) -> Result<Vec<Finding>> {
        let cache = KvCache::open(&self.cache_path, policy.cache_refresh_hours)?;
        let snap = match self.load_snapshot(&cache).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("threat feed unavailable, skipping: {e}");
                return Ok(Vec::new());
            }
        };
        let mut out: Vec<Finding> = Vec::new();
        for pkg in packages {
            if pkg.ecosystem != Ecosystem::Npm {
                continue;
            }
            if snap.npm.contains(&pkg.name.to_ascii_lowercase()) {
                out.push(Finding {
                    package: pkg.clone(),
                    kind: FindingKind::Malware,
                    id: format!("ossf-malicious:{}", pkg.name),
                    aliases: vec![],
                    summary:
                        "Listed in OSSF malicious-packages feed (community-reported malicious npm package)"
                            .to_string(),
                    severity: FindingSeverity::Critical,
                    fixed_versions: vec![],
                    references: vec![format!(
                        "https://github.com/ossf/malicious-packages/tree/main/osv/malicious/npm/{}",
                        pkg.name
                    )],
                    details: serde_json::json!({
                        "source": "ossf-malicious-packages",
                    }),
                });
            }
        }
        Ok(out)
    }
}

#[derive(Debug, Deserialize)]
struct GithubTree {
    tree: Vec<GithubTreeEntry>,
}

#[derive(Debug, Deserialize)]
struct GithubTreeEntry {
    path: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn npm(name: &str) -> PackageRef {
        PackageRef::new(Ecosystem::Npm, name, "1.0.0")
    }

    #[tokio::test]
    async fn flags_packages_in_feed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tree": [
                    {"path": "osv/malicious/npm/evil-pkg/2024-01-01.json"},
                    {"path": "osv/malicious/npm/another-bad/2024-02-01.json"},
                    {"path": "osv/malicious/pypi/some-pkg/x.json"}
                ]
            })))
            .mount(&server)
            .await;

        let dir = TempDir::new().unwrap();
        let evaluator = ThreatFeedEvaluator::with_url(
            dir.path().join("cache.db"),
            format!("{}/", server.uri()),
        )
        .unwrap();
        let mut policy = Policy::default();
        policy.threat_feed_enabled = true;
        let pkgs = vec![npm("evil-pkg"), npm("safe-pkg"), npm("ANOTHER-BAD")];
        let findings = evaluator.evaluate(&pkgs, &policy).await.unwrap();
        let names: Vec<&str> = findings.iter().map(|f| f.package.name.as_str()).collect();
        assert!(names.contains(&"evil-pkg"));
        assert!(names.contains(&"ANOTHER-BAD")); // case-insensitive match
        assert!(!names.contains(&"safe-pkg"));
        assert!(findings
            .iter()
            .all(|f| f.severity == FindingSeverity::Critical));
        assert!(findings.iter().all(|f| f.kind == FindingKind::Malware));
    }

    #[tokio::test]
    async fn feed_failure_does_not_break_audit() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let dir = TempDir::new().unwrap();
        let evaluator = ThreatFeedEvaluator::with_url(
            dir.path().join("cache.db"),
            format!("{}/", server.uri()),
        )
        .unwrap();
        let mut policy = Policy::default();
        policy.threat_feed_enabled = true;
        let pkgs = vec![npm("anything")];
        let findings = evaluator.evaluate(&pkgs, &policy).await.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn cached_snapshot_skips_http() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tree": [{"path": "osv/malicious/npm/cached-bad/x.json"}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let dir = TempDir::new().unwrap();
        let evaluator = ThreatFeedEvaluator::with_url(
            dir.path().join("cache.db"),
            format!("{}/", server.uri()),
        )
        .unwrap();
        let mut policy = Policy::default();
        policy.threat_feed_enabled = true;
        let pkgs = vec![npm("cached-bad")];
        let _ = evaluator.evaluate(&pkgs, &policy).await.unwrap();
        let _ = evaluator.evaluate(&pkgs, &policy).await.unwrap();
        // wiremock asserts expect(1) on Drop — second call must hit cache.
    }
}

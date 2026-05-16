//! OSSF malicious-packages threat feed.
//!
//! Pulls the OpenSSF `malicious-packages` repository tree, extracts
//! the per-ecosystem index of known-malicious package names, and on
//! each run resolves any installed package whose name appears in that
//! index against the actual OSV-shaped advisory JSON files for that
//! package — applying version-range matching so we only flag the
//! versions OSSF actually marks malicious, not every version of a
//! pkg name that ever shipped a bad release.
//!
//! Source: https://github.com/ossf/malicious-packages
//!
//! ## Coverage
//!
//! As of 2026-Q2, the feed lists ~6000 npm entries plus PyPI / RubyGems
//! / crates.io. We index npm only for now (matches our resolver scope).
//!
//! ## Two-stage protocol
//!
//! Stage A — index (one HTTP call, cached per `cache_refresh_hours`):
//!   Fetch the GitHub Trees response, extract every npm package name
//!   that has at least one MAL-* entry. Plus, per-pkg, the file paths
//!   so stage B can fetch them directly.
//!
//! Stage B — per-pkg fetch (only on hit):
//!   For each installed pkg whose name is in the index, fetch each
//!   MAL-*.json from raw.githubusercontent.com, parse as OSV, and
//!   range-match the installed version. Cached per package name with
//!   the same TTL as stage A. Worst case == one HTTP per OSSF-listed
//!   pkg in your dep graph; in practice almost all dep graphs hit zero.
//!
//! Acts as a complement to OSV, not a replacement: OSV still gets
//! consulted for full advisory metadata (severity, references, etc.).

use crate::advisory::Advisory;
use crate::cache::KvCache;
use crate::ecosystem::{Ecosystem, PackageRef};
use crate::finding::{Evaluator, Finding, FindingKind, FindingSeverity};
use crate::policy::Policy;
use crate::range::version_in_ranges;
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// GitHub Trees API for the OSSF malicious-packages repo. Returns up
/// to 100k entries in one call when `recursive=1`. Each entry path
/// is `osv/malicious/npm/<pkg>/<MAL-id>.json`.
const FEED_TREE_URL: &str =
    "https://api.github.com/repos/ossf/malicious-packages/git/trees/main?recursive=1";

/// raw.githubusercontent.com base for fetching the per-MAL JSON files
/// the index points at.
const RAW_BASE_URL: &str = "https://raw.githubusercontent.com/ossf/malicious-packages/main";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct FeedSnapshot {
    /// Map of lowercased npm package name → list of MAL JSON paths
    /// inside the OSSF repo. Each path is the value for the `path`
    /// field returned by the GitHub Trees API; we use them verbatim
    /// when fetching from `raw.githubusercontent.com`.
    npm: HashMap<String, Vec<String>>,
}

pub struct ThreatFeedEvaluator {
    cache_path: PathBuf,
    http: reqwest::Client,
    feed_url: String,
    /// Base URL for fetching individual MAL JSON files. Overridable
    /// for tests so we don't hit GitHub from the test suite.
    raw_base_url: String,
}

impl ThreatFeedEvaluator {
    pub fn new(cache_path: PathBuf) -> Result<Self> {
        Self::with_urls(
            cache_path,
            FEED_TREE_URL.to_string(),
            RAW_BASE_URL.to_string(),
        )
    }

    /// Test helper accepting both upstream URLs so wiremock can stand in
    /// for the GitHub Trees API and the raw.githubusercontent.com host.
    pub fn with_urls(cache_path: PathBuf, feed_url: String, raw_base_url: String) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("guardep-threat-feed/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build reqwest client")?;
        Ok(Self {
            cache_path,
            http,
            feed_url,
            raw_base_url,
        })
    }

    /// Backwards-compat shim used by the original test suite that took
    /// only the index URL. Routes raw fetches at the same base because
    /// in single-mock-server tests both endpoints sit behind the same
    /// host.
    pub fn with_url(cache_path: PathBuf, feed_url: String) -> Result<Self> {
        let raw_base = feed_url
            .trim_end_matches('/')
            .trim_end_matches("/git/trees/main?recursive=1")
            .to_string();
        Self::with_urls(cache_path, feed_url, raw_base)
    }

    async fn load_snapshot(&self, cache: &KvCache) -> Result<FeedSnapshot> {
        if let Some(payload) = cache.get("threat_feed", "ossf-index")? {
            if let Ok(snap) = serde_json::from_str::<FeedSnapshot>(&payload) {
                return Ok(snap);
            }
        }
        let snap = self.fetch_index().await?;
        let _ = cache.put("threat_feed", "ossf-index", &serde_json::to_string(&snap)?);
        Ok(snap)
    }

    async fn fetch_index(&self) -> Result<FeedSnapshot> {
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
        let mut npm: HashMap<String, Vec<String>> = HashMap::new();
        for entry in body.tree {
            // Path shape: osv/malicious/npm/<pkg>/<file>.json
            // For scoped pkgs the path is osv/malicious/npm/@scope/pkg/<file>.json.
            let parts: Vec<&str> = entry.path.split('/').collect();
            if parts.len() < 4 {
                continue;
            }
            if parts[0] != "osv" || parts[1] != "malicious" || parts[2] != "npm" {
                continue;
            }
            // We only care about leaf files (.json), not directory rows.
            if !entry.path.ends_with(".json") {
                continue;
            }
            // Pkg name is parts[3]; for scoped pkgs it's parts[3..5] joined.
            let (name, _) = if parts[3].starts_with('@') && parts.len() >= 5 {
                (format!("{}/{}", parts[3], parts[4]), 5)
            } else {
                (parts[3].to_string(), 4)
            };
            if name.is_empty() {
                continue;
            }
            npm.entry(name.to_ascii_lowercase())
                .or_default()
                .push(entry.path);
        }
        Ok(FeedSnapshot { npm })
    }

    /// Stage B: fetch every MAL JSON for a package and convert into
    /// our `Advisory` shape. Cached per pkg name with the same TTL as
    /// the index. Tolerates per-file fetch / parse failures by logging
    /// and skipping — one bad file shouldn't blank the whole pkg.
    async fn load_advisories(
        &self,
        cache: &KvCache,
        pkg_name: &str,
        paths: &[String],
    ) -> Result<Vec<Advisory>> {
        let cache_key = pkg_name.to_ascii_lowercase();
        if let Some(payload) = cache.get("threat_feed_pkg", &cache_key)? {
            if let Ok(advs) = serde_json::from_str::<Vec<Advisory>>(&payload) {
                return Ok(advs);
            }
        }
        let mut advs: Vec<Advisory> = Vec::new();
        for path in paths {
            let url = format!("{}/{}", self.raw_base_url.trim_end_matches('/'), path);
            let resp = match self.http.get(&url).send().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("OSSF MAL fetch failed for {url}: {e}");
                    continue;
                }
            };
            if !resp.status().is_success() {
                tracing::warn!("OSSF MAL {url} returned {}", resp.status());
                continue;
            }
            let body = match resp.text().await {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("OSSF MAL body read failed for {url}: {e}");
                    continue;
                }
            };
            let vuln: crate::osv::OsvVuln = match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("OSSF MAL parse failed for {url}: {e}");
                    continue;
                }
            };
            advs.push(crate::osv::convert(vuln, Ecosystem::Npm, pkg_name));
        }
        let _ = cache.put(
            "threat_feed_pkg",
            &cache_key,
            &serde_json::to_string(&advs)?,
        );
        Ok(advs)
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

        // Group installed packages by lowercased name so we fetch the
        // OSSF MAL JSONs once per name regardless of how many versions
        // of that name appear in the dep graph.
        let mut by_name: HashMap<String, Vec<&PackageRef>> = HashMap::new();
        for pkg in packages {
            if pkg.ecosystem != Ecosystem::Npm {
                continue;
            }
            let key = pkg.name.to_ascii_lowercase();
            if snap.npm.contains_key(&key) {
                by_name.entry(key).or_default().push(pkg);
            }
        }

        let mut out: Vec<Finding> = Vec::new();
        for (key, pkgs) in by_name {
            let paths = match snap.npm.get(&key) {
                Some(p) => p,
                None => continue,
            };
            let advs = match self.load_advisories(&cache, &key, paths).await {
                Ok(a) => a,
                Err(e) => {
                    tracing::warn!("OSSF advisories load failed for {key}: {e}");
                    continue;
                }
            };
            if advs.is_empty() {
                continue;
            }
            for pkg in pkgs {
                for adv in &advs {
                    if !version_in_ranges(&pkg.version, pkg.ecosystem, &adv.ranges) {
                        continue;
                    }
                    out.push(Finding {
                        package: pkg.clone(),
                        kind: FindingKind::Malware,
                        id: adv.id.clone(),
                        aliases: adv.aliases.clone(),
                        summary: if adv.summary.is_empty() {
                            format!(
                                "OSSF malicious-packages: {}@{} matches {}",
                                pkg.name, pkg.version, adv.id
                            )
                        } else {
                            adv.summary.clone()
                        },
                        severity: FindingSeverity::Critical,
                        fixed_versions: adv.fixed_versions.clone(),
                        references: {
                            let mut refs = adv.references.clone();
                            refs.push(format!(
                                "https://github.com/ossf/malicious-packages/tree/main/osv/malicious/npm/{}",
                                pkg.name
                            ));
                            refs
                        },
                        details: serde_json::json!({
                            "source": "ossf-malicious-packages",
                        }),
                    });
                }
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

    fn npm(name: &str, version: &str) -> PackageRef {
        PackageRef::new(Ecosystem::Npm, name, version)
    }

    /// MAL-shaped OSV JSON: name `pkg`, malicious in `[introduced..fixed)`.
    fn mal_json(id: &str, pkg: &str, introduced: &str, fixed: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "summary": format!("Malicious code in {pkg}"),
            "affected": [{
                "package": { "ecosystem": "npm", "name": pkg },
                "ranges": [{
                    "type": "SEMVER",
                    "events": [
                        { "introduced": introduced },
                        { "fixed": fixed },
                    ]
                }]
            }],
            "database_specific": { "guardep_test_marker": true }
        })
    }

    /// Stand up a single mock server that serves both the GitHub Trees
    /// index and the per-MAL JSON files. Index path is `/`, raw paths
    /// hang off the same host so the with_url backwards-compat shim
    /// can route them.
    async fn mock_server_with_tree(tree_paths: &[&str]) -> wiremock::MockServer {
        let server = MockServer::start().await;
        let entries: Vec<serde_json::Value> = tree_paths
            .iter()
            .map(|p| serde_json::json!({ "path": *p }))
            .collect();
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "tree": entries })),
            )
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn flags_only_versions_in_affected_range() {
        let server = mock_server_with_tree(&["osv/malicious/npm/evil-pkg/MAL-2026-1.json"]).await;
        Mock::given(method("GET"))
            .and(path("/osv/malicious/npm/evil-pkg/MAL-2026-1.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(mal_json(
                "MAL-2026-1",
                "evil-pkg",
                "1.0.0",
                "1.0.2",
            )))
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
        let pkgs = vec![
            npm("evil-pkg", "0.9.0"), // pre-introduced: should NOT flag
            npm("evil-pkg", "1.0.1"), // in range: SHOULD flag
            npm("evil-pkg", "1.0.2"), // at fixed: should NOT flag
            npm("safe-pkg", "1.0.0"), // not in feed at all
        ];
        let findings = evaluator.evaluate(&pkgs, &policy).await.unwrap();
        let hit_versions: Vec<&str> = findings
            .iter()
            .filter(|f| f.package.name == "evil-pkg")
            .map(|f| f.package.version.as_str())
            .collect();
        assert_eq!(hit_versions, vec!["1.0.1"]);
        assert!(findings
            .iter()
            .all(|f| f.severity == FindingSeverity::Critical));
        assert!(findings.iter().all(|f| f.kind == FindingKind::Malware));
        // ID comes from the MAL entry, not synthesised.
        assert_eq!(findings[0].id, "MAL-2026-1");
    }

    #[tokio::test]
    async fn skips_pkgs_not_in_index() {
        let server = mock_server_with_tree(&[]).await;
        let dir = TempDir::new().unwrap();
        let evaluator = ThreatFeedEvaluator::with_url(
            dir.path().join("cache.db"),
            format!("{}/", server.uri()),
        )
        .unwrap();
        let mut policy = Policy::default();
        policy.threat_feed_enabled = true;
        let pkgs = vec![npm("safe-pkg", "1.0.0")];
        let findings = evaluator.evaluate(&pkgs, &policy).await.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn case_insensitive_name_match() {
        let server = mock_server_with_tree(&["osv/malicious/npm/evil-pkg/MAL-2026-1.json"]).await;
        Mock::given(method("GET"))
            .and(path("/osv/malicious/npm/evil-pkg/MAL-2026-1.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(mal_json(
                "MAL-2026-1",
                "evil-pkg",
                "1.0.0",
                "1.1.0",
            )))
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
        let pkgs = vec![npm("EVIL-PKG", "1.0.5")];
        let findings = evaluator.evaluate(&pkgs, &policy).await.unwrap();
        assert_eq!(findings.len(), 1);
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
        let pkgs = vec![npm("anything", "1.0.0")];
        let findings = evaluator.evaluate(&pkgs, &policy).await.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn cached_index_skips_http() {
        // Index served once; second evaluate() must read from cache.
        let server = mock_server_with_tree(&["osv/malicious/npm/cached-bad/MAL-X.json"]).await;
        Mock::given(method("GET"))
            .and(path("/osv/malicious/npm/cached-bad/MAL-X.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(mal_json(
                "MAL-X",
                "cached-bad",
                "1.0.0",
                "2.0.0",
            )))
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
        let pkgs = vec![npm("cached-bad", "1.5.0")];
        let first = evaluator.evaluate(&pkgs, &policy).await.unwrap();
        let second = evaluator.evaluate(&pkgs, &policy).await.unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        // Both runs returned the same id; second went through cache for
        // both index and per-pkg advisories.
        assert_eq!(first[0].id, second[0].id);
    }
}

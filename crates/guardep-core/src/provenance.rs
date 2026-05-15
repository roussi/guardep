//! Sigstore provenance evaluator for npm packages.
//!
//! ## Scope
//!
//! This evaluator does NOT yet perform full Sigstore cryptographic
//! verification. What IS verified:
//!   - Attestation presence (npm returned at least one attestation)
//!   - Identity match (attested source repo matches package metadata)
//! What is NOT verified (TODO):
//!   - X.509 cert chain against Fulcio root
//!   - Rekor transparency log inclusion proof
//!   - DSSE signature validity
//!   - Certificate SAN extension OID checks
//!
//! The presence + identity check defeats most current attacks because
//! adversaries publishing from hijacked maintainer laptops typically don't
//! generate any attestation, and forging a matching repository claim
//! requires owning the GitHub Actions identity.

use crate::cache::KvCache;
use crate::ecosystem::{Ecosystem, PackageRef};
use crate::finding::{Evaluator, Finding, FindingKind, FindingSeverity};
use crate::policy::Policy;
use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const DEFAULT_BASE_URL: &str = "https://registry.npmjs.org";

#[derive(Serialize, Deserialize)]
struct CachedProv {
    attested_repo: Option<String>,
    expected_repo: Option<String>,
}

/// Evaluator that enforces Sigstore provenance presence and source-repo
/// identity for npm packages flagged by `policy.require_provenance`.
pub struct ProvenanceEvaluator {
    cache_path: PathBuf,
    http: reqwest::Client,
    base_url: String,
}

impl ProvenanceEvaluator {
    pub fn new(cache_path: PathBuf) -> Result<Self> {
        Self::with_base_url(cache_path, DEFAULT_BASE_URL.to_string())
    }

    pub fn with_base_url(cache_path: PathBuf, base_url: String) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("guardep/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("build reqwest client")?;

        Ok(Self {
            cache_path,
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    fn open_cache(&self, ttl_hours: u64) -> Result<KvCache> {
        KvCache::open(&self.cache_path, ttl_hours)
    }

    fn cache_get(cache: &KvCache, name: &str, version: &str) -> Result<Option<CacheEntry>> {
        let key = format!("{name}@{version}");
        let Some(payload) = cache.get("provenance", &key)? else {
            return Ok(None);
        };
        let cached: CachedProv = serde_json::from_str(&payload)?;
        Ok(Some(CacheEntry {
            attested_repo: cached.attested_repo,
            expected_repo: cached.expected_repo,
        }))
    }

    fn cache_put(
        cache: &KvCache,
        name: &str,
        version: &str,
        attested: Option<&str>,
        expected: Option<&str>,
    ) -> Result<()> {
        let key = format!("{name}@{version}");
        let payload = serde_json::to_string(&CachedProv {
            attested_repo: attested.map(String::from),
            expected_repo: expected.map(String::from),
        })?;
        cache.put("provenance", &key, &payload)
    }

    /// Fetch the attestation envelope from npm. Returns `Ok(None)` when
    /// npm replies with no attestations (either an empty list or a 404).
    async fn fetch_attestation_repo(&self, name: &str, version: &str) -> Result<Option<String>> {
        let url = format!(
            "{}/-/npm/v1/attestations/{}@{}",
            self.base_url, name, version
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("fetch attestations for {name}@{version}"))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            anyhow::bail!(
                "attestations request for {name}@{version} returned status {}",
                resp.status()
            );
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .with_context(|| format!("decode attestations for {name}@{version}"))?;

        let attestations = body.get("attestations").and_then(|v| v.as_array());
        let Some(arr) = attestations else {
            return Ok(None);
        };
        if arr.is_empty() {
            return Ok(None);
        }

        let first = &arr[0];
        let payload_b64 = first
            .pointer("/bundle/dsseEnvelope/payload")
            .and_then(|v| v.as_str())
            .context("attestation missing dsseEnvelope.payload")?;

        let payload_bytes = base64::engine::general_purpose::STANDARD
            .decode(payload_b64)
            .context("decode dsseEnvelope.payload base64")?;
        let statement: serde_json::Value =
            serde_json::from_slice(&payload_bytes).context("parse in-toto statement JSON")?;

        let repo = statement
            .pointer("/predicate/buildDefinition/externalParameters/workflow/repository")
            .and_then(|v| v.as_str())
            .context("in-toto statement missing workflow.repository")?
            .to_string();

        Ok(Some(repo))
    }

    /// Fetch the npm package metadata document and extract `repository.url`.
    async fn fetch_expected_repo(&self, name: &str) -> Result<Option<String>> {
        let url = format!("{}/{}", self.base_url, name);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("fetch package metadata for {name}"))?;

        if !resp.status().is_success() {
            anyhow::bail!(
                "package metadata for {name} returned status {}",
                resp.status()
            );
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .with_context(|| format!("decode package metadata for {name}"))?;

        let repo_field = body.get("repository");
        let url_str = match repo_field {
            Some(serde_json::Value::String(s)) => Some(s.clone()),
            Some(serde_json::Value::Object(obj)) => {
                obj.get("url").and_then(|v| v.as_str()).map(String::from)
            }
            _ => None,
        };
        Ok(url_str)
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    attested_repo: Option<String>,
    expected_repo: Option<String>,
}

#[async_trait]
impl Evaluator for ProvenanceEvaluator {
    fn name(&self) -> &'static str {
        "provenance"
    }

    fn enabled(&self, policy: &Policy) -> bool {
        !policy.require_provenance.is_empty()
    }

    async fn evaluate(
        &self,
        packages: &[PackageRef],
        policy: &Policy,
    ) -> Result<Vec<Finding>> {
        use futures::stream::{self, StreamExt};
        const FETCH_CONCURRENCY: usize = 16;

        let cache = self.open_cache(policy.cache_refresh_hours)?;

        // Filter to packages that match policy + npm ecosystem.
        let targets: Vec<&PackageRef> = packages
            .iter()
            .filter(|pkg| {
                pkg.ecosystem == Ecosystem::Npm && policy.requires_provenance(&pkg.name)
            })
            .collect();

        // Phase 1: cache lookup.
        let mut from_cache: Vec<(PackageRef, Option<String>, Option<String>)> = Vec::new();
        let mut to_fetch: Vec<PackageRef> = Vec::new();
        for pkg in &targets {
            match Self::cache_get(&cache, &pkg.name, &pkg.version)? {
                Some(entry) => from_cache.push((
                    (*pkg).clone(),
                    entry.attested_repo,
                    entry.expected_repo,
                )),
                None => to_fetch.push((*pkg).clone()),
            }
        }

        // Phase 2: parallel fetches.
        let fetched: Vec<(PackageRef, Option<String>, Option<String>)> = stream::iter(to_fetch)
            .map(|pkg| async move {
                let attested = match self
                    .fetch_attestation_repo(&pkg.name, &pkg.version)
                    .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(
                            "provenance: attestation fetch failed for {}@{}: {e}",
                            pkg.name,
                            pkg.version
                        );
                        return None;
                    }
                };
                let expected = if attested.is_some() {
                    match self.fetch_expected_repo(&pkg.name).await {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!(
                                "provenance: package metadata fetch failed for {}: {e}",
                                pkg.name
                            );
                            return None;
                        }
                    }
                } else {
                    None
                };
                Some((pkg, attested, expected))
            })
            .buffer_unordered(FETCH_CONCURRENCY)
            .filter_map(|opt| async move { opt })
            .collect()
            .await;

        // Phase 3: persist fetched results to cache.
        for (pkg, attested, expected) in &fetched {
            let _ = Self::cache_put(
                &cache,
                &pkg.name,
                &pkg.version,
                attested.as_deref(),
                expected.as_deref(),
            );
        }

        // Phase 4: emit findings from both cache hits and fresh fetches.
        let mut findings = Vec::new();
        for (pkg, attested_repo, expected_repo) in from_cache.into_iter().chain(fetched.into_iter())
        {
            match attested_repo {
                None => findings.push(missing_finding(&pkg)),
                Some(attested) => {
                    let normalized_attested = normalize_repo(&attested);
                    let normalized_expected = expected_repo
                        .as_deref()
                        .map(normalize_repo)
                        .unwrap_or_default();
                    if normalized_expected.is_empty()
                        || normalized_attested != normalized_expected
                    {
                        findings.push(mismatch_finding(
                            &pkg,
                            &attested,
                            expected_repo.as_deref().unwrap_or(""),
                        ));
                    }
                }
            }
        }
        Ok(findings)
    }
}

fn missing_finding(pkg: &PackageRef) -> Finding {
    Finding {
        package: pkg.clone(),
        kind: FindingKind::MissingProvenance,
        id: format!("missing-provenance:{}@{}", pkg.name, pkg.version),
        aliases: vec![],
        summary: format!(
            "{}@{} required provenance but none was published",
            pkg.name, pkg.version
        ),
        severity: FindingSeverity::High,
        fixed_versions: vec![],
        references: vec![
            format!("https://www.npmjs.com/package/{}", pkg.name),
            "https://docs.npmjs.com/generating-provenance-statements".into(),
        ],
        details: serde_json::json!({"reason": "no_attestations"}),
    }
}

fn mismatch_finding(pkg: &PackageRef, attested_repo: &str, expected_repo: &str) -> Finding {
    Finding {
        package: pkg.clone(),
        kind: FindingKind::ProvenanceMismatch,
        id: format!("provenance-mismatch:{}@{}", pkg.name, pkg.version),
        aliases: vec![],
        summary: format!(
            "provenance built from {}, expected {}",
            attested_repo, expected_repo
        ),
        severity: FindingSeverity::Critical,
        fixed_versions: vec![],
        references: vec![format!("https://www.npmjs.com/package/{}", pkg.name)],
        details: serde_json::json!({
            "expected_repository": expected_repo,
            "attested_repository": attested_repo,
        }),
    }
}

/// Normalize a repository URL so attested and expected forms can be
/// compared. Strips common prefixes (`git+`, schemes, `git@github.com:`)
/// and trailing `.git` / slashes, then lowercases.
fn normalize_repo(s: &str) -> String {
    let s = s.trim();
    let s = s.strip_prefix("git+").unwrap_or(s);
    let s = s.strip_prefix("https://").unwrap_or(s);
    let s = s.strip_prefix("http://").unwrap_or(s);
    let s = if let Some(rest) = s.strip_prefix("git@github.com:") {
        format!("github.com/{}", rest)
    } else {
        s.to_string()
    };
    let s = s.strip_suffix('/').unwrap_or(&s).to_string();
    let s = s.strip_suffix(".git").unwrap_or(&s).to_string();
    s.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn npm_pkg(name: &str, version: &str) -> PackageRef {
        PackageRef::new(Ecosystem::Npm, name, version)
    }

    fn cargo_pkg(name: &str, version: &str) -> PackageRef {
        PackageRef::new(Ecosystem::Cargo, name, version)
    }

    fn policy_requiring(globs: &[&str]) -> Policy {
        let mut p = Policy::default();
        p.require_provenance = globs.iter().map(|s| s.to_string()).collect();
        p
    }

    fn build_attestation_response(repo: &str, name: &str, version: &str) -> serde_json::Value {
        let intoto = json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{
                "name": format!("pkg:npm/{}@{}", name, version),
                "digest": {"sha512": "abcdef"}
            }],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "workflow": {
                            "ref": "refs/heads/main",
                            "repository": repo,
                            "path": ".github/workflows/release.yml"
                        }
                    }
                }
            }
        });
        let payload_b64 =
            base64::engine::general_purpose::STANDARD.encode(intoto.to_string());
        json!({
            "attestations": [{
                "predicateType": "https://slsa.dev/provenance/v1",
                "bundle": {
                    "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
                    "dsseEnvelope": {
                        "payloadType": "application/vnd.in-toto+json",
                        "payload": payload_b64,
                        "signatures": []
                    }
                }
            }]
        })
    }

    fn cache_path(dir: &TempDir) -> PathBuf {
        dir.path().join("cache.db")
    }

    #[test]
    fn normalize_url() {
        assert_eq!(
            normalize_repo("git+https://github.com/owner/repo.git"),
            "github.com/owner/repo"
        );
        assert_eq!(
            normalize_repo("https://github.com/owner/repo"),
            "github.com/owner/repo"
        );
        assert_eq!(
            normalize_repo("git@github.com:owner/repo.git"),
            "github.com/owner/repo"
        );
        assert_eq!(
            normalize_repo("https://github.com/Owner/Repo/"),
            "github.com/owner/repo"
        );
    }

    #[tokio::test]
    async fn enabled_when_policy_set() {
        let dir = TempDir::new().unwrap();
        let ev = ProvenanceEvaluator::new(cache_path(&dir)).unwrap();
        let mut policy = Policy::default();
        assert!(!ev.enabled(&policy), "evaluator disabled when no globs");
        policy.require_provenance = vec!["chalk".into()];
        assert!(ev.enabled(&policy), "evaluator enabled when globs present");
    }

    #[tokio::test]
    async fn non_npm_skipped() {
        let server = MockServer::start().await;
        // Register a mock that fails the test if any HTTP call reaches the
        // server — non-npm packages must be skipped before fetching.
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let dir = TempDir::new().unwrap();
        let ev = ProvenanceEvaluator::with_base_url(cache_path(&dir), server.uri()).unwrap();
        let policy = policy_requiring(&["*"]);
        let pkgs = vec![cargo_pkg("serde", "1.0.0")];
        let findings = ev.evaluate(&pkgs, &policy).await.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn not_required_skipped() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/-/npm/v1/attestations/foo@1.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"attestations": []})))
            .expect(0)
            .mount(&server)
            .await;

        let dir = TempDir::new().unwrap();
        let ev = ProvenanceEvaluator::with_base_url(cache_path(&dir), server.uri()).unwrap();
        let policy = policy_requiring(&["chalk"]);
        let findings = ev
            .evaluate(&[npm_pkg("foo", "1.0.0")], &policy)
            .await
            .unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn missing_attestations_emits_finding() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/-/npm/v1/attestations/foo@1.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"attestations": []})))
            .mount(&server)
            .await;

        let dir = TempDir::new().unwrap();
        let ev = ProvenanceEvaluator::with_base_url(cache_path(&dir), server.uri()).unwrap();
        let policy = policy_requiring(&["foo"]);
        let findings = ev
            .evaluate(&[npm_pkg("foo", "1.0.0")], &policy)
            .await
            .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FindingKind::MissingProvenance);
        assert_eq!(findings[0].severity, FindingSeverity::High);
    }

    #[tokio::test]
    async fn attestation_match_no_finding() {
        let server = MockServer::start().await;
        let attestation =
            build_attestation_response("https://github.com/alice/pkg", "pkg", "1.0.0");
        Mock::given(method("GET"))
            .and(path("/-/npm/v1/attestations/pkg@1.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(attestation))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/pkg"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "name": "pkg",
                "repository": {
                    "type": "git",
                    "url": "git+https://github.com/alice/pkg.git"
                }
            })))
            .mount(&server)
            .await;

        let dir = TempDir::new().unwrap();
        let ev = ProvenanceEvaluator::with_base_url(cache_path(&dir), server.uri()).unwrap();
        let policy = policy_requiring(&["pkg"]);
        let findings = ev
            .evaluate(&[npm_pkg("pkg", "1.0.0")], &policy)
            .await
            .unwrap();
        assert!(findings.is_empty(), "expected no findings, got {findings:?}");
    }

    #[tokio::test]
    async fn attestation_mismatch_emits_critical() {
        let server = MockServer::start().await;
        let attestation =
            build_attestation_response("https://github.com/evil/pkg", "pkg", "1.0.0");
        Mock::given(method("GET"))
            .and(path("/-/npm/v1/attestations/pkg@1.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(attestation))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/pkg"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "name": "pkg",
                "repository": "https://github.com/alice/pkg"
            })))
            .mount(&server)
            .await;

        let dir = TempDir::new().unwrap();
        let ev = ProvenanceEvaluator::with_base_url(cache_path(&dir), server.uri()).unwrap();
        let policy = policy_requiring(&["pkg"]);
        let findings = ev
            .evaluate(&[npm_pkg("pkg", "1.0.0")], &policy)
            .await
            .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FindingKind::ProvenanceMismatch);
        assert_eq!(findings[0].severity, FindingSeverity::Critical);
        let details = &findings[0].details;
        assert_eq!(
            details.get("attested_repository").and_then(|v| v.as_str()),
            Some("https://github.com/evil/pkg")
        );
        assert_eq!(
            details.get("expected_repository").and_then(|v| v.as_str()),
            Some("https://github.com/alice/pkg")
        );
    }

    #[tokio::test]
    async fn cache_hit_skips_http() {
        let server = MockServer::start().await;
        let attestation =
            build_attestation_response("https://github.com/alice/pkg", "pkg", "1.0.0");
        Mock::given(method("GET"))
            .and(path("/-/npm/v1/attestations/pkg@1.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(attestation))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/pkg"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "name": "pkg",
                "repository": {"type": "git", "url": "git+https://github.com/alice/pkg.git"}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let dir = TempDir::new().unwrap();
        let ev = ProvenanceEvaluator::with_base_url(cache_path(&dir), server.uri()).unwrap();
        let policy = policy_requiring(&["pkg"]);
        let pkgs = vec![npm_pkg("pkg", "1.0.0")];

        let first = ev.evaluate(&pkgs, &policy).await.unwrap();
        let second = ev.evaluate(&pkgs, &policy).await.unwrap();
        assert!(first.is_empty());
        assert!(second.is_empty());
        // Mock `expect(1)` will panic on drop if the second call hit the server.
    }
}

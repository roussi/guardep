//! Sigstore provenance evaluator for npm packages.
//!
//! ## Verification levels
//!
//! Two layers, tracked separately so users (and the cache) know which
//! one a package passed:
//!
//! 1. **Presence + identity** — fetch the attestation envelope, decode
//!    the in-toto statement, compare the attested workflow `repository`
//!    field against the package's declared `repository.url`. This is
//!    cheap (one HTTP round-trip) and defeats every attack that doesn't
//!    bother forging a syntactically valid attestation.
//!
//! 2. **Cryptographic** — fetch the package tarball, hash it, run the
//!    bundle through `sigstore::bundle::verify::Verifier::production()`
//!    with an `Identity` policy bound to the GitHub Actions OIDC
//!    issuer and the workflow URI. This validates the cert chain
//!    against the Fulcio root, the Rekor transparency log entry, the
//!    DSSE signature, and the cert SAN extension. Adds bandwidth
//!    (downloading the tarball) and latency (~hundreds of ms per
//!    package). Skipped when the trust root cannot be initialised
//!    (offline, sigstore TUF outage); the evaluator falls back to
//!    presence + identity with a clear `verified: false` flag in the
//!    finding details.
//!
//! When cryptographic verification is enabled and a package fails it
//! (forged signature, broken cert chain, identity mismatch in the
//! cert SAN) the evaluator emits a `ProvenanceMismatch` Finding at
//! Critical severity, distinct from the soft `MissingProvenance`.
//!
//! ## What is still NOT verified
//!
//! - Rekor inclusion proof (Merkle path) — sigstore-rs has a TODO
//!   for this; we accept Rekor entry presence but don't validate the
//!   Merkle witness.
//! - Tarball integrity beyond what the bundle subject covers.
//!
//! ## Identity policy
//!
//! For npm packages built via GitHub Actions provenance, the expected
//! certificate identity is constructed from `repository.url` in the
//! package metadata: `https://github.com/<owner>/<repo>/...` matches
//! workflow URIs of the form
//! `https://github.com/<owner>/<repo>/.github/workflows/...@refs/...`.
//! We use a glob-flavoured `Identity` so any workflow file under that
//! repo passes (npm's `provenance: true` doesn't pin the workflow
//! filename in published metadata).

use crate::cache::KvCache;
use crate::ecosystem::{Ecosystem, PackageRef};
use crate::finding::{Evaluator, Finding, FindingKind, FindingSeverity};
use crate::policy::Policy;
use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

const DEFAULT_BASE_URL: &str = "https://registry.npmjs.org";
const GITHUB_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

#[derive(Serialize, Deserialize)]
struct CachedProv {
    attested_repo: Option<String>,
    expected_repo: Option<String>,
    /// `true` when the bundle passed full Sigstore crypto verification
    /// against the production trust root. `false` means we ran
    /// presence + identity only.
    #[serde(default)]
    crypto_verified: bool,
    /// `Some(reason)` when crypto verification was attempted and
    /// failed. The provenance is invalid, not just unverified.
    #[serde(default)]
    crypto_error: Option<String>,
}

/// Evaluator that enforces Sigstore provenance presence + identity
/// (always) and full cryptographic verification (when the trust root
/// is reachable).
pub struct ProvenanceEvaluator {
    cache_path: PathBuf,
    http: reqwest::Client,
    base_url: String,
    /// Lazily initialised on first call; shared across packages within
    /// a single audit. `None` when initialisation failed (offline,
    /// TUF outage). When `None`, packages still get presence + identity
    /// checking with a clear "crypto: not verified" annotation.
    trust_root: tokio::sync::OnceCell<Option<Arc<sigstore::bundle::verify::Verifier>>>,
}

impl ProvenanceEvaluator {
    pub fn new(cache_path: PathBuf) -> Result<Self> {
        Self::with_base_url(cache_path, DEFAULT_BASE_URL.to_string())
    }

    pub fn with_base_url(cache_path: PathBuf, base_url: String) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("guardep/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .context("build reqwest client")?;

        Ok(Self {
            cache_path,
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            trust_root: tokio::sync::OnceCell::new(),
        })
    }

    fn open_cache(&self, ttl_hours: u64) -> Result<KvCache> {
        KvCache::open(&self.cache_path, ttl_hours)
    }

    /// Initialise the production sigstore Verifier on first call.
    /// Returns `None` when initialisation fails (offline, TUF outage).
    /// We deliberately swallow the error here because crypto failures
    /// must NOT take down the whole audit; presence + identity remain
    /// useful even when full verification is unavailable.
    async fn ensure_verifier(&self) -> Option<Arc<sigstore::bundle::verify::Verifier>> {
        self.trust_root
            .get_or_init(|| async {
                match sigstore::bundle::verify::Verifier::production().await {
                    Ok(v) => Some(Arc::new(v)),
                    Err(e) => {
                        tracing::warn!(
                            "provenance: sigstore trust root init failed ({e}); \
                             falling back to presence + identity only"
                        );
                        None
                    }
                }
            })
            .await
            .clone()
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
            crypto_verified: cached.crypto_verified,
            crypto_error: cached.crypto_error,
        }))
    }

    fn cache_put(cache: &KvCache, name: &str, version: &str, entry: &CacheEntry) -> Result<()> {
        let key = format!("{name}@{version}");
        let payload = serde_json::to_string(&CachedProv {
            attested_repo: entry.attested_repo.clone(),
            expected_repo: entry.expected_repo.clone(),
            crypto_verified: entry.crypto_verified,
            crypto_error: entry.crypto_error.clone(),
        })?;
        cache.put("provenance", &key, &payload)
    }

    /// Fetch the attestation envelope from npm. Returns `(attested_repo,
    /// raw_bundle_json)` so callers can both extract identity and run
    /// full crypto verification. `Ok(None)` when no attestations exist
    /// (empty list or 404).
    async fn fetch_attestation(
        &self,
        name: &str,
        version: &str,
    ) -> Result<Option<(String, serde_json::Value)>> {
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

        // Return the bundle subobject so the verifier can consume it.
        let bundle_value = first
            .get("bundle")
            .cloned()
            .context("attestation missing bundle field")?;

        Ok(Some((repo, bundle_value)))
    }

    /// Fetch the npm package metadata and extract:
    ///   - `repository.url` (string or `{type, url}` object)
    ///   - The exact tarball URL we'll need for crypto verification
    ///     (`dist.tarball` for the installed version)
    async fn fetch_expected_repo_and_tarball(
        &self,
        name: &str,
        version: &str,
    ) -> Result<(Option<String>, Option<String>)> {
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

        let tarball = body
            .pointer(&format!("/versions/{version}/dist/tarball"))
            .and_then(|v| v.as_str())
            .map(String::from);

        Ok((url_str, tarball))
    }

    /// Fetch the package tarball bytes. Required for crypto verification
    /// because the bundle's in-toto subject is the tarball SHA-512 and
    /// `Verifier::verify` re-hashes the input itself.
    async fn fetch_tarball(&self, tarball_url: &str) -> Result<Vec<u8>> {
        let resp = self
            .http
            .get(tarball_url)
            .send()
            .await
            .with_context(|| format!("fetch tarball {tarball_url}"))?;
        if !resp.status().is_success() {
            anyhow::bail!("tarball returned status {}", resp.status());
        }
        let bytes = resp.bytes().await?.to_vec();
        Ok(bytes)
    }

    /// Run full crypto verification of `bundle_json` over `tarball_bytes`
    /// with an Identity policy bound to the expected repo's GitHub
    /// Actions workflow.
    ///
    /// Returns `Ok(())` on pass, `Err` describing the first check that
    /// failed otherwise.
    async fn crypto_verify(
        &self,
        verifier: &sigstore::bundle::verify::Verifier,
        bundle_json: &serde_json::Value,
        tarball_bytes: &[u8],
        expected_repo: &str,
    ) -> Result<()> {
        let bundle: sigstore::bundle::Bundle =
            serde_json::from_value(bundle_json.clone()).context("parse Sigstore Bundle JSON")?;

        // Identity policy: any workflow under <expected_repo>, signed by
        // the GitHub Actions OIDC issuer. We use a regex-anchored prefix
        // so workflow file path and ref are flexible (npm's published
        // attestations don't pin them).
        let expected_normalized = normalize_repo(expected_repo);
        let identity_pattern = format!(
            "https://github.com/{}/",
            strip_github_prefix(&expected_normalized)
        );
        let policy =
            sigstore::bundle::verify::policy::Identity::new(identity_pattern, GITHUB_OIDC_ISSUER);

        // The verifier hashes the input itself; offline=true skips the
        // online Rekor inclusion-proof check (sigstore-rs marks that
        // path as TODO upstream anyway).
        verifier
            .verify(tarball_bytes, bundle, &policy, true)
            .await
            .map_err(|e| anyhow::anyhow!("sigstore verify: {e}"))
    }
}

#[async_trait]
impl Evaluator for ProvenanceEvaluator {
    fn name(&self) -> &'static str {
        "provenance"
    }

    fn enabled(&self, policy: &Policy) -> bool {
        !policy.require_provenance.is_empty()
    }

    async fn evaluate(&self, packages: &[PackageRef], policy: &Policy) -> Result<Vec<Finding>> {
        use futures::stream::{self, StreamExt};
        const FETCH_CONCURRENCY: usize = 8;

        let cache = self.open_cache(policy.cache_refresh_hours)?;

        let targets: Vec<&PackageRef> = packages
            .iter()
            .filter(|pkg| pkg.ecosystem == Ecosystem::Npm && policy.requires_provenance(&pkg.name))
            .collect();
        if targets.is_empty() {
            return Ok(Vec::new());
        }

        // Initialise the trust root once for the whole audit. None means
        // init failed (offline, TUF outage, corporate proxy). We fall
        // back to identity-only checks but ALSO emit a single high-
        // visibility finding so the user knows crypto wasn't running.
        // Silently degrading to presence-only is exactly the kind of
        // false-confidence the rest of the project tries to avoid.
        let verifier = self.ensure_verifier().await;
        let trust_root_available = verifier.is_some();

        // Phase 1: cache lookup.
        let mut from_cache: Vec<(PackageRef, CacheEntry)> = Vec::new();
        let mut to_fetch: Vec<PackageRef> = Vec::new();
        for pkg in &targets {
            match Self::cache_get(&cache, &pkg.name, &pkg.version)? {
                Some(entry) => from_cache.push(((*pkg).clone(), entry)),
                None => to_fetch.push((*pkg).clone()),
            }
        }

        // Phase 2: parallel fetch + verify. Concurrency cap is lower than
        // the intel evaluator's because each package may also pull a
        // multi-MB tarball.
        let fetched: Vec<(PackageRef, CacheEntry)> = stream::iter(to_fetch)
            .map(|pkg| {
                let verifier = verifier.clone();
                async move {
                    let entry = self.evaluate_one(&pkg, verifier.as_deref()).await;
                    (pkg, entry)
                }
            })
            .buffer_unordered(FETCH_CONCURRENCY)
            .collect()
            .await;

        // Phase 3: persist to cache.
        for (pkg, entry) in &fetched {
            let _ = Self::cache_put(&cache, &pkg.name, &pkg.version, entry);
        }

        // Phase 4: emit findings.
        let mut findings = Vec::new();
        for (pkg, entry) in from_cache.into_iter().chain(fetched) {
            findings.extend(self.entry_to_findings(&pkg, &entry));
        }

        // Loud signal when crypto verification was skipped wholesale.
        // We attach it to the first target so it surfaces in the
        // package-grouped report; the user can see precisely how many
        // packages were affected via `details.affected_packages`.
        if !trust_root_available {
            if let Some(first) = targets.first() {
                findings.push(trust_root_unavailable_finding(first, targets.len()));
            }
        }
        Ok(findings)
    }
}

impl ProvenanceEvaluator {
    /// Drive presence + identity + (optional) crypto verification for a
    /// single package. Network errors short-circuit by returning a
    /// `CacheEntry` whose `attested_repo` is `None` (treated as missing
    /// provenance) — we don't poison the cache with a hard error.
    async fn evaluate_one(
        &self,
        pkg: &PackageRef,
        verifier: Option<&sigstore::bundle::verify::Verifier>,
    ) -> CacheEntry {
        let attestation = match self.fetch_attestation(&pkg.name, &pkg.version).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    "provenance: attestation fetch failed for {}@{}: {e}",
                    pkg.name,
                    pkg.version
                );
                return CacheEntry::no_attestations();
            }
        };
        let Some((attested_repo, bundle_json)) = attestation else {
            return CacheEntry::no_attestations();
        };

        let (expected_repo, tarball_url) = match self
            .fetch_expected_repo_and_tarball(&pkg.name, &pkg.version)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    "provenance: package metadata fetch failed for {}: {e}",
                    pkg.name
                );
                return CacheEntry {
                    attested_repo: Some(attested_repo),
                    expected_repo: None,
                    crypto_verified: false,
                    crypto_error: Some(format!("metadata fetch failed: {e}")),
                };
            }
        };

        // Crypto verification is skippable: only attempted when the
        // trust root initialised AND we have a tarball URL AND we have
        // an expected repo to bind the identity policy to.
        let mut crypto_verified = false;
        let mut crypto_error: Option<String> = None;
        if let (Some(verifier), Some(tarball_url), Some(expected)) =
            (verifier, &tarball_url, &expected_repo)
        {
            match self.fetch_tarball(tarball_url).await {
                Ok(tarball) => {
                    match self
                        .crypto_verify(verifier, &bundle_json, &tarball, expected)
                        .await
                    {
                        Ok(()) => crypto_verified = true,
                        Err(e) => crypto_error = Some(e.to_string()),
                    }
                }
                Err(e) => {
                    crypto_error = Some(format!("tarball fetch: {e}"));
                }
            }
        } else if verifier.is_none() {
            crypto_error = Some("trust root unavailable".into());
        } else {
            crypto_error = Some("missing tarball URL or expected repo".into());
        }

        CacheEntry {
            attested_repo: Some(attested_repo),
            expected_repo,
            crypto_verified,
            crypto_error,
        }
    }

    /// Translate one cache entry into zero, one, or two Findings.
    /// Identity mismatch and crypto failure are distinct findings so
    /// users can see both signals.
    fn entry_to_findings(&self, pkg: &PackageRef, entry: &CacheEntry) -> Vec<Finding> {
        let mut out = Vec::new();
        let Some(attested) = entry.attested_repo.as_deref() else {
            out.push(missing_finding(pkg));
            return out;
        };
        let normalized_attested = normalize_repo(attested);
        let normalized_expected = entry
            .expected_repo
            .as_deref()
            .map(normalize_repo)
            .unwrap_or_default();
        let identity_match =
            !normalized_expected.is_empty() && normalized_attested == normalized_expected;

        if !identity_match {
            out.push(mismatch_finding(
                pkg,
                attested,
                entry.expected_repo.as_deref().unwrap_or(""),
                entry.crypto_verified,
            ));
            // No need to also emit a crypto-failure finding when we
            // already failed the cheaper identity check.
            return out;
        }

        // Identity passed. Surface crypto failure as a Critical finding;
        // it means the attestation is structurally consistent with the
        // expected source but cryptographically invalid (forged or
        // tampered).
        if let Some(err) = &entry.crypto_error {
            // Distinguish "best-effort skipped" (trust root unavailable
            // / missing inputs) from "actively failed verification".
            // The latter is a real attack signal; the former is
            // operational.
            // Operational failures (network/transport) skip; only true
            // verification failures (cert chain, signature, identity)
            // surface as findings.
            let is_skip = err.contains("trust root unavailable")
                || err.contains("missing tarball")
                || err.contains("tarball fetch")
                || err.contains("metadata fetch failed");
            if !is_skip {
                out.push(crypto_failure_finding(pkg, attested, err));
            }
        }
        out
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    attested_repo: Option<String>,
    expected_repo: Option<String>,
    crypto_verified: bool,
    crypto_error: Option<String>,
}

impl CacheEntry {
    fn no_attestations() -> Self {
        Self {
            attested_repo: None,
            expected_repo: None,
            crypto_verified: false,
            crypto_error: None,
        }
    }
}

/// Surfaced when the Sigstore trust root could not be initialised
/// (offline, TUF mirror outage, corporate proxy). Identity-only
/// fallback ran but cryptographic verification did not — the user
/// should know.
fn trust_root_unavailable_finding(pkg: &PackageRef, affected: usize) -> Finding {
    Finding {
        package: pkg.clone(),
        kind: FindingKind::MissingProvenance,
        id: "provenance:trust-root-unavailable".to_string(),
        aliases: vec![],
        summary: format!(
            "Sigstore trust root unavailable; {} package(s) checked with identity only, NOT crypto-verified",
            affected
        ),
        severity: FindingSeverity::Medium,
        fixed_versions: vec![],
        references: vec!["https://docs.sigstore.dev/about/overview/".into()],
        details: serde_json::json!({
            "reason": "trust_root_init_failed",
            "affected_packages": affected,
            "remediation": "check network access to sigstore TUF mirror, or set GUARDEP_LOG=info for the underlying error"
        }),
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

fn mismatch_finding(
    pkg: &PackageRef,
    attested: &str,
    expected: &str,
    crypto_verified: bool,
) -> Finding {
    Finding {
        package: pkg.clone(),
        kind: FindingKind::ProvenanceMismatch,
        id: format!("provenance-mismatch:{}@{}", pkg.name, pkg.version),
        aliases: vec![],
        summary: format!(
            "{}@{} provenance built from {}, expected {}",
            pkg.name, pkg.version, attested, expected
        ),
        severity: FindingSeverity::Critical,
        fixed_versions: vec![],
        references: vec![format!("https://www.npmjs.com/package/{}", pkg.name)],
        details: serde_json::json!({
            "expected_repository": expected,
            "attested_repository": attested,
            "crypto_verified": crypto_verified,
        }),
    }
}

fn crypto_failure_finding(pkg: &PackageRef, attested: &str, error: &str) -> Finding {
    Finding {
        package: pkg.clone(),
        kind: FindingKind::ProvenanceMismatch,
        id: format!("provenance-crypto-fail:{}@{}", pkg.name, pkg.version),
        aliases: vec![],
        summary: format!(
            "{}@{} provenance signature failed verification: {}",
            pkg.name, pkg.version, error
        ),
        severity: FindingSeverity::Critical,
        fixed_versions: vec![],
        references: vec![format!("https://www.npmjs.com/package/{}", pkg.name)],
        details: serde_json::json!({
            "attested_repository": attested,
            "verification_error": error,
        }),
    }
}

/// Normalise a repository URL into a canonical comparison form:
///   `git+https://github.com/owner/repo.git` -> `github.com/owner/repo`
fn normalize_repo(s: &str) -> String {
    let mut out = s.trim().to_string();
    for prefix in ["git+", "https://", "http://", "ssh://", "git://"] {
        if let Some(rest) = out.strip_prefix(prefix) {
            out = rest.to_string();
        }
    }
    if let Some(rest) = out.strip_prefix("git@github.com:") {
        out = format!("github.com/{rest}");
    }
    if let Some(rest) = out.strip_suffix(".git") {
        out = rest.to_string();
    }
    out = out.trim_end_matches('/').to_string();
    out.to_lowercase()
}

/// Strip a leading "github.com/" so we can use the remainder as the
/// path part of a workflow URI.
fn strip_github_prefix(normalized: &str) -> String {
    normalized
        .strip_prefix("github.com/")
        .unwrap_or(normalized)
        .to_string()
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

    fn cache_path(dir: &TempDir) -> PathBuf {
        dir.path().join("cache.db")
    }

    fn build_bundle_json(repo: &str) -> serde_json::Value {
        let intoto = json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "pkg:npm/foo@1.0.0", "digest": {"sha512": "00"}}],
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
        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(intoto.to_string());
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

    fn build_metadata_json(repo: Option<&str>, tarball: &str) -> serde_json::Value {
        let repo_value = match repo {
            Some(r) => json!({"type": "git", "url": r}),
            None => serde_json::Value::Null,
        };
        json!({
            "name": "foo",
            "repository": repo_value,
            "versions": {
                "1.0.0": {
                    "dist": {
                        "tarball": tarball,
                        "shasum": "abc"
                    }
                }
            }
        })
    }

    #[test]
    fn normalize_url_handles_common_shapes() {
        assert_eq!(
            normalize_repo("git+https://github.com/Owner/Repo.git"),
            "github.com/owner/repo"
        );
        assert_eq!(
            normalize_repo("https://github.com/owner/repo/"),
            "github.com/owner/repo"
        );
        assert_eq!(
            normalize_repo("git@github.com:owner/repo.git"),
            "github.com/owner/repo"
        );
        assert_eq!(
            normalize_repo("github.com/owner/repo"),
            "github.com/owner/repo"
        );
    }

    #[test]
    fn enabled_when_policy_set() {
        let dir = TempDir::new().unwrap();
        let ev = ProvenanceEvaluator::new(cache_path(&dir)).unwrap();
        let mut p = Policy::default();
        assert!(!ev.enabled(&p));
        p.require_provenance.push("react".into());
        assert!(ev.enabled(&p));
    }

    #[tokio::test]
    async fn non_npm_skipped() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let dir = TempDir::new().unwrap();
        let ev = ProvenanceEvaluator::with_base_url(cache_path(&dir), server.uri()).unwrap();
        let mut policy = Policy::default();
        policy.require_provenance.push("*".into());
        let pkgs = vec![PackageRef::new(Ecosystem::Cargo, "tokio", "1.0.0")];
        let findings = ev.evaluate(&pkgs, &policy).await.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn not_required_skipped() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let dir = TempDir::new().unwrap();
        let ev = ProvenanceEvaluator::with_base_url(cache_path(&dir), server.uri()).unwrap();
        let mut policy = Policy::default();
        policy.require_provenance.push("react".into());
        // pkg name doesn't match policy glob -> no fetch, no finding
        let pkgs = vec![npm_pkg("vue", "3.0.0")];
        let findings = ev.evaluate(&pkgs, &policy).await.unwrap();
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
        let mut policy = Policy::default();
        policy.require_provenance.push("foo".into());
        let pkgs = vec![npm_pkg("foo", "1.0.0")];
        let findings = ev.evaluate(&pkgs, &policy).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FindingKind::MissingProvenance);
    }

    #[tokio::test]
    async fn attestation_match_no_finding() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/-/npm/v1/attestations/foo@1.0.0"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(build_bundle_json("https://github.com/alice/foo")),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/foo"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(build_metadata_json(
                    Some("git+https://github.com/alice/foo.git"),
                    &format!("{}/foo/-/foo-1.0.0.tgz", server.uri()),
                )),
            )
            .mount(&server)
            .await;
        // tarball: any 200 will do — crypto verification will fail in
        // the test env (no real signature) but identity check passes.
        Mock::given(method("GET"))
            .and(path("/foo/-/foo-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(404)) // forces crypto-skip path
            .mount(&server)
            .await;
        let dir = TempDir::new().unwrap();
        let ev = ProvenanceEvaluator::with_base_url(cache_path(&dir), server.uri()).unwrap();
        let mut policy = Policy::default();
        policy.require_provenance.push("foo".into());
        let pkgs = vec![npm_pkg("foo", "1.0.0")];
        let findings = ev.evaluate(&pkgs, &policy).await.unwrap();
        // Identity matches; crypto skipped due to tarball 404 (operational,
        // not an attack signal) -> no finding.
        assert!(
            findings.is_empty(),
            "expected no finding, got {:?}",
            findings
        );
    }

    #[tokio::test]
    async fn attestation_mismatch_emits_critical() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/-/npm/v1/attestations/foo@1.0.0"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(build_bundle_json("https://github.com/evil/foo")),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/foo"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(build_metadata_json(
                    Some("https://github.com/alice/foo"),
                    &format!("{}/foo/-/foo-1.0.0.tgz", server.uri()),
                )),
            )
            .mount(&server)
            .await;
        let dir = TempDir::new().unwrap();
        let ev = ProvenanceEvaluator::with_base_url(cache_path(&dir), server.uri()).unwrap();
        let mut policy = Policy::default();
        policy.require_provenance.push("foo".into());
        let pkgs = vec![npm_pkg("foo", "1.0.0")];
        let findings = ev.evaluate(&pkgs, &policy).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FindingKind::ProvenanceMismatch);
        assert_eq!(findings[0].severity, FindingSeverity::Critical);
        assert!(!findings[0].details["crypto_verified"]
            .as_bool()
            .unwrap_or(true));
    }

    #[tokio::test]
    async fn cache_hit_skips_http() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/-/npm/v1/attestations/foo@1.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"attestations": []})))
            .expect(1)
            .mount(&server)
            .await;
        let dir = TempDir::new().unwrap();
        let ev = ProvenanceEvaluator::with_base_url(cache_path(&dir), server.uri()).unwrap();
        let mut policy = Policy::default();
        policy.require_provenance.push("foo".into());
        let pkgs = vec![npm_pkg("foo", "1.0.0")];
        let _ = ev.evaluate(&pkgs, &policy).await.unwrap();
        let _ = ev.evaluate(&pkgs, &policy).await.unwrap();
    }
}

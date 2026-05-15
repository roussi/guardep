//! Package risk intelligence evaluator.
//!
//! Pulls per-package metadata from the npm registry and computes a 0-100
//! risk score using simple supply-chain heuristics: single-maintainer,
//! few versions, fresh publish, abandonment, typosquat candidates,
//! missing source repository. Results are cached in SQLite to avoid
//! hammering the registry on every run.

use crate::ecosystem::{Ecosystem, PackageRef};
use crate::finding::{Evaluator, Finding, FindingKind, FindingSeverity};
use crate::policy::Policy;
use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

/// Top ~200 npm packages by weekly downloads. Used as the typosquat
/// reference set: a package whose Levenshtein distance to one of these
/// is <= 2 is flagged. Includes packages that themselves frequently
/// appear in transitive trees (e.g. cypress, chai, acorn) so they are
/// recognised as legitimate rather than typosquat candidates.
const TOP_PACKAGES: &[&str] = &[
    // Core runtime / utility
    "react",
    "react-dom",
    "lodash",
    "axios",
    "express",
    "chalk",
    "commander",
    "debug",
    "moment",
    "request",
    "tslib",
    "semver",
    "glob",
    "async",
    "uuid",
    "dotenv",
    "typescript",
    "jest",
    "eslint",
    "prettier",
    "webpack",
    "babel-core",
    "mocha",
    "underscore",
    "jquery",
    "bluebird",
    "body-parser",
    "mongoose",
    "cors",
    "fs-extra",
    // Build tooling
    "vite",
    "rollup",
    "esbuild",
    "parcel",
    "gulp",
    "grunt",
    "browserify",
    "ts-node",
    "tsx",
    "swc",
    "rspack",
    "tsup",
    "tsdown",
    // React ecosystem
    "react-router",
    "react-router-dom",
    "redux",
    "react-redux",
    "next",
    "gatsby",
    "remix",
    "vue",
    "vue-router",
    "vuex",
    "pinia",
    "svelte",
    "angular",
    "preact",
    "solid-js",
    // HTTP / async
    "node-fetch",
    "got",
    "ky",
    "superagent",
    "isomorphic-fetch",
    "ws",
    "socket.io",
    "socket.io-client",
    "engine.io",
    // Test frameworks
    "jest",
    "vitest",
    "mocha",
    "chai",
    "sinon",
    "ava",
    "tap",
    "tape",
    "cypress",
    "playwright",
    "puppeteer",
    "karma",
    "jasmine",
    "@testing-library/react",
    "@testing-library/jest-dom",
    "supertest",
    // Linters / formatters
    "eslint",
    "prettier",
    "stylelint",
    "tslint",
    "biome",
    "rome",
    "@typescript-eslint/parser",
    "@typescript-eslint/eslint-plugin",
    // Bundler plugins
    "webpack-cli",
    "webpack-dev-server",
    "html-webpack-plugin",
    "mini-css-extract-plugin",
    "css-loader",
    "style-loader",
    "babel-loader",
    "ts-loader",
    "file-loader",
    "postcss-loader",
    "@babel/core",
    "@babel/preset-env",
    "@babel/preset-react",
    "@babel/preset-typescript",
    "@babel/runtime",
    // CSS
    "tailwindcss",
    "postcss",
    "autoprefixer",
    "sass",
    "less",
    "stylus",
    "styled-components",
    "emotion",
    "@emotion/react",
    "@emotion/styled",
    // Server frameworks
    "fastify",
    "koa",
    "hapi",
    "nest",
    "@nestjs/core",
    "@nestjs/common",
    "express-session",
    "passport",
    "jsonwebtoken",
    "bcrypt",
    "bcryptjs",
    // Date / utility
    "date-fns",
    "dayjs",
    "luxon",
    "rxjs",
    "ramda",
    // Validation
    "zod",
    "yup",
    "joi",
    "ajv",
    "validator",
    "class-validator",
    // Database
    "pg",
    "mysql",
    "mysql2",
    "sqlite3",
    "redis",
    "ioredis",
    "knex",
    "prisma",
    "@prisma/client",
    "sequelize",
    "typeorm",
    "mongodb",
    // Files / streams
    "fs-extra",
    "graceful-fs",
    "rimraf",
    "del",
    "globby",
    "fast-glob",
    "minimatch",
    "chokidar",
    "tar",
    "archiver",
    "unzipper",
    // CLI tooling
    "yargs",
    "minimist",
    "inquirer",
    "ora",
    "boxen",
    "figlet",
    "cli-table",
    // Process / utilities
    "execa",
    "shelljs",
    "cross-spawn",
    "spawn-async",
    "node-pty",
    "dotenv-cli",
    "concurrently",
    "npm-run-all",
    "wait-on",
    // AST / parsing
    "acorn",
    "espree",
    "esprima",
    "babel-parser",
    "@babel/parser",
    "esbuild-wasm",
    "estree-walker",
    "magic-string",
    // Logging
    "winston",
    "bunyan",
    "pino",
    "morgan",
    "log4js",
    // GraphQL
    "graphql",
    "apollo-server",
    "@apollo/client",
    "graphql-tag",
    // Mocking / fixtures
    "nock",
    "msw",
    "faker",
    "@faker-js/faker",
    "casual",
    // Markdown / parsing
    "marked",
    "markdown-it",
    "remark",
    "rehype",
    "highlight.js",
    "shiki",
    "prismjs",
    // Misc heavy hitters
    "qs",
    "querystring",
    "form-data",
    "mime",
    "mime-types",
    "colors",
    "kleur",
    "picocolors",
    "ansi-colors",
    "ansi-styles",
    "strip-ansi",
    "wrap-ansi",
    "string-width",
    "deep-equal",
    "deepmerge",
    "lodash.merge",
    "lodash.get",
    "object-assign",
    "extend",
    "merge-descriptors",
    "uuid",
    "nanoid",
    "shortid",
    "cuid",
    // Crypto / parsing
    "asn1",
    "asn1.js",
    "tweetnacl",
    "node-forge",
    "crypto-js",
    "bn.js",
    "elliptic",
    "hash.js",
    "sha.js",
    // Iconography / fonts
    "lucide",
    "lucide-react",
    "lucide-vue-next",
    "react-icons",
    "@fortawesome/fontawesome-free",
    "feather-icons",
    // Bundlers' workspace deps
    "rollup-plugin-typescript2",
    "@rollup/plugin-node-resolve",
    "@rollup/plugin-commonjs",
    "vite-plugin-vue",
    // Worker / concurrency
    "worker-threads",
    "piscina",
    "comlink",
];

/// Substring exclusions: when a candidate name CONTAINS a top-pkg name
/// (or vice versa), it is almost certainly a legitimate ecosystem
/// package (`chai-as-promised`, `cypress-axe`, `react-router`) rather
/// than a typosquat. Keeps false positives down without sacrificing
/// real typosquat detection (which is character-substitution, not
/// substring containment).
fn is_legit_relative(name: &str, top: &str) -> bool {
    if name == top {
        return true;
    }
    if name.contains(top) || top.contains(name) {
        return true;
    }
    // Common compositional patterns
    if name.starts_with(&format!("{top}-"))
        || name.starts_with(&format!("{top}."))
        || name.ends_with(&format!("-{top}"))
        || name.ends_with(&format!(".{top}"))
    {
        return true;
    }
    false
}

const DEFAULT_BASE_URL: &str = "https://registry.npmjs.org";

/// Reduced metadata snapshot: what we cache and score on.
///
/// Public to support the validation-set integration test in `tests/`.
/// External callers should not depend on the field shape stability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelSnapshot {
    pub maintainer_count: usize,
    pub version_count: usize,
    /// RFC3339 publish time of the *installed* version, if known.
    pub installed_published_at: Option<String>,
    /// RFC3339 last-modified time of the package as a whole.
    pub modified_at: Option<String>,
    /// dist-tags.latest, if present.
    pub latest_tag: Option<String>,
    /// RFC3339 publish time of the dist-tags.latest version, if known.
    pub latest_published_at: Option<String>,
    /// Whether a `repository` field of any shape was present.
    pub has_repository: bool,
    /// Weekly download count from the npm downloads API. None when the
    /// lookup failed or hasn't been performed yet. Used as a reputation
    /// cross-check to suppress typosquat false positives on legitimately
    /// popular packages whose names happen to be Lev-close to top-list
    /// entries (e.g. `cypress` vs `express`).
    #[serde(default)]
    pub weekly_downloads: Option<u64>,
}

pub struct IntelEvaluator {
    cache_path: PathBuf,
    http: reqwest::Client,
    base_url: String,
}

impl IntelEvaluator {
    pub fn new(cache_path: PathBuf) -> Result<Self> {
        Self::with_base_url(cache_path, DEFAULT_BASE_URL.to_string())
    }

    /// Test helper: override the registry base URL.
    pub fn with_base_url(cache_path: PathBuf, base_url: String) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("guardep-intel/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build reqwest client")?;
        Ok(Self {
            cache_path,
            http,
            base_url,
        })
    }

    fn open_cache(&self, ttl_hours: u64) -> Result<crate::cache::KvCache> {
        crate::cache::KvCache::open(&self.cache_path, ttl_hours)
    }

    fn cache_get(cache: &crate::cache::KvCache, package: &str) -> Result<Option<IntelSnapshot>> {
        let Some(payload) = cache.get("intel", package)? else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_str(&payload)?))
    }

    fn cache_put(cache: &crate::cache::KvCache, package: &str, snap: &IntelSnapshot) -> Result<()> {
        let payload = serde_json::to_string(snap)?;
        cache.put("intel", package, &payload)
    }

    async fn fetch(&self, name: &str) -> Result<IntelSnapshot> {
        // npm registry accepts `@scope/pkg` directly in the path.
        let url = format!("{}/{}", self.base_url.trim_end_matches('/'), name);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        if !resp.status().is_success() {
            anyhow::bail!("registry returned {} for {}", resp.status(), name);
        }
        let body: Value = resp.json().await.context("parse registry JSON")?;
        let mut snap = snapshot_from_metadata(&body);

        // Best-effort downloads lookup. The downloads API lives at a
        // different host and only resolves unscoped names; failures are
        // silently ignored, leaving `weekly_downloads = None`.
        if !name.starts_with('@') {
            snap.weekly_downloads = self.fetch_weekly_downloads(name).await.ok();
        }
        Ok(snap)
    }

    async fn fetch_weekly_downloads(&self, name: &str) -> Result<u64> {
        let url = format!(
            "{}/downloads/point/last-week/{}",
            self.downloads_base_url(),
            name
        );
        let resp = self.http.get(&url).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("downloads API returned {}", resp.status());
        }
        let body: Value = resp.json().await?;
        body.get("downloads")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow::anyhow!("missing downloads field"))
    }

    /// The npm downloads API host. Defaults to api.npmjs.org but uses
    /// the override base_url when it's clearly a test fixture (i.e.
    /// the registry base_url is a non-default host like 127.0.0.1 used
    /// by wiremock). Tests serve both /<pkg> and /downloads/...
    /// endpoints from the same MockServer for simplicity.
    fn downloads_base_url(&self) -> String {
        if self.base_url.contains("npmjs.org") {
            "https://api.npmjs.org".to_string()
        } else {
            self.base_url.trim_end_matches('/').to_string()
        }
    }
}

#[async_trait]
impl Evaluator for IntelEvaluator {
    fn name(&self) -> &'static str {
        "intel"
    }

    fn enabled(&self, _policy: &Policy) -> bool {
        true
    }

    async fn evaluate(&self, packages: &[PackageRef], policy: &Policy) -> Result<Vec<Finding>> {
        use futures::stream::{self, StreamExt};
        const FETCH_CONCURRENCY: usize = 32;

        let cache = self.open_cache(policy.cache_refresh_hours)?;

        // Phase 1: cache lookup, sequential against SQLite (fast).
        let mut hits: Vec<(PackageRef, IntelSnapshot)> = Vec::new();
        let mut misses: Vec<PackageRef> = Vec::new();
        for pkg in packages {
            if pkg.ecosystem != Ecosystem::Npm {
                continue;
            }
            match Self::cache_get(&cache, &pkg.name) {
                Ok(Some(snap)) => hits.push((pkg.clone(), snap)),
                Ok(None) => misses.push(pkg.clone()),
                Err(e) => tracing::warn!("intel cache read failed for {}: {e}", pkg.name),
            }
        }

        // Phase 2: parallel HTTP fetches for misses, bounded concurrency.
        // 32 concurrent registry requests is well within polite limits and
        // collapses ~700 sequential fetches from ~35s to ~1-2s.
        let fetched: Vec<(PackageRef, IntelSnapshot)> = stream::iter(misses)
            .map(|pkg| async move {
                match self.fetch(&pkg.name).await {
                    Ok(s) => Some((pkg, s)),
                    Err(e) => {
                        tracing::warn!("intel fetch failed for {}: {e}", pkg.name);
                        None
                    }
                }
            })
            .buffer_unordered(FETCH_CONCURRENCY)
            .filter_map(|opt| async move { opt })
            .collect()
            .await;

        // Phase 3: write fetched snapshots back to cache.
        for (pkg, snap) in &fetched {
            if let Err(e) = Self::cache_put(&cache, &pkg.name, snap) {
                tracing::warn!("intel cache put failed for {}: {e}", pkg.name);
            }
        }

        // Phase 4: score everything.
        let mut findings: Vec<Finding> = Vec::new();
        for (pkg, snap) in hits.iter().chain(fetched.iter()) {
            let installed_published_at = snap.installed_published_at.clone();
            if let Some(f) = score_package(pkg, snap, policy, installed_published_at) {
                findings.push(f);
            }
        }
        Ok(findings)
    }
}

/// Extract just the fields we care about from a full npm metadata document.
fn snapshot_from_metadata(body: &Value) -> IntelSnapshot {
    let maintainer_count = body
        .get("maintainers")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);

    let versions = body.get("versions").and_then(Value::as_object);
    let version_count = versions.map(|m| m.len()).unwrap_or(0);

    let latest_tag = body
        .get("dist-tags")
        .and_then(|d| d.get("latest"))
        .and_then(Value::as_str)
        .map(|s| s.to_string());

    let time = body.get("time").and_then(Value::as_object);

    let modified_at = time
        .and_then(|t| t.get("modified"))
        .and_then(Value::as_str)
        .map(|s| s.to_string());

    let latest_published_at = match (&latest_tag, time) {
        (Some(tag), Some(t)) => t.get(tag).and_then(Value::as_str).map(|s| s.to_string()),
        _ => None,
    };

    // We don't know the installed version at snapshot time. As a proxy,
    // capture the latest version's publish time and let scoring use
    // whichever timestamp is present.
    let installed_published_at = latest_published_at.clone();

    let has_repository = body
        .get("repository")
        .map(|r| match r {
            Value::String(s) => !s.is_empty(),
            Value::Object(o) => o
                .get("url")
                .and_then(Value::as_str)
                .map(|u| !u.is_empty())
                .unwrap_or(false),
            _ => false,
        })
        .unwrap_or(false);

    IntelSnapshot {
        maintainer_count,
        version_count,
        installed_published_at,
        modified_at,
        latest_tag,
        latest_published_at,
        has_repository,
        weekly_downloads: None,
    }
}

fn parse_ts(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn days_since(ts: &str, now: DateTime<Utc>) -> Option<i64> {
    let dt = parse_ts(ts)?;
    Some((now - dt).num_days())
}

/// Reasons in priority order; first match wins for the `id` slug.
/// `single-maintainer` is intentionally last because it's the median
/// state of npm and almost never the most actionable reason in a
/// composite finding.
const REASON_PRIORITY: &[&str] = &[
    "typosquat",
    "fresh-publish",
    "abandoned",
    "few-versions",
    "no-source",
    "very-fresh-latest",
    "single-maintainer",
];

fn primary_reason(reasons: &[String]) -> &str {
    for candidate in REASON_PRIORITY {
        if reasons.iter().any(|r| r == candidate) {
            return candidate;
        }
    }
    reasons.first().map(|s| s.as_str()).unwrap_or("risk")
}

/// Public scoring entrypoint for validation-set integration tests.
/// External callers should treat this as test-only API.
pub fn score_package_for_test(
    pkg: &PackageRef,
    snap: &IntelSnapshot,
    policy: &Policy,
) -> Option<Finding> {
    score_package(pkg, snap, policy, snap.installed_published_at.clone())
}

fn score_package(
    pkg: &PackageRef,
    snap: &IntelSnapshot,
    policy: &Policy,
    installed_published_at: Option<String>,
) -> Option<Finding> {
    let now = Utc::now();
    let mut score: i32 = 0;
    let mut reasons: Vec<String> = Vec::new();

    if snap.maintainer_count == 1 {
        score += 25;
        reasons.push("single-maintainer".into());
    }

    if snap.version_count > 0 && snap.version_count <= 5 {
        score += 15;
        reasons.push("few-versions".into());
    }

    let published_days_ago = installed_published_at
        .as_deref()
        .and_then(|ts| days_since(ts, now));
    if let Some(days) = published_days_ago {
        if days >= 0 && (days as u32) < policy.warn_if_fresh_publish_days {
            score += 20;
            reasons.push("fresh-publish".into());
        }
    }

    let modified_days_ago = snap
        .modified_at
        .as_deref()
        .and_then(|ts| days_since(ts, now));
    if let Some(days) = modified_days_ago {
        if days >= 0 && (days as u32) > policy.warn_if_unmaintained_days {
            score += 15;
            reasons.push("abandoned".into());
        }
    }

    // Typosquat detection, suppressed when the candidate is itself a
    // popular package (reputation cross-check). E.g. `cypress` is
    // Lev-distance 2 from `express` but has 7M+ weekly downloads.
    let typosquat_target = typosquat_candidate(&pkg.name);
    let typosquat_target = match typosquat_target {
        Some(t) if !looks_legitimately_popular(snap) => Some(t),
        _ => None,
    };
    if typosquat_target.is_some() {
        score += 30;
        reasons.push("typosquat".into());
    }

    if !snap.has_repository {
        score += 10;
        reasons.push("no-source".into());
    }

    let latest_published_days_ago = snap
        .latest_published_at
        .as_deref()
        .and_then(|ts| days_since(ts, now));
    if let Some(days) = latest_published_days_ago {
        if (0..1).contains(&days) {
            score += 5;
            reasons.push("very-fresh-latest".into());
        }
    }

    let score = score.clamp(0, 100) as u8;

    // Single-maintainer is the median state of npm — taken alone it's
    // weak signal, so we emit it at `Info` and let the display
    // threshold filter it out. Users who lower `--severity info` still
    // see it; everyone else doesn't.
    let only_reason_is_single_maintainer = reasons.len() == 1 && reasons[0] == "single-maintainer";

    let mut severity = if only_reason_is_single_maintainer {
        FindingSeverity::Info
    } else {
        match score {
            s if s >= 80 => FindingSeverity::Critical,
            s if s >= 60 => FindingSeverity::High,
            s if s >= 40 => FindingSeverity::Medium,
            s if s >= 20 => FindingSeverity::Low,
            _ => return None,
        }
    };

    if policy.block_typosquats
        && reasons.iter().any(|r| r == "typosquat")
        && (severity as u8) < (FindingSeverity::High as u8)
    {
        severity = FindingSeverity::High;
    }

    let primary = primary_reason(&reasons).to_string();
    let summary = format!(
        "Risk score {} ({:?}): {}",
        score,
        severity,
        reasons.join(", ")
    );

    let typosquat_of_value = match typosquat_target {
        Some(t) => Value::String(t.to_string()),
        None => Value::Null,
    };

    let details = serde_json::json!({
        "score": score,
        "reasons": reasons,
        "maintainers": snap.maintainer_count,
        "version_count": snap.version_count,
        "published_days_ago": published_days_ago,
        "modified_days_ago": modified_days_ago,
        "typosquat_of": typosquat_of_value,
    });

    Some(Finding {
        package: pkg.clone(),
        kind: FindingKind::RiskScore,
        id: format!("risk:{}:{}", primary, pkg.name),
        aliases: vec![],
        summary,
        severity,
        fixed_versions: vec![],
        references: vec![format!("https://www.npmjs.com/package/{}", pkg.name)],
        details,
    })
}

/// Levenshtein with early bail when length difference > 2.
pub(crate) fn lev_distance(a: &str, b: &str) -> usize {
    let a_bytes: Vec<char> = a.chars().collect();
    let b_bytes: Vec<char> = b.chars().collect();
    let la = a_bytes.len();
    let lb = b_bytes.len();
    if (la as i64 - lb as i64).abs() > 2 {
        return usize::MAX;
    }
    if la == 0 {
        return lb;
    }
    if lb == 0 {
        return la;
    }
    let mut prev: Vec<usize> = (0..=lb).collect();
    let mut curr: Vec<usize> = vec![0; lb + 1];
    for i in 1..=la {
        curr[0] = i;
        for j in 1..=lb {
            let cost = if a_bytes[i - 1] == b_bytes[j - 1] {
                0
            } else {
                1
            };
            let del = prev[j] + 1;
            let ins = curr[j - 1] + 1;
            let sub = prev[j - 1] + cost;
            curr[j] = del.min(ins).min(sub);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[lb]
}

/// Maximum allowed Lev distance, scaled by name length. Short names
/// (4-5 chars) collide too easily under distance 2 (`pend` vs `pino`
/// is distance 2, `temp` vs `tape` is distance 2). Require an exact
/// match for very short names; otherwise allow up to distance 2 only
/// when the names are at least 6 characters.
fn max_distance_for(len: usize) -> usize {
    match len {
        0..=4 => 1,
        5 => 1,
        _ => 2,
    }
}

fn typosquat_candidate(name: &str) -> Option<&'static str> {
    if name.len() < 5 {
        return None;
    }
    if name.starts_with('@') {
        return None;
    }
    if TOP_PACKAGES.contains(&name) {
        return None;
    }
    let max_d = max_distance_for(name.len());
    for top in TOP_PACKAGES {
        // Names with very different lengths can't be typo-related.
        if (top.len() as i64 - name.len() as i64).unsigned_abs() as usize > max_d {
            continue;
        }
        // Skip when the candidate is a legit relative of `top`
        // (compositional naming like `react-router`, substring overlap
        // like `cypress-axe`).
        if is_legit_relative(name, top) {
            return None;
        }
        let d = lev_distance(name, top);
        if d == 0 {
            return None; // exact match shouldn't get flagged
        }
        if d <= max_d {
            return Some(top);
        }
    }
    None
}

/// Reputation cross-check. Before flagging a typosquat, decide whether
/// the candidate is itself a legitimate package whose name happens to
/// be Lev-close to a top-list entry. Returns true when the typosquat
/// flag should be SUPPRESSED.
///
/// Signals (any one suppresses):
///   - Weekly downloads >= 100k (when the npm downloads API works)
///   - Version count >= 25 AND has a repository (mature published pkg)
///   - Multiple maintainers (>= 3) AND has a repository
///
/// The npm downloads API is currently flaky (returns a JSON-schema
/// placeholder for some queries) so we rely on the structural proxies
/// from the registry document, which we always have.
pub(crate) fn looks_legitimately_popular(snap: &IntelSnapshot) -> bool {
    if snap.weekly_downloads.unwrap_or(0) >= 100_000 {
        return true;
    }
    if snap.version_count >= 15 && snap.has_repository {
        return true;
    }
    if snap.maintainer_count >= 2 && snap.has_repository {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use tempfile::TempDir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn npm(name: &str, version: &str) -> PackageRef {
        PackageRef::new(Ecosystem::Npm, name, version)
    }

    fn cache_path(dir: &TempDir) -> PathBuf {
        dir.path().join("cache.db")
    }

    fn metadata(
        maintainers: usize,
        versions: &[&str],
        latest: &str,
        modified: &str,
        latest_published: &str,
        installed: Option<(&str, &str)>,
        repository: bool,
    ) -> Value {
        let mut maint = Vec::new();
        for i in 0..maintainers {
            maint.push(serde_json::json!({"name": format!("user{i}")}));
        }
        let mut versions_obj = serde_json::Map::new();
        for v in versions {
            versions_obj.insert((*v).to_string(), serde_json::json!({}));
        }
        let mut time = serde_json::Map::new();
        time.insert("modified".into(), Value::String(modified.into()));
        time.insert(latest.to_string(), Value::String(latest_published.into()));
        if let Some((v, ts)) = installed {
            time.insert(v.into(), Value::String(ts.into()));
        }
        let repo = if repository {
            serde_json::json!({"type": "git", "url": "https://github.com/x/y"})
        } else {
            Value::Null
        };
        let mut root = serde_json::json!({
            "maintainers": maint,
            "versions": versions_obj,
            "dist-tags": {"latest": latest},
            "time": time,
        });
        if !repo.is_null() {
            root.as_object_mut()
                .unwrap()
                .insert("repository".into(), repo);
        }
        root
    }

    fn rfc3339_days_ago(days: i64) -> String {
        let dt = Utc::now() - Duration::days(days);
        dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }

    #[test]
    fn lev_distance_basic() {
        assert_eq!(lev_distance("loadsh", "lodash"), 2);
        assert_eq!(lev_distance("react", "reat"), 1);
        assert_eq!(lev_distance("axios", "axioss"), 1);
        assert_eq!(lev_distance("foo", "foo"), 0);
    }

    #[test]
    fn typosquat_detection() {
        assert!(typosquat_candidate("loadsh").is_some());
        assert!(typosquat_candidate("lodash").is_none());
        assert!(typosquat_candidate("@scope/loadsh").is_none());
        assert!(typosquat_candidate("ax").is_none()); // too short
    }

    fn make_snapshot(
        maintainers: usize,
        versions: usize,
        installed: Option<String>,
        modified: Option<String>,
        latest: Option<String>,
        latest_published: Option<String>,
        has_repo: bool,
    ) -> IntelSnapshot {
        IntelSnapshot {
            maintainer_count: maintainers,
            version_count: versions,
            installed_published_at: installed,
            modified_at: modified,
            latest_tag: latest,
            latest_published_at: latest_published,
            has_repository: has_repo,
            weekly_downloads: None,
        }
    }

    #[test]
    fn severity_boundaries() {
        let policy = Policy::default();

        // 79: maintainers=1 (25) + few-versions (15) + fresh-publish (20)
        // + abandoned (15) + no-source (10) = 85, reduce abandoned/no-source.
        // Weights are fixed, so validate the boundary mapping function-
        // style by synthesising snapshots and checking the resulting
        // severity.

        // 80 -> Critical: 25 + 30 (typosquat) + 15 + 10 = 80. Use a
        // typosquat name to land exactly there.
        let snap_80 = make_snapshot(1, 3, None, None, None, None, false);
        // loadsh: typosquat (+30), single-maintainer (+25), few-versions (+15), no-source (+10) = 80
        let pkg = npm("loadsh", "1.0.0");
        let f = score_package(&pkg, &snap_80, &policy, None).expect("emit");
        assert_eq!(f.severity, FindingSeverity::Critical);

        // 65 -> High (just normal package, no typosquat):
        // single-maintainer (25) + few-versions (15) + abandoned (15) + no-source (10) = 65
        let old = (Utc::now() - Duration::days(policy.warn_if_unmaintained_days as i64 + 30))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let snap_65 = make_snapshot(1, 3, None, Some(old.clone()), None, None, false);
        let pkg = npm("safepkgname", "1.0.0");
        let f = score_package(&pkg, &snap_65, &policy, None).expect("emit");
        assert_eq!(f.severity, FindingSeverity::High);
        assert!(f.details["score"].as_u64().unwrap() < 80);
        assert!(f.details["score"].as_u64().unwrap() >= 60);

        // Medium: 40-59. single-maintainer (25) + few-versions (15) = 40
        let snap_40 = make_snapshot(1, 3, None, None, None, None, true);
        let pkg = npm("safepkgname", "1.0.0");
        let f = score_package(&pkg, &snap_40, &policy, None).expect("emit");
        assert_eq!(f.severity, FindingSeverity::Medium);

        // single-maintainer alone (weight 25) emits at Info regardless of
        // policy. Display threshold (in FindingsReport) decides whether
        // it shows up in the user-facing table.
        let snap_25 = make_snapshot(1, 50, None, None, None, None, true);
        let pkg = npm("safepkgname", "1.0.0");
        let f = score_package(&pkg, &snap_25, &policy, None)
            .expect("single-maintainer alone is emitted at Info");
        assert_eq!(f.severity, FindingSeverity::Info);

        // <20 -> no emit. Healthy: 5 maintainers, lots of versions, repo present
        let snap_low = make_snapshot(5, 50, None, None, None, None, true);
        let pkg = npm("safepkgname", "1.0.0");
        assert!(score_package(&pkg, &snap_low, &policy, None).is_none());
    }

    #[tokio::test]
    async fn single_maintainer_fresh_publish() {
        let server = MockServer::start().await;
        let yesterday = rfc3339_days_ago(1);
        let body = metadata(
            1,
            &["1.0.0", "1.0.1"],
            "1.0.1",
            &yesterday,
            &yesterday,
            Some(("1.0.0", &yesterday)),
            true,
        );
        Mock::given(method("GET"))
            .and(path("/freshpkg"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let dir = TempDir::new().unwrap();
        let evaluator = IntelEvaluator::with_base_url(cache_path(&dir), server.uri()).unwrap();
        let policy = Policy::default();
        let pkgs = vec![npm("freshpkg", "1.0.0")];
        let findings = evaluator.evaluate(&pkgs, &policy).await.unwrap();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(
            f.severity >= FindingSeverity::Medium,
            "expected at least Medium, got {:?} score={}",
            f.severity,
            f.details["score"]
        );
        let reasons = f.details["reasons"].as_array().unwrap();
        let strs: Vec<&str> = reasons.iter().map(|r| r.as_str().unwrap()).collect();
        assert!(strs.contains(&"single-maintainer"));
        assert!(strs.contains(&"fresh-publish"));
    }

    #[tokio::test]
    async fn cache_hit_skips_http() {
        let server = MockServer::start().await;
        let yesterday = rfc3339_days_ago(1);
        let body = metadata(
            1,
            &["1.0.0"],
            "1.0.0",
            &yesterday,
            &yesterday,
            Some(("1.0.0", &yesterday)),
            true,
        );
        Mock::given(method("GET"))
            .and(path("/cachedpkg"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;

        let dir = TempDir::new().unwrap();
        let evaluator = IntelEvaluator::with_base_url(cache_path(&dir), server.uri()).unwrap();
        let policy = Policy::default();
        let pkgs = vec![npm("cachedpkg", "1.0.0")];
        let _ = evaluator.evaluate(&pkgs, &policy).await.unwrap();
        let _ = evaluator.evaluate(&pkgs, &policy).await.unwrap();
        // wiremock verifies expect(1) on Drop.
    }

    #[tokio::test]
    async fn registry_error_doesnt_fail() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/badpkg"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let yesterday = rfc3339_days_ago(1);
        let good_body = metadata(
            1,
            &["1.0.0", "1.0.1"],
            "1.0.1",
            &yesterday,
            &yesterday,
            Some(("1.0.0", &yesterday)),
            true,
        );
        Mock::given(method("GET"))
            .and(path("/goodpkg"))
            .respond_with(ResponseTemplate::new(200).set_body_json(good_body))
            .mount(&server)
            .await;

        let dir = TempDir::new().unwrap();
        let evaluator = IntelEvaluator::with_base_url(cache_path(&dir), server.uri()).unwrap();
        let policy = Policy::default();
        let pkgs = vec![npm("badpkg", "1.0.0"), npm("goodpkg", "1.0.0")];
        let findings = evaluator.evaluate(&pkgs, &policy).await.unwrap();
        // Only goodpkg should produce a finding; the bad one is skipped.
        assert!(findings.iter().any(|f| f.package.name == "goodpkg"));
        assert!(!findings.iter().any(|f| f.package.name == "badpkg"));
    }

    #[tokio::test]
    async fn non_npm_skipped() {
        let dir = TempDir::new().unwrap();
        let evaluator =
            IntelEvaluator::with_base_url(cache_path(&dir), "http://127.0.0.1:1".to_string())
                .unwrap();
        let policy = Policy::default();
        let pkgs = vec![PackageRef::new(Ecosystem::Cargo, "serde", "1.0.0")];
        let findings = evaluator.evaluate(&pkgs, &policy).await.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn block_typosquats_forces_high() {
        let server = MockServer::start().await;
        // Suspicious metadata so the popularity cross-check does NOT
        // suppress the typosquat: single maintainer, few versions,
        // no repository.
        let yesterday = rfc3339_days_ago(1);
        let body = metadata(
            1,
            &["1.0.0", "1.0.1"],
            "1.0.1",
            &yesterday,
            &yesterday,
            Some(("1.0.0", &yesterday)),
            false,
        );
        Mock::given(method("GET"))
            .and(path("/loadsh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let dir = TempDir::new().unwrap();
        let evaluator = IntelEvaluator::with_base_url(cache_path(&dir), server.uri()).unwrap();
        let mut policy = Policy::default();
        policy.block_typosquats = true;
        let pkgs = vec![npm("loadsh", "1.0.0")];
        let findings = evaluator.evaluate(&pkgs, &policy).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].severity >= FindingSeverity::High,
            "expected at least High, got {:?}",
            findings[0].severity
        );
        assert_eq!(findings[0].details["typosquat_of"].as_str(), Some("lodash"));
    }

    /// Single-maintainer-only is emitted at Info severity. It's noisy
    /// (>50% of npm packages have one maintainer) so the display
    /// threshold (`min_display_severity = Low` by default) hides it.
    /// `--severity info` surfaces it for users who want the full audit.
    #[test]
    fn single_maintainer_only_emits_info() {
        let snap = make_snapshot(1, 50, None, None, None, None, true);
        let pkg = npm("solo", "1.0.0");
        let policy = Policy::default();
        let f = score_package(&pkg, &snap, &policy, None).expect("emit at Info");
        assert_eq!(f.severity, FindingSeverity::Info);
        assert_eq!(f.details["reasons"][0].as_str(), Some("single-maintainer"));
    }

    /// When single-maintainer is combined with another reason (e.g.
    /// fresh-publish) the finding fires at its normal severity even
    /// without the opt-in.
    #[test]
    fn single_maintainer_with_companion_reason_still_fires() {
        let yesterday = rfc3339_days_ago(1);
        let snap = make_snapshot(1, 50, Some(yesterday.clone()), None, None, None, true);
        let pkg = npm("solo", "1.0.0");
        let policy = Policy::default();
        let f = score_package(&pkg, &snap, &policy, Some(yesterday))
            .expect("composite signal should still emit");
        // Above Info: composite signals don't get demoted.
        assert!(f.severity > FindingSeverity::Info);
    }

    /// Reputation cross-check: a name that LOOKS like a typosquat but
    /// ships with multiple maintainers + repo + many versions is
    /// treated as legitimate and the typosquat flag is suppressed.
    #[tokio::test]
    async fn typosquat_suppressed_when_legit_metadata() {
        let server = MockServer::start().await;
        let mut versions = Vec::new();
        for i in 0..30 {
            versions.push(format!("1.0.{i}"));
        }
        let v_refs: Vec<&str> = versions.iter().map(|s| s.as_str()).collect();
        let body = metadata(
            5,
            &v_refs,
            "1.0.29",
            "2024-01-01T00:00:00.000Z",
            "2024-01-01T00:00:00.000Z",
            Some(("1.0.0", "2024-01-01T00:00:00.000Z")),
            true, // has repo
        );
        Mock::given(method("GET"))
            .and(path("/loadsh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let dir = TempDir::new().unwrap();
        let evaluator = IntelEvaluator::with_base_url(cache_path(&dir), server.uri()).unwrap();
        let policy = Policy::default();
        let pkgs = vec![npm("loadsh", "1.0.0")];
        let findings = evaluator.evaluate(&pkgs, &policy).await.unwrap();
        // No typosquat reason should fire because metadata looks healthy.
        for f in &findings {
            assert!(
                !f.id.starts_with("risk:typosquat"),
                "typosquat should be suppressed for legit-looking pkg, got {}",
                f.id
            );
        }
    }
}

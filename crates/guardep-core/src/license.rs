//! License finding evaluator.
//!
//! Reads `node_modules/<pkg>/package.json#license` for every installed
//! npm package and emits one `Finding` per problem:
//!
//! - `license:missing`      — no license field at all
//! - `license:unidentified` — non-SPDX string (e.g. `SEE LICENSE`, a URL,
//!   arbitrary text); we cannot safely interpret what is permitted
//! - `license:denied`       — declared license matches the deny-list in
//!   `policy.license_deny`
//!
//! Closes Socket alert type `unidentifiedLicense` and adds opt-in
//! deny-list enforcement that Socket charges for in its license-policy
//! tier. Authoritative source is `package.json#license`; scanning the
//! LICENSE/COPYING file is out of scope (different lib problem) — see
//! the doc comment on `read_license` for the trade-off.
//!
//! ## Policy mapping
//!
//! - `denied`       → `Critical` severity
//! - `unidentified` → `High` severity (action governed by `license_unidentified`)
//! - `missing`      → `Medium` severity (action governed by `license_missing`)
//!
//! `Policy::decide_finding` maps these tiers back to Allow/Warn/Block
//! through the dedicated `License` arm so users can override.

use crate::ecosystem::{Ecosystem, PackageRef};
use crate::finding::{Evaluator, Finding, FindingKind, FindingSeverity};
use crate::policy::Policy;
use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::path::PathBuf;

pub struct LicenseEvaluator {
    project_root: PathBuf,
}

impl LicenseEvaluator {
    pub fn new(project_root: PathBuf) -> Self {
        Self { project_root }
    }

    fn pkg_json(&self, name: &str) -> PathBuf {
        self.project_root
            .join("node_modules")
            .join(name)
            .join("package.json")
    }
}

#[async_trait]
impl Evaluator for LicenseEvaluator {
    fn name(&self) -> &'static str {
        "license"
    }

    fn enabled(&self, _policy: &Policy) -> bool {
        true
    }

    async fn evaluate(&self, packages: &[PackageRef], policy: &Policy) -> Result<Vec<Finding>> {
        let mut out: Vec<Finding> = Vec::new();
        for pkg in packages {
            if pkg.ecosystem != Ecosystem::Npm {
                continue;
            }
            let raw = match std::fs::read_to_string(self.pkg_json(&pkg.name)) {
                Ok(s) => s,
                Err(_) => continue, // package not installed; skip
            };
            let parsed: Value = match serde_json::from_str(&raw) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let declared = read_license(&parsed);
            if let Some(finding) = classify(pkg, declared.as_deref(), policy) {
                out.push(finding);
            }
        }
        Ok(out)
    }
}

/// Pull the license string out of a parsed `package.json`. Tolerates
/// the legacy shapes:
///   - `"license": "MIT"`           — the standard form
///   - `"license": { "type": "MIT" }` — pre-2016 npm shape, still seen
///   - `"licenses": [ { "type": "MIT" } ]` — even older array form
///
/// Returns `None` for missing or malformed fields. Scanning the
/// LICENSE file is out of scope — match Socket's `unidentifiedLicense`
/// behavior (declared field is the source of truth) and avoid an
/// expensive per-package file walk for a low-yield signal.
fn read_license(v: &Value) -> Option<String> {
    if let Some(s) = v.get("license").and_then(|x| x.as_str()) {
        return Some(s.trim().to_string());
    }
    if let Some(t) = v
        .get("license")
        .and_then(|x| x.get("type"))
        .and_then(|x| x.as_str())
    {
        return Some(t.trim().to_string());
    }
    if let Some(arr) = v.get("licenses").and_then(|x| x.as_array()) {
        let parts: Vec<String> = arr
            .iter()
            .filter_map(|e| {
                e.get("type")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string())
            })
            .collect();
        if !parts.is_empty() {
            return Some(parts.join(" OR "));
        }
    }
    None
}

fn classify(pkg: &PackageRef, declared: Option<&str>, policy: &Policy) -> Option<Finding> {
    match declared {
        None => Some(make(
            pkg,
            "missing",
            None,
            FindingSeverity::Medium,
            "License field missing".to_string(),
        )),
        Some(s) => {
            // Deny-list check first (so a denied SPDX still trips the
            // Critical path, not the unidentified path).
            if !policy.license_deny.is_empty() && license_matches_denylist(s, &policy.license_deny)
            {
                return Some(make(
                    pkg,
                    "denied",
                    Some(s),
                    FindingSeverity::Critical,
                    format!("License '{s}' is on the configured deny list"),
                ));
            }
            // Recognized SPDX ID (or AND/OR/WITH expression of them) =>
            // OK. Anything else => unidentified.
            if is_spdx_expression(s) {
                return None;
            }
            Some(make(
                pkg,
                "unidentified",
                Some(s),
                FindingSeverity::High,
                format!("License '{s}' is not a recognized SPDX identifier"),
            ))
        }
    }
}

/// Case-insensitive containment over the SPDX ID atoms in the
/// expression. We don't try to evaluate `(MIT OR Apache-2.0)` style
/// boolean logic — if any atom is on the deny list we treat the whole
/// thing as denied. That is intentionally strict: a pkg declaring
/// "GPL-3.0 OR MIT" has GPL-3.0 as a chosen-by-you possibility.
fn license_matches_denylist(declared: &str, deny: &std::collections::HashSet<String>) -> bool {
    let atoms = spdx_atoms(declared);
    let lower_deny: std::collections::HashSet<String> =
        deny.iter().map(|s| s.to_ascii_lowercase()).collect();
    atoms
        .iter()
        .any(|a| lower_deny.contains(&a.to_ascii_lowercase()))
}

/// Extract SPDX-id-shaped atoms from an expression, splitting on the
/// boolean operators and trimming parens.
fn spdx_atoms(expr: &str) -> Vec<String> {
    expr.split(['(', ')', ' ', '\t', '\n', ','])
        .filter(|s| !s.is_empty())
        .filter(|s| {
            let lower = s.to_ascii_lowercase();
            !matches!(lower.as_str(), "or" | "and" | "with")
        })
        .map(|s| s.to_string())
        .collect()
}

/// True if the input is a recognized SPDX ID, an SPDX expression
/// composed of recognized IDs, or one of the few legacy aliases npm
/// continues to accept (`UNLICENSED`).
fn is_spdx_expression(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let atoms = spdx_atoms(s);
    if atoms.is_empty() {
        return false;
    }
    atoms.iter().all(|a| is_known_spdx(a))
}

fn is_known_spdx(id: &str) -> bool {
    let lower = id.to_ascii_lowercase();
    // Strip a trailing `+` (SPDX shorthand for "or later", e.g. GPL-2.0+)
    let lower = lower.trim_end_matches('+');
    // Cover the SPDX ids that account for ~99.9% of npm packages plus
    // npm's own escape hatch `UNLICENSED`. Source: SPDX 3.x license
    // list, filtered to the ids that actually appear at scale on npm.
    matches!(
        lower,
        "0bsd"
            | "afl-1.1"
            | "afl-1.2"
            | "afl-2.0"
            | "afl-2.1"
            | "afl-3.0"
            | "agpl-1.0"
            | "agpl-1.0-only"
            | "agpl-1.0-or-later"
            | "agpl-3.0"
            | "agpl-3.0-only"
            | "agpl-3.0-or-later"
            | "apache-1.0"
            | "apache-1.1"
            | "apache-2.0"
            | "artistic-1.0"
            | "artistic-2.0"
            | "blueoak-1.0.0"
            | "bsd-1-clause"
            | "bsd-2-clause"
            | "bsd-2-clause-patent"
            | "bsd-3-clause"
            | "bsd-3-clause-clear"
            | "bsd-4-clause"
            | "bsl-1.0"
            | "cc-by-1.0"
            | "cc-by-2.0"
            | "cc-by-3.0"
            | "cc-by-4.0"
            | "cc-by-sa-3.0"
            | "cc-by-sa-4.0"
            | "cc0-1.0"
            | "cddl-1.0"
            | "cddl-1.1"
            | "cecill-2.1"
            | "epl-1.0"
            | "epl-2.0"
            | "eupl-1.1"
            | "eupl-1.2"
            | "gpl-1.0"
            | "gpl-1.0-only"
            | "gpl-1.0-or-later"
            | "gpl-2.0"
            | "gpl-2.0-only"
            | "gpl-2.0-or-later"
            | "gpl-3.0"
            | "gpl-3.0-only"
            | "gpl-3.0-or-later"
            | "isc"
            | "lgpl-2.0"
            | "lgpl-2.0-only"
            | "lgpl-2.0-or-later"
            | "lgpl-2.1"
            | "lgpl-2.1-only"
            | "lgpl-2.1-or-later"
            | "lgpl-3.0"
            | "lgpl-3.0-only"
            | "lgpl-3.0-or-later"
            | "mit"
            | "mit-0"
            | "mpl-1.1"
            | "mpl-2.0"
            | "ms-pl"
            | "ms-rl"
            | "ofl-1.1"
            | "openssl"
            | "postgresql"
            | "python-2.0"
            | "ruby"
            | "sissl"
            | "unicode-dfs-2016"
            | "unlicense"
            | "unlicensed"
            | "vim"
            | "wtfpl"
            | "x11"
            | "zlib"
            | "zlib-acknowledgement"
            | "zpl-2.1"
    )
}

fn make(
    pkg: &PackageRef,
    issue: &'static str,
    declared: Option<&str>,
    severity: FindingSeverity,
    summary: String,
) -> Finding {
    let id = format!("license:{issue}:{}", pkg.name);
    let details = serde_json::json!({
        "issue": issue,
        "declared": declared,
    });
    Finding {
        package: pkg.clone(),
        kind: FindingKind::License,
        id,
        aliases: vec![],
        summary,
        severity,
        fixed_versions: vec![],
        references: vec![format!("https://www.npmjs.com/package/{}", pkg.name)],
        details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn npm(name: &str, ver: &str) -> PackageRef {
        PackageRef::new(Ecosystem::Npm, name, ver)
    }

    fn json(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn read_license_string_form() {
        assert_eq!(
            read_license(&json(r#"{"license":"MIT"}"#)).as_deref(),
            Some("MIT")
        );
    }

    #[test]
    fn read_license_object_form() {
        assert_eq!(
            read_license(&json(r#"{"license":{"type":"Apache-2.0"}}"#)).as_deref(),
            Some("Apache-2.0")
        );
    }

    #[test]
    fn read_license_legacy_array_form() {
        let v = json(r#"{"licenses":[{"type":"MIT"},{"type":"Apache-2.0"}]}"#);
        assert_eq!(read_license(&v).as_deref(), Some("MIT OR Apache-2.0"));
    }

    #[test]
    fn read_license_missing_returns_none() {
        assert_eq!(read_license(&json(r#"{"name":"x"}"#)), None);
    }

    #[test]
    fn classify_missing_emits_medium() {
        let pkg = npm("solo", "1.0.0");
        let f = classify(&pkg, None, &Policy::default()).expect("emit");
        assert_eq!(f.severity, FindingSeverity::Medium);
        assert_eq!(f.details["issue"], "missing");
    }

    #[test]
    fn classify_known_spdx_does_not_emit() {
        let pkg = npm("good", "1.0.0");
        assert!(classify(&pkg, Some("MIT"), &Policy::default()).is_none());
        assert!(classify(&pkg, Some("apache-2.0"), &Policy::default()).is_none());
        assert!(classify(&pkg, Some("(MIT OR Apache-2.0)"), &Policy::default()).is_none());
    }

    #[test]
    fn classify_unidentified_emits_high() {
        let pkg = npm("custom", "1.0.0");
        let f = classify(&pkg, Some("SEE LICENSE IN README"), &Policy::default()).expect("emit");
        assert_eq!(f.severity, FindingSeverity::High);
        assert_eq!(f.details["issue"], "unidentified");
        assert_eq!(f.details["declared"], "SEE LICENSE IN README");
    }

    #[test]
    fn classify_denylist_emits_critical_even_for_known_spdx() {
        let pkg = npm("copyleft", "1.0.0");
        let mut policy = Policy::default();
        policy.license_deny = HashSet::from(["GPL-3.0".to_string()]);
        let f = classify(&pkg, Some("GPL-3.0"), &policy).expect("emit");
        assert_eq!(f.severity, FindingSeverity::Critical);
        assert_eq!(f.details["issue"], "denied");
    }

    #[test]
    fn classify_denylist_matches_inside_or_expression() {
        // `MIT OR GPL-3.0` means downstream may pick GPL-3.0 — strict
        // interpretation: deny the whole package.
        let pkg = npm("dual", "1.0.0");
        let mut policy = Policy::default();
        policy.license_deny = HashSet::from(["GPL-3.0".to_string()]);
        let f = classify(&pkg, Some("MIT OR GPL-3.0"), &policy).expect("emit");
        assert_eq!(f.severity, FindingSeverity::Critical);
    }

    #[test]
    fn classify_denylist_case_insensitive() {
        let pkg = npm("p", "1.0.0");
        let mut policy = Policy::default();
        policy.license_deny = HashSet::from(["gpl-3.0".to_string()]);
        let f = classify(&pkg, Some("GPL-3.0"), &policy).expect("emit");
        assert_eq!(f.details["issue"], "denied");
    }

    #[test]
    fn spdx_plus_suffix_recognized() {
        // GPL-2.0+ is shorthand for "GPL-2.0 or later".
        assert!(is_known_spdx("GPL-2.0+"));
        assert!(is_known_spdx("LGPL-2.1+"));
    }

    #[test]
    fn unlicensed_is_recognized() {
        // npm-specific marker meaning "no license, do not redistribute".
        // Documented behavior, not unidentified.
        assert!(is_known_spdx("UNLICENSED"));
    }
}

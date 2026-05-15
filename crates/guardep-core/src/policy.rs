use crate::advisory::{Severity, ThreatClass};
use crate::finding::{FindingKind, FindingSeverity};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Warn,
    Block,
}

impl Action {
    pub fn rank(self) -> u8 {
        match self {
            Action::Allow => 0,
            Action::Warn => 1,
            Action::Block => 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    // ── Vulnerability/CVE policy ─────────────────────────────────────────
    #[serde(default = "default_block")]
    pub malware: Action,
    #[serde(default = "default_block")]
    pub critical_cve: Action,
    #[serde(default = "default_warn")]
    pub high_cve: Action,
    #[serde(default = "default_allow")]
    pub medium_cve: Action,
    #[serde(default = "default_allow")]
    pub low_cve: Action,

    // ── Postinstall script policy (Phase 1A) ─────────────────────────────
    /// How to react when a package ships a postinstall/install/preinstall
    /// script that scored 0 on the heuristic detector (no suspicious
    /// patterns matched). Default is `allow`: most install scripts
    /// (`node install.js`, `node-gyp rebuild`) are benign and surfacing
    /// every one creates noise. Set to `warn` to audit every script.
    #[serde(default = "default_allow")]
    pub postinstall_default: Action,
    /// Action when the heuristic flags a script as suspicious
    /// (Medium/High by combined regex+AST score, but with no
    /// unambiguously-malicious pattern). Default `warn` because
    /// without dataflow analysis we can't reliably distinguish
    /// suspicious-looking-but-benign install scripts (esbuild,
    /// electron, native bindings) from real attacks.
    #[serde(default = "default_warn")]
    pub postinstall_suspicious: Action,
    /// Action when the heuristic flags a script as critical (an
    /// unambiguously-malicious pattern fired: credential file read,
    /// base64-decode chained with dynamic code execution, etc).
    /// Always blocks by default; these patterns have no innocent
    /// explanation.
    #[serde(default = "default_block")]
    pub postinstall_critical: Action,

    // ── Risk score policy (Phase 1C) ─────────────────────────────────────
    /// Block any package whose computed risk score exceeds this (0-100).
    #[serde(default = "default_risk_block")]
    pub block_if_risk_score_above: u8,
    /// Warn if risk score exceeds this.
    #[serde(default = "default_risk_warn")]
    pub warn_if_risk_score_above: u8,
    /// Warn when a package has not been updated in N days.
    #[serde(default = "default_unmaintained_days")]
    pub warn_if_unmaintained_days: u32,
    /// Block typosquat candidates (Levenshtein distance ≤ 2 from top-N
    /// popular packages).
    #[serde(default = "default_true")]
    pub block_typosquats: bool,
    /// Warn when a package version was published less than N days ago
    /// (fresh-publish risk window for compromise detection).
    #[serde(default = "default_fresh_publish_days")]
    pub warn_if_fresh_publish_days: u32,
    /// Minimum severity to *display* in reports. Findings below this
    /// threshold are dropped from table/JSON output entirely. Does not
    /// affect what evaluators emit or what the policy blocks/warns on
    /// — `decide_action` still runs for every finding. Default `Low`
    /// hides only `Info`/`Unknown` rows. Set to `Critical` to see
    /// only the most urgent issues, or `Info` to see everything.
    #[serde(default = "default_min_display_severity")]
    pub min_display_severity: FindingSeverity,

    // ── Provenance policy (Phase 1B) ─────────────────────────────────────
    /// Glob patterns for packages that MUST have valid Sigstore provenance.
    /// Examples: `["@*/*", "chalk", "debug", "react"]`
    #[serde(default)]
    pub require_provenance: Vec<String>,
    /// Action when a required-provenance package has none.
    #[serde(default = "default_block")]
    pub missing_provenance: Action,
    /// Action when provenance is present but doesn't match expected source.
    #[serde(default = "default_block")]
    pub provenance_mismatch: Action,

    // ── General ──────────────────────────────────────────────────────────
    /// Format: "name@version" (e.g. "axios@1.13.2"). Suppresses all findings.
    #[serde(default)]
    pub allowlist: HashSet<String>,
    /// Per-finding allowlist: `{ "axios@1.13.2": ["GHSA-43fc-jf86-j433"] }`.
    /// Allows surgical suppression without blanket-allowing the package.
    #[serde(default)]
    pub finding_allowlist: HashMap<String, HashSet<String>>,
    /// Refresh advisory cache every N hours.
    #[serde(default = "default_refresh")]
    pub cache_refresh_hours: u64,

    // ── Exploit enrichment (EPSS / KEV) ──────────────────────────────────
    /// Promote any CVE listed in CISA KEV to Critical regardless of CVSS.
    /// Default true: KEV membership means confirmed in-the-wild exploit.
    #[serde(default = "default_true")]
    pub kev_promote_to_critical: bool,
    /// EPSS score (0.0..1.0) at or above which severity is bumped one
    /// tier (Low → Medium → High → Critical). Default 0.5 = the CVE has
    /// a >= 50% probability of being exploited within 30 days per FIRST.
    /// Set to a value > 1.0 to disable EPSS-based promotion entirely.
    #[serde(default = "default_epss_threshold")]
    pub epss_promote_threshold: f32,

    // ── Source behavior scan ────────────────────────────────────────────
    /// Enable cross-file source-behavior scanning of installed packages
    /// (network/fs/env/eval/dynamic-require/entropy/minified). Adds
    /// 50ms-2s per audit depending on dep tree size. Default true.
    #[serde(default = "default_true")]
    pub source_scan_enabled: bool,
    /// Emit one finding per call-site instead of aggregating per
    /// (package, behavior). Default false to keep reports compact;
    /// downstream tooling that wants byte-range granularity per hit
    /// can opt in via `--granular` on the CLI.
    #[serde(default)]
    pub source_scan_granular: bool,

    // ── License policy ──────────────────────────────────────────────────
    /// SPDX identifiers (or expressions) to block. Matched
    /// case-insensitively against the package's declared license.
    /// Example: `["GPL-3.0", "AGPL-3.0", "GPL-2.0-only"]`. Empty by
    /// default — no surprise blocks.
    #[serde(default)]
    pub license_deny: HashSet<String>,
    /// Action when a package declares no license at all.
    #[serde(default = "default_warn")]
    pub license_missing: Action,
    /// Action when a package declares a license that is not a
    /// recognized SPDX identifier (e.g. `"SEE LICENSE IN ..."`,
    /// arbitrary URLs, custom strings).
    #[serde(default = "default_warn")]
    pub license_unidentified: Action,

    // ── OSSF threat feed ────────────────────────────────────────────────
    /// Pull the OSSF malicious-packages feed and flag any matched
    /// package as Critical malware. Independent of OSV — OSSF entries
    /// often land hours-to-days before OSV indexes them. Default true.
    #[serde(default = "default_true")]
    pub threat_feed_enabled: bool,
}

fn default_block() -> Action {
    Action::Block
}
fn default_warn() -> Action {
    Action::Warn
}
fn default_allow() -> Action {
    Action::Allow
}
fn default_refresh() -> u64 {
    6
}
fn default_risk_block() -> u8 {
    85
}
fn default_risk_warn() -> u8 {
    60
}
fn default_unmaintained_days() -> u32 {
    730
}
fn default_fresh_publish_days() -> u32 {
    7
}
fn default_true() -> bool {
    true
}
fn default_min_display_severity() -> FindingSeverity {
    FindingSeverity::Low
}
fn default_epss_threshold() -> f32 {
    0.5
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            malware: Action::Block,
            critical_cve: Action::Block,
            high_cve: Action::Warn,
            medium_cve: Action::Allow,
            low_cve: Action::Allow,
            postinstall_default: Action::Allow,
            postinstall_suspicious: Action::Warn,
            postinstall_critical: Action::Block,
            block_if_risk_score_above: 85,
            warn_if_risk_score_above: 60,
            warn_if_unmaintained_days: 730,
            block_typosquats: true,
            warn_if_fresh_publish_days: 7,
            min_display_severity: FindingSeverity::Low,
            require_provenance: Vec::new(),
            missing_provenance: Action::Block,
            provenance_mismatch: Action::Block,
            allowlist: HashSet::new(),
            finding_allowlist: HashMap::new(),
            cache_refresh_hours: 6,
            kev_promote_to_critical: true,
            epss_promote_threshold: 0.5,
            source_scan_enabled: true,
            source_scan_granular: false,
            license_deny: HashSet::new(),
            license_missing: Action::Warn,
            license_unidentified: Action::Warn,
            threat_feed_enabled: true,
        }
    }
}

impl Policy {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path)?;
        let cfg: PolicyFile = toml::from_str(&raw)?;
        Ok(cfg.policy.unwrap_or_default())
    }

    /// Legacy advisory decision path. Retained for callers that still
    /// reason about `(ThreatClass, Severity)` pairs; new code should
    /// prefer `decide_finding`.
    pub fn decide(&self, class: ThreatClass, severity: Severity) -> Action {
        match class {
            ThreatClass::Malware => self.malware,
            ThreatClass::Vulnerability => match severity {
                Severity::Critical => self.critical_cve,
                Severity::High => self.high_cve,
                Severity::Medium => self.medium_cve,
                Severity::Low | Severity::Unknown => self.low_cve,
                Severity::Info => Action::Allow,
            },
        }
    }

    /// Unified decision path used by [`finding::decide_action`].
    /// Maps a `(FindingKind, FindingSeverity)` pair to an [`Action`].
    pub fn decide_finding(&self, kind: FindingKind, severity: FindingSeverity) -> Action {
        // Info tier never blocks or warns regardless of kind. It's the
        // opt-in surface for noise-by-default signals.
        if severity == FindingSeverity::Info {
            return Action::Allow;
        }
        match kind {
            FindingKind::Malware => self.malware,
            FindingKind::Vulnerability => match severity {
                FindingSeverity::Critical => self.critical_cve,
                FindingSeverity::High => self.high_cve,
                FindingSeverity::Medium => self.medium_cve,
                FindingSeverity::Low | FindingSeverity::Unknown | FindingSeverity::Info => {
                    self.low_cve
                }
            },
            FindingKind::PostinstallScript => match severity {
                FindingSeverity::Critical => self.postinstall_critical,
                FindingSeverity::High | FindingSeverity::Medium => self.postinstall_suspicious,
                FindingSeverity::Low | FindingSeverity::Unknown | FindingSeverity::Info => {
                    self.postinstall_default
                }
            },
            FindingKind::RiskScore => match severity {
                FindingSeverity::Critical | FindingSeverity::High => Action::Block,
                FindingSeverity::Medium => Action::Warn,
                FindingSeverity::Low | FindingSeverity::Unknown | FindingSeverity::Info => {
                    Action::Allow
                }
            },
            FindingKind::MissingProvenance => self.missing_provenance,
            FindingKind::ProvenanceMismatch => self.provenance_mismatch,
            FindingKind::SourceBehavior => match severity {
                FindingSeverity::Critical => Action::Block,
                FindingSeverity::High => Action::Warn,
                _ => Action::Allow,
            },
            // License action is encoded in the finding's severity by
            // `LicenseEvaluator` (Critical → deny-list hit, High →
            // unidentified, Medium → missing). Mapping mirrors that.
            FindingKind::License => match severity {
                FindingSeverity::Critical => Action::Block,
                FindingSeverity::High | FindingSeverity::Medium => Action::Warn,
                _ => Action::Allow,
            },
        }
    }

    pub fn is_allowlisted(&self, key: &str) -> bool {
        self.allowlist.contains(key)
    }

    pub fn is_finding_allowlisted(&self, pkg_key: &str, finding_id: &str) -> bool {
        self.finding_allowlist
            .get(pkg_key)
            .map(|set| set.contains(finding_id))
            .unwrap_or(false)
    }

    /// True when the package matches any glob in `require_provenance`.
    pub fn requires_provenance(&self, package_name: &str) -> bool {
        self.require_provenance
            .iter()
            .any(|pat| glob_match(pat, package_name))
    }
}

/// Minimal glob: supports `*` (any chars). For npm-scoped patterns like
/// `@*/*` this is sufficient; we don't need full POSIX glob.
fn glob_match(pattern: &str, name: &str) -> bool {
    if pattern == name {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == name;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut cursor = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 && !name[cursor..].starts_with(part) {
            return false;
        }
        match name[cursor..].find(part) {
            Some(idx) => cursor += idx + part.len(),
            None => return false,
        }
    }
    if !parts.last().map(|p| p.is_empty()).unwrap_or(true) {
        let last = parts.last().unwrap();
        if !name.ends_with(last) {
            return false;
        }
    }
    true
}

#[derive(Debug, Deserialize)]
struct PolicyFile {
    policy: Option<Policy>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_scoped_packages() {
        assert!(glob_match("@*/*", "@scope/pkg"));
        assert!(glob_match("chalk", "chalk"));
        assert!(!glob_match("chalk", "chalkboard"));
        assert!(glob_match("react*", "react-dom"));
        assert!(glob_match("*-loader", "css-loader"));
    }

    #[test]
    fn requires_provenance_glob() {
        let mut p = Policy::default();
        p.require_provenance = vec!["@*/*".into(), "chalk".into()];
        assert!(p.requires_provenance("@scope/pkg"));
        assert!(p.requires_provenance("chalk"));
        assert!(!p.requires_provenance("debug"));
    }

    #[test]
    fn finding_allowlist_per_id() {
        let mut p = Policy::default();
        p.finding_allowlist.insert(
            "axios@1.13.2".into(),
            HashSet::from(["GHSA-43fc-jf86-j433".into()]),
        );
        assert!(p.is_finding_allowlisted("axios@1.13.2", "GHSA-43fc-jf86-j433"));
        assert!(!p.is_finding_allowlisted("axios@1.13.2", "OTHER"));
        assert!(!p.is_finding_allowlisted("other@1.0.0", "GHSA-43fc-jf86-j433"));
    }

    #[test]
    fn unified_decide_finding_for_vulnerability() {
        let p = Policy::default();
        assert_eq!(
            p.decide_finding(FindingKind::Vulnerability, FindingSeverity::Critical),
            Action::Block
        );
        assert_eq!(
            p.decide_finding(FindingKind::Vulnerability, FindingSeverity::High),
            Action::Warn
        );
    }

    #[test]
    fn postinstall_severity_routing() {
        let p = Policy::default();
        assert_eq!(
            p.decide_finding(FindingKind::PostinstallScript, FindingSeverity::Critical),
            Action::Block
        );
        // Medium-severity postinstall maps to the "suspicious" tier,
        // which now defaults to Warn (not Block) because without
        // dataflow analysis the heuristic produces too many false
        // positives at the Medium level (e.g. esbuild's install.js
        // legitimately spawns child processes with computed paths).
        assert_eq!(
            p.decide_finding(FindingKind::PostinstallScript, FindingSeverity::Medium),
            Action::Warn
        );
        // Score-0 / Low postinstall now defaults to Allow because
        // most npm install scripts are benign (`node install.js`,
        // `node-gyp rebuild`). Users opt into auditing them by
        // setting `postinstall_default = "warn"` in guardep.toml.
        assert_eq!(
            p.decide_finding(FindingKind::PostinstallScript, FindingSeverity::Low),
            Action::Allow
        );
    }
}

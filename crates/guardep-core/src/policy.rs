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
    /// patterns matched). Default is `allow` — most install scripts
    /// (`node install.js`, `node-gyp rebuild`) are benign and surfacing
    /// every one creates noise. Set to `warn` to audit every script.
    #[serde(default = "default_allow")]
    pub postinstall_default: Action,
    /// Action when heuristic detector flags a script as suspicious
    /// (network calls + cred fs reads, base64+eval, etc.)
    #[serde(default = "default_block")]
    pub postinstall_suspicious: Action,
    /// Action when heuristic flags a script as critical (clear malware
    /// pattern). Always block by default.
    #[serde(default = "default_block")]
    pub postinstall_critical: Action,
    /// Pre-approved script SHA-256 hashes (skip review).
    #[serde(default)]
    pub allowed_script_hashes: HashSet<String>,

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

/// Pre-approved SHA-256 hashes of common, well-known benign install
/// scripts. Suppresses noise from packages that legitimately ship
/// `node install.js`, `node-gyp rebuild`, etc. Users can extend this
/// list via `policy.allowed_script_hashes` in `guardep.toml`.
fn default_allowed_script_hashes() -> HashSet<String> {
    [
        // "node install.js" — electron, esbuild, many native bindings
        "912d4d8f507b7b392ae422a459f98da94669a742e4cc43cfe061e630ee2846fe",
        // "node ./install.js"
        "ffcd30ee02ebe94ed91aaad2947b2a122838d0715e725833711b409c70c79605",
        // "node ./scripts/install.js"
        "e8d389f3116b70488031adf8aba2d570bfcad5ae8e67d8ccc74199f0b4cb6733",
        // "node-gyp rebuild" — universal native module build
        "55941a60816361a50d221482fed3b3842464f10af4371a667af4268d13b953a2",
        // "prebuild-install || node-gyp rebuild"
        "582bbd5982901bafc7a72276d195e371d76dc1d1dd5d3e425682444c4feaa8aa",
        // "prebuild-install"
        "1b461934a7812831db18e5b164fc30d04975b4f5cc06b28329048364ed56b4d1",
        // "node-gyp configure && node-gyp build"
        "7bb94ff9a61d8ca73928728f2386f0f418841064b87b07e7fef5585482d30fab",
        // "npm run build"
        "16c0e4305ac213dff39fc82b69b6e08aeeb8758e33cd72d7c409752a70e9f054",
        // "node dist/index.js --exec install" — cypress
        "d4951105d74d2e8a684c155c9ef75e2916c3a6ee3ce58f8d11db131011f882c4",
        // "node ./script/select-7z-arch.js" — electron-winstaller
        "06ad330351c94e886bde150af9e3b834cc509db3be24a650749871087f2d7518",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
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
            postinstall_suspicious: Action::Block,
            postinstall_critical: Action::Block,
            allowed_script_hashes: default_allowed_script_hashes(),
            block_if_risk_score_above: 85,
            warn_if_risk_score_above: 60,
            warn_if_unmaintained_days: 730,
            block_typosquats: true,
            warn_if_fresh_publish_days: 7,
            require_provenance: Vec::new(),
            missing_provenance: Action::Block,
            provenance_mismatch: Action::Block,
            allowlist: HashSet::new(),
            finding_allowlist: HashMap::new(),
            cache_refresh_hours: 6,
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

    /// Legacy advisory decision path used by `matcher::evaluate`.
    pub fn decide(&self, class: ThreatClass, severity: Severity) -> Action {
        match class {
            ThreatClass::Malware => self.malware,
            ThreatClass::Vulnerability => match severity {
                Severity::Critical => self.critical_cve,
                Severity::High => self.high_cve,
                Severity::Medium => self.medium_cve,
                Severity::Low | Severity::Unknown => self.low_cve,
            },
        }
    }

    /// Unified decision path used by [`finding::decide_action`].
    /// Maps a `(FindingKind, FindingSeverity)` pair to an [`Action`].
    pub fn decide_finding(&self, kind: FindingKind, severity: FindingSeverity) -> Action {
        match kind {
            FindingKind::Malware => self.malware,
            FindingKind::Vulnerability => match severity {
                FindingSeverity::Critical => self.critical_cve,
                FindingSeverity::High => self.high_cve,
                FindingSeverity::Medium => self.medium_cve,
                FindingSeverity::Low | FindingSeverity::Unknown => self.low_cve,
            },
            FindingKind::PostinstallScript => match severity {
                FindingSeverity::Critical => self.postinstall_critical,
                FindingSeverity::High | FindingSeverity::Medium => self.postinstall_suspicious,
                FindingSeverity::Low | FindingSeverity::Unknown => self.postinstall_default,
            },
            FindingKind::RiskScore => match severity {
                FindingSeverity::Critical | FindingSeverity::High => Action::Block,
                FindingSeverity::Medium => Action::Warn,
                FindingSeverity::Low | FindingSeverity::Unknown => Action::Allow,
            },
            FindingKind::MissingProvenance => self.missing_provenance,
            FindingKind::ProvenanceMismatch => self.provenance_mismatch,
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

    pub fn is_script_hash_allowed(&self, sha256: &str) -> bool {
        self.allowed_script_hashes.contains(sha256)
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
        p.finding_allowlist
            .insert("axios@1.13.2".into(), HashSet::from(["GHSA-43fc-jf86-j433".into()]));
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
        assert_eq!(
            p.decide_finding(FindingKind::PostinstallScript, FindingSeverity::Medium),
            Action::Block // mapped to "suspicious" tier
        );
        // Score-0 / Low postinstall now defaults to Allow — most npm
        // install scripts are benign (`node install.js`, `node-gyp
        // rebuild`). Users opt into auditing them by setting
        // `postinstall_default = "warn"` in guardep.toml.
        assert_eq!(
            p.decide_finding(FindingKind::PostinstallScript, FindingSeverity::Low),
            Action::Allow
        );
    }
}

//! Unified finding model and evaluator trait.
//!
//! Each subsystem (OSV advisories, postinstall scripts, package risk
//! intelligence, Sigstore provenance) emits findings that share the same
//! lifecycle: produced by an [`Evaluator`], scored by [`Policy`], rendered
//! and aggregated together in the verdict.

use crate::ecosystem::PackageRef;
use crate::policy::{Action, Policy};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Identifier classes findings carry — used by the policy engine to decide
/// which knob applies. Each new evaluator adds a variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// CVE / advisory match (OSV)
    Vulnerability,
    /// Compromised publish (Shai-Hulud, hijack, MAL-* ID)
    Malware,
    /// Suspicious or known-bad postinstall/install/preinstall script
    PostinstallScript,
    /// Package risk score above threshold (low maintainer count, fresh
    /// publish, ownership transfer, typosquat, ghost package, etc.)
    RiskScore,
    /// Missing or invalid Sigstore provenance attestation
    MissingProvenance,
    /// Provenance present but linked source repo doesn't match expected
    ProvenanceMismatch,
}

impl FindingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FindingKind::Vulnerability => "vulnerability",
            FindingKind::Malware => "malware",
            FindingKind::PostinstallScript => "postinstall_script",
            FindingKind::RiskScore => "risk_score",
            FindingKind::MissingProvenance => "missing_provenance",
            FindingKind::ProvenanceMismatch => "provenance_mismatch",
        }
    }
}

/// Severity tier shared across finding kinds. Vulnerabilities use it for
/// CVSS bucketing; risk/postinstall/provenance findings map their internal
/// score onto this scale. `Info` is below `Low` and never blocks/warns
/// at default policy — it exists so callers can opt into surfacing
/// signals that are typically noise (e.g. single-maintainer alone).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Unknown,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// One issue produced by an evaluator. Stable across kinds so reporting and
/// dedup can treat all findings uniformly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Affected package
    pub package: PackageRef,
    /// What kind of issue this is
    pub kind: FindingKind,
    /// Stable identifier — for advisories: GHSA/CVE/MAL ID;
    /// for postinstall: script SHA-256;
    /// for risk: deterministic policy slug ("typosquat:lodash", "fresh-publish");
    /// for provenance: "missing:<pkg>@<ver>" or "mismatch:<pkg>@<ver>".
    pub id: String,
    /// Aliases (CVE-* alongside GHSA-*, etc.). Empty for non-advisory kinds.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// One-line description shown in reports.
    pub summary: String,
    /// Severity tier
    pub severity: FindingSeverity,
    /// Suggested fix versions (for advisories: from OSV; for risk: empty;
    /// for provenance: empty; for postinstall: empty).
    #[serde(default)]
    pub fixed_versions: Vec<String>,
    /// External references (GHSA URL, npm page, audit log entry, etc.)
    #[serde(default)]
    pub references: Vec<String>,
    /// Free-form structured detail (script hash, npm metadata, sigstore
    /// transparency log entry, etc.). Renderers may surface specific keys.
    #[serde(default)]
    pub details: serde_json::Value,
}

impl Finding {
    pub fn dedup_key(&self) -> (String, String, &str) {
        (
            format!("{}@{}", self.package.name, self.package.version),
            self.id.clone(),
            self.kind.as_str(),
        )
    }
}

/// Trait every finding source implements. Evaluators are async because
/// most fetch from external sources (OSV, npm registry, sigstore log).
#[async_trait]
pub trait Evaluator: Send + Sync {
    fn name(&self) -> &'static str;
    /// Whether this evaluator is enabled by current policy. Cheap check —
    /// allows an audit run to skip wiring an evaluator entirely when the
    /// user disabled it.
    fn enabled(&self, policy: &Policy) -> bool;
    async fn evaluate(&self, packages: &[PackageRef], policy: &Policy) -> anyhow::Result<Vec<Finding>>;
}

/// Apply policy to assign an [`Action`] to a finding. Allowlist check is
/// done by the caller (policy engine has the registry of allowlisted
/// `name@version` keys).
pub fn decide_action(policy: &Policy, finding: &Finding) -> Action {
    let key = format!("{}@{}", finding.package.name, finding.package.version);
    if policy.is_allowlisted(&key) {
        return Action::Allow;
    }
    if policy.is_finding_allowlisted(&key, &finding.id) {
        return Action::Allow;
    }
    policy.decide_finding(finding.kind, finding.severity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::Ecosystem;

    fn pkg() -> PackageRef {
        PackageRef::new(Ecosystem::Npm, "x", "1.0.0")
    }

    #[test]
    fn finding_dedup_key_combines_kind() {
        let a = Finding {
            package: pkg(),
            kind: FindingKind::Vulnerability,
            id: "GHSA-1".into(),
            aliases: vec![],
            summary: String::new(),
            severity: FindingSeverity::High,
            fixed_versions: vec![],
            references: vec![],
            details: serde_json::Value::Null,
        };
        let b = Finding {
            kind: FindingKind::Malware,
            ..a.clone()
        };
        assert_ne!(a.dedup_key(), b.dedup_key());
    }
}

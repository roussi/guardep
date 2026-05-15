//! Aggregate report shape consumed by the CLI renderer.
//!
//! Replaces the legacy `Verdict`/`MatchResult` types. A `FindingsReport`
//! is the single immutable artefact that flows from the registry +
//! policy decisions to the renderer (table or JSON).

use crate::finding::{decide_action, Finding, FindingKind, FindingSeverity};
use crate::policy::{Action, Policy};
use serde::Serialize;
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize)]
pub struct ScoredFinding {
    pub finding: Finding,
    pub action: Action,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingsReport {
    pub items: Vec<ScoredFinding>,
}

impl FindingsReport {
    /// Default: drops Allow-tier findings except `Info` severity ones
    /// (those are explicit informational rows the user opted into via
    /// per-evaluator policy).
    pub fn from_findings(findings: Vec<Finding>, policy: &Policy) -> Self {
        Self::build(findings, policy, false)
    }

    /// `--info` mode: keep every finding regardless of action. Used
    /// when the user wants the full picture, including things default
    /// policy filters as Allow (Low CVEs, etc.).
    pub fn from_findings_verbose(findings: Vec<Finding>, policy: &Policy) -> Self {
        Self::build(findings, policy, true)
    }

    fn build(findings: Vec<Finding>, policy: &Policy, keep_allow: bool) -> Self {
        let items: Vec<ScoredFinding> = findings
            .into_iter()
            .map(|f| {
                let action = decide_action(policy, &f);
                ScoredFinding { finding: f, action }
            })
            .filter(|s| {
                if keep_allow {
                    return true;
                }
                s.action != Action::Allow || s.finding.severity == FindingSeverity::Info
            })
            .collect();
        Self { items }
    }

    pub fn should_block(&self) -> bool {
        self.items.iter().any(|s| s.action == Action::Block)
    }

    pub fn has_warnings(&self) -> bool {
        self.items.iter().any(|s| s.action == Action::Warn)
    }

    pub fn count_blocks(&self) -> usize {
        self.items.iter().filter(|s| s.action == Action::Block).count()
    }

    pub fn count_warnings(&self) -> usize {
        self.items.iter().filter(|s| s.action == Action::Warn).count()
    }

    pub fn count_malware(&self) -> usize {
        self.items
            .iter()
            .filter(|s| s.finding.kind == FindingKind::Malware)
            .count()
    }

    pub fn count_info(&self) -> usize {
        self.items
            .iter()
            .filter(|s| s.finding.severity == FindingSeverity::Info)
            .count()
    }

    /// Provenance verification breakdown across the audit. Returns
    /// `(missing, mismatched, trust_root_unavailable)`. Used by the
    /// summary line so users see at a glance whether crypto
    /// verification actually ran or was degraded.
    pub fn provenance_breakdown(&self) -> ProvenanceBreakdown {
        let mut out = ProvenanceBreakdown::default();
        for s in &self.items {
            match s.finding.kind {
                crate::finding::FindingKind::MissingProvenance => {
                    if s.finding.id == "provenance:trust-root-unavailable" {
                        out.trust_root_unavailable_for = s
                            .finding
                            .details
                            .get("affected_packages")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0)
                            as usize;
                    } else {
                        out.missing += 1;
                    }
                }
                crate::finding::FindingKind::ProvenanceMismatch => out.mismatched += 1,
                _ => {}
            }
        }
        out
    }

    /// Dedup by `(package_name, package_version, finding_kind, finding_id)`.
    /// Same vulnerability can surface multiple times when one package is
    /// installed under multiple lockfile paths; we want one row.
    pub fn deduped(&self) -> Vec<&ScoredFinding> {
        let mut seen: HashSet<(String, String, &'static str, String)> = HashSet::new();
        let mut out = Vec::new();
        for s in &self.items {
            let key = (
                s.finding.package.name.clone(),
                s.finding.package.version.clone(),
                s.finding.kind.as_str(),
                s.finding.id.clone(),
            );
            if seen.insert(key) {
                out.push(s);
            }
        }
        out
    }

    /// Total raw matches (pre-dedup). Useful for the summary line.
    pub fn raw_count(&self) -> usize {
        self.items.len()
    }
}

/// Surface-level summary of provenance-related findings. Distinguishes
/// "we checked and the package didn't ship provenance" (missing) from
/// "we couldn't even run the check because the trust root was
/// unreachable" (trust_root_unavailable_for).
#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct ProvenanceBreakdown {
    pub missing: usize,
    pub mismatched: usize,
    pub trust_root_unavailable_for: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::{Ecosystem, PackageRef};

    fn pkg(name: &str, ver: &str) -> PackageRef {
        PackageRef::new(Ecosystem::Npm, name, ver)
    }

    fn make_finding(name: &str, ver: &str, kind: FindingKind, sev: FindingSeverity) -> Finding {
        Finding {
            package: pkg(name, ver),
            kind,
            id: format!("test:{name}"),
            aliases: vec![],
            summary: String::new(),
            severity: sev,
            fixed_versions: vec![],
            references: vec![],
            details: serde_json::Value::Null,
        }
    }

    #[test]
    fn malware_critical_blocks_by_default() {
        let f = make_finding("x", "1.0.0", FindingKind::Malware, FindingSeverity::Critical);
        let r = FindingsReport::from_findings(vec![f], &Policy::default());
        assert!(r.should_block());
        assert_eq!(r.count_blocks(), 1);
    }

    #[test]
    fn low_cve_filtered_out_by_default() {
        let f = make_finding(
            "x",
            "1.0.0",
            FindingKind::Vulnerability,
            FindingSeverity::Low,
        );
        let r = FindingsReport::from_findings(vec![f], &Policy::default());
        assert!(r.items.is_empty(), "low CVE should be Allow-filtered");
    }

    #[test]
    fn info_row_kept_even_when_action_is_allow() {
        let f = make_finding("x", "1.0.0", FindingKind::RiskScore, FindingSeverity::Info);
        let r = FindingsReport::from_findings(vec![f], &Policy::default());
        assert_eq!(r.items.len(), 1);
        assert_eq!(r.count_info(), 1);
        assert!(!r.should_block());
        assert!(!r.has_warnings());
    }

    #[test]
    fn dedup_collapses_duplicate_finding() {
        let f1 = make_finding("x", "1.0.0", FindingKind::Vulnerability, FindingSeverity::High);
        let f2 = f1.clone();
        let r = FindingsReport::from_findings(vec![f1, f2], &Policy::default());
        assert_eq!(r.raw_count(), 2);
        assert_eq!(r.deduped().len(), 1);
    }
}

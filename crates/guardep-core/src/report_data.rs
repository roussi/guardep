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
    /// Build a report by scoring every finding through `policy.decide_action`,
    /// then dropping rows whose severity is below `policy.min_display_severity`.
    /// Rows are sorted Critical → Info (severity desc, then package name)
    /// so the most urgent issues land at the top of the table.
    pub fn from_findings(findings: Vec<Finding>, policy: &Policy) -> Self {
        let mut items: Vec<ScoredFinding> = findings
            .into_iter()
            .map(|f| {
                let action = decide_action(policy, &f);
                ScoredFinding { finding: f, action }
            })
            .filter(|s| s.finding.severity >= policy.min_display_severity)
            .collect();
        items.sort_by(|a, b| {
            b.finding
                .severity
                .cmp(&a.finding.severity)
                .then_with(|| a.finding.package.name.cmp(&b.finding.package.name))
                .then_with(|| a.finding.package.version.cmp(&b.finding.package.version))
                .then_with(|| a.finding.id.cmp(&b.finding.id))
        });
        Self { items }
    }

    pub fn should_block(&self) -> bool {
        self.items.iter().any(|s| s.action == Action::Block)
    }

    pub fn has_warnings(&self) -> bool {
        self.items.iter().any(|s| s.action == Action::Warn)
    }

    pub fn count_blocks(&self) -> usize {
        self.items
            .iter()
            .filter(|s| s.action == Action::Block)
            .count()
    }

    pub fn count_warnings(&self) -> usize {
        self.items
            .iter()
            .filter(|s| s.action == Action::Warn)
            .count()
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
                        out.trust_root_unavailable_for =
                            s.finding
                                .details
                                .get("affected_packages")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0) as usize;
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
        let f = make_finding(
            "x",
            "1.0.0",
            FindingKind::Malware,
            FindingSeverity::Critical,
        );
        let r = FindingsReport::from_findings(vec![f], &Policy::default());
        assert!(r.should_block());
        assert_eq!(r.count_blocks(), 1);
    }

    #[test]
    fn low_cve_kept_at_default_threshold() {
        let f = make_finding(
            "x",
            "1.0.0",
            FindingKind::Vulnerability,
            FindingSeverity::Low,
        );
        let r = FindingsReport::from_findings(vec![f], &Policy::default());
        assert_eq!(r.items.len(), 1, "low CVE is at threshold, should be kept");
        assert_eq!(r.items[0].action, crate::policy::Action::Allow);
    }

    #[test]
    fn info_dropped_at_default_threshold() {
        let f = make_finding("x", "1.0.0", FindingKind::RiskScore, FindingSeverity::Info);
        let r = FindingsReport::from_findings(vec![f], &Policy::default());
        assert!(
            r.items.is_empty(),
            "Info < Low threshold by default, should be filtered"
        );
    }

    #[test]
    fn info_kept_when_threshold_lowered() {
        let f = make_finding("x", "1.0.0", FindingKind::RiskScore, FindingSeverity::Info);
        let mut policy = Policy::default();
        policy.min_display_severity = FindingSeverity::Info;
        let r = FindingsReport::from_findings(vec![f], &policy);
        assert_eq!(r.items.len(), 1);
    }

    #[test]
    fn high_threshold_drops_everything_below() {
        let mut policy = Policy::default();
        policy.min_display_severity = FindingSeverity::High;
        let findings = vec![
            make_finding("a", "1", FindingKind::Vulnerability, FindingSeverity::Low),
            make_finding(
                "b",
                "1",
                FindingKind::Vulnerability,
                FindingSeverity::Medium,
            ),
            make_finding("c", "1", FindingKind::Vulnerability, FindingSeverity::High),
            make_finding(
                "d",
                "1",
                FindingKind::Vulnerability,
                FindingSeverity::Critical,
            ),
        ];
        let r = FindingsReport::from_findings(findings, &policy);
        assert_eq!(r.items.len(), 2, "only High + Critical should remain");
    }

    #[test]
    fn findings_sorted_critical_to_info() {
        let mut policy = Policy::default();
        policy.min_display_severity = FindingSeverity::Info;
        let findings = vec![
            make_finding("z", "1", FindingKind::Vulnerability, FindingSeverity::Low),
            make_finding(
                "a",
                "1",
                FindingKind::Vulnerability,
                FindingSeverity::Critical,
            ),
            make_finding(
                "m",
                "1",
                FindingKind::Vulnerability,
                FindingSeverity::Medium,
            ),
            make_finding("k", "1", FindingKind::Vulnerability, FindingSeverity::High),
        ];
        let r = FindingsReport::from_findings(findings, &policy);
        let order: Vec<&str> = r
            .items
            .iter()
            .map(|s| s.finding.package.name.as_str())
            .collect();
        assert_eq!(order, vec!["a", "k", "m", "z"]);
    }

    #[test]
    fn dedup_collapses_duplicate_finding() {
        let f1 = make_finding(
            "x",
            "1.0.0",
            FindingKind::Vulnerability,
            FindingSeverity::High,
        );
        let f2 = f1.clone();
        let r = FindingsReport::from_findings(vec![f1, f2], &Policy::default());
        assert_eq!(r.raw_count(), 2);
        assert_eq!(r.deduped().len(), 1);
    }
}

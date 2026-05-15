//! Bridge: convert unified `Finding`s back into the legacy
//! `Verdict`/`MatchResult` shape so the existing CLI renderer can
//! display findings from all evaluators (postinstall, intel,
//! provenance) alongside OSV advisories without a full rewrite.

use crate::advisory::{Advisory, Severity as AdvSeverity, ThreatClass};
use crate::finding::{decide_action, Finding, FindingKind, FindingSeverity};
use crate::matcher::{MatchResult, Verdict};
use crate::policy::{Action, Policy};

/// Convert a flat list of findings (from the parallel evaluator
/// registry) into a `Verdict` the legacy renderer understands.
///
/// Each `Finding` becomes a synthetic `Advisory` carrying the original
/// finding's id, summary, severity, references, and (for postinstall /
/// risk / provenance) a class tag we encode into `ThreatClass::Malware`
/// when the finding kind warrants a malware-equivalent treatment, else
/// `ThreatClass::Vulnerability`.
pub fn findings_to_verdict(findings: Vec<Finding>, policy: &Policy) -> Verdict {
    let matches: Vec<MatchResult> = findings
        .into_iter()
        .map(|f| {
            let action = decide_action(policy, &f);
            let class = legacy_class_for_kind(f.kind, f.severity);
            let severity = legacy_severity(f.severity);
            let pkg = f.package.clone();
            let advisory = Advisory {
                id: f.id,
                aliases: f.aliases,
                ecosystem: pkg.ecosystem,
                package: pkg.name.clone(),
                summary: f.summary,
                severity,
                class,
                ranges: vec![],
                fixed_versions: f.fixed_versions,
                references: f.references,
            };
            MatchResult {
                package: pkg,
                advisory,
                action,
            }
        })
        .filter(|m| m.action != Action::Allow)
        .collect();

    Verdict { matches }
}

/// Map (kind, severity) onto the legacy `ThreatClass` the renderer uses
/// for the red MALWARE column vs the yellow CVE column.
///
/// Heuristic-only kinds (PostinstallScript, RiskScore) only render as
/// MALWARE when the heuristic itself reports `Critical`. A low-severity
/// postinstall (e.g. score-0 `node install.js`) renders as CVE so it
/// doesn't masquerade as a confirmed compromise.
fn legacy_class_for_kind(kind: FindingKind, severity: FindingSeverity) -> ThreatClass {
    match kind {
        // Confirmed malware records (MAL-* IDs, OSV-classified) always MALWARE
        FindingKind::Malware => ThreatClass::Malware,
        // Provenance mismatch is a strong signal — usually means hijack
        FindingKind::ProvenanceMismatch => ThreatClass::Malware,
        // Heuristic kinds: only MALWARE when the heuristic itself screamed
        FindingKind::PostinstallScript | FindingKind::RiskScore => {
            if severity == FindingSeverity::Critical {
                ThreatClass::Malware
            } else {
                ThreatClass::Vulnerability
            }
        }
        // Plain CVEs and missing provenance render as CVE
        FindingKind::Vulnerability | FindingKind::MissingProvenance => ThreatClass::Vulnerability,
    }
}

fn legacy_severity(s: FindingSeverity) -> AdvSeverity {
    match s {
        FindingSeverity::Critical => AdvSeverity::Critical,
        FindingSeverity::High => AdvSeverity::High,
        FindingSeverity::Medium => AdvSeverity::Medium,
        FindingSeverity::Low => AdvSeverity::Low,
        FindingSeverity::Unknown => AdvSeverity::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::{Ecosystem, PackageRef};

    fn pkg() -> PackageRef {
        PackageRef::new(Ecosystem::Npm, "x", "1.0.0")
    }

    #[test]
    fn malware_kind_renders_as_malware() {
        let f = Finding {
            package: pkg(),
            kind: FindingKind::Malware,
            id: "MAL-1".into(),
            aliases: vec![],
            summary: "compromised".into(),
            severity: FindingSeverity::Critical,
            fixed_versions: vec![],
            references: vec![],
            details: serde_json::Value::Null,
        };
        let v = findings_to_verdict(vec![f], &Policy::default());
        assert_eq!(v.matches.len(), 1);
        assert_eq!(v.matches[0].advisory.class, ThreatClass::Malware);
        assert_eq!(v.matches[0].action, Action::Block);
    }

    #[test]
    fn postinstall_critical_renders_as_malware_class() {
        let f = Finding {
            package: pkg(),
            kind: FindingKind::PostinstallScript,
            id: "script:postinstall:abc".into(),
            aliases: vec![],
            summary: "suspicious".into(),
            severity: FindingSeverity::Critical,
            fixed_versions: vec![],
            references: vec![],
            details: serde_json::Value::Null,
        };
        let v = findings_to_verdict(vec![f], &Policy::default());
        assert_eq!(v.matches[0].advisory.class, ThreatClass::Malware);
    }

    /// A score-0 postinstall (e.g. `node install.js`) must NOT render
    /// as MALWARE — that masquerades as a confirmed compromise.
    #[test]
    fn postinstall_low_renders_as_cve_class() {
        let mut policy = Policy::default();
        policy.postinstall_default = Action::Warn; // force the finding through
        let f = Finding {
            package: pkg(),
            kind: FindingKind::PostinstallScript,
            id: "script:postinstall:def".into(),
            aliases: vec![],
            summary: "node install.js".into(),
            severity: FindingSeverity::Low,
            fixed_versions: vec![],
            references: vec![],
            details: serde_json::Value::Null,
        };
        let v = findings_to_verdict(vec![f], &policy);
        assert_eq!(v.matches.len(), 1);
        assert_eq!(v.matches[0].advisory.class, ThreatClass::Vulnerability);
    }

    #[test]
    fn risk_renders_as_cve_class() {
        let f = Finding {
            package: pkg(),
            kind: FindingKind::RiskScore,
            id: "risk:typosquat:loadsh".into(),
            aliases: vec![],
            summary: "typosquat of lodash".into(),
            severity: FindingSeverity::High,
            fixed_versions: vec![],
            references: vec![],
            details: serde_json::Value::Null,
        };
        let v = findings_to_verdict(vec![f], &Policy::default());
        assert_eq!(v.matches[0].advisory.class, ThreatClass::Vulnerability);
    }

    #[test]
    fn allow_action_filtered_out() {
        let f = Finding {
            package: pkg(),
            kind: FindingKind::Vulnerability,
            id: "GHSA-x".into(),
            aliases: vec![],
            summary: "low".into(),
            severity: FindingSeverity::Low,
            fixed_versions: vec![],
            references: vec![],
            details: serde_json::Value::Null,
        };
        let v = findings_to_verdict(vec![f], &Policy::default());
        assert!(v.matches.is_empty(), "Low CVE should be allow-filtered");
    }

}

use anyhow::Result;
use comfy_table::{presets::UTF8_FULL, Cell, Color, Table};
use guardep_core::advisory::{Severity, ThreatClass};
use guardep_core::matcher::{MatchResult, Verdict};
use guardep_core::policy::Action;
use owo_colors::OwoColorize;
use serde::Serialize;
use std::collections::BTreeMap;

pub fn print_verdict(verdict: &Verdict, collapse: bool) {
    let deduped = verdict.deduped();
    if deduped.is_empty() {
        println!("{} no advisories matched", "✓".green().bold());
        return;
    }

    if collapse {
        print_collapsed(&deduped);
    } else {
        print_expanded(&deduped);
    }
    print_summary(verdict, deduped.len(), collapse);
}

fn print_expanded(deduped: &[&MatchResult]) {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["", "Package", "Advisory", "Class", "Severity", "Fix", "Action"]);

    for m in deduped {
        let icon = row_icon(m.action, m.advisory.severity);
        let class = class_cell(m.advisory.class);
        let fix = m
            .advisory
            .fixed_versions
            .first()
            .cloned()
            .unwrap_or_else(|| "—".to_string());
        table.add_row(vec![
            icon,
            Cell::new(format!("{}@{}", m.package.name, m.package.version)),
            Cell::new(&m.advisory.id),
            class,
            Cell::new(format!("{:?}", m.advisory.severity)),
            Cell::new(fix),
            Cell::new(format!("{:?}", m.action).to_uppercase()),
        ]);
    }
    println!("{table}");
}

fn print_collapsed(deduped: &[&MatchResult]) {
    let groups = group_by_package(deduped);

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        "", "Package", "#", "Advisories", "Class", "Severity", "Min", "Safe", "Action",
    ]);

    for (key, items) in &groups {
        let action = worst_action(items);
        let severity = max_severity(items);
        let class = worst_class(items);
        let targets = fix_targets(items);
        let advisory_ids: Vec<&str> = items.iter().map(|m| m.advisory.id.as_str()).collect();

        table.add_row(vec![
            row_icon(action, severity),
            Cell::new(key),
            Cell::new(items.len().to_string()),
            Cell::new(advisory_ids.join(", ")),
            class_cell(class),
            Cell::new(format!("{severity:?}")),
            Cell::new(targets.min_label()),
            Cell::new(targets.safe_label()),
            Cell::new(format!("{action:?}").to_uppercase()),
        ]);
    }
    println!("{table}");
}

fn group_by_package<'a>(deduped: &[&'a MatchResult]) -> BTreeMap<String, Vec<&'a MatchResult>> {
    let mut groups: BTreeMap<String, Vec<&'a MatchResult>> = BTreeMap::new();
    for m in deduped {
        let key = format!("{}@{}", m.package.name, m.package.version);
        groups.entry(key).or_default().push(*m);
    }
    groups
}

fn worst_action(items: &[&MatchResult]) -> Action {
    items
        .iter()
        .map(|m| m.action)
        .max_by_key(|a| match a {
            Action::Block => 2,
            Action::Warn => 1,
            Action::Allow => 0,
        })
        .unwrap_or(Action::Allow)
}

fn max_severity(items: &[&MatchResult]) -> Severity {
    items
        .iter()
        .map(|m| m.advisory.severity)
        .max_by_key(|s| match s {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Info => 1,
            Severity::Unknown => 0,
        })
        .unwrap_or(Severity::Unknown)
}

fn worst_class(items: &[&MatchResult]) -> ThreatClass {
    if items.iter().any(|m| m.advisory.class == ThreatClass::Malware) {
        ThreatClass::Malware
    } else {
        ThreatClass::Vulnerability
    }
}

/// Suggested upgrade targets for a package with N matched advisories.
///
/// `min`  = smallest in-major bump that clears at least one advisory.
///          Cheapest patch but may leave other CVEs unfixed.
/// `safe` = smallest in-major bump that clears ALL advisories — i.e. the
///          max of each advisory's earliest in-major fix. None if at least
///          one advisory has no in-major fix (user must major-upgrade).
/// `cross_major_fallback` = smallest fix across any major when no in-major
///                          fix exists for any advisory. Breaking change.
/// `cleared_at_min` = how many of N advisories the `min` bump resolves.
/// `total` = total advisories grouped (N).
#[derive(Debug, Clone, Default)]
pub struct FixTargets {
    pub min: Option<String>,
    pub safe: Option<String>,
    pub cross_major_fallback: Option<String>,
    pub cleared_at_min: usize,
    pub total: usize,
    pub breaking: bool,
}

impl FixTargets {
    pub fn min_label(&self) -> String {
        match &self.min {
            Some(v) => format!("{v} ({}/{})", self.cleared_at_min, self.total),
            None => match &self.cross_major_fallback {
                Some(v) => format!("{v} (breaking)"),
                None => "—".to_string(),
            },
        }
    }

    pub fn safe_label(&self) -> String {
        match &self.safe {
            Some(v) => format!("{v} ({}/{})", self.total, self.total),
            None => match &self.cross_major_fallback {
                Some(v) => format!("{v} (breaking)"),
                None => "—".to_string(),
            },
        }
    }
}

pub fn fix_targets(items: &[&MatchResult]) -> FixTargets {
    let total = items.len();
    let mut out = FixTargets {
        total,
        ..Default::default()
    };

    let Some(installed_str) = items.first().map(|m| m.package.version.as_str()) else {
        return out;
    };
    let Ok(inst) = semver::Version::parse(installed_str) else {
        // Non-semver — give up on smart selection, dump first fix per advisory.
        return out;
    };

    // Per-advisory smallest in-major fix > installed.
    let mut per_advisory_in_major: Vec<semver::Version> = Vec::new();
    let mut all_in_major: std::collections::BTreeSet<semver::Version> = std::collections::BTreeSet::new();
    let mut any_cross_major: std::collections::BTreeSet<semver::Version> = std::collections::BTreeSet::new();
    let mut advisories_without_in_major_fix = 0usize;

    for m in items {
        let parsed: Vec<semver::Version> = m
            .advisory
            .fixed_versions
            .iter()
            .filter_map(|v| semver::Version::parse(v).ok())
            .collect();

        let in_major: Vec<&semver::Version> = parsed
            .iter()
            .filter(|v| v.major == inst.major && **v > inst)
            .collect();

        match in_major.iter().min().cloned().cloned() {
            Some(smallest) => {
                all_in_major.insert(smallest.clone());
                per_advisory_in_major.push(smallest);
            }
            None => {
                advisories_without_in_major_fix += 1;
                for v in &parsed {
                    if *v > inst {
                        any_cross_major.insert(v.clone());
                    }
                }
            }
        }
    }

    // min: smallest in-major fix across all advisories
    if let Some(min) = all_in_major.iter().next() {
        out.min = Some(min.to_string());
        out.cleared_at_min = per_advisory_in_major
            .iter()
            .filter(|fix| **fix <= *min)
            .count();
    }

    // safe: max of per-advisory smallest in-major fixes — only valid when
    // every advisory has an in-major fix
    if advisories_without_in_major_fix == 0 && !per_advisory_in_major.is_empty() {
        if let Some(safe) = per_advisory_in_major.iter().max() {
            out.safe = Some(safe.to_string());
        }
    }

    // cross-major fallback when no in-major fix exists at all
    if out.min.is_none() {
        if let Some(v) = any_cross_major.iter().next() {
            out.cross_major_fallback = Some(v.to_string());
            out.breaking = true;
        }
    } else if advisories_without_in_major_fix > 0 {
        // partial in-major coverage; safe target needs cross-major
        if let Some(v) = any_cross_major.iter().max() {
            out.cross_major_fallback = Some(v.to_string());
        }
    }

    out
}

fn action_icon(action: Action) -> Cell {
    match action {
        Action::Block => Cell::new("✗").fg(Color::Red),
        Action::Warn => Cell::new("!").fg(Color::Yellow),
        Action::Allow => Cell::new("•").fg(Color::Grey),
    }
}

/// Variant that knows about Info severity — Info findings have action
/// Allow but should render with a distinct cyan `i` so they don't blend
/// in with suppressed entries.
fn row_icon(action: Action, severity: Severity) -> Cell {
    if action == Action::Allow && severity == Severity::Info {
        return Cell::new("i").fg(Color::Cyan);
    }
    action_icon(action)
}

fn class_cell(class: ThreatClass) -> Cell {
    match class {
        ThreatClass::Malware => Cell::new("MALWARE").fg(Color::Red),
        ThreatClass::Vulnerability => Cell::new("CVE").fg(Color::Yellow),
    }
}

fn print_summary(verdict: &Verdict, deduped_total: usize, collapsed: bool) {
    let blocks = verdict.count_blocks();
    let warns = verdict.count_warnings();
    let malware = verdict.count_malware();
    let raw_total = verdict.matches.len();

    let group_count = if collapsed {
        let mut s = std::collections::BTreeSet::new();
        for m in &verdict.matches {
            s.insert(format!("{}@{}", m.package.name, m.package.version));
        }
        Some(s.len())
    } else {
        None
    };

    println!();
    let groups_part = group_count
        .map(|g| format!(", {} affected package{}", g, if g == 1 { "" } else { "s" }))
        .unwrap_or_default();

    if blocks > 0 {
        println!(
            "{} {} block(s), {} warning(s), {} malware finding(s) across {} unique advisor{}{} ({} raw)",
            "✗".red().bold(),
            blocks.to_string().red().bold(),
            warns.to_string().yellow(),
            malware.to_string().red(),
            deduped_total,
            if deduped_total == 1 { "y" } else { "ies" },
            groups_part,
            raw_total
        );
    } else if warns > 0 {
        println!(
            "{} {} warning(s), {} malware finding(s) across {} unique advisor{}{} ({} raw)",
            "!".yellow().bold(),
            warns.to_string().yellow().bold(),
            malware.to_string().red(),
            deduped_total,
            if deduped_total == 1 { "y" } else { "ies" },
            groups_part,
            raw_total
        );
    } else {
        println!("{} clean", "✓".green().bold());
    }
}

#[derive(Serialize)]
struct JsonReport<'a> {
    summary: JsonSummary,
    findings: JsonFindings<'a>,
}

#[derive(Serialize)]
struct JsonSummary {
    blocks: usize,
    warnings: usize,
    malware: usize,
    unique_findings: usize,
    raw_matches: usize,
    affected_packages: Option<usize>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum JsonFindings<'a> {
    Expanded(Vec<JsonFinding<'a>>),
    Collapsed(Vec<JsonGroup<'a>>),
}

#[derive(Serialize)]
struct JsonFinding<'a> {
    package: &'a str,
    version: &'a str,
    advisory_id: &'a str,
    class: &'static str,
    severity: String,
    action: String,
    fix: Option<&'a str>,
    references: &'a [String],
}

#[derive(Serialize)]
struct JsonGroup<'a> {
    package: String,
    version: String,
    count: usize,
    advisory_ids: Vec<&'a str>,
    class: &'static str,
    severity: String,
    action: String,
    fix_min: Option<String>,
    fix_min_clears: usize,
    fix_safe: Option<String>,
    cross_major_fallback: Option<String>,
    breaking: bool,
}

pub fn print_json(verdict: &Verdict, collapse: bool) -> Result<()> {
    let deduped = verdict.deduped();

    let findings = if collapse {
        let groups = group_by_package(&deduped);
        let collapsed: Vec<JsonGroup> = groups
            .into_iter()
            .map(|(key, items)| {
                let (name, version) = split_key(&key);
                let action = worst_action(&items);
                let class = worst_class(&items);
                let severity = max_severity(&items);
                let targets = fix_targets(&items);
                JsonGroup {
                    package: name.to_string(),
                    version: version.to_string(),
                    count: items.len(),
                    advisory_ids: items.iter().map(|m| m.advisory.id.as_str()).collect(),
                    class: match class {
                        ThreatClass::Malware => "malware",
                        ThreatClass::Vulnerability => "cve",
                    },
                    severity: format!("{severity:?}").to_lowercase(),
                    action: format!("{action:?}").to_lowercase(),
                    fix_min: targets.min,
                    fix_min_clears: targets.cleared_at_min,
                    fix_safe: targets.safe,
                    cross_major_fallback: targets.cross_major_fallback,
                    breaking: targets.breaking,
                }
            })
            .collect();
        JsonFindings::Collapsed(collapsed)
    } else {
        let expanded: Vec<JsonFinding> = deduped
            .iter()
            .map(|m| JsonFinding {
                package: &m.package.name,
                version: &m.package.version,
                advisory_id: &m.advisory.id,
                class: match m.advisory.class {
                    ThreatClass::Malware => "malware",
                    ThreatClass::Vulnerability => "cve",
                },
                severity: format!("{:?}", m.advisory.severity).to_lowercase(),
                action: format!("{:?}", m.action).to_lowercase(),
                fix: m.advisory.fixed_versions.first().map(String::as_str),
                references: &m.advisory.references,
            })
            .collect();
        JsonFindings::Expanded(expanded)
    };

    let affected_packages = if collapse {
        let mut s = std::collections::BTreeSet::new();
        for m in &verdict.matches {
            s.insert(format!("{}@{}", m.package.name, m.package.version));
        }
        Some(s.len())
    } else {
        None
    };

    let report = JsonReport {
        summary: JsonSummary {
            blocks: verdict.count_blocks(),
            warnings: verdict.count_warnings(),
            malware: verdict.count_malware(),
            unique_findings: deduped.len(),
            raw_matches: verdict.matches.len(),
            affected_packages,
        },
        findings,
    };

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

/// Split "name@version" into (name, version), handling scoped packages
/// like "@xmldom/xmldom@0.8.11" where the leading '@' is part of the name.
fn split_key(key: &str) -> (&str, &str) {
    let bytes = key.as_bytes();
    // find last '@' that is not at index 0
    let mut split_at = None;
    for (i, &b) in bytes.iter().enumerate().rev() {
        if b == b'@' && i != 0 {
            split_at = Some(i);
            break;
        }
    }
    match split_at {
        Some(i) => (&key[..i], &key[i + 1..]),
        None => (key, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardep_core::advisory::{Advisory, AffectedRange, Severity};
    use guardep_core::ecosystem::{Ecosystem, PackageRef};

    #[test]
    fn split_scoped() {
        assert_eq!(split_key("@xmldom/xmldom@0.8.11"), ("@xmldom/xmldom", "0.8.11"));
        assert_eq!(split_key("axios@1.13.2"), ("axios", "1.13.2"));
        assert_eq!(split_key("@scope/pkg@1.0.0-beta.1"), ("@scope/pkg", "1.0.0-beta.1"));
    }

    fn mk(installed: &str, fixes: &[&str]) -> MatchResult {
        MatchResult {
            package: PackageRef::new(Ecosystem::Npm, "p", installed),
            advisory: Advisory {
                id: "X".into(),
                aliases: vec![],
                ecosystem: Ecosystem::Npm,
                package: "p".into(),
                summary: String::new(),
                severity: Severity::High,
                class: ThreatClass::Vulnerability,
                ranges: vec![AffectedRange {
                    introduced: None,
                    fixed: None,
                    versions: vec![],
                }],
                fixed_versions: fixes.iter().map(|s| s.to_string()).collect(),
                references: vec![],
            },
            action: Action::Warn,
        }
    }

    #[test]
    fn single_advisory_in_major() {
        let m = mk("5.1.6", &["3.1.3", "4.2.4", "5.1.7", "5.1.8", "9.0.7"]);
        let t = fix_targets(&[&m]);
        assert_eq!(t.min.as_deref(), Some("5.1.7"));
        assert_eq!(t.safe.as_deref(), Some("5.1.7"));
        assert_eq!(t.cleared_at_min, 1);
        assert_eq!(t.total, 1);
        assert!(!t.breaking);
    }

    #[test]
    fn falls_back_to_cross_major_when_no_in_major_fix() {
        let m = mk("5.1.6", &["6.0.1", "7.0.0"]);
        let t = fix_targets(&[&m]);
        assert!(t.min.is_none());
        assert!(t.safe.is_none());
        assert_eq!(t.cross_major_fallback.as_deref(), Some("6.0.1"));
        assert!(t.breaking);
    }

    #[test]
    fn ignores_fixes_below_installed() {
        let m = mk("5.1.7", &["5.1.6", "5.1.8"]);
        let t = fix_targets(&[&m]);
        assert_eq!(t.min.as_deref(), Some("5.1.8"));
        assert_eq!(t.safe.as_deref(), Some("5.1.8"));
    }

    /// The motivating scenario: staircase CVEs.
    /// installed 1.0.0, advisories chained:
    ///   CVE-A fixed in 1.0.1
    ///   CVE-B fixed in 1.0.2
    ///   CVE-C fixed in 1.0.3
    /// Min bump (1.0.1) clears only CVE-A. Safe target is 1.0.3.
    #[test]
    fn staircase_cves_min_vs_safe() {
        let a = mk("1.0.0", &["1.0.1"]);
        let b = mk("1.0.0", &["1.0.2"]);
        let c = mk("1.0.0", &["1.0.3"]);
        let t = fix_targets(&[&a, &b, &c]);
        assert_eq!(t.min.as_deref(), Some("1.0.1"));
        assert_eq!(t.cleared_at_min, 1);
        assert_eq!(t.safe.as_deref(), Some("1.0.3"));
        assert_eq!(t.total, 3);
    }

    /// All CVEs share a single fix → min == safe, cleared = total.
    #[test]
    fn all_cves_one_fix() {
        let a = mk("1.13.2", &["1.13.5"]);
        let b = mk("1.13.2", &["1.13.5"]);
        let c = mk("1.13.2", &["1.13.5"]);
        let t = fix_targets(&[&a, &b, &c]);
        assert_eq!(t.min, t.safe);
        assert_eq!(t.cleared_at_min, 3);
    }

    /// Mixed: 2 CVEs have in-major fix, 1 has only cross-major fix.
    /// Safe must be None (no full in-major coverage), cross-major filled.
    #[test]
    fn partial_in_major_coverage() {
        let a = mk("6.2.1", &["6.2.2"]);
        let b = mk("6.2.1", &["6.2.5"]);
        let c = mk("6.2.1", &["7.5.0"]); // no 6.x fix
        let t = fix_targets(&[&a, &b, &c]);
        assert_eq!(t.min.as_deref(), Some("6.2.2"));
        assert_eq!(t.cleared_at_min, 1);
        assert!(t.safe.is_none());
        assert_eq!(t.cross_major_fallback.as_deref(), Some("7.5.0"));
    }

    #[test]
    fn min_label_format() {
        let a = mk("1.0.0", &["1.0.1"]);
        let b = mk("1.0.0", &["1.0.3"]);
        let t = fix_targets(&[&a, &b]);
        assert_eq!(t.min_label(), "1.0.1 (1/2)");
        assert_eq!(t.safe_label(), "1.0.3 (2/2)");
    }

    #[test]
    fn empty_when_no_fixes() {
        let m = mk("1.0.0", &[]);
        let t = fix_targets(&[&m]);
        assert!(t.min.is_none());
        assert!(t.safe.is_none());
        assert!(t.cross_major_fallback.is_none());
    }
}

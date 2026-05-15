use anyhow::Result;
use comfy_table::{presets::UTF8_FULL, Cell, Color, Table};
#[cfg(test)]
use guardep_core::FindingKind;
use guardep_core::{Action, DisplayClass, FindingSeverity, FindingsReport, ScoredFinding};
use owo_colors::OwoColorize;
use serde::Serialize;
use std::collections::BTreeMap;

pub fn print_verdict(report: &FindingsReport, collapse: bool) {
    let deduped = report.deduped();
    if deduped.is_empty() {
        println!("{} no findings", "OK".green().bold());
        return;
    }

    if collapse {
        print_collapsed(&deduped);
    } else {
        print_expanded(&deduped);
    }
    print_summary(report, deduped.len(), collapse);
}

fn print_expanded(deduped: &[&ScoredFinding]) {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        "", "Package", "Finding", "Class", "Severity", "Fix", "Action",
    ]);

    for s in deduped {
        let icon = row_icon(s.action, s.finding.severity);
        let class = class_cell(s.finding.display_class(), s.finding.severity);
        let fix = s
            .finding
            .fixed_versions
            .first()
            .cloned()
            .unwrap_or_else(|| "-".to_string());
        table.add_row(vec![
            icon,
            Cell::new(format!(
                "{}@{}",
                s.finding.package.name, s.finding.package.version
            )),
            Cell::new(finding_label(&s.finding)),
            class,
            Cell::new(format!("{:?}", s.finding.severity)),
            Cell::new(fix),
            Cell::new(format!("{:?}", s.action).to_uppercase()),
        ]);
    }
    println!("{table}");
}

// For RiskScore findings, render the composite score + contributing
// reasons instead of just the primary-reason slug. Mirrors how Socket
// surfaces a single quality score per package backed by its inputs,
// so the table reflects what actually drove the severity (e.g. score
// 45 from `few-versions + single-maintainer`) rather than implying
// any single reason crossed a threshold on its own.
fn finding_label(f: &guardep_core::Finding) -> String {
    use guardep_core::FindingKind;
    if matches!(f.kind, FindingKind::Vulnerability | FindingKind::Malware) {
        return format!("{}{}", f.id, exploit_suffix(f));
    }
    if matches!(f.kind, FindingKind::SourceBehavior) {
        let label = f
            .details
            .get("label")
            .and_then(|v| v.as_str())
            .unwrap_or("source behavior");
        let n = f
            .details
            .get("occurrences")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        return format!("{label} (x{n})");
    }
    if matches!(f.kind, FindingKind::License) {
        let issue = f
            .details
            .get("issue")
            .and_then(|v| v.as_str())
            .unwrap_or("issue");
        let declared = f
            .details
            .get("declared")
            .and_then(|v| v.as_str())
            .unwrap_or("(none)");
        return format!("License {issue}: {declared}");
    }
    if !matches!(f.kind, FindingKind::RiskScore) {
        return f.id.clone();
    }
    let score = f.details.get("score").and_then(|v| v.as_u64());
    let reasons: Vec<&str> = f
        .details
        .get("reasons")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|r| r.as_str()).collect())
        .unwrap_or_default();

    match (score, reasons.is_empty()) {
        (Some(s), false) => format!("risk {} ({}): {}", f.package.name, s, reasons.join(", ")),
        (Some(s), true) => format!("risk {} ({})", f.package.name, s),
        (None, false) => format!("risk {}: {}", f.package.name, reasons.join(", ")),
        (None, true) => f.id.clone(),
    }
}

/// Render KEV / EPSS badges next to a CVE id. Empty when neither is
/// present so cached/un-enriched findings stay clean.
fn exploit_suffix(f: &guardep_core::Finding) -> String {
    let kev = f
        .details
        .get("kev")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let percentile = f
        .details
        .get("epss")
        .and_then(|v| v.get("percentile"))
        .and_then(|v| v.as_f64());
    let mut parts: Vec<String> = Vec::new();
    if kev {
        parts.push("KEV".to_string());
    }
    if let Some(p) = percentile {
        // Show the percentile as p<N> rounded so a 0.991 reads "p99".
        let n = (p * 100.0).round() as u32;
        parts.push(format!("EPSS p{n}"));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" [{}]", parts.join(" "))
    }
}

fn print_collapsed(deduped: &[&ScoredFinding]) {
    let groups = group_by_package(deduped);

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        "", "Package", "#", "Findings", "Class", "Severity", "Min", "Safe", "Action",
    ]);

    for (key, items) in &groups {
        let action = worst_action(items);
        let severity = max_severity(items);
        let class = worst_class(items);
        let targets = fix_targets(items);
        let labels: Vec<String> = items.iter().map(|s| finding_label(&s.finding)).collect();

        table.add_row(vec![
            row_icon(action, severity),
            Cell::new(key),
            Cell::new(items.len().to_string()),
            Cell::new(labels.join(", ")),
            class_cell(class, severity),
            Cell::new(format!("{severity:?}")),
            Cell::new(targets.min_label()),
            Cell::new(targets.safe_label()),
            Cell::new(format!("{action:?}").to_uppercase()),
        ]);
    }
    println!("{table}");
}

fn group_by_package<'a>(deduped: &[&'a ScoredFinding]) -> BTreeMap<String, Vec<&'a ScoredFinding>> {
    let mut groups: BTreeMap<String, Vec<&'a ScoredFinding>> = BTreeMap::new();
    for s in deduped {
        let key = format!("{}@{}", s.finding.package.name, s.finding.package.version);
        groups.entry(key).or_default().push(*s);
    }
    groups
}

fn worst_action(items: &[&ScoredFinding]) -> Action {
    items
        .iter()
        .map(|s| s.action)
        .max_by_key(|a| match a {
            Action::Block => 2,
            Action::Warn => 1,
            Action::Allow => 0,
        })
        .unwrap_or(Action::Allow)
}

fn max_severity(items: &[&ScoredFinding]) -> FindingSeverity {
    items
        .iter()
        .map(|s| s.finding.severity)
        .max_by_key(|s| match s {
            FindingSeverity::Critical => 5,
            FindingSeverity::High => 4,
            FindingSeverity::Medium => 3,
            FindingSeverity::Low => 2,
            FindingSeverity::Info => 1,
            FindingSeverity::Unknown => 0,
        })
        .unwrap_or(FindingSeverity::Unknown)
}

/// Worst (most-malware-like) display class across a group's findings.
fn worst_class(items: &[&ScoredFinding]) -> DisplayClass {
    items
        .iter()
        .map(|s| s.finding.display_class())
        .fold(DisplayClass::Cve, DisplayClass::merge)
}

/// Suggested upgrade targets for a package with N matched findings.
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
                None => "-".to_string(),
            },
        }
    }

    pub fn safe_label(&self) -> String {
        match &self.safe {
            Some(v) => format!("{v} ({}/{})", self.total, self.total),
            None => match &self.cross_major_fallback {
                Some(v) => format!("{v} (breaking)"),
                None => "-".to_string(),
            },
        }
    }
}

pub fn fix_targets(items: &[&ScoredFinding]) -> FixTargets {
    let total = items.len();
    let mut out = FixTargets {
        total,
        ..Default::default()
    };

    let Some(installed_str) = items.first().map(|s| s.finding.package.version.as_str()) else {
        return out;
    };
    let Ok(inst) = semver::Version::parse(installed_str) else {
        return out;
    };

    let mut per_finding_in_major: Vec<semver::Version> = Vec::new();
    let mut all_in_major: std::collections::BTreeSet<semver::Version> =
        std::collections::BTreeSet::new();
    let mut any_cross_major: std::collections::BTreeSet<semver::Version> =
        std::collections::BTreeSet::new();
    let mut findings_without_in_major_fix = 0usize;

    for s in items {
        let parsed: Vec<semver::Version> = s
            .finding
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
                per_finding_in_major.push(smallest);
            }
            None => {
                findings_without_in_major_fix += 1;
                for v in &parsed {
                    if *v > inst {
                        any_cross_major.insert(v.clone());
                    }
                }
            }
        }
    }

    if let Some(min) = all_in_major.iter().next() {
        out.min = Some(min.to_string());
        out.cleared_at_min = per_finding_in_major
            .iter()
            .filter(|fix| **fix <= *min)
            .count();
    }

    if findings_without_in_major_fix == 0 && !per_finding_in_major.is_empty() {
        if let Some(safe) = per_finding_in_major.iter().max() {
            out.safe = Some(safe.to_string());
        }
    }

    if out.min.is_none() {
        if let Some(v) = any_cross_major.iter().next() {
            out.cross_major_fallback = Some(v.to_string());
            out.breaking = true;
        }
    } else if findings_without_in_major_fix > 0 {
        if let Some(v) = any_cross_major.iter().max() {
            out.cross_major_fallback = Some(v.to_string());
        }
    }

    out
}

fn action_icon(action: Action) -> Cell {
    match action {
        Action::Block => Cell::new("X").fg(Color::Red),
        Action::Warn => Cell::new("!").fg(Color::Yellow),
        Action::Allow => Cell::new(".").fg(Color::Grey),
    }
}

/// Variant that knows about Info severity — Info findings have action
/// Allow but should render with a distinct cyan `i` so they don't blend
/// in with suppressed entries.
fn row_icon(action: Action, severity: FindingSeverity) -> Cell {
    if action == Action::Allow && severity == FindingSeverity::Info {
        return Cell::new("i").fg(Color::Cyan);
    }
    action_icon(action)
}

fn class_cell(class: DisplayClass, severity: FindingSeverity) -> Cell {
    if severity == FindingSeverity::Info {
        return Cell::new("INFO").fg(Color::Cyan);
    }
    match class {
        DisplayClass::Malware => Cell::new("MALWARE").fg(Color::Red),
        DisplayClass::Cve => Cell::new("CVE").fg(Color::Yellow),
    }
}

fn print_summary(report: &FindingsReport, deduped_total: usize, collapsed: bool) {
    let blocks = report.count_blocks();
    let warns = report.count_warnings();
    let malware = report.count_malware();
    let info = report.count_info();
    let raw_total = report.raw_count();

    let group_count = if collapsed {
        let mut s = std::collections::BTreeSet::new();
        for sf in &report.items {
            s.insert(format!(
                "{}@{}",
                sf.finding.package.name, sf.finding.package.version
            ));
        }
        Some(s.len())
    } else {
        None
    };

    println!();
    let groups_part = group_count
        .map(|g| format!(", {} affected package{}", g, if g == 1 { "" } else { "s" }))
        .unwrap_or_default();
    let info_part = if info > 0 {
        format!(", {info} info")
    } else {
        String::new()
    };

    if blocks > 0 {
        println!(
            "{} {} block(s), {} warning(s), {} malware finding(s){} across {} unique{} ({} raw)",
            "X".red().bold(),
            blocks.to_string().red().bold(),
            warns.to_string().yellow(),
            malware.to_string().red(),
            info_part,
            deduped_total,
            groups_part,
            raw_total
        );
    } else if warns > 0 {
        println!(
            "{} {} warning(s), {} malware finding(s){} across {} unique{} ({} raw)",
            "!".yellow().bold(),
            warns.to_string().yellow().bold(),
            malware.to_string().red(),
            info_part,
            deduped_total,
            groups_part,
            raw_total
        );
    } else if info > 0 {
        println!(
            "{} clean ({} info finding(s) shown across {} unique)",
            "OK".green().bold(),
            info,
            deduped_total
        );
    } else {
        println!("{} clean", "OK".green().bold());
    }

    // Provenance breakdown — surfaces whether crypto verification
    // actually ran. If trust root was unavailable, this is the only
    // place the user sees that.
    let prov = report.provenance_breakdown();
    if prov.trust_root_unavailable_for > 0 {
        println!(
            "{} provenance: {} package(s) checked with identity only (trust root unavailable)",
            "!".yellow(),
            prov.trust_root_unavailable_for
        );
    }
    if prov.missing > 0 || prov.mismatched > 0 {
        println!(
            "  provenance breakdown: {} missing, {} mismatched",
            prov.missing, prov.mismatched
        );
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
    info: usize,
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
    finding_id: &'a str,
    kind: &'static str,
    class: &'static str,
    severity: String,
    action: String,
    fix: Option<&'a str>,
    references: &'a [String],
    details: &'a serde_json::Value,
}

#[derive(Serialize)]
struct JsonGroup<'a> {
    package: String,
    version: String,
    count: usize,
    class: &'static str,
    severity: String,
    action: String,
    fix_min: Option<String>,
    fix_min_clears: usize,
    fix_safe: Option<String>,
    cross_major_fallback: Option<String>,
    breaking: bool,
    /// Per-finding details — kind, severity, references, evaluator
    /// `details` payload. Consumers wanting just IDs can do
    /// `.findings | map(.finding_id)` in jq. We don't ship a
    /// separate `finding_ids` field anymore; the data was duplicated.
    /// Lets CI consumers introspect a group without
    /// re-running with `--format json` minus `--collapse`.
    findings: Vec<JsonGroupFinding<'a>>,
}

#[derive(Serialize)]
struct JsonGroupFinding<'a> {
    finding_id: &'a str,
    kind: &'static str,
    severity: String,
    action: String,
    summary: &'a str,
    fix: Option<&'a str>,
    references: &'a [String],
    details: &'a serde_json::Value,
}

pub fn print_json(report: &FindingsReport, collapse: bool) -> Result<()> {
    let deduped = report.deduped();

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
                let per_finding: Vec<JsonGroupFinding> = items
                    .iter()
                    .map(|s| JsonGroupFinding {
                        finding_id: s.finding.id.as_str(),
                        kind: s.finding.kind.as_str(),
                        severity: format!("{:?}", s.finding.severity).to_lowercase(),
                        action: format!("{:?}", s.action).to_lowercase(),
                        summary: s.finding.summary.as_str(),
                        fix: s.finding.fixed_versions.first().map(String::as_str),
                        references: &s.finding.references,
                        details: &s.finding.details,
                    })
                    .collect();
                JsonGroup {
                    package: name.to_string(),
                    version: version.to_string(),
                    count: items.len(),
                    class: match class {
                        DisplayClass::Malware => "malware",
                        DisplayClass::Cve => "cve",
                    },
                    severity: format!("{severity:?}").to_lowercase(),
                    action: format!("{action:?}").to_lowercase(),
                    fix_min: targets.min,
                    fix_min_clears: targets.cleared_at_min,
                    fix_safe: targets.safe,
                    cross_major_fallback: targets.cross_major_fallback,
                    breaking: targets.breaking,
                    findings: per_finding,
                }
            })
            .collect();
        JsonFindings::Collapsed(collapsed)
    } else {
        let expanded: Vec<JsonFinding> = deduped
            .iter()
            .map(|s| JsonFinding {
                package: &s.finding.package.name,
                version: &s.finding.package.version,
                finding_id: &s.finding.id,
                kind: s.finding.kind.as_str(),
                class: match s.finding.display_class() {
                    DisplayClass::Malware => "malware",
                    DisplayClass::Cve => "cve",
                },
                severity: format!("{:?}", s.finding.severity).to_lowercase(),
                action: format!("{:?}", s.action).to_lowercase(),
                fix: s.finding.fixed_versions.first().map(String::as_str),
                references: &s.finding.references,
                details: &s.finding.details,
            })
            .collect();
        JsonFindings::Expanded(expanded)
    };

    let affected_packages = if collapse {
        let mut s = std::collections::BTreeSet::new();
        for sf in &report.items {
            s.insert(format!(
                "{}@{}",
                sf.finding.package.name, sf.finding.package.version
            ));
        }
        Some(s.len())
    } else {
        None
    };

    let out = JsonReport {
        summary: JsonSummary {
            blocks: report.count_blocks(),
            warnings: report.count_warnings(),
            malware: report.count_malware(),
            info: report.count_info(),
            unique_findings: deduped.len(),
            raw_matches: report.raw_count(),
            affected_packages,
        },
        findings,
    };

    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn split_key(key: &str) -> (&str, &str) {
    let bytes = key.as_bytes();
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
    use guardep_core::ecosystem::{Ecosystem, PackageRef};
    use guardep_core::finding::Finding;

    #[test]
    fn split_scoped() {
        assert_eq!(
            split_key("@xmldom/xmldom@0.8.11"),
            ("@xmldom/xmldom", "0.8.11")
        );
        assert_eq!(split_key("axios@1.13.2"), ("axios", "1.13.2"));
        assert_eq!(
            split_key("@scope/pkg@1.0.0-beta.1"),
            ("@scope/pkg", "1.0.0-beta.1")
        );
    }

    fn mk(installed: &str, fixes: &[&str]) -> ScoredFinding {
        ScoredFinding {
            finding: Finding {
                package: PackageRef::new(Ecosystem::Npm, "p", installed),
                kind: FindingKind::Vulnerability,
                id: "X".into(),
                aliases: vec![],
                summary: String::new(),
                severity: FindingSeverity::High,
                fixed_versions: fixes.iter().map(|s| s.to_string()).collect(),
                references: vec![],
                details: serde_json::Value::Null,
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

    #[test]
    fn all_cves_one_fix() {
        let a = mk("1.13.2", &["1.13.5"]);
        let b = mk("1.13.2", &["1.13.5"]);
        let c = mk("1.13.2", &["1.13.5"]);
        let t = fix_targets(&[&a, &b, &c]);
        assert_eq!(t.min, t.safe);
        assert_eq!(t.cleared_at_min, 3);
    }

    #[test]
    fn partial_in_major_coverage() {
        let a = mk("6.2.1", &["6.2.2"]);
        let b = mk("6.2.1", &["6.2.5"]);
        let c = mk("6.2.1", &["7.5.0"]);
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

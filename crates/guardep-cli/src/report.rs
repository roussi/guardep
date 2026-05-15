use anyhow::Result;
use comfy_table::{presets::UTF8_FULL, Cell, Color, Table};
use guardep_core::advisory::ThreatClass;
use guardep_core::matcher::{MatchResult, Verdict};
use guardep_core::policy::Action;
use owo_colors::OwoColorize;
use serde::Serialize;

pub fn print_verdict(verdict: &Verdict) {
    let deduped = verdict.deduped();
    if deduped.is_empty() {
        println!("{} no advisories matched", "✓".green().bold());
        return;
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["", "Package", "Advisory", "Class", "Severity", "Fix", "Action"]);

    for m in &deduped {
        let icon = match m.action {
            Action::Block => Cell::new("✗").fg(Color::Red),
            Action::Warn => Cell::new("!").fg(Color::Yellow),
            Action::Allow => Cell::new("•").fg(Color::Grey),
        };
        let class = match m.advisory.class {
            ThreatClass::Malware => Cell::new("MALWARE").fg(Color::Red),
            ThreatClass::Vulnerability => Cell::new("CVE").fg(Color::Yellow),
        };
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
    print_summary(verdict, deduped.len());
}

fn print_summary(verdict: &Verdict, deduped_total: usize) {
    let blocks = verdict.count_blocks();
    let warns = verdict.count_warnings();
    let malware = verdict.count_malware();
    let raw_total = verdict.matches.len();

    println!();
    if blocks > 0 {
        println!(
            "{} {} block(s), {} warning(s), {} malware finding(s) across {} unique advisor{} ({} raw)",
            "✗".red().bold(),
            blocks.to_string().red().bold(),
            warns.to_string().yellow(),
            malware.to_string().red(),
            deduped_total,
            if deduped_total == 1 { "y" } else { "ies" },
            raw_total
        );
    } else if warns > 0 {
        println!(
            "{} {} warning(s), {} malware finding(s) across {} unique advisor{} ({} raw)",
            "!".yellow().bold(),
            warns.to_string().yellow().bold(),
            malware.to_string().red(),
            deduped_total,
            if deduped_total == 1 { "y" } else { "ies" },
            raw_total
        );
    } else {
        println!("{} clean", "✓".green().bold());
    }
}

#[derive(Serialize)]
struct JsonReport<'a> {
    summary: JsonSummary,
    findings: Vec<JsonFinding<'a>>,
}

#[derive(Serialize)]
struct JsonSummary {
    blocks: usize,
    warnings: usize,
    malware: usize,
    unique_findings: usize,
    raw_matches: usize,
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

pub fn print_json(verdict: &Verdict) -> Result<()> {
    let deduped: Vec<&MatchResult> = verdict.deduped();
    let findings: Vec<JsonFinding> = deduped
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

    let report = JsonReport {
        summary: JsonSummary {
            blocks: verdict.count_blocks(),
            warnings: verdict.count_warnings(),
            malware: verdict.count_malware(),
            unique_findings: deduped.len(),
            raw_matches: verdict.matches.len(),
        },
        findings,
    };

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

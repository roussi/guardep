//! SARIF 2.1.0 emitter for guardep findings.
//!
//! Maps each `Finding` to a SARIF `result` object so the audit output
//! drops directly into GitHub code-scanning, GitLab, Sonar, and any
//! other consumer of the OASIS SARIF 2.1.0 schema.
//!
//! ## Mapping
//!
//! - `tool.driver.name`             → "guardep"
//! - `tool.driver.version` → CARGO_PKG_VERSION
//! - `tool.driver.rules[]` → unique (kind, behavior?) tuples seen in
//!   the run. ruleId is `kind` or `kind:behavior`.
//! - `results[].ruleId` → rule lookup key
//! - `results[].level` → SARIF level mapped from severity
//!   (Critical/High → `error`, Medium → `warning`, Low → `note`,
//!   Info/Unknown → `none`)
//! - `results[].message.text` → finding summary
//! - `results[].locations[]` → one entry per source-behavior location
//!   with byte range; CVE findings get a single artifact location
//!   pointing at the package.
//! - `results[].properties.*` → EPSS / KEV / fix metadata
//!
//! Aligns with GitHub code-scanning's expectations: severity is
//! attached to both the rule (defaultConfiguration.level) and each
//! result, partial fingerprints use the package coordinates so
//! repeated scans stay deduplicated.

use anyhow::Result;
use guardep_core::{Finding, FindingKind, FindingSeverity, FindingsReport};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub fn print_sarif(report: &FindingsReport) -> Result<()> {
    let doc = build_sarif(report);
    println!("{}", serde_json::to_string_pretty(&doc)?);
    Ok(())
}

fn build_sarif(report: &FindingsReport) -> Value {
    let findings: Vec<&Finding> = report.deduped().iter().map(|s| &s.finding).collect();

    // Collect distinct rules so SARIF consumers can render per-rule
    // help text and severity defaults. Key on (ruleId) so we keep one
    // entry per rule regardless of how many findings cite it.
    let mut rules: BTreeMap<String, Value> = BTreeMap::new();
    for f in &findings {
        let id = rule_id(f);
        rules.entry(id.clone()).or_insert_with(|| {
            json!({
                "id": id,
                "name": rule_name(f),
                "shortDescription": { "text": rule_short_desc(f) },
                "fullDescription": { "text": rule_full_desc(f) },
                "defaultConfiguration": { "level": severity_to_level(f.severity) },
                "helpUri": rule_help_uri(f),
                "properties": {
                    "category": rule_category(f),
                }
            })
        });
    }

    let results: Vec<Value> = findings.iter().map(|f| build_result(f)).collect();

    json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "guardep",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/aroussi/guardep",
                        "rules": rules.into_values().collect::<Vec<_>>(),
                    }
                },
                "results": results,
            }
        ]
    })
}

fn build_result(f: &Finding) -> Value {
    let mut props = serde_json::Map::new();
    props.insert("package".into(), json!(f.package.name));
    props.insert("version".into(), json!(f.package.version));
    props.insert("kind".into(), json!(f.kind.as_str()));
    if !f.fixed_versions.is_empty() {
        props.insert("fixedVersions".into(), json!(f.fixed_versions));
    }
    if let Some(score) = f
        .details
        .get("epss")
        .and_then(|e| e.get("score"))
        .and_then(|v| v.as_f64())
    {
        props.insert("epssScore".into(), json!(score));
    }
    if let Some(p) = f
        .details
        .get("epss")
        .and_then(|e| e.get("percentile"))
        .and_then(|v| v.as_f64())
    {
        props.insert("epssPercentile".into(), json!(p));
    }
    if let Some(true) = f.details.get("kev").and_then(|v| v.as_bool()) {
        props.insert("kev".into(), json!(true));
    }

    let locations = result_locations(f);

    // Partial fingerprint stays stable across runs as long as the
    // package coordinates and rule are unchanged. Lets GitHub code-
    // scanning collapse duplicate alerts across PRs.
    let fingerprint = format!("{}@{}::{}", f.package.name, f.package.version, f.id);

    json!({
        "ruleId": rule_id(f),
        "level": severity_to_level(f.severity),
        "message": { "text": f.summary },
        "locations": locations,
        "partialFingerprints": {
            "guardepCoordinate/v1": fingerprint,
        },
        "properties": Value::Object(props),
    })
}

fn result_locations(f: &Finding) -> Vec<Value> {
    // Source-behavior findings carry per-call-site locations in
    // details.locations[]; lift those into SARIF physicalLocation
    // entries so code-scanning can highlight the exact byte span.
    if let Some(arr) = f.details.get("locations").and_then(|v| v.as_array()) {
        let mut out = Vec::new();
        for loc in arr.iter().take(50) {
            let file = loc
                .get("file")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let line = loc.get("line").and_then(|v| v.as_u64()).unwrap_or(0);
            let bytes = loc.get("bytes");
            let mut artifact = json!({
                "uri": format!("node_modules/{}/{}", f.package.name, file),
            });
            // Region: byte offset when known, line otherwise.
            let region = if let Some(b) = bytes {
                let start = b.get("start").and_then(|v| v.as_u64()).unwrap_or(0);
                let end = b.get("end").and_then(|v| v.as_u64()).unwrap_or(start);
                json!({
                    "byteOffset": start,
                    "byteLength": end.saturating_sub(start),
                    "startLine": if line > 0 { line } else { 1 },
                })
            } else {
                json!({
                    "startLine": if line > 0 { line } else { 1 },
                })
            };
            // GitHub code-scanning needs the URI inside artifactLocation.
            let phys = json!({
                "artifactLocation": artifact.take(),
                "region": region,
            });
            out.push(json!({ "physicalLocation": phys }));
        }
        if !out.is_empty() {
            return out;
        }
    }
    // Fallback: a single location pointing at the package.json so the
    // result is anchored somewhere in the repo.
    vec![json!({
        "physicalLocation": {
            "artifactLocation": {
                "uri": format!("package.json"),
            },
            "region": { "startLine": 1 }
        },
        "logicalLocations": [
            { "fullyQualifiedName": format!("{}@{}", f.package.name, f.package.version) }
        ]
    })]
}

fn severity_to_level(s: FindingSeverity) -> &'static str {
    // SARIF "level" enum: error / warning / note / none.
    // Map Critical+High → error, Medium → warning, Low → note,
    // Info/Unknown → none.
    match s {
        FindingSeverity::Critical | FindingSeverity::High => "error",
        FindingSeverity::Medium => "warning",
        FindingSeverity::Low => "note",
        FindingSeverity::Info | FindingSeverity::Unknown => "none",
    }
}

fn rule_id(f: &Finding) -> String {
    // For source-behavior findings the behavior is the meaningful rule
    // identifier. For CVE/license/risk we use the kind alone since the
    // specific advisory ID belongs in `results[].ruleId`-adjacent
    // metadata via partialFingerprints.
    if f.kind == FindingKind::SourceBehavior {
        if let Some(b) = f.details.get("behavior").and_then(|v| v.as_str()) {
            return format!("source_behavior/{b}");
        }
    }
    f.kind.as_str().to_string()
}

fn rule_name(f: &Finding) -> String {
    match f.kind {
        FindingKind::Vulnerability => "Vulnerable dependency".into(),
        FindingKind::Malware => "Known-malicious dependency".into(),
        FindingKind::PostinstallScript => "Suspicious install script".into(),
        FindingKind::RiskScore => "Package risk score".into(),
        FindingKind::MissingProvenance => "Missing Sigstore provenance".into(),
        FindingKind::ProvenanceMismatch => "Mismatched Sigstore provenance".into(),
        FindingKind::License => "License policy issue".into(),
        FindingKind::SourceBehavior => f
            .details
            .get("label")
            .and_then(|v| v.as_str())
            .unwrap_or("Source behavior")
            .to_string(),
    }
}

fn rule_short_desc(f: &Finding) -> String {
    match f.kind {
        FindingKind::Vulnerability => {
            "Package matches a CVE in OSV.dev (optionally enriched with EPSS / CISA KEV)."
                .into()
        }
        FindingKind::Malware => {
            "Package matches a confirmed malware advisory (OSV) or the OSSF malicious-packages feed."
                .into()
        }
        FindingKind::PostinstallScript => {
            "Install lifecycle script matches a risky pattern.".into()
        }
        FindingKind::RiskScore => {
            "Composite risk score crossed a configured threshold.".into()
        }
        FindingKind::MissingProvenance => "Package required to ship Sigstore provenance does not.".into(),
        FindingKind::ProvenanceMismatch => "Sigstore attestation does not match expected source.".into(),
        FindingKind::License => "License is missing, unidentified, or on the deny-list.".into(),
        FindingKind::SourceBehavior => "Package source contains a flagged dynamic behavior.".into(),
    }
}

fn rule_full_desc(f: &Finding) -> String {
    rule_short_desc(f)
}

fn rule_help_uri(f: &Finding) -> String {
    match f.kind {
        FindingKind::Vulnerability | FindingKind::Malware => {
            // First reference often points at the GHSA / advisory.
            f.references
                .first()
                .cloned()
                .unwrap_or_else(|| "https://osv.dev".into())
        }
        _ => format!("https://www.npmjs.com/package/{}", f.package.name),
    }
}

fn rule_category(f: &Finding) -> &'static str {
    match f.kind {
        FindingKind::Vulnerability => "vulnerability",
        FindingKind::Malware => "malware",
        FindingKind::PostinstallScript => "install-script",
        FindingKind::RiskScore => "risk-score",
        FindingKind::MissingProvenance | FindingKind::ProvenanceMismatch => "provenance",
        FindingKind::License => "license",
        FindingKind::SourceBehavior => "source-behavior",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardep_core::ecosystem::{Ecosystem, PackageRef};
    use guardep_core::policy::Policy;

    fn npm(name: &str, version: &str) -> PackageRef {
        PackageRef::new(Ecosystem::Npm, name, version)
    }

    fn sample_cve() -> Finding {
        Finding {
            package: npm("axios", "0.21.0"),
            kind: FindingKind::Vulnerability,
            id: "GHSA-43fc-jf86-j433".into(),
            aliases: vec!["CVE-2026-25639".into()],
            summary: "DoS via __proto__".into(),
            severity: FindingSeverity::High,
            fixed_versions: vec!["1.13.5".into()],
            references: vec!["https://github.com/advisories/GHSA-43fc-jf86-j433".into()],
            details: serde_json::json!({
                "epss": { "score": 0.04, "percentile": 0.92 },
                "kev": false,
            }),
        }
    }

    fn sample_behavior() -> Finding {
        Finding {
            package: npm("debug", "2.6.9"),
            kind: FindingKind::SourceBehavior,
            id: "behavior:env_vars:debug".into(),
            aliases: vec![],
            summary: "Environment variable access (4 occurrences in debug)".into(),
            severity: FindingSeverity::Low,
            fixed_versions: vec![],
            references: vec![],
            details: serde_json::json!({
                "behavior": "env_vars",
                "label": "Environment variable access",
                "occurrences": 4,
                "locations": [
                    { "file": "src/node.js", "line": 12, "bytes": { "start": 200, "end": 220 }, "note": "DEBUG" }
                ]
            }),
        }
    }

    #[test]
    fn empty_inputs_produce_valid_skeleton() {
        let report = FindingsReport::from_findings(vec![], &Policy::default());
        let doc = build_sarif(&report);
        assert_eq!(doc["version"], "2.1.0");
        assert_eq!(doc["runs"][0]["tool"]["driver"]["name"], "guardep");
        assert!(doc["runs"][0]["results"].as_array().unwrap().is_empty());
    }

    #[test]
    fn cve_finding_emits_error_level_with_epss_props() {
        let report = FindingsReport::from_findings(vec![sample_cve()], &Policy::default());
        let doc = build_sarif(&report);
        let result = &doc["runs"][0]["results"][0];
        assert_eq!(result["level"], "error");
        assert_eq!(result["ruleId"], "vulnerability");
        assert_eq!(result["properties"]["package"], "axios");
        assert_eq!(result["properties"]["version"], "0.21.0");
        assert!((result["properties"]["epssPercentile"].as_f64().unwrap() - 0.92).abs() < 1e-6);
    }

    #[test]
    fn source_behavior_emits_byte_offset_region() {
        let report = FindingsReport::from_findings(vec![sample_behavior()], &Policy::default());
        let doc = build_sarif(&report);
        let result = &doc["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "source_behavior/env_vars");
        assert_eq!(result["level"], "note");
        let region = &result["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["byteOffset"], 200);
        assert_eq!(region["byteLength"], 20);
    }

    #[test]
    fn rule_set_is_unique_per_rule_id() {
        // Two findings with the same kind should produce one rule entry.
        let mut a = sample_cve();
        let mut b = sample_cve();
        a.id = "GHSA-AAAA".into();
        b.id = "GHSA-BBBB".into();
        b.package.version = "0.21.1".into();
        let report = FindingsReport::from_findings(vec![a, b], &Policy::default());
        let doc = build_sarif(&report);
        let rules = doc["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["id"], "vulnerability");
    }
}

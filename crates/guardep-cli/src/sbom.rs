//! CycloneDX 1.5 SBOM emitter.
//!
//! Emits a JSON document conforming to the CycloneDX 1.5 specification
//! (https://cyclonedx.org/docs/1.5/json/) covering:
//!
//!   - `components[]`         — every resolved dep as a `library`
//!     component with PURL, version, and bom-ref (used to link
//!     vulnerabilities back to the affected component).
//!   - `vulnerabilities[]`    — every CVE finding, linked to its
//!     component via `affects[].ref`. Includes `id` (CVE/GHSA),
//!     `source.name`, `ratings[]` (severity), `description`, and EPSS
//!     `score`/`percentile` when available.
//!
//! Goal: match Socket's `export/cdx/<id>` endpoint shape so the same
//! downstream tooling (Dependency-Track, OWASP Defectdojo, GitHub
//! dependency review) ingests guardep output without translation.

use anyhow::Result;
use guardep_core::{
    ecosystem::Ecosystem, FindingKind, FindingSeverity, FindingsReport, PackageRef,
};
use serde_json::{json, Value};

/// Serialize the audit result as a CycloneDX 1.5 JSON document and
/// print it on stdout. Errors only when serialization fails, which
/// shouldn't happen for our shape.
pub fn print_cyclonedx(packages: &[PackageRef], report: &FindingsReport) -> Result<()> {
    let doc = build_cyclonedx(packages, report);
    let s = serde_json::to_string_pretty(&doc)?;
    println!("{s}");
    Ok(())
}

fn build_cyclonedx(packages: &[PackageRef], report: &FindingsReport) -> Value {
    let serial = format!("urn:uuid:{}", uuid_v4_hex());
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let components: Vec<Value> = packages
        .iter()
        .map(|p| {
            json!({
                "type": "library",
                "bom-ref": bom_ref(p),
                "name": p.name,
                "version": p.version,
                "purl": purl_for(p),
            })
        })
        .collect();

    // Map findings → CycloneDX vulnerabilities. We include only
    // Vulnerability and Malware kinds; risk-score / source-behavior
    // findings don't fit the CVE-shaped schema and would clutter the
    // output for downstream tools that expect strict CVE rows.
    let mut vulns: Vec<Value> = Vec::new();
    for s in &report.deduped() {
        let f = &s.finding;
        if !matches!(f.kind, FindingKind::Vulnerability | FindingKind::Malware) {
            continue;
        }
        let mut entry = json!({
            "bom-ref": format!("vuln:{}:{}", f.package.name, f.id),
            "id": f.id,
            "source": { "name": vuln_source(&f.id) },
            "ratings": [
                {
                    "source": { "name": vuln_source(&f.id) },
                    "severity": severity_label(f.severity),
                }
            ],
            "description": f.summary,
            "affects": [
                { "ref": bom_ref(&f.package) }
            ],
        });
        if !f.aliases.is_empty() {
            entry["references"] = json!(f
                .aliases
                .iter()
                .map(|a| json!({ "id": a, "source": { "name": vuln_source(a) } }))
                .collect::<Vec<_>>());
        }
        if !f.fixed_versions.is_empty() {
            entry["recommendation"] = json!(format!("Update to {}", f.fixed_versions.join(", ")));
        }
        // EPSS / KEV enrichment, when present, lifts straight into the
        // vendor-specific properties bag. CycloneDX has no native
        // field for either yet — properties are the supported escape
        // hatch.
        let mut props: Vec<Value> = Vec::new();
        if let Some(score) = f
            .details
            .get("epss")
            .and_then(|e| e.get("score"))
            .and_then(|v| v.as_f64())
        {
            props.push(json!({ "name": "guardep:epss:score", "value": format!("{score}") }));
        }
        if let Some(pct) = f
            .details
            .get("epss")
            .and_then(|e| e.get("percentile"))
            .and_then(|v| v.as_f64())
        {
            props.push(json!({ "name": "guardep:epss:percentile", "value": format!("{pct}") }));
        }
        if let Some(true) = f.details.get("kev").and_then(|v| v.as_bool()) {
            props.push(json!({ "name": "guardep:kev", "value": "true" }));
        }
        if !props.is_empty() {
            entry["properties"] = json!(props);
        }
        vulns.push(entry);
    }

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [
                {
                    "vendor": "guardep",
                    "name": "guardep",
                    "version": env!("CARGO_PKG_VERSION"),
                }
            ]
        },
        "components": components,
        "vulnerabilities": vulns,
    })
}

fn bom_ref(p: &PackageRef) -> String {
    format!(
        "pkg:{}/{}@{}",
        ecosystem_slug(p.ecosystem),
        p.name,
        p.version
    )
}

fn purl_for(p: &PackageRef) -> String {
    bom_ref(p)
}

fn ecosystem_slug(e: Ecosystem) -> &'static str {
    match e {
        Ecosystem::Npm => "npm",
        Ecosystem::Maven => "maven",
        Ecosystem::Cargo => "cargo",
        Ecosystem::PyPI => "pypi",
    }
}

fn severity_label(s: FindingSeverity) -> &'static str {
    match s {
        FindingSeverity::Critical => "critical",
        FindingSeverity::High => "high",
        FindingSeverity::Medium => "medium",
        FindingSeverity::Low => "low",
        FindingSeverity::Info | FindingSeverity::Unknown => "info",
    }
}

fn vuln_source(id: &str) -> &'static str {
    if id.starts_with("CVE-") {
        "NVD"
    } else if id.starts_with("GHSA-") {
        "GitHub Advisory Database"
    } else {
        "OSV"
    }
}

/// Minimal v4 UUID generator without pulling in the `uuid` crate.
/// Format: 8-4-4-4-12 hex chars; bits 12-15 of time_hi_and_version
/// set to 0100 (version 4); bits 6-7 of clock_seq_hi to 10 (variant).
fn uuid_v4_hex() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // Mix in some address-of state to make the value path-dependent.
    let stack_addr = (&nanos as *const _) as usize as u128;
    let raw: u128 = nanos
        .wrapping_mul(6364136223846793005)
        .wrapping_add(stack_addr);
    let bytes = raw.to_be_bytes();
    let mut b = bytes;
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 10xx
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3],
        b[4], b[5],
        b[6], b[7],
        b[8], b[9],
        b[10], b[11], b[12], b[13], b[14], b[15],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardep_core::ecosystem::PackageRef;
    use guardep_core::policy::Policy;
    use guardep_core::{Finding, FindingKind, FindingSeverity};

    fn npm(name: &str, version: &str) -> PackageRef {
        PackageRef::new(Ecosystem::Npm, name, version)
    }

    #[test]
    fn empty_inputs_produce_valid_skeleton() {
        let pkgs: Vec<PackageRef> = vec![];
        let report = FindingsReport::from_findings(vec![], &Policy::default());
        let doc = build_cyclonedx(&pkgs, &report);
        assert_eq!(doc["bomFormat"], "CycloneDX");
        assert_eq!(doc["specVersion"], "1.5");
        assert_eq!(doc["version"], 1);
        assert!(doc["components"].as_array().unwrap().is_empty());
        assert!(doc["vulnerabilities"].as_array().unwrap().is_empty());
    }

    #[test]
    fn components_get_purl_and_bom_ref() {
        let pkgs = vec![npm("axios", "0.21.0"), npm("lodash", "4.17.20")];
        let report = FindingsReport::from_findings(vec![], &Policy::default());
        let doc = build_cyclonedx(&pkgs, &report);
        let components = doc["components"].as_array().unwrap();
        assert_eq!(components.len(), 2);
        let axios = &components[0];
        assert_eq!(axios["type"], "library");
        assert_eq!(axios["name"], "axios");
        assert_eq!(axios["version"], "0.21.0");
        assert_eq!(axios["purl"], "pkg:npm/axios@0.21.0");
        assert_eq!(axios["bom-ref"], "pkg:npm/axios@0.21.0");
    }

    #[test]
    fn vulnerabilities_link_to_components_via_bom_ref() {
        let pkgs = vec![npm("axios", "0.21.0")];
        let finding = Finding {
            package: npm("axios", "0.21.0"),
            kind: FindingKind::Vulnerability,
            id: "GHSA-43fc-jf86-j433".into(),
            aliases: vec!["CVE-2026-25639".into()],
            summary: "DoS via __proto__".into(),
            severity: FindingSeverity::High,
            fixed_versions: vec!["1.13.5".into()],
            references: vec![],
            details: serde_json::json!({
                "epss": {"score": 0.04, "percentile": 0.92},
                "kev": false,
            }),
        };
        let report = FindingsReport::from_findings(vec![finding], &Policy::default());
        let doc = build_cyclonedx(&pkgs, &report);
        let v = &doc["vulnerabilities"][0];
        assert_eq!(v["id"], "GHSA-43fc-jf86-j433");
        assert_eq!(v["affects"][0]["ref"], "pkg:npm/axios@0.21.0");
        assert_eq!(v["ratings"][0]["severity"], "high");
        assert_eq!(v["recommendation"], "Update to 1.13.5");
        let props = v["properties"].as_array().unwrap();
        assert!(props.iter().any(|p| p["name"] == "guardep:epss:percentile"));
    }

    #[test]
    fn risk_score_findings_excluded_from_vulns() {
        let pkgs = vec![npm("solo", "1.0.0")];
        let f = Finding {
            package: npm("solo", "1.0.0"),
            kind: FindingKind::RiskScore,
            id: "risk:abandoned:solo".into(),
            aliases: vec![],
            summary: String::new(),
            severity: FindingSeverity::Medium,
            fixed_versions: vec![],
            references: vec![],
            details: serde_json::Value::Null,
        };
        let report = FindingsReport::from_findings(vec![f], &Policy::default());
        let doc = build_cyclonedx(&pkgs, &report);
        assert!(doc["vulnerabilities"].as_array().unwrap().is_empty());
    }
}

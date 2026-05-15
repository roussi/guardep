use crate::advisory::{Advisory, AffectedRange, Severity, ThreatClass};
use crate::ecosystem::{Ecosystem, PackageRef};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const OSV_QUERY: &str = "https://api.osv.dev/v1/query";
const OSV_QUERYBATCH: &str = "https://api.osv.dev/v1/querybatch";
const OSV_VULNS: &str = "https://api.osv.dev/v1/vulns";
const BATCH_SIZE: usize = 1000;

pub struct OsvClient {
    http: reqwest::Client,
}

impl OsvClient {
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("guardep/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Self { http })
    }

    /// Single-package query (kept for cache-miss path).
    pub async fn query(&self, pkg: &PackageRef) -> Result<Vec<Advisory>> {
        let body = OsvQuery::from(pkg);
        let resp: OsvResponse = self
            .http
            .post(OSV_QUERY)
            .json(&body)
            .send()
            .await
            .context("OSV request failed")?
            .error_for_status()?
            .json()
            .await
            .context("OSV response decode failed")?;
        Ok(resp
            .vulns
            .unwrap_or_default()
            .into_iter()
            .map(|v| convert(v, pkg.ecosystem, &pkg.name))
            .collect())
    }

    /// Batch query: chunks into groups of BATCH_SIZE.
    /// Returns advisories aligned by index with `packages`.
    pub async fn query_batch(&self, packages: &[PackageRef]) -> Result<Vec<Vec<Advisory>>> {
        let mut out: Vec<Vec<Advisory>> = vec![Vec::new(); packages.len()];

        for (chunk_start, chunk) in packages.chunks(BATCH_SIZE).enumerate() {
            let queries: Vec<OsvQuery> = chunk.iter().map(OsvQuery::from).collect();
            let body = OsvBatchQuery { queries };

            let batch: OsvBatchResponse = self
                .http
                .post(OSV_QUERYBATCH)
                .json(&body)
                .send()
                .await
                .context("OSV batch request failed")?
                .error_for_status()?
                .json()
                .await
                .context("OSV batch decode failed")?;

            for (i, result) in batch.results.into_iter().enumerate() {
                let global_idx = chunk_start * BATCH_SIZE + i;
                let pkg = &packages[global_idx];
                let stub_vulns = result.vulns.unwrap_or_default();
                if stub_vulns.is_empty() {
                    continue;
                }
                // Batch returns only IDs; hydrate full records.
                let mut full: Vec<Advisory> = Vec::with_capacity(stub_vulns.len());
                for stub in stub_vulns {
                    match self.fetch_vuln(&stub.id).await {
                        Ok(adv) => full.push(convert(adv, pkg.ecosystem, &pkg.name)),
                        Err(e) => tracing::warn!("hydrate {} failed: {e}", stub.id),
                    }
                }
                out[global_idx] = full;
            }
        }
        Ok(out)
    }

    async fn fetch_vuln(&self, id: &str) -> Result<OsvVuln> {
        let url = format!("{OSV_VULNS}/{id}");
        let v: OsvVuln = self
            .http
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(v)
    }
}

#[derive(Serialize)]
struct OsvBatchQuery {
    queries: Vec<OsvQuery>,
}

#[derive(Serialize)]
struct OsvQuery {
    version: String,
    package: OsvPackage,
}

impl From<&PackageRef> for OsvQuery {
    fn from(p: &PackageRef) -> Self {
        Self {
            version: p.version.clone(),
            package: OsvPackage {
                name: p.name.clone(),
                ecosystem: p.ecosystem.as_osv().to_string(),
            },
        }
    }
}

#[derive(Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Deserialize)]
struct OsvResponse {
    vulns: Option<Vec<OsvVuln>>,
}

#[derive(Deserialize)]
struct OsvBatchResponse {
    results: Vec<OsvBatchResult>,
}

#[derive(Deserialize)]
struct OsvBatchResult {
    vulns: Option<Vec<OsvVulnStub>>,
}

#[derive(Deserialize)]
struct OsvVulnStub {
    id: String,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    references: Vec<OsvReference>,
    #[serde(default)]
    database_specific: serde_json::Value,
}

#[derive(Deserialize)]
struct OsvAffected {
    #[serde(default)]
    ranges: Vec<OsvRange>,
    #[serde(default)]
    versions: Vec<String>,
    #[serde(default)]
    database_specific: serde_json::Value,
}

#[derive(Deserialize)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Deserialize)]
struct OsvEvent {
    #[serde(default)]
    introduced: Option<String>,
    #[serde(default)]
    fixed: Option<String>,
}

#[derive(Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}

#[derive(Deserialize)]
struct OsvReference {
    url: String,
}

fn convert(v: OsvVuln, ecosystem: Ecosystem, package: &str) -> Advisory {
    let ranges: Vec<AffectedRange> = v
        .affected
        .iter()
        .flat_map(|a| {
            let explicit = a.versions.clone();
            let derived: Vec<AffectedRange> = a
                .ranges
                .iter()
                .map(|r| {
                    let introduced = r
                        .events
                        .iter()
                        .find_map(|e| e.introduced.clone())
                        .filter(|s| s != "0");
                    let fixed = r.events.iter().find_map(|e| e.fixed.clone());
                    AffectedRange {
                        introduced,
                        fixed,
                        versions: vec![],
                    }
                })
                .collect();
            let mut out = derived;
            if !explicit.is_empty() {
                out.push(AffectedRange {
                    introduced: None,
                    fixed: None,
                    versions: explicit,
                });
            }
            out
        })
        .collect();

    let fixed_versions: Vec<String> = ranges.iter().filter_map(|r| r.fixed.clone()).collect();

    let severity = parse_severity(&v.severity, &v.database_specific, &v.affected);
    let class = classify(&v.id, &v.summary, &v.database_specific);

    Advisory {
        id: v.id,
        aliases: v.aliases,
        ecosystem,
        package: package.to_string(),
        summary: v.summary,
        severity,
        class,
        ranges,
        fixed_versions,
        references: v.references.into_iter().map(|r| r.url).collect(),
    }
}

/// Severity parsing priority:
///   1. `database_specific.severity` (GHSA: "LOW"/"MODERATE"/"HIGH"/"CRITICAL")
///   2. CVSS numeric base score from `severity[].score` (last component after final `/`)
///   3. CVSS vector heuristic
///   4. Per-affected `database_specific.cwe_ids` fallback (rare)
fn parse_severity(
    scores: &[OsvSeverity],
    db_specific: &serde_json::Value,
    affected: &[OsvAffected],
) -> Severity {
    // 1. GHSA string
    if let Some(s) = db_specific.get("severity").and_then(|v| v.as_str()) {
        if let Some(sev) = match_label(s) {
            return sev;
        }
    }
    for a in affected {
        if let Some(s) = a.database_specific.get("severity").and_then(|v| v.as_str()) {
            if let Some(sev) = match_label(s) {
                return sev;
            }
        }
    }

    // 2. CVSS numeric base score
    for s in scores {
        if s.kind.starts_with("CVSS") {
            if let Some(score) = extract_cvss_base(&s.score) {
                return cvss_to_severity(score);
            }
        }
    }

    // 3. CVSS vector heuristic (legacy fallback)
    for s in scores {
        if s.kind.starts_with("CVSS") {
            let v = &s.score;
            let net = v.contains("/AV:N");
            let high_impact = v.contains("/C:H") || v.contains("/I:H") || v.contains("/A:H");
            if net && high_impact {
                return Severity::High;
            }
        }
    }

    Severity::Unknown
}

fn match_label(label: &str) -> Option<Severity> {
    match label.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => Some(Severity::Critical),
        "HIGH" => Some(Severity::High),
        "MODERATE" | "MEDIUM" => Some(Severity::Medium),
        "LOW" => Some(Severity::Low),
        _ => None,
    }
}

/// Extract base score from a CVSS vector or "CVSS:3.1/...".
/// OSV sometimes encodes pure number ("9.8"), sometimes full vector.
fn extract_cvss_base(score: &str) -> Option<f32> {
    if let Ok(n) = score.trim().parse::<f32>() {
        return Some(n);
    }
    // Some sources append "(9.8)" at end
    if let (Some(open), Some(close)) = (score.rfind('('), score.rfind(')')) {
        if open < close {
            if let Ok(n) = score[open + 1..close].parse::<f32>() {
                return Some(n);
            }
        }
    }
    None
}

fn cvss_to_severity(score: f32) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else if score > 0.0 {
        Severity::Low
    } else {
        Severity::Unknown
    }
}

fn classify(id: &str, summary: &str, db_specific: &serde_json::Value) -> ThreatClass {
    let s = summary.to_lowercase();
    if id.starts_with("MAL-")
        || s.contains("malicious")
        || s.contains("compromised")
        || s.contains("supply chain")
        || s.contains("shai-hulud")
    {
        return ThreatClass::Malware;
    }
    if let Some(t) = db_specific.get("type").and_then(|v| v.as_str()) {
        if t.eq_ignore_ascii_case("malware") {
            return ThreatClass::Malware;
        }
    }
    ThreatClass::Vulnerability
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cvss_buckets() {
        assert_eq!(cvss_to_severity(9.8), Severity::Critical);
        assert_eq!(cvss_to_severity(7.5), Severity::High);
        assert_eq!(cvss_to_severity(5.0), Severity::Medium);
        assert_eq!(cvss_to_severity(2.0), Severity::Low);
        assert_eq!(cvss_to_severity(0.0), Severity::Unknown);
    }

    #[test]
    fn extract_numeric() {
        assert_eq!(extract_cvss_base("9.8"), Some(9.8));
        assert_eq!(extract_cvss_base("CVSS:3.1/AV:N (7.5)"), Some(7.5));
        assert_eq!(extract_cvss_base("garbage"), None);
    }

    #[test]
    fn label_match() {
        assert_eq!(match_label("CRITICAL"), Some(Severity::Critical));
        assert_eq!(match_label("moderate"), Some(Severity::Medium));
        assert_eq!(match_label("nope"), None);
    }
}

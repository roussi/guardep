use crate::ecosystem::Ecosystem;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreatClass {
    /// Vulnerability in legitimate, non-malicious code (CVE).
    Vulnerability,
    /// Compromised package publish (Shai-Hulud, typosquat, hijack).
    Malware,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedRange {
    /// First version known affected (inclusive). None = from start.
    pub introduced: Option<String>,
    /// First version that fixes it (exclusive). None = no fix yet.
    pub fixed: Option<String>,
    /// Explicit version list (when ranges don't apply).
    #[serde(default)]
    pub versions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advisory {
    pub id: String,
    pub aliases: Vec<String>,
    pub ecosystem: Ecosystem,
    pub package: String,
    pub summary: String,
    pub severity: Severity,
    pub class: ThreatClass,
    pub ranges: Vec<AffectedRange>,
    pub fixed_versions: Vec<String>,
    pub references: Vec<String>,
}

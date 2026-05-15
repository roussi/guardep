use crate::advisory::{Severity, ThreatClass};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Warn,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default = "default_block")]
    pub malware: Action,
    #[serde(default = "default_block")]
    pub critical_cve: Action,
    #[serde(default = "default_warn")]
    pub high_cve: Action,
    #[serde(default = "default_allow")]
    pub medium_cve: Action,
    #[serde(default = "default_allow")]
    pub low_cve: Action,
    /// Format: "name@version" (e.g. "axios@1.13.2"). Suppresses block/warn.
    #[serde(default)]
    pub allowlist: HashSet<String>,
    /// Refresh advisory cache every N hours.
    #[serde(default = "default_refresh")]
    pub cache_refresh_hours: u64,
}

fn default_block() -> Action {
    Action::Block
}
fn default_warn() -> Action {
    Action::Warn
}
fn default_allow() -> Action {
    Action::Allow
}
fn default_refresh() -> u64 {
    6
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            malware: Action::Block,
            critical_cve: Action::Block,
            high_cve: Action::Warn,
            medium_cve: Action::Allow,
            low_cve: Action::Allow,
            allowlist: HashSet::new(),
            cache_refresh_hours: 6,
        }
    }
}

impl Policy {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path)?;
        let cfg: PolicyFile = toml::from_str(&raw)?;
        Ok(cfg.policy.unwrap_or_default())
    }

    pub fn decide(&self, class: ThreatClass, severity: Severity) -> Action {
        match class {
            ThreatClass::Malware => self.malware,
            ThreatClass::Vulnerability => match severity {
                Severity::Critical => self.critical_cve,
                Severity::High => self.high_cve,
                Severity::Medium => self.medium_cve,
                Severity::Low | Severity::Unknown => self.low_cve,
            },
        }
    }

    pub fn is_allowlisted(&self, key: &str) -> bool {
        self.allowlist.contains(key)
    }
}

#[derive(Debug, Deserialize)]
struct PolicyFile {
    policy: Option<Policy>,
}

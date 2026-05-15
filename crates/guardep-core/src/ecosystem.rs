use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    Maven,
    Cargo,
    PyPI,
}

impl Ecosystem {
    pub fn as_osv(&self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Maven => "Maven",
            Ecosystem::Cargo => "crates.io",
            Ecosystem::PyPI => "PyPI",
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_osv())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PackageRef {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
}

impl PackageRef {
    pub fn new(ecosystem: Ecosystem, name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            ecosystem,
            name: name.into(),
            version: version.into(),
        }
    }
}

impl fmt::Display for PackageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name, self.version)
    }
}

use crate::ecosystem::{Ecosystem, PackageRef};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;

pub trait Resolver {
    fn resolve(&self, project_root: &Path) -> Result<Vec<PackageRef>>;
}

pub struct NpmLockResolver;

impl Resolver for NpmLockResolver {
    fn resolve(&self, project_root: &Path) -> Result<Vec<PackageRef>> {
        let lock_path = project_root.join("package-lock.json");
        if !lock_path.exists() {
            anyhow::bail!("package-lock.json not found in {}", project_root.display());
        }
        let raw = std::fs::read_to_string(&lock_path).context("read lockfile")?;
        let lock: NpmLock = serde_json::from_str(&raw).context("parse lockfile")?;
        let mut out: BTreeSet<PackageRef> = BTreeSet::new();
        if let Some(packages) = lock.packages {
            for (path, entry) in packages {
                if path.is_empty() {
                    continue; // root project
                }
                let name = entry.name.unwrap_or_else(|| {
                    path.rsplit("node_modules/")
                        .next()
                        .unwrap_or(&path)
                        .to_string()
                });
                let Some(version) = entry.version else { continue };
                out.insert(PackageRef::new(Ecosystem::Npm, name, version));
            }
        }
        Ok(out.into_iter().collect())
    }
}

impl PartialOrd for PackageRef {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PackageRef {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.name.as_str(), self.version.as_str())
            .cmp(&(other.name.as_str(), other.version.as_str()))
    }
}

#[derive(Deserialize)]
struct NpmLock {
    #[serde(default)]
    packages: Option<std::collections::BTreeMap<String, NpmLockEntry>>,
}

#[derive(Deserialize)]
struct NpmLockEntry {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
}

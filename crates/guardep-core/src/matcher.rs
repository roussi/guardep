use crate::advisory::{Advisory, AffectedRange, ThreatClass};
use crate::ecosystem::{Ecosystem, PackageRef};
use crate::policy::{Action, Policy};
use semver::Version;

#[derive(Debug, Clone)]
pub struct MatchResult {
    pub package: PackageRef,
    pub advisory: Advisory,
    pub action: Action,
}

#[derive(Debug)]
pub struct Verdict {
    pub matches: Vec<MatchResult>,
}

impl Verdict {
    pub fn should_block(&self) -> bool {
        self.matches.iter().any(|m| m.action == Action::Block)
    }

    pub fn has_warnings(&self) -> bool {
        self.matches.iter().any(|m| m.action == Action::Warn)
    }

    pub fn count_blocks(&self) -> usize {
        self.matches.iter().filter(|m| m.action == Action::Block).count()
    }

    pub fn count_warnings(&self) -> usize {
        self.matches.iter().filter(|m| m.action == Action::Warn).count()
    }

    pub fn count_malware(&self) -> usize {
        self.matches
            .iter()
            .filter(|m| m.advisory.class == ThreatClass::Malware)
            .count()
    }

    /// Dedup by (package_name, package_version, advisory_id) — same vuln may
    /// surface multiple times when the same package is installed under
    /// different lockfile paths.
    pub fn deduped(&self) -> Vec<&MatchResult> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for m in &self.matches {
            let key = (
                m.package.name.as_str(),
                m.package.version.as_str(),
                m.advisory.id.as_str(),
            );
            if seen.insert(key) {
                out.push(m);
            }
        }
        out
    }
}

pub fn evaluate(
    packages: &[PackageRef],
    advisories: &[Advisory],
    policy: &Policy,
) -> Verdict {
    let mut matches = Vec::new();
    for pkg in packages {
        for adv in advisories {
            if adv.ecosystem != pkg.ecosystem || adv.package != pkg.name {
                continue;
            }
            if !version_in_ranges(&pkg.version, pkg.ecosystem, &adv.ranges) {
                continue;
            }
            let key = format!("{}@{}", pkg.name, pkg.version);
            let action = if policy.is_allowlisted(&key) {
                Action::Allow
            } else {
                policy.decide(adv.class, adv.severity)
            };
            if action == Action::Allow {
                continue;
            }
            matches.push(MatchResult {
                package: pkg.clone(),
                advisory: adv.clone(),
                action,
            });
        }
    }
    Verdict { matches }
}

fn version_in_ranges(version: &str, eco: Ecosystem, ranges: &[AffectedRange]) -> bool {
    for r in ranges {
        if r.versions.iter().any(|v| v == version) {
            return true;
        }
        if matches!(eco, Ecosystem::Npm | Ecosystem::Cargo) {
            if let Ok(v) = Version::parse(version) {
                let above_introduced = match &r.introduced {
                    None => true,
                    Some(intro) => Version::parse(intro)
                        .map(|i| v >= i)
                        .unwrap_or(false),
                };
                let below_fixed = match &r.fixed {
                    None => true,
                    Some(fix) => Version::parse(fix)
                        .map(|f| v < f)
                        .unwrap_or(true),
                };
                if above_introduced && below_fixed {
                    return true;
                }
            }
        } else {
            // Maven/PyPI: lexicographic fallback. TODO: maven version comparator.
            let above = match &r.introduced {
                None => true,
                Some(i) => version >= i.as_str(),
            };
            let below = match &r.fixed {
                None => true,
                Some(f) => version < f.as_str(),
            };
            if above && below {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::Severity;

    fn npm_adv(name: &str, intro: Option<&str>, fixed: Option<&str>, class: ThreatClass) -> Advisory {
        Advisory {
            id: "TEST-1".into(),
            aliases: vec![],
            ecosystem: Ecosystem::Npm,
            package: name.into(),
            summary: "test".into(),
            severity: Severity::High,
            class,
            ranges: vec![AffectedRange {
                introduced: intro.map(String::from),
                fixed: fixed.map(String::from),
                versions: vec![],
            }],
            fixed_versions: vec![],
            references: vec![],
        }
    }

    #[test]
    fn blocks_malware_in_range() {
        let pkg = PackageRef::new(Ecosystem::Npm, "chalk", "5.6.1");
        let adv = npm_adv("chalk", Some("5.6.1"), Some("5.6.2"), ThreatClass::Malware);
        let policy = Policy::default();
        let v = evaluate(&[pkg], &[adv], &policy);
        assert!(v.should_block());
    }

    #[test]
    fn allows_safe_version() {
        let pkg = PackageRef::new(Ecosystem::Npm, "chalk", "4.1.2");
        let adv = npm_adv("chalk", Some("5.6.1"), Some("5.6.2"), ThreatClass::Malware);
        let policy = Policy::default();
        let v = evaluate(&[pkg], &[adv], &policy);
        assert!(v.matches.is_empty());
    }

    #[test]
    fn allowlist_overrides_block() {
        let pkg = PackageRef::new(Ecosystem::Npm, "axios", "1.13.2");
        let adv = npm_adv("axios", Some("1.0.0"), Some("1.16.0"), ThreatClass::Vulnerability);
        let mut policy = Policy::default();
        policy.critical_cve = Action::Block;
        policy.high_cve = Action::Block;
        policy.allowlist.insert("axios@1.13.2".into());
        let v = evaluate(&[pkg], &[adv], &policy);
        assert!(v.matches.is_empty());
    }
}

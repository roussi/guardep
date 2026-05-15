//! Semver range matching shared by every evaluator that consumes
//! `AffectedRange` data (currently only OSV).

use crate::advisory::AffectedRange;
use crate::ecosystem::Ecosystem;
use crate::maven_version;
use semver::Version;

/// True when `version` falls inside any of `ranges` for the given
/// ecosystem. Maven and PyPI fall back to lexicographic compare today;
/// see TODO in body for tighter handling.
pub fn version_in_ranges(version: &str, eco: Ecosystem, ranges: &[AffectedRange]) -> bool {
    for r in ranges {
        if !r.versions.is_empty() {
            // Explicit versions list is authoritative: only listed
            // versions match. introduced/fixed bounds are ignored when
            // an explicit list is provided.
            if r.versions.iter().any(|v| v == version) {
                return true;
            }
            continue;
        }
        if matches!(eco, Ecosystem::Npm | Ecosystem::Cargo) {
            if let Ok(v) = Version::parse(version) {
                let above_introduced = match &r.introduced {
                    None => true,
                    Some(intro) => Version::parse(intro).map(|i| v >= i).unwrap_or(false),
                };
                let below_fixed = match &r.fixed {
                    None => true,
                    Some(fix) => Version::parse(fix).map(|f| v < f).unwrap_or(true),
                };
                if above_introduced && below_fixed {
                    return true;
                }
            }
        } else if eco == Ecosystem::Maven {
            // Maven: faithful Apache version-order comparator.
            let above = match &r.introduced {
                None => true,
                Some(i) => maven_version::ge(version, i),
            };
            let below = match &r.fixed {
                None => true,
                Some(f) => maven_version::lt(version, f),
            };
            if above && below {
                return true;
            }
        } else {
            // PyPI: lexicographic fallback for now (PEP 440 is a
            // separate beast; rare in our pipelines).
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

    fn r(intro: Option<&str>, fixed: Option<&str>) -> AffectedRange {
        AffectedRange {
            introduced: intro.map(String::from),
            fixed: fixed.map(String::from),
            versions: vec![],
        }
    }

    #[test]
    fn npm_range_inclusive_introduced_exclusive_fixed() {
        let ranges = vec![r(Some("1.2.3"), Some("1.2.5"))];
        assert!(version_in_ranges("1.2.3", Ecosystem::Npm, &ranges));
        assert!(version_in_ranges("1.2.4", Ecosystem::Npm, &ranges));
        assert!(!version_in_ranges("1.2.5", Ecosystem::Npm, &ranges));
        assert!(!version_in_ranges("1.2.2", Ecosystem::Npm, &ranges));
    }

    #[test]
    fn npm_range_open_ended_fix_means_no_fix_yet() {
        let ranges = vec![r(Some("1.0.0"), None)];
        assert!(version_in_ranges("999.0.0", Ecosystem::Npm, &ranges));
    }

    #[test]
    fn maven_range_uses_qualifier_aware_compare() {
        let ranges = vec![r(Some("1.0.0-alpha"), Some("1.0.0"))];
        // alpha is before release, so 1.0.0-alpha matches, 1.0.0 does not.
        assert!(version_in_ranges("1.0.0-alpha", Ecosystem::Maven, &ranges));
        assert!(version_in_ranges("1.0.0-rc1", Ecosystem::Maven, &ranges));
        assert!(!version_in_ranges("1.0.0", Ecosystem::Maven, &ranges));
        assert!(!version_in_ranges("1.0.0-sp1", Ecosystem::Maven, &ranges));
    }

    #[test]
    fn maven_numeric_minor_not_lexicographic() {
        let ranges = vec![r(Some("1.0.0"), Some("1.10.0"))];
        // 1.9.0 < 1.10.0 numerically; lex comparison would say 1.9 > 1.10.
        assert!(version_in_ranges("1.9.0", Ecosystem::Maven, &ranges));
        assert!(!version_in_ranges("1.10.0", Ecosystem::Maven, &ranges));
        assert!(!version_in_ranges("1.11.0", Ecosystem::Maven, &ranges));
    }

    #[test]
    fn explicit_versions_list_takes_precedence() {
        let ranges = vec![AffectedRange {
            introduced: None,
            fixed: None,
            versions: vec!["5.6.1".into()],
        }];
        assert!(version_in_ranges("5.6.1", Ecosystem::Npm, &ranges));
        assert!(!version_in_ranges("5.6.2", Ecosystem::Npm, &ranges));
    }
}

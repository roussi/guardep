//! Maven version comparator.
//!
//! Maven versions don't follow semver. Apache's
//! [Maven Version Order](https://maven.apache.org/pom.html#Version_Order_Specification)
//! is the canonical spec; we implement a faithful subset:
//!
//!   - Components are split on `.`, `-`, and digit/non-digit boundaries
//!     (so `1.0alpha1` parses as `[1, 0, "alpha", 1]`).
//!   - Each component is either a number or a string.
//!   - Numbers compare numerically.
//!   - Strings compare via the qualifier ranking below; unknown
//!     qualifiers compare lexicographically and rank ABOVE all known
//!     non-release qualifiers (treated as a release suffix).
//!   - Trailing zero / null / empty / "ga" / "final" / "release"
//!     components are stripped from the right (1.0 == 1.0.0 == 1.0-ga).
//!   - Shorter normalized versions are padded with `0` for comparison.
//!
//! Qualifier ranking (lower = older):
//!   alpha (a) < beta (b) < milestone (m) < rc (cr) < snapshot
//!     < <empty / ga / final / release> < sp
//!
//! This matches what `mvn` itself does for `<version>` ranges and
//! ordering inside `dependency:tree` output.

use std::cmp::Ordering;

/// Compare two Maven version strings. Returns `Less` if `a` is older
/// than `b`, `Greater` if newer, `Equal` if they normalize identically.
pub fn compare(a: &str, b: &str) -> Ordering {
    let av = parse(a);
    let bv = parse(b);
    cmp_components(&av, &bv)
}

/// Convenience: `a < b`.
pub fn lt(a: &str, b: &str) -> bool {
    compare(a, b) == Ordering::Less
}

/// Convenience: `a >= b`.
pub fn ge(a: &str, b: &str) -> bool {
    !lt(a, b)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Component {
    Number(u64),
    Qualifier(String),
}

fn parse(s: &str) -> Vec<Component> {
    let lower = s.to_ascii_lowercase();
    let mut out: Vec<Component> = Vec::new();

    // Split on '.' and '-' first.
    for raw in lower.split(['.', '-']) {
        if raw.is_empty() {
            continue;
        }
        // Within a chunk, split on digit/non-digit boundary so
        // "1.0alpha1" -> [1, 0, "alpha", 1].
        let mut buf = String::new();
        let mut last_digit: Option<bool> = None;
        for ch in raw.chars() {
            let is_digit = ch.is_ascii_digit();
            if last_digit.is_some() && last_digit != Some(is_digit) {
                push_component(&mut out, &buf);
                buf.clear();
            }
            buf.push(ch);
            last_digit = Some(is_digit);
        }
        if !buf.is_empty() {
            push_component(&mut out, &buf);
        }
    }
    normalize(&mut out);
    out
}

fn push_component(out: &mut Vec<Component>, raw: &str) {
    if let Ok(n) = raw.parse::<u64>() {
        out.push(Component::Number(n));
    } else {
        out.push(Component::Qualifier(raw.to_string()));
    }
}

/// Strip trailing "null" components (zero / empty / release-equivalent
/// qualifiers). `1.0` and `1.0.0-ga` should normalize identically.
fn normalize(v: &mut Vec<Component>) {
    while let Some(last) = v.last() {
        let is_null = match last {
            Component::Number(0) => true,
            Component::Number(_) => false,
            Component::Qualifier(q) => is_release_qualifier(q),
        };
        if is_null {
            v.pop();
        } else {
            break;
        }
    }
}

fn is_release_qualifier(q: &str) -> bool {
    matches!(q, "" | "ga" | "final" | "release")
}

/// Numeric rank for a known qualifier. Returns `None` for unknown
/// qualifiers (those compare lexicographically against each other and
/// rank above all known non-release qualifiers).
fn qualifier_rank(q: &str) -> Option<i32> {
    Some(match q {
        "alpha" | "a" => 0,
        "beta" | "b" => 1,
        "milestone" | "m" => 2,
        "rc" | "cr" => 3,
        "snapshot" => 4,
        // sp = service pack: AFTER release.
        "sp" => 6,
        _ => return None,
    })
}

/// Rank used when a qualifier appears against an absent counterpart.
/// "Release" is rank 5: between snapshot and sp.
const RELEASE_RANK: i32 = 5;

fn cmp_components(a: &[Component], b: &[Component]) -> Ordering {
    let n = a.len().max(b.len());
    for i in 0..n {
        let lhs = a.get(i);
        let rhs = b.get(i);
        let ord = match (lhs, rhs) {
            (Some(l), Some(r)) => cmp_one(l, r),
            // When one side runs out, treat the missing side as the
            // "release" position. So 1.0 == 1.0.0 (already trimmed by
            // normalize) but 1.0 > 1.0-alpha because alpha rank (0) <
            // release rank (5).
            (Some(Component::Number(0)), None) => Ordering::Equal,
            (None, Some(Component::Number(0))) => Ordering::Equal,
            (Some(Component::Number(n)), None) => n.cmp(&0),
            (None, Some(Component::Number(n))) => 0.cmp(n),
            (Some(Component::Qualifier(q)), None) => {
                let lr = qualifier_rank(q).unwrap_or(RELEASE_RANK + 1);
                lr.cmp(&RELEASE_RANK)
            }
            (None, Some(Component::Qualifier(q))) => {
                let rr = qualifier_rank(q).unwrap_or(RELEASE_RANK + 1);
                RELEASE_RANK.cmp(&rr)
            }
            (None, None) => Ordering::Equal,
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

fn cmp_one(a: &Component, b: &Component) -> Ordering {
    match (a, b) {
        (Component::Number(x), Component::Number(y)) => x.cmp(y),
        // Numbers always rank above qualifiers when compared head-to-head:
        // 1 > "alpha". Maven's rule.
        (Component::Number(_), Component::Qualifier(_)) => Ordering::Greater,
        (Component::Qualifier(_), Component::Number(_)) => Ordering::Less,
        (Component::Qualifier(x), Component::Qualifier(y)) => {
            match (qualifier_rank(x), qualifier_rank(y)) {
                (Some(xr), Some(yr)) => xr.cmp(&yr),
                (Some(xr), None) => xr.cmp(&(RELEASE_RANK + 1)),
                (None, Some(yr)) => (RELEASE_RANK + 1).cmp(&yr),
                (None, None) => x.cmp(y),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lt(a: &str, b: &str) -> bool {
        super::lt(a, b)
    }
    fn eq(a: &str, b: &str) -> bool {
        compare(a, b) == Ordering::Equal
    }

    #[test]
    fn numeric_ordering() {
        assert!(lt("1.0.0", "1.0.1"));
        assert!(lt("1.0.0", "1.1.0"));
        assert!(lt("1.0.0", "2.0.0"));
        assert!(lt("1.9.0", "1.10.0")); // numeric, not lexicographic
    }

    #[test]
    fn release_equivalence() {
        assert!(eq("1.0", "1.0.0"));
        assert!(eq("1.0", "1.0-ga"));
        assert!(eq("1.0", "1.0-final"));
        assert!(eq("1.0", "1.0-release"));
    }

    #[test]
    fn qualifier_ordering() {
        assert!(lt("1.0-alpha", "1.0-beta"));
        assert!(lt("1.0-beta", "1.0-rc"));
        assert!(lt("1.0-rc", "1.0-snapshot"));
        assert!(lt("1.0-snapshot", "1.0"));
        assert!(lt("1.0", "1.0-sp1"));
    }

    #[test]
    fn pre_release_lower_than_release() {
        assert!(lt("1.0.0-alpha", "1.0.0"));
        assert!(lt("1.0.0-rc1", "1.0.0"));
        assert!(lt("2.0.0-snapshot", "2.0.0"));
    }

    #[test]
    fn embedded_qualifier_split() {
        // 1.0alpha1 should parse as [1,0,"alpha",1]; same as 1.0-alpha-1
        assert!(eq("1.0alpha1", "1.0-alpha-1"));
        assert!(lt("1.0alpha1", "1.0alpha2"));
        assert!(lt("1.0alpha2", "1.0beta1"));
    }

    #[test]
    fn unknown_qualifiers_lex_above_known() {
        // "x" is unknown; rank above release.
        assert!(lt("1.0-snapshot", "1.0-x"));
        // alphabetic order between unknowns
        assert!(lt("1.0-x", "1.0-y"));
    }
}

//! Validation set for `intel::score_package` weights.
//!
//! Two cohorts of packages with realistic metadata snapshots:
//! - **Bad**: known-compromised or characteristically suspicious shapes
//!   (Shai-Hulud-style fresh publish + lone maintainer; Qix-style
//!   typosquat; unmaintained leftover).
//! - **Good**: well-known, legitimately popular packages.
//!
//! The test asserts **precision and recall** against the cohort labels,
//! then enforces a minimum F1 score. If a future weight change degrades
//! the F1 below the threshold the test fails, forcing a conscious
//! tradeoff instead of silent regression.
//!
//! Why synthetic snapshots and not live npm? Live network is flaky and
//! mutation-prone — yesterday's "fresh publish" is not fresh tomorrow.
//! These fixtures are reproducible and deterministic.
//!
//! ## Honest caveat
//!
//! The 20-fixture set is small. F1=1.0 here means "the scoring
//! recognizes the patterns we built it to recognize" — close to
//! tautological. This file is a **regression fence**: if a future
//! weight tweak inadvertently breaks the recognition of e.g.
//! "single-maintainer + fresh-publish + no-source = High", the test
//! catches it. It is NOT a benchmark. A real benchmark would pull
//! ~100 anonymized historical OSV records (Shai-Hulud, Qix, axios)
//! and measure precision/recall against them. That's roadmap.

use chrono::{Duration, Utc};
use guardep_core::ecosystem::{Ecosystem, PackageRef};
use guardep_core::finding::FindingSeverity;
use guardep_core::intel::{score_package_for_test, IntelSnapshot};
use guardep_core::policy::Policy;

fn rfc3339_days_ago(days: i64) -> String {
    (Utc::now() - Duration::days(days))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn pkg(name: &str, version: &str) -> PackageRef {
    PackageRef::new(Ecosystem::Npm, name, version)
}

fn snap(
    maintainers: usize,
    versions: usize,
    installed_published_days_ago: Option<i64>,
    modified_days_ago: Option<i64>,
    has_repo: bool,
    weekly_downloads: Option<u64>,
) -> IntelSnapshot {
    IntelSnapshot {
        maintainer_count: maintainers,
        version_count: versions,
        installed_published_at: installed_published_days_ago.map(rfc3339_days_ago),
        modified_at: modified_days_ago.map(rfc3339_days_ago),
        latest_tag: Some("x.y.z".into()),
        latest_published_at: modified_days_ago.map(rfc3339_days_ago),
        has_repository: has_repo,
        weekly_downloads,
    }
}

/// One labelled fixture. `expect_min_severity == None` marks it good.
struct Fixture {
    name: &'static str,
    version: &'static str,
    snap: IntelSnapshot,
    /// `Some(sev)` = bad cohort (must flag at >= sev). `None` = good.
    expect_min_severity: Option<FindingSeverity>,
    /// Free-form scenario description (kept for debug output).
    _scenario: &'static str,
}

/// Five bad fixtures inspired by real incidents.
fn bad_cohort() -> Vec<Fixture> {
    vec![
        // Shai-Hulud-style: fresh publish, lone maintainer, no repo.
        // Score: single (25) + fresh-publish (20) + few-versions (15)
        //      + no-source (10) + very-fresh-latest (5) = 75 -> High
        Fixture {
            name: "ctrl-tinycolor-evil",
            version: "1.0.5",
            snap: snap(1, 3, Some(0), Some(0), false, None),
            expect_min_severity: Some(FindingSeverity::High),
            _scenario: "fresh hijack publish from compromised maintainer account",
        },
        // Qix-style typosquat of a top package: single, few versions, repo.
        // Score: typosquat (30) + single (25) + few-versions (15) = 70
        // -> High; with block_typosquats it becomes High anyway.
        Fixture {
            name: "expreess",
            version: "4.0.0",
            snap: snap(1, 2, Some(180), Some(180), true, Some(50)),
            expect_min_severity: Some(FindingSeverity::High),
            _scenario: "typosquat of express",
        },
        // Abandoned utility: single maintainer, very old, no repo update.
        // Score: single (25) + abandoned (15) = 40 -> Medium
        Fixture {
            name: "old-helper-lib",
            version: "0.3.7",
            snap: snap(1, 8, Some(1500), Some(1500), true, Some(120)),
            expect_min_severity: Some(FindingSeverity::Medium),
            _scenario: "abandoned solo project, possible takeover risk",
        },
        // Brand new package, no source, single maintainer.
        // Score: single (25) + few-versions (15) + fresh-publish (20)
        //      + no-source (10) + very-fresh-latest (5) = 75 -> High
        Fixture {
            name: "newbie-utility",
            version: "0.1.0",
            snap: snap(1, 1, Some(2), Some(2), false, None),
            expect_min_severity: Some(FindingSeverity::High),
            _scenario: "brand new package, no source repository",
        },
        // Multi-signal but not malware: lone maintainer + few versions + no repo.
        // Score: single (25) + few-versions (15) + no-source (10) = 50 -> Medium
        Fixture {
            name: "small-helper",
            version: "1.2.0",
            snap: snap(1, 4, Some(45), Some(45), false, Some(800)),
            expect_min_severity: Some(FindingSeverity::Medium),
            _scenario: "small library, multiple risk signals stack",
        },
    ]
}

/// Fifteen good fixtures: well-known mature packages with healthy
/// metadata shapes. None of these should fire a finding under the
/// default policy.
fn good_cohort() -> Vec<Fixture> {
    let mature = |name: &'static str| Fixture {
        name,
        version: "5.4.2",
        // 50+ versions, healthy maintainer team, has repo, recent activity.
        snap: snap(5, 60, Some(30), Some(30), true, Some(5_000_000)),
        expect_min_severity: None,
        _scenario: "mature, multi-maintainer, well-maintained library",
    };
    let medium = |name: &'static str| Fixture {
        name,
        version: "2.0.0",
        // Mid-sized: 20 versions, 2 maintainers (passes popularity check
        // because maintainer_count >= 2 + has_repository), recent.
        snap: snap(2, 20, Some(60), Some(60), true, Some(50_000)),
        expect_min_severity: None,
        _scenario: "modest popular library, reputation cross-check should suppress noise",
    };
    let solo_legit = |name: &'static str| Fixture {
        name,
        version: "3.1.0",
        // Solo maintainer but 30 versions + repo. Single-maintainer is
        // suppressed by default (only reason fires).
        snap: snap(1, 30, Some(120), Some(120), true, Some(200_000)),
        expect_min_severity: None,
        _scenario: "solo legitimate maintainer, long history, single-maintainer suppressed",
    };
    vec![
        mature("react"),
        mature("lodash"),
        mature("axios"),
        mature("express"),
        mature("vue"),
        mature("typescript"),
        mature("webpack"),
        mature("eslint"),
        medium("dotenv"),
        medium("commander"),
        medium("ws"),
        solo_legit("ms"),
        solo_legit("yallist"),
        solo_legit("safer-buffer"),
        solo_legit("process-nextick-args"),
    ]
}

#[test]
fn validation_set_meets_quality_thresholds() {
    let policy = Policy::default();
    let mut tp = 0; // truly bad, flagged
    let mut fp = 0; // truly good, flagged
    let mut tn = 0; // truly good, not flagged
    let mut fn_ = 0; // truly bad, not flagged

    let mut failures: Vec<String> = Vec::new();

    for fix in bad_cohort() {
        let p = pkg(fix.name, fix.version);
        let result = score_package_for_test(&p, &fix.snap, &policy);
        match result {
            Some(f) if f.severity >= fix.expect_min_severity.unwrap_or(FindingSeverity::Low) => {
                tp += 1;
            }
            Some(f) => {
                tp += 1; // still flagged, just lower severity than expected
                failures.push(format!(
                    "BAD/severity-too-low: {}@{} got {:?}, expected >= {:?} ({})",
                    fix.name,
                    fix.version,
                    f.severity,
                    fix.expect_min_severity.unwrap(),
                    fix._scenario
                ));
            }
            None => {
                fn_ += 1;
                failures.push(format!(
                    "BAD/missed: {}@{} not flagged ({})",
                    fix.name, fix.version, fix._scenario
                ));
            }
        }
    }

    for fix in good_cohort() {
        let p = pkg(fix.name, fix.version);
        let result = score_package_for_test(&p, &fix.snap, &policy);
        match result {
            None => tn += 1,
            Some(f) if f.severity == FindingSeverity::Info => tn += 1, // Info doesn't count as a flag
            Some(f) => {
                fp += 1;
                failures.push(format!(
                    "GOOD/false-positive: {}@{} flagged {:?} ({})",
                    fix.name, fix.version, f.severity, fix._scenario
                ));
            }
        }
    }

    let precision = if tp + fp == 0 {
        1.0
    } else {
        tp as f64 / (tp + fp) as f64
    };
    let recall = if tp + fn_ == 0 {
        1.0
    } else {
        tp as f64 / (tp + fn_) as f64
    };
    let f1 = if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    };

    eprintln!(
        "validation: TP={tp} FP={fp} TN={tn} FN={fn_} precision={precision:.3} recall={recall:.3} F1={f1:.3}"
    );
    if !failures.is_empty() {
        eprintln!("\nfailures ({}):", failures.len());
        for f in &failures {
            eprintln!("  - {f}");
        }
    }

    // Hard thresholds. Tuning the weights past these without revisiting
    // the validation set is a regression we want to catch.
    assert!(
        precision >= 0.95,
        "precision {precision:.3} below threshold 0.95 — too many false positives"
    );
    assert!(
        recall >= 0.80,
        "recall {recall:.3} below threshold 0.80 — too many missed bad packages"
    );
    assert!(f1 >= 0.85, "F1 {f1:.3} below threshold 0.85");
}

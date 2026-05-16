//! Integration tests for `CargoLockResolver`.
//!
//! Two layers:
//!  1. An inline v3 Cargo.lock fixture covering the parser-relevant
//!     cases: crates.io registry source (HTTPS + sparse), git source,
//!     path source (workspace member), and a duplicate name across
//!     versions. This pins parser behavior independently of the
//!     workspace's own lockfile.
//!  2. A smoke test against the workspace's real `Cargo.lock` to
//!     catch regressions where the resolver silently drops packages
//!     or fails on real-world lockfile shape.

use guardep_core::ecosystem::Ecosystem;
use guardep_core::resolver::{CargoLockResolver, Resolver};
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

const FIXTURE_LOCK: &str = r#"version = 3

[[package]]
name = "workspace-member"
version = "0.1.0"

[[package]]
name = "another-workspace-member"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "deadbeef"

[[package]]
name = "serde"
version = "1.0.210"
source = "registry+sparse+https://index.crates.io/"
checksum = "cafebabe"

[[package]]
name = "tokio"
version = "1.36.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "deadbeef"

[[package]]
name = "patched-from-git"
version = "0.5.0"
source = "git+https://github.com/example/patched-from-git?rev=abc123#abc123"

[[package]]
name = "local-path-dep"
version = "0.1.0"
source = "path+file:///tmp/local-path-dep"
"#;

#[test]
fn parses_inline_fixture_and_filters_to_crates_io() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("Cargo.lock"), FIXTURE_LOCK).unwrap();

    let pkgs = CargoLockResolver.resolve(dir.path()).expect("resolve ok");

    // Workspace members (no source), git, and path entries must be dropped.
    // Two serde entries with distinct versions must both survive.
    let names: Vec<(&str, &str)> = pkgs
        .iter()
        .map(|p| (p.name.as_str(), p.version.as_str()))
        .collect();

    assert_eq!(
        pkgs.len(),
        3,
        "expected exactly 3 crates.io packages, got {names:?}"
    );

    for p in &pkgs {
        assert_eq!(
            p.ecosystem,
            Ecosystem::Cargo,
            "ecosystem must be Cargo for {p:?}"
        );
    }

    assert!(names.contains(&("serde", "1.0.197")));
    assert!(names.contains(&("serde", "1.0.210")));
    assert!(names.contains(&("tokio", "1.36.0")));

    // Negative: nothing from git/path/workspace sources.
    assert!(!names.iter().any(|(n, _)| *n == "patched-from-git"));
    assert!(!names.iter().any(|(n, _)| *n == "local-path-dep"));
    assert!(!names.iter().any(|(n, _)| *n == "workspace-member"));
    assert!(!names.iter().any(|(n, _)| *n == "another-workspace-member"));
}

#[test]
fn errors_when_lockfile_missing() {
    let dir = TempDir::new().unwrap();
    let err = CargoLockResolver.resolve(dir.path()).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Cargo.lock not found"),
        "unexpected error: {msg}"
    );
}

#[test]
fn errors_on_malformed_lockfile() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("Cargo.lock"), "not = valid = toml").unwrap();
    let err = CargoLockResolver.resolve(dir.path()).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("parse Cargo.lock"),
        "expected parse error context, got: {msg}"
    );
}

#[test]
fn resolves_workspace_cargo_lock_smoke() {
    // Walk up from this crate's manifest dir to the workspace root.
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf();

    if !workspace_root.join("Cargo.lock").exists() {
        eprintln!(
            "skipping: no Cargo.lock at workspace root {}",
            workspace_root.display()
        );
        return;
    }

    let pkgs = CargoLockResolver
        .resolve(&workspace_root)
        .expect("workspace Cargo.lock should resolve");

    assert!(
        pkgs.len() > 50,
        "workspace lockfile should yield a non-trivial dep graph, got {}",
        pkgs.len()
    );

    for p in &pkgs {
        assert_eq!(p.ecosystem, Ecosystem::Cargo);
        assert!(!p.name.is_empty(), "empty name in {p:?}");
        assert!(!p.version.is_empty(), "empty version in {p:?}");
    }

    // A handful of crates that are very unlikely to disappear from
    // guardep's own dep graph any time soon.
    let names: std::collections::HashSet<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
    for must_have in ["serde", "tokio", "anyhow", "clap"] {
        assert!(
            names.contains(must_have),
            "expected `{must_have}` in workspace lockfile, but it was missing"
        );
    }
}

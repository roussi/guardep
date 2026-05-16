//! Integration test for `CargoDryRunResolver`. Runs only when
//! `CARGO_DRY_RUN_NETWORK=1` is set, mirroring the convention used by
//! `maven_resolver_integration.rs`. The resolver shells out to the real
//! `cargo` binary and hits crates.io, which is too slow / flaky to run
//! by default on every developer's `cargo test`.
//!
//! When the gate is unset the test is a no-op so the suite stays green
//! on bare machines. CI can opt in with `CARGO_DRY_RUN_NETWORK=1`.

use guardep_core::ecosystem::Ecosystem;
use guardep_core::resolver::{CargoDryRunAction, CargoDryRunResolver, Resolver};
use std::fs;
use tempfile::TempDir;

fn network_enabled() -> bool {
    std::env::var("CARGO_DRY_RUN_NETWORK").ok().as_deref() == Some("1")
}

#[test]
fn add_resolves_new_dep_and_transitives() {
    if !network_enabled() {
        eprintln!("skipping: CARGO_DRY_RUN_NETWORK=1 not set");
        return;
    }

    let dir = TempDir::new().unwrap();
    // Minimal lib manifest. The resolver itself creates the placeholder
    // `src/lib.rs`; we just need a `[package]` here.
    fs::write(
        dir.path().join("Cargo.toml"),
        r#"[package]
name = "guardep-test-fixture"
version = "0.1.0"
edition = "2021"
"#,
    )
    .unwrap();

    // Pick a crate with a small, deterministic graph. `cfg-if` has zero
    // dependencies, so the resolver should yield exactly one package.
    let resolver = CargoDryRunResolver::new(
        CargoDryRunAction::Add,
        vec!["add".to_string(), "cfg-if@1".to_string()],
    );
    let pkgs = resolver
        .resolve(dir.path())
        .expect("CargoDryRunResolver should resolve cfg-if when cargo is on PATH");

    assert!(
        pkgs.iter()
            .any(|p| p.name == "cfg-if" && p.ecosystem == Ecosystem::Cargo),
        "expected cfg-if in resolved packages, got {pkgs:?}"
    );
}

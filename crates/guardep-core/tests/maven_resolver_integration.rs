//! Integration test for `MavenTreeResolver`. Runs only when
//! `MAVEN_AVAILABLE=1` is set in the test env (CI sets it after
//! installing maven). Without it the test is skipped — we don't want
//! `cargo test` on a bare developer machine to fail just because mvn
//! isn't installed.
//!
//! The test pom uses a single dependency on a tiny artifact
//! (`com.google.code.findbugs:jsr305`) so the transitive graph is
//! deterministic and the `mvn dependency:tree` invocation is fast.

use guardep_core::ecosystem::Ecosystem;
use guardep_core::resolver::{MavenTreeResolver, Resolver};
use std::fs;
use tempfile::TempDir;

fn maven_available() -> bool {
    std::env::var("MAVEN_AVAILABLE").ok().as_deref() == Some("1")
}

#[test]
fn resolves_minimal_pom_when_mvn_present() {
    if !maven_available() {
        eprintln!("skipping: MAVEN_AVAILABLE=1 not set");
        return;
    }

    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("pom.xml"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>dev.guardep.test</groupId>
  <artifactId>fixture</artifactId>
  <version>1.0.0</version>
  <packaging>jar</packaging>
  <dependencies>
    <dependency>
      <groupId>com.google.code.findbugs</groupId>
      <artifactId>jsr305</artifactId>
      <version>3.0.2</version>
    </dependency>
  </dependencies>
</project>
"#,
    )
    .unwrap();

    let pkgs = MavenTreeResolver
        .resolve(dir.path())
        .expect("MavenTreeResolver should succeed when mvn is on PATH");

    // The root project (id 1) is skipped, so we get exactly the
    // declared transitive dependency.
    assert!(
        pkgs.iter()
            .any(|p| p.name == "com.google.code.findbugs:jsr305"
                && p.version == "3.0.2"
                && p.ecosystem == Ecosystem::Maven),
        "expected jsr305 in resolved packages, got {pkgs:?}"
    );
}

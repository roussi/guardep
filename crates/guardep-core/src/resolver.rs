//! Lockfile resolvers.
//!
//! Each implementation extracts the resolved dependency graph from a
//! package manager's lockfile (or, where lockfiles can't be trusted, a
//! dry-run resolution). The trait is sync because every implementation
//! either reads files locally or shells out and waits — async would
//! buy nothing here.

use crate::ecosystem::{Ecosystem, PackageRef};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub trait Resolver {
    fn resolve(&self, project_root: &Path) -> Result<Vec<PackageRef>>;
}

// ── npm package-lock.json (lockfile v2/v3) ───────────────────────────────

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
                    continue; // root project entry
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

// ── pnpm-lock.yaml ────────────────────────────────────────────────────────

pub struct PnpmLockResolver;

impl Resolver for PnpmLockResolver {
    fn resolve(&self, project_root: &Path) -> Result<Vec<PackageRef>> {
        let lock_path = project_root.join("pnpm-lock.yaml");
        if !lock_path.exists() {
            anyhow::bail!("pnpm-lock.yaml not found in {}", project_root.display());
        }
        let raw = std::fs::read_to_string(&lock_path).context("read pnpm lockfile")?;
        // pnpm-lock keys under `packages:` look like `/<name>@<version>` or
        // `/<scope>/<name>@<version>(<peer-suffix>)`. We avoid pulling in
        // a YAML parser by walking lines: find the `packages:` block, then
        // top-level keys starting with `  /`.
        let mut out: BTreeSet<PackageRef> = BTreeSet::new();
        let mut in_packages_block = false;
        for line in raw.lines() {
            let trimmed_full = line.trim_end();
            if trimmed_full.is_empty() {
                continue;
            }
            // top-level section heading
            if !line.starts_with(' ') && trimmed_full.ends_with(':') {
                in_packages_block = trimmed_full == "packages:";
                continue;
            }
            if !in_packages_block {
                continue;
            }
            // Want lines like `  /name@version:` (2-space indent).
            let Some(rest) = line.strip_prefix("  /") else {
                continue;
            };
            let Some(key) = rest.strip_suffix(':') else {
                // Some pnpm versions use single-quoted keys: `  '/name@1.0(peer)':`
                let Some(stripped) = rest
                    .strip_prefix('\'')
                    .and_then(|s| s.strip_suffix("':"))
                else {
                    continue;
                };
                if let Some(pkg) = parse_pnpm_key(stripped) {
                    out.insert(pkg);
                }
                continue;
            };
            if let Some(pkg) = parse_pnpm_key(key) {
                out.insert(pkg);
            }
        }
        Ok(out.into_iter().collect())
    }
}

/// Parse a pnpm package key like `react@18.2.0(peer)` or
/// `@scope/pkg@1.0.0`. Strips peer-suffix in parens.
fn parse_pnpm_key(key: &str) -> Option<PackageRef> {
    // Drop trailing "(...)" peer/optional suffix (may nest).
    let head = match key.find('(') {
        Some(i) => &key[..i],
        None => key,
    };
    // Last '@' that is not at index 0 separates name from version
    // (works for both `name@1.0` and `@scope/name@1.0`).
    let split_at = head
        .char_indices()
        .rev()
        .find(|(i, c)| *c == '@' && *i != 0)?
        .0;
    let name = &head[..split_at];
    let version = &head[split_at + 1..];
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some(PackageRef::new(Ecosystem::Npm, name, version))
}

// ── yarn.lock (Berry-only minimal parser) ────────────────────────────────
// yarn v1 (classic) lockfile is YAML-ish but irregular; v2+ (Berry) is
// proper YAML. We support both formats by walking lines: a stanza begins
// with one or more dependency descriptors ending in `:`, followed by an
// indented `version "x.y.z"` line.

pub struct YarnLockResolver;

impl Resolver for YarnLockResolver {
    fn resolve(&self, project_root: &Path) -> Result<Vec<PackageRef>> {
        let lock_path = project_root.join("yarn.lock");
        if !lock_path.exists() {
            anyhow::bail!("yarn.lock not found in {}", project_root.display());
        }
        let raw = std::fs::read_to_string(&lock_path).context("read yarn lockfile")?;

        let mut out: BTreeSet<PackageRef> = BTreeSet::new();
        let mut current_descriptors: Vec<String> = Vec::new();
        let mut current_version: Option<String> = None;

        for line in raw.lines() {
            // Skip comments and blank lines
            if line.is_empty() || line.starts_with('#') {
                // blank line ends a stanza
                if line.is_empty() && !current_descriptors.is_empty() {
                    flush_yarn_stanza(&current_descriptors, &current_version, &mut out);
                    current_descriptors.clear();
                    current_version = None;
                }
                continue;
            }
            // A stanza header is at column 0 and ends with `:`
            if !line.starts_with(' ') && line.trim_end().ends_with(':') {
                // Flush previous stanza if any
                if !current_descriptors.is_empty() {
                    flush_yarn_stanza(&current_descriptors, &current_version, &mut out);
                    current_descriptors.clear();
                    current_version = None;
                }
                // header may be `"foo@^1.0", "foo@^1.1":` or `foo@^1.0:`
                let head = line.trim_end().trim_end_matches(':');
                for desc in head.split(',') {
                    let cleaned = desc.trim().trim_matches('"').to_string();
                    if !cleaned.is_empty() {
                        current_descriptors.push(cleaned);
                    }
                }
                continue;
            }
            // Indented `  version "..."` line
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix("version ") {
                let v = rest.trim().trim_matches('"').trim_matches('\'').to_string();
                current_version = Some(v);
            } else if let Some(rest) = trimmed.strip_prefix("version:") {
                // Berry style: `  version: 1.2.3`
                current_version = Some(rest.trim().to_string());
            }
        }
        // Final stanza
        if !current_descriptors.is_empty() {
            flush_yarn_stanza(&current_descriptors, &current_version, &mut out);
        }

        Ok(out.into_iter().collect())
    }
}

fn flush_yarn_stanza(
    descriptors: &[String],
    version: &Option<String>,
    out: &mut BTreeSet<PackageRef>,
) {
    let Some(version) = version else {
        return;
    };
    // Use first descriptor's name (all descriptors in a stanza share the
    // same package name; only the version range differs).
    let Some(first) = descriptors.first() else {
        return;
    };
    // Strip a "npm:" or "patch:" protocol prefix Berry sometimes emits.
    let trimmed = first
        .strip_prefix("npm:")
        .or_else(|| first.strip_prefix("patch:"))
        .unwrap_or(first);
    // Split off the version range to get the package name.
    let split_at = trimmed
        .char_indices()
        .rev()
        .find(|(i, c)| *c == '@' && *i != 0);
    let Some((idx, _)) = split_at else {
        return;
    };
    let name = &trimmed[..idx];
    if name.is_empty() {
        return;
    }
    out.insert(PackageRef::new(Ecosystem::Npm, name, version));
}

// ── Auto-detect ──────────────────────────────────────────────────────────

/// Pick the right resolver based on which lockfile/manifest is present.
/// Returns the file used so callers can report it.
pub fn auto_resolve(project_root: &Path) -> Result<(Vec<PackageRef>, &'static str)> {
    // Probed in order; first match wins. npm-family lockfiles are
    // probed first because they're cheap and the most common case.
    let candidates: &[(&str, &dyn Fn() -> Box<dyn Resolver>)] = &[
        ("package-lock.json", &|| Box::new(NpmLockResolver)),
        ("pnpm-lock.yaml", &|| Box::new(PnpmLockResolver)),
        ("yarn.lock", &|| Box::new(YarnLockResolver)),
        ("pom.xml", &|| Box::new(MavenTreeResolver)),
    ];
    for (name, ctor) in candidates {
        let path: PathBuf = project_root.join(name);
        if path.exists() {
            let resolver = ctor();
            let pkgs = resolver.resolve(project_root)?;
            return Ok((pkgs, name));
        }
    }
    anyhow::bail!(
        "no supported manifest in {} (looked for package-lock.json, \
         pnpm-lock.yaml, yarn.lock, pom.xml)",
        project_root.display()
    )
}

// ── PackageRef sort impls (used by all resolvers) ────────────────────────

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

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write(dir: &Path, name: &str, contents: &str) {
        std::fs::write(dir.join(name), contents).unwrap();
    }

    #[test]
    fn parses_pnpm_simple_keys() {
        let p = parse_pnpm_key("react@18.2.0").unwrap();
        assert_eq!(p.name, "react");
        assert_eq!(p.version, "18.2.0");

        let p = parse_pnpm_key("@scope/pkg@1.0.0").unwrap();
        assert_eq!(p.name, "@scope/pkg");
        assert_eq!(p.version, "1.0.0");
    }

    #[test]
    fn parses_pnpm_with_peer_suffix() {
        let p = parse_pnpm_key("react-dom@18.2.0(react@18.2.0)").unwrap();
        assert_eq!(p.name, "react-dom");
        assert_eq!(p.version, "18.2.0");
    }

    #[test]
    fn pnpm_resolver_extracts_packages() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "pnpm-lock.yaml",
            "lockfileVersion: '6.0'\n\
             \n\
             packages:\n  \
             /react@18.2.0:\n    resolution: {integrity: sha512-...}\n  \
             /react-dom@18.2.0(react@18.2.0):\n    resolution: {integrity: sha512-...}\n  \
             /@scope/pkg@1.0.0:\n    resolution: {integrity: sha512-...}\n",
        );
        let pkgs = PnpmLockResolver.resolve(dir.path()).unwrap();
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"react"));
        assert!(names.contains(&"react-dom"));
        assert!(names.contains(&"@scope/pkg"));
    }

    #[test]
    fn yarn_v1_resolver_extracts_packages() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "yarn.lock",
            "# yarn lockfile v1\n\
             \n\
             \"react@^18.0.0\", \"react@^18.2.0\":\n  \
             version \"18.2.0\"\n  \
             resolved \"https://registry.yarnpkg.com/react/-/react-18.2.0.tgz\"\n\
             \n\
             \"@scope/pkg@^1.0.0\":\n  \
             version \"1.0.5\"\n",
        );
        let pkgs = YarnLockResolver.resolve(dir.path()).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.iter().any(|p| p.name == "react" && p.version == "18.2.0"));
        assert!(pkgs.iter().any(|p| p.name == "@scope/pkg" && p.version == "1.0.5"));
    }

    #[test]
    fn yarn_berry_resolver_extracts_packages() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "yarn.lock",
            "__metadata:\n  version: 6\n\n\
             \"react@npm:^18.2.0\":\n  \
             version: 18.2.0\n  \
             resolution: \"react@npm:18.2.0\"\n",
        );
        let pkgs = YarnLockResolver.resolve(dir.path()).unwrap();
        assert!(pkgs.iter().any(|p| p.name == "react" && p.version == "18.2.0"));
    }

    #[test]
    fn parses_maven_tgf_skipping_root_and_edges() {
        let raw = "1 com.example:my-app:jar:1.0.0\n\
                   2 org.apache.commons:commons-lang3:jar:3.12.0:compile\n\
                   3 com.fasterxml.jackson.core:jackson-core:jar:2.15.0:compile\n\
                   4 com.fasterxml.jackson.core:jackson-databind:jar:2.15.0-snapshot:compile\n\
                   #\n\
                   1 2 compile\n\
                   1 3 compile\n";
        let pkgs = parse_tgf(raw);
        // root project (1) is skipped; we get 3 deps.
        assert_eq!(pkgs.len(), 3);
        assert!(pkgs
            .iter()
            .any(|p| p.name == "org.apache.commons:commons-lang3" && p.version == "3.12.0"));
        assert!(pkgs
            .iter()
            .any(|p| p.name == "com.fasterxml.jackson.core:jackson-databind"
                && p.version == "2.15.0-snapshot"));
        // ecosystem is Maven, not Npm
        for p in &pkgs {
            assert_eq!(p.ecosystem, Ecosystem::Maven);
        }
    }

    #[test]
    fn parses_maven_tgf_handles_blank_lines_and_no_edges() {
        let raw = "\n\
                   1 com.example:my-app:jar:1.0.0\n\
                   \n\
                   2 com.x:y:jar:0.1.0\n";
        let pkgs = parse_tgf(raw);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "com.x:y");
    }

    #[test]
    fn auto_resolve_picks_npm_lock_when_present() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/x":{"version":"1.0.0"}}}"#,
        );
        let (pkgs, kind) = auto_resolve(dir.path()).unwrap();
        assert_eq!(kind, "package-lock.json");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "x");
    }

    #[test]
    fn auto_resolve_falls_through_to_pnpm() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "pnpm-lock.yaml",
            "packages:\n  /react@18.2.0:\n    resolution: {}\n",
        );
        let (pkgs, kind) = auto_resolve(dir.path()).unwrap();
        assert_eq!(kind, "pnpm-lock.yaml");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "react");
    }

    #[test]
    fn auto_resolve_errors_when_nothing_present() {
        let dir = TempDir::new().unwrap();
        let err = auto_resolve(dir.path()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("no supported manifest"));
    }
}

// ── Maven dependency-tree resolver ──────────────────────────────────────
//
// Maven projects must be resolved through `mvn` itself: there's no
// static lockfile and the transitive graph depends on the local Maven
// settings (mirrors, profiles, parent POM resolution). We shell out to
// `mvn dependency:tree -DoutputType=tgf` and parse the TGF output.
//
// TGF (Trivial Graph Format) emitted by maven-dependency-plugin looks
// like:
//
//   1 com.example:my-app:jar:1.0.0
//   2 org.apache.commons:commons-lang3:jar:3.12.0:compile
//   ...
//   #
//   1 2 compile
//   ...
//
// We need only the node lines (before `#`); each is `<id> <gav>` where
// `gav` is `group:artifact:packaging:version[:scope]`. We emit one
// `PackageRef` per artifact, ecosystem `Maven`, name = `group:artifact`,
// version = `version`. The root project (id 1) is skipped.

pub struct MavenTreeResolver;

impl Resolver for MavenTreeResolver {
    fn resolve(&self, project_root: &Path) -> Result<Vec<PackageRef>> {
        let pom = project_root.join("pom.xml");
        if !pom.exists() {
            anyhow::bail!("pom.xml not found in {}", project_root.display());
        }

        // Use a temp file so we don't depend on capturing mvn's stdout
        // (Maven prints lifecycle banners to stdout regardless of -q).
        let tmp = tempfile::NamedTempFile::new().context("create tempfile for mvn output")?;
        let output_path = tmp.path().to_path_buf();
        drop(tmp); // we just need the path; mvn will create the file

        let status = Command::new("mvn")
            .arg("-q")
            .arg("dependency:tree")
            .arg("-DoutputType=tgf")
            .arg(format!("-DoutputFile={}", output_path.display()))
            .arg("-DappendOutput=false")
            .current_dir(project_root)
            .status()
            .context("invoke `mvn dependency:tree`")?;

        if !status.success() {
            anyhow::bail!("mvn dependency:tree exited {}", status);
        }

        let raw = std::fs::read_to_string(&output_path)
            .with_context(|| format!("read tgf output from {}", output_path.display()))?;
        let _ = std::fs::remove_file(&output_path);

        Ok(parse_tgf(&raw))
    }
}

fn parse_tgf(raw: &str) -> Vec<PackageRef> {
    let mut out: BTreeSet<PackageRef> = BTreeSet::new();
    for line in raw.lines() {
        // Section delimiter: stop at `#` (edges follow).
        if line.trim_start().starts_with('#') {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Split off the leading numeric ID. The root project is id 1
        // and represents the project being audited; skip it.
        let (id, rest) = match line.split_once(' ') {
            Some(parts) => parts,
            None => continue,
        };
        if id == "1" {
            continue;
        }
        let rest = rest.trim();
        let parts: Vec<&str> = rest.split(':').collect();
        if parts.len() < 4 {
            continue;
        }
        let group = parts[0];
        let artifact = parts[1];
        // parts[2] is packaging (jar/pom/war/...); ignored
        let version = parts[3];
        if group.is_empty() || artifact.is_empty() || version.is_empty() {
            continue;
        }
        let name = format!("{group}:{artifact}");
        out.insert(PackageRef::new(Ecosystem::Maven, name, version));
    }
    out.into_iter().collect()
}

// ── Dry-run resolver ─────────────────────────────────────────────────────
//
// `npm install --dry-run --json` resolves what *would* be installed
// without writing to disk. We use this when intercepting a CLI command
// like `npm install foo@latest`: the existing lockfile doesn't yet
// include `foo`, so reading it would let `foo` slip past the audit.
// Dry-run gives us the resolved graph including the new package.
//
// Important: dry-run STILL EXECUTES `prepare` lifecycle scripts on git
// dependencies, so this is not a complete defense for git: deps. For
// registry deps (the ~99% case) it's safe.

use std::process::Command;

pub struct NpmDryRunResolver {
    pub args: Vec<String>,
}

impl NpmDryRunResolver {
    /// `args` are forwarded to npm: e.g. `["install", "foo@latest"]`.
    pub fn new(args: Vec<String>) -> Self {
        Self { args }
    }
}

impl Resolver for NpmDryRunResolver {
    fn resolve(&self, project_root: &Path) -> Result<Vec<PackageRef>> {
        let output = Command::new("npm")
            .args(&self.args)
            .arg("--dry-run")
            .arg("--json")
            .arg("--package-lock-only")
            .current_dir(project_root)
            .output()
            .context("invoke `npm install --dry-run --json`")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "npm dry-run exited {}: {}",
                output.status.code().unwrap_or(-1),
                stderr.trim()
            );
        }

        let body = String::from_utf8_lossy(&output.stdout);
        let parsed: serde_json::Value = serde_json::from_str(&body)
            .with_context(|| format!("parse npm dry-run JSON: {body}"))?;

        let mut out: BTreeSet<PackageRef> = BTreeSet::new();

        // Newer npm (10+) emits `{"added":[{"name":..,"version":..}],
        // "removed":[],...}`. We collect added + remaining.
        if let Some(added) = parsed.get("added").and_then(|v| v.as_array()) {
            for entry in added {
                if let (Some(name), Some(version)) = (
                    entry.get("name").and_then(|v| v.as_str()),
                    entry.get("version").and_then(|v| v.as_str()),
                ) {
                    out.insert(PackageRef::new(Ecosystem::Npm, name, version));
                }
            }
        }

        // We additionally pull in everything in the existing lockfile
        // (post-dry-run npm has updated package-lock in the cwd because
        // --package-lock-only without --no-save mutates the file).
        // Read the freshly-resolved lockfile to include transitive deps
        // that are unchanged.
        if let Ok(extra) = NpmLockResolver.resolve(project_root) {
            for p in extra {
                out.insert(p);
            }
        }

        Ok(out.into_iter().collect())
    }
}

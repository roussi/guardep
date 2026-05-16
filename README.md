<h1 align="center">guardep</h1>

<p align="center">
  <strong>Package-manager firewall.</strong><br>
  Deterministic dependency gate for <strong>npm / pnpm / yarn / mvn</strong>
  installs, with <strong>Gradle</strong> audit support and a roadmap to
  full Gradle enforcement. Blocks risky dependencies <em>before</em>
  install-time code can run - not after.
</p>

<p align="center">
  <a href="https://github.com/roussi/guardep/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/roussi/guardep/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/roussi/guardep/actions/workflows/audit.yml"><img alt="Audit" src="https://github.com/roussi/guardep/actions/workflows/audit.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-blue.svg"></a>
  <a href="https://www.rust-lang.org/"><img alt="Built with Rust" src="https://img.shields.io/badge/Built%20with-Rust-orange.svg"></a>
  <img alt="Status" src="https://img.shields.io/badge/Status-MVP-yellow.svg">
</p>

---

Most dependency scanners are audit tools: they inspect lockfiles, repos,
SBOMs, or built artifacts after a dependency has already entered the
workflow. In JavaScript that gap is especially dangerous because
`postinstall` can execute during installation. By the time a scanner reports
the issue, a compromised package may already have run. The 2025 Shai-Hulud
worm and the April 2026 Mini Shai-Hulud TanStack/SAP/axios compromises both
worked because that window stays open.

`guardep` closes that window at the package-manager boundary. It intercepts
supported install commands, resolves the intended dependency graph, evaluates
it with advisory, malware-feed, package-intel, source-behavior, license,
install-script, and provenance checks, then refuses to forward to the real
package manager when policy is violated.

The strongest path today is JavaScript: npm, pnpm, and yarn shims.
Maven gets both an `mvn install`/`package`/`verify` shim and a
dependency-tree audit resolver. Gradle is audited via
`gradle dependencies` (Groovy or Kotlin DSL); a Gradle shim is on
the roadmap.

## Quick start

```bash
# macOS arm64 / Linux: one-liner
brew tap roussi/tap && brew install guardep

# Audit any project
guardep audit --path ~/code/my-frontend

# Wire npm/pnpm/yarn/mvn through guardep system-wide (asks first; reversible)
guardep install-shims

# Now every install is gated:
cd ~/code/my-frontend
npm install              # blocked if any critical CVE / known malware / suspicious script
```

Other platforms (Intel macOS, Windows, build from source) → see [Installation](#installation) below.

Uninstall any time: `guardep uninstall-shims` strips the shims and rc edits. Backups are restored from `<rc>.guardep.bak`.

## Features

- **Package-manager firewall.** PATH shims sit between you and `npm`/`pnpm`/`yarn`. guardep audits the resolved graph before forwarding. Critical/malware findings exit 2; the real package manager never runs.
- **Multi-source evaluators in parallel.** OSV.dev advisories, OSSF malicious-package feed, npm registry intel, source-behavior scanning, license checks, install-script analysis, and Sigstore provenance.
- **EPSS + CISA KEV CVE enrichment.** Every CVE finding is annotated with its EPSS exploit-probability percentile and a KEV badge when the CVE is on CISA's Known Exploited Vulnerabilities list. KEV membership force-promotes severity to Critical; configurable EPSS threshold bumps severity one tier.
- **Composite risk scoring.** Weighted 0-100 score from transparent reasons. Single-maintainer alone -> Info; few-versions + fresh-publish + single-maintainer -> Medium; typosquat alone -> High.
- **Source behavior scanning.** Detects eval, dynamic require, network access, filesystem access, environment variable reads, URL strings, and high-entropy strings in installed package source. Aggregated per (package, behavior) by default; `--granular` switches to one finding per call-site with byte ranges.
- **License and deprecation findings.** Flags missing, unidentified, or deny-listed licenses and npm versions explicitly deprecated by maintainers.
- **Maintainer-rotation detector.** Snapshots the npm maintainer set per package and flags package-takeover risk when the set changes between scans (after a 12h stabilisation window so first-ever scans don't false-positive).
- **Multiple output formats.** `--format` accepts `table` (default), `json`, `cyclonedx` (CycloneDX 1.5 SBOM), and `sarif` (SARIF 2.1.0 ready for GitHub code-scanning).
- **PR-aware diff.** `guardep diff --base ./worktrees/main --head .` reports only the findings the head adds. Drop-in [`.github/actions/guardep-diff`](./.github/actions/guardep-diff/) composite action uploads SARIF to code-scanning automatically.
- **AST static analysis** of postinstall scripts. Detects process-spawn, credential reads, dynamic code execution, base64-decode -> eval chains, dynamic require/import, network calls. AST results promote regex severity (never demote).
- **Sigstore crypto verification.** Fulcio cert chain, DSSE signature, SCT. Identity bound to GitHub Actions OIDC. Falls back to presence + identity offline. Rekor inclusion proof pending upstream sigstore-rs release.
- **Honest output.** Findings sorted Critical -> Info, alphabetical within tier. `--severity` filters display threshold. `--fail-on` controls exit code separately. Composite risk scores show every contributing reason.
- **Reversible install.** `install-shims` backs up rc files to `<file>.guardep.bak` and brackets edits with marker comments. `uninstall-shims` strips the block exactly.

### Capability matrix

| Capability                            | Status                                                                                     |
| ------------------------------------- | ------------------------------------------------------------------------------------------ |
| Audit existing lockfile               | Works. npm/pnpm/yarn lockfiles parsed, evaluators run in parallel.                         |
| OSV.dev advisory matching             | Works. Batch endpoint, SQLite cache, semver range matching, per-major fix selection.       |
| OSSF malicious-package feed           | Works. Two-stage protocol with OSV-shape version-range matching so only versions actually marked malicious flag (no name-only false positives). |
| npm registry risk scoring             | Works. Maintainer count, version count, fresh-publish, abandonment, typosquat detection.   |
| Source behavior scanning              | Works when package source is present in `node_modules`; audit/CI signal, not a complete pre-download guarantee. |
| License checks                        | Works. Missing, unidentified, and configured deny-list findings.                           |
| Deprecated versions                   | Works. Emits findings when the installed npm version is marked deprecated.                 |
| Postinstall script analysis           | Regex heuristic + AST static analysis of referenced JS files (process spawn, cred reads, eval chains, network calls). |
| Sigstore provenance                   | Presence + identity + full crypto verification (Fulcio cert chain, DSSE, SCT). Inclusion proof pending sigstore-rs upstream release. |
| Pre-install gate (`npm ci`)           | Works when invoked through the shim AND lockfile is up-to-date.                            |
| Pre-install gate (`npm install foo`)  | Works via temp-dir dry-run resolution (copies `package.json` into a tempdir, materializes lockfile with `npm install --package-lock-only --ignore-scripts`, audits the result). |
| Maven                                 | Audit resolver via `mvn dependency:tree -DoutputType=tgf` plus a shim that intercepts `mvn install`/`package`/`verify` and refuses to forward on block. |
| Gradle                                | Audit resolver via `gradle dependencies --configuration runtimeClasspath` (prefers `./gradlew`); Groovy and Kotlin DSL both supported. Shim still planned. |
| Maintainer-rotation (`new-maintainer`) | Works. Diffs cached maintainer set against fresh registry snapshot; gated by a 12h stabilisation window. |
| SARIF output                          | Works. SARIF 2.1.0 with byte-range physicalLocation for source-behavior findings; ready for GitHub code-scanning. |
| GitHub Action                         | Works. Composite action at [`.github/actions/guardep-diff`](./.github/actions/guardep-diff/) wraps `guardep diff` and uploads SARIF. |
| Bypass via `/usr/local/bin/npm`       | **Possible.** PATH-based shim is not airtight against an attacker who already has shell access. |

## Installation

Pick the row for your platform.

### macOS arm64 (M1 / M2 / M3 / M4) — Homebrew

```bash
brew tap roussi/tap        # NOT `roussi/guardep`; tap repo is `homebrew-tap`
brew install guardep
```

### macOS Intel — Homebrew via Rosetta 2

The native `x86_64-apple-darwin` binary is deferred to a later
release because GitHub-hosted Intel macOS runners are deprecated.
Until then the arm64 binary runs transparently under Rosetta 2
(macOS 13+ ships Rosetta; guardep is pure Rust with no
arch-specific syscalls).

```bash
arch -arm64 brew tap roussi/tap
arch -arm64 brew install --formula guardep
```

If you'd rather skip Rosetta, use the [build-from-source](#any-platform--build-from-source) path below.

### Linux x86_64 / Linux arm64 — Homebrew

[Linuxbrew](https://docs.brew.sh/Homebrew-on-Linux) works the same way:

```bash
brew tap roussi/tap
brew install guardep
```

Or grab the tarball directly from the [latest release](https://github.com/roussi/guardep/releases/latest):

```bash
TAG=v0.1.0   # check https://github.com/roussi/guardep/releases/latest
ARCH=x86_64  # or aarch64
curl -L "https://github.com/roussi/guardep/releases/download/${TAG}/guardep-${TAG#v}-${ARCH}-unknown-linux-gnu.tar.gz" | tar -xz
sudo install -m 0755 "guardep-${TAG#v}-${ARCH}-unknown-linux-gnu/guardep" /usr/local/bin/guardep
```

### Windows x86_64 — release zip

```powershell
$tag    = "v0.1.0"   # check https://github.com/roussi/guardep/releases/latest
$asset  = "guardep-$($tag.TrimStart('v'))-x86_64-pc-windows-msvc.zip"
Invoke-WebRequest "https://github.com/roussi/guardep/releases/download/$tag/$asset" -OutFile $asset
Expand-Archive $asset -DestinationPath .
# Move guardep.exe somewhere on your PATH, e.g.:
Move-Item ".\guardep-$($tag.TrimStart('v'))-x86_64-pc-windows-msvc\guardep.exe" "$env:USERPROFILE\bin\guardep.exe"
```

### Any platform — build from source

Requires Rust ≥ 1.81.

```bash
# Stable, pinned to a tag
cargo install --git https://github.com/roussi/guardep guardep-cli --tag v0.1.0

# Or HEAD of main
cargo install --git https://github.com/roussi/guardep guardep-cli

# Or a local clone for hacking
git clone https://github.com/roussi/guardep && cd guardep
cargo build --release
sudo install -m 0755 target/release/guardep /usr/local/bin/guardep
```

`cargo install` puts the binary at `~/.cargo/bin/guardep`; make sure that is on your PATH.

### Verify the install

```bash
guardep --version    # → guardep 0.1.0
guardep --help
```

### crates.io

`cargo install guardep-cli` from the public registry will work
once the first tag is published there (planned for v0.1.x). Until
then use the `--git` form above.

### Wire it through your shell

`guardep install-shims` does two things:

1. Symlinks `~/.guardep/bin/{npm,pnpm,yarn,mvn}` to the guardep binary.
2. Prepends `~/.guardep/bin` to `PATH` in `~/.zshrc`, `~/.bashrc`, `~/.bash_profile`, `~/.config/fish/config.fish` (Unix) or `$PROFILE` (Windows PowerShell).

Each rc file is backed up to `<file>.guardep.bak` before the first edit. Changes sit between `# >>> guardep-shim >>>` / `# <<< guardep-shim <<<` marker comments so removal is exact. On a tty the command asks before editing; in CI / piped input it proceeds.

Flags:
- `--no-wire-path` - symlinks only, edit PATH yourself.
- `--yes` / `-y` - skip the interactive prompt.
- `--force` - overwrite existing symlinks and re-inject the rc block.

Reverse with `guardep uninstall-shims`: strips the symlinks and the marker block from every rc file. Backups stay in place.

## Usage

### Audit a project

```bash
guardep audit --path ./frontend
guardep audit --path ./frontend --collapse                 # one row per package
guardep audit --path ./frontend --collapse --format json   # CI-friendly
guardep audit --path ./frontend --format cyclonedx         # CycloneDX 1.5 SBOM
guardep audit --path ./frontend --format sarif             # SARIF 2.1.0 for code-scanning
guardep audit --path ./frontend --severity high            # only High + Critical
guardep audit --path ./frontend --severity info            # show everything (incl. single-maintainer noise)
guardep audit --path ./frontend --fail-on warn             # CI: exit 1 on warnings too
guardep audit --path ./frontend --granular                 # one finding per source-behavior call-site
guardep --verbose audit --path ./frontend                  # evaluator timings + HTTP logs
```

Severity levels (high -> low): `critical`, `high`, `medium`, `low` (default), `info`.
Findings are sorted Critical -> Info, then alphabetically by package within each tier.

### Use as a shim

After `guardep install-shims` and a shell restart:

```bash
cd ./my-project
npm install      # audited; blocks if malware/critical
pnpm install     # audited
yarn install     # audited
mvn install      # audited; mvn package and verify also intercepted
```

Bypass for one command (calls the real binary directly, skips
audit; loud warning to stderr so the bypass shows up in CI / shell
history). Two equivalent forms:

```bash
guardep skip npm install               # subcommand form
GUARDEP_BYPASS=1 npm install           # env-var form, composable in scripts
```

Both refuse to run when `GUARDEP_STRICT=1` is set (orgs that want
zero bypass in CI add it to the workflow env). The legacy
`$(which -a npm | grep -v guardep | head -1) install` still works
but is no longer the documented path.

Exit codes:
- `0`: clean
- `1`: warnings (only when `--fail-on warn`)
- `2`: blocks (default fail level)
- Other non-zero: real package manager exit code passed through

### CI / JSON

```bash
guardep audit --path . --collapse --format json --fail-on warn | tee guardep.json
jq '.summary' guardep.json
```

### PR-aware diff (only NEW findings)

Compare two project states and report only the findings the head adds over
the base. Designed to slot into PR CI: clone the merge-base into a worktree,
point `--base` at it and `--head` at the working tree.

```bash
guardep diff --base ./worktrees/main --head .                  # new findings only
guardep diff --base ./worktrees/main --head . --fail-on warn   # exit 1 on new warnings
guardep diff --base ./worktrees/main --head . --format json    # CI-friendly
```

### SARIF export (GitHub code-scanning)

```bash
guardep audit --path . --format sarif > guardep.sarif
guardep diff --base ./worktrees/main --head . --format sarif > diff.sarif
```

Map: source-behavior findings carry byte-range
`physicalLocation.region.byteOffset` / `byteLength`; CVE findings
expose EPSS / KEV as `properties[]` with keys `guardep:epss:score`,
`guardep:epss:percentile`, `guardep:kev`. Drop into
`github/codeql-action/upload-sarif@v3` or use the bundled GitHub
Action below.

### GitHub Action

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: roussi/guardep/.github/actions/guardep-diff@main
  with:
    fail-on: block
```

Resolves the base ref, runs `guardep diff`, exposes
`new-blocks` / `new-warnings` outputs, and (when `format=sarif`)
uploads to code-scanning. See
[`.github/actions/guardep-diff/README.md`](./.github/actions/guardep-diff/README.md)
for inputs, outputs, and pinning examples.

### CycloneDX SBOM export

Emit a CycloneDX 1.5 JSON document covering every resolved component plus
all advisory findings (with EPSS / KEV passthrough as `properties[]`).
Compatible with Dependency-Track, OWASP Defectdojo, and GitHub dependency
review.

```bash
guardep audit --path . --format cyclonedx > sbom.json
```

## Configuration

Drop `guardep.toml` at your project root:

```toml
[policy]
# OSV advisory policy
malware       = "block"
critical_cve  = "block"
high_cve      = "warn"
medium_cve    = "allow"
low_cve       = "allow"

# Postinstall script policy
postinstall_default    = "allow"   # score-0 scripts (most installs)
postinstall_suspicious = "warn"    # mid-tier (suspicious-looking but ambiguous)
postinstall_critical   = "block"   # unambiguous patterns (cred read, base64+eval)

# Risk scoring policy
block_if_risk_score_above  = 85
warn_if_risk_score_above   = 60
warn_if_unmaintained_days  = 730
warn_if_fresh_publish_days = 7
block_typosquats           = true
min_display_severity       = "low"   # `info`/`low`/`medium`/`high`/`critical`. Findings below this are dropped from the report.

# Provenance policy
require_provenance   = []           # globs: ["@*/*", "chalk", "react"]
missing_provenance   = "block"
provenance_mismatch  = "block"

# Cache TTL (hours)
cache_refresh_hours = 6

# Allowlists
allowlist = []                                # blanket: "axios@1.13.2"
[policy.finding_allowlist]                    # surgical, by finding ID
# "axios@1.13.2" = ["GHSA-43fc-jf86-j433"]
# "esbuild@0.25.12" = ["script:postinstall:912d4d8f..."]
```

> Postinstall findings are suppressed via `finding_allowlist` (the
> same machinery as OSV findings), keyed by `pkg@version` and the
> stable finding ID (e.g. `script:postinstall:<sha>`). There's no
> separate "trust this script hash" knob - finding IDs already
> include the script hash and are scoped to a specific package, so
> a malicious version of the same package wouldn't match the same
> ID.

## Architecture

```
crates/
  guardep-core/   Finding model, Evaluator trait, EvaluatorRegistry,
                  OSV / threat feed / Intel / source scan /
                  License / Postinstall / Provenance evaluators,
                  SQLite cache, semver matcher, policy engine,
                  lockfile resolvers
  guardep-cli/    Binary + shim dispatch (busybox argv0 pattern) +
                  commands (audit, diff, fix, install-shims, info,
                  cache)
```

All evaluators implement one trait and run concurrently. Findings are merged,
deduped, and rendered together.

## Threat model

**Defends against:**
- Compromised package publishes that rely on a `postinstall` hook firing.
- Known CVEs in transitive dependencies, gated by severity per policy.
- Known malicious packages from the OSSF malicious-package feed.
- Suspicious install scripts, via regex + AST scoring of script bodies and any referenced JS files.
- Suspicious package-source behavior in audit/CI contexts where package source is already present.
- Missing, unidentified, or deny-listed package licenses.
- Typosquats of popular packages, with reputation cross-check to suppress legit lookalikes (e.g. `cypress` vs `express`).
- Missing or mismatched Sigstore provenance for packages flagged in policy.

**Does NOT defend against:**
- **Targeted attacks against guardep itself.** A malicious shell rc, modified shim binary, or PATH manipulation defeats it.
- **Bypass via absolute path.** `/usr/local/bin/npm` skips the shim entirely. This is by design - the shim is friction, not enforcement.
- **`--no-package-lock`.** The shim refuses to proceed in this mode (exit 1) rather than running blind.
- **Yarn lockfiles, pre-Berry.** Currently parses `package-lock.json` and Berry's resolved lockfile only.
- **Forged Sigstore attestations.** We verify presence, identity, Fulcio cert chain, SCT, and DSSE signature. We do **not** yet verify the Rekor inclusion proof - the implementation [merged upstream](https://github.com/sigstore/sigstore-rs/pull/543) in Jan 2026 but isn't in a published `sigstore` crate version. Pinned to released crates.io versions only (no `git` deps for crypto code); will bump as soon as the next sigstore release ships.
- **Zero-day malware not yet in OSV or the OSSF feed** that also passes the postinstall, source-behavior, and risk-scoring heuristics.
- **Vulnerabilities in code your team writes.** Use SAST/DAST for that.
- **Container base image vulnerabilities.** Use [Trivy](https://github.com/aquasecurity/trivy) for that.

## How it compares

|                                   | npm audit | OSV-Scanner | Trivy        | Socket / Phylum  | **guardep**          |
| --------------------------------- | --------- | ----------- | ------------ | ---------------- | -------------------- |
| Package-manager enforcement       | no        | no          | no           | yes              | **npm/pnpm/yarn/mvn now; Gradle planned** |
| PR / lockfile audit               | yes       | yes         | partial      | yes              | **yes**              |
| Multi-source dependency intel     | partial   | no          | no           | yes              | **yes**              |
| Malware-class policy              | no        | no          | indirect     | yes              | **yes (OSV + OSSF, version-aware)** |
| Source behavior scanning          | no        | no          | no           | yes              | **yes, deterministic heuristics** |
| Postinstall script analysis       | no        | no          | no           | yes              | **yes, regex + AST** |
| Risk scoring                      | no        | no          | no           | yes              | **yes**              |
| Maintainer-rotation detection     | no        | no          | no           | yes              | **yes (snapshot diff)** |
| License policy                    | no        | no          | yes          | yes              | **yes (deny-list)**  |
| Provenance enforcement            | partial   | no          | no           | partial          | **full crypto verification** |
| EPSS + KEV CVE enrichment         | no        | no          | no           | no               | **yes**              |
| CycloneDX SBOM export             | no        | partial     | yes          | yes (paid)       | **yes**              |
| SARIF / code-scanning             | no        | yes         | yes          | yes              | **yes (with byte-range locations)** |
| PR-aware diff (new findings only) | no        | no          | no           | yes (paid)       | **yes**              |
| GitHub Action                     | no        | yes         | yes          | yes              | **yes (composite action wired to SARIF)** |
| Open source                       | yes       | yes         | yes          | no               | **yes (MIT)**        |
| Container / IaC scan              | no        | no          | yes          | no               | no                   |

## Roadmap

- [x] **Temp-dir pre-install resolution.** Audits the intended graph (`npm install foo@latest`), not just the existing lockfile.
- [x] **AST postinstall analysis** via `swc_ecma_parser`. Cross-file dataflow is still future work.
- [x] **Source behavior, license, deprecated-version, OSSF threat-feed (version-aware), and maintainer-rotation findings.**
- [x] **Sigstore crypto verification.** Fulcio cert chain, DSSE signature, SCT, identity policy bound to the GitHub Actions OIDC issuer.
- [x] **Maven resolver** (`mvn dependency:tree -DoutputType=tgf`) with Apache version-order comparator.
- [x] **Maven shim.** Intercepts `mvn install`/`package`/`verify` and refuses to forward on block.
- [x] **Gradle audit resolver** (`gradle dependencies --configuration runtimeClasspath`); Groovy and Kotlin DSL both supported.
- [x] **CycloneDX 1.5 SBOM** + **SARIF 2.1.0** output (with byte-range locations for source-behavior findings).
- [x] **`guardep diff`** PR-aware audit + composite **GitHub Action** that wraps it and uploads SARIF.
- [x] **Crates.io metadata** + **Homebrew formula template** wired for the first tagged release.
- [x] **Cross-platform PATH wiring** (zsh, bash, fish, PowerShell) with idempotent install + clean uninstall.
- [x] **Multi-OS release pipeline** (Linux x86/arm, macOS x86/arm, Windows x86) building tarballs + zips + sha256s, attached to GitHub Releases.
- [ ] **Rekor inclusion proof.** Pending [sigstore-rs#543](https://github.com/sigstore/sigstore-rs/pull/543) shipping to crates.io.
- [ ] **First tagged release** publishing to the Homebrew tap and crates.io.
- [ ] **Gradle shim** (intercept install-equivalent invocations).
- [ ] **Cargo / pip / RubyGems** ecosystem support beyond Maven + npm.

## Contributing

Issues and PRs welcome. Before opening a PR, run the local mirror of CI:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
```

Or just `claude` and run `/pre-push` - the bundled slash command (in [`.claude/commands/`](./.claude/commands/)) does all of the above and a `cargo audit` pass. The project ships an opinionated [`.claude/`](./.claude/) setup so contributors using Claude Code inherit the same conventions, hooks, and permissions.

Useful one-offs while hacking:

```bash
# Bust the SQLite advisory cache to force fresh OSV fetches
rm -f ~/Library/Caches/dev.guardep.guardep/*.db    # macOS
rm -f ~/.cache/guardep/*.db                         # Linux

# Run guardep against a fixture without rebuilding
cargo run -- audit --path /path/to/project --collapse
```

## Acknowledgements

- [OSV.dev](https://osv.dev/) for the unified advisory database.
- [GitHub Advisory Database](https://github.com/advisories) for primary reporting.
- [Sigstore](https://www.sigstore.dev/) and the npm provenance team for making attestation tractable.
- [Trivy](https://github.com/aquasecurity/trivy), [OSV-Scanner](https://github.com/google/osv-scanner), [Socket](https://socket.dev), and [Phylum](https://phylum.io) for proving the model and pushing the field forward.

## License

MIT - see [LICENSE](LICENSE).

<sub>guardep is not affiliated with, endorsed by, or sponsored by any of the projects or vendors named above.</sub>

<h1 align="center">guardep</h1>

<p align="center">
  <strong>Package-manager firewall.</strong><br>
  Deterministic dependency gate for <strong>npm / pnpm / yarn today</strong>,
  with <strong>Maven / Gradle</strong> enforcement on the roadmap.
  Blocks risky dependencies <em>before</em> install-time code can run - not after.
</p>

<p align="center">
  <a href="https://github.com/aroussi/guardep/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/aroussi/guardep/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/aroussi/guardep/actions/workflows/audit.yml"><img alt="Audit" src="https://github.com/aroussi/guardep/actions/workflows/audit.yml/badge.svg"></a>
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

The strongest path today is JavaScript: npm, pnpm, and yarn shims. Maven
dependency resolution is implemented for audit workflows, and Maven/Gradle
enforcement is the next expansion.

## Quick start

```bash
git clone https://github.com/aroussi/guardep && cd guardep
cargo build --release

# Audit any project
./target/release/guardep audit --path ~/code/my-frontend

# Wire npm/pnpm/yarn through guardep system-wide (asks first; reversible)
./target/release/guardep install-shims

# Now every install is gated:
cd ~/code/my-frontend
npm install              # blocked if any critical CVE / known malware / suspicious script
```

Uninstall any time: `guardep uninstall-shims` strips the shims and rc edits. Backups are restored from `<rc>.guardep.bak`.

## Features

- **Package-manager firewall.** PATH shims sit between you and `npm`/`pnpm`/`yarn`. guardep audits the resolved graph before forwarding. Critical/malware findings exit 2; the real package manager never runs.
- **Multi-source evaluators in parallel.** OSV.dev advisories, OSSF malicious-package feed, npm registry intel, source-behavior scanning, license checks, install-script analysis, and Sigstore provenance.
- **EPSS + CISA KEV CVE enrichment.** Every CVE finding is annotated with its EPSS exploit-probability percentile and a KEV badge when the CVE is on CISA's Known Exploited Vulnerabilities list. KEV membership force-promotes severity to Critical; configurable EPSS threshold bumps severity one tier.
- **Composite risk scoring.** Weighted 0-100 score from transparent reasons. Single-maintainer alone -> Info; few-versions + fresh-publish + single-maintainer -> Medium; typosquat alone -> High.
- **Source behavior scanning.** Detects eval, dynamic require, network access, filesystem access, environment variable reads, URL strings, and high-entropy strings in installed package source.
- **License and deprecation findings.** Flags missing, unidentified, or deny-listed licenses and npm versions explicitly deprecated by maintainers.
- **AST static analysis** of postinstall scripts. Detects process-spawn, credential reads, dynamic code execution, base64-decode -> eval chains, dynamic require/import, network calls. AST results promote regex severity (never demote).
- **Sigstore crypto verification.** Fulcio cert chain, DSSE signature, SCT. Identity bound to GitHub Actions OIDC. Falls back to presence + identity offline. Rekor inclusion proof pending upstream sigstore-rs release.
- **Honest output.** Findings sorted Critical -> Info, alphabetical within tier. `--severity` filters display threshold. `--fail-on` controls exit code separately. Composite risk scores show every contributing reason.
- **Reversible install.** `install-shims` backs up rc files to `<file>.guardep.bak` and brackets edits with marker comments. `uninstall-shims` strips the block exactly.

### Capability matrix

| Capability                            | Status                                                                                     |
| ------------------------------------- | ------------------------------------------------------------------------------------------ |
| Audit existing lockfile               | Works. npm/pnpm/yarn lockfiles parsed, evaluators run in parallel.                         |
| OSV.dev advisory matching             | Works. Batch endpoint, SQLite cache, semver range matching, per-major fix selection.       |
| OSSF malicious-package feed           | Works. Flags matched packages as malware independent of OSV advisory lag.                  |
| npm registry risk scoring             | Works. Maintainer count, version count, fresh-publish, abandonment, typosquat detection.   |
| Source behavior scanning              | Works when package source is present in `node_modules`; audit/CI signal, not a complete pre-download guarantee. |
| License checks                        | Works. Missing, unidentified, and configured deny-list findings.                           |
| Deprecated versions                   | Works. Emits findings when the installed npm version is marked deprecated.                 |
| Postinstall script analysis           | Regex heuristic + AST static analysis of referenced JS files (process spawn, cred reads, eval chains, network calls). |
| Sigstore provenance                   | Presence + identity + full crypto verification (Fulcio cert chain, DSSE, SCT). Inclusion proof pending sigstore-rs upstream release. |
| Pre-install gate (`npm ci`)           | Works when invoked through the shim AND lockfile is up-to-date.                            |
| Pre-install gate (`npm install foo`)  | Works via temp-dir dry-run resolution (copies `package.json` into a tempdir, materializes lockfile with `npm install --package-lock-only --ignore-scripts`, audits the result). |
| Maven                                 | Audit resolver works via `mvn dependency:tree -DoutputType=tgf`. OSV ranges use Apache version-order comparator. No shim yet. |
| Gradle                                | Planned.                                                                                   |
| Bypass via `/usr/local/bin/npm`       | **Possible.** PATH-based shim is not airtight against an attacker who already has shell access. |

## Installation

### From source (only option for now)

Pre-built binaries via `guardep install-shims` and `cargo install` are coming with the first tagged release. For now, build locally:

```bash
git clone https://github.com/aroussi/guardep && cd guardep
cargo build --release
sudo install -m 0755 target/release/guardep /usr/local/bin/guardep   # optional
```

### Wire it through your shell

`guardep install-shims` does two things:

1. Symlinks `~/.guardep/bin/{npm,pnpm,yarn}` to the guardep binary.
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
guardep audit --path ./frontend --severity high            # only High + Critical
guardep audit --path ./frontend --severity info            # show everything (incl. single-maintainer noise)
guardep audit --path ./frontend --fail-on warn             # CI: exit 1 on warnings too
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
```

Bypass for one command (calls real binary directly, skips audit):

```bash
$(which -a npm | grep -v guardep | head -1) install
```

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

|                                  | npm audit | OSV-Scanner | Trivy        | Socket / Phylum  | **guardep**          |
| -------------------------------- | --------- | ----------- | ------------ | ---------------- | -------------------- |
| Package-manager enforcement      | no        | no          | no           | yes              | **npm/pnpm/yarn now; Maven/Gradle planned** |
| PR / lockfile audit              | yes       | yes         | partial      | yes              | **yes**              |
| Multi-source dependency intel    | partial   | no          | no           | yes              | **yes**              |
| Malware-class policy             | no        | no          | indirect     | yes              | **yes**              |
| Source behavior scanning         | no        | no          | no           | yes              | **yes, deterministic heuristics** |
| Postinstall script analysis      | no        | no          | no           | yes              | **yes, regex + AST** |
| Risk scoring                     | no        | no          | no           | yes              | **yes**              |
| License policy                   | no        | no          | yes          | yes              | **yes (deny-list)**  |
| Provenance enforcement           | partial   | no          | no           | partial          | **full crypto verification** |
| EPSS + KEV CVE enrichment        | no        | no          | no           | no               | **yes**              |
| CycloneDX SBOM export            | no        | partial     | yes          | yes (paid)       | **yes**              |
| PR-aware diff (new findings only)| no        | no          | no           | yes (paid)       | **yes**              |
| Open source                      | yes       | yes         | yes          | no               | **yes (MIT)**        |
| Container / IaC scan             | no        | no          | yes          | no               | no                   |

## Roadmap

- [x] **Temp-dir pre-install resolution.** Audits the intended graph (`npm install foo@latest`), not just the existing lockfile.
- [x] **AST postinstall analysis** via `swc_ecma_parser`. Cross-file dataflow is still future work.
- [x] **Source behavior, license, deprecated-version, and OSSF threat-feed findings.**
- [x] **Sigstore crypto verification.** Fulcio cert chain, DSSE signature, SCT, identity policy bound to the GitHub Actions OIDC issuer.
- [x] **Maven resolver** (`mvn dependency:tree -DoutputType=tgf`) with Apache version-order comparator.
- [x] **Cross-platform PATH wiring** (zsh, bash, fish, PowerShell) with idempotent install + clean uninstall.
- [x] **Multi-OS release pipeline** (Linux x86/arm, macOS x86/arm, Windows x86) building tarballs + zips + sha256s, attached to GitHub Releases.
- [ ] **Rekor inclusion proof.** Pending [sigstore-rs#543](https://github.com/sigstore/sigstore-rs/pull/543) shipping to crates.io.
- [ ] **GitHub Action wrapper** around `guardep diff` for PR-aware enforcement.
- [ ] **SARIF output.**
- [ ] **Homebrew tap** + `cargo install guardep`.
- [ ] **Maven shim** (intercept install-equivalent invocations).
- [ ] **Gradle resolver.**
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

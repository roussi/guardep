# guardep

> Deterministic supply-chain audit and pre-install gate for **npm / pnpm / yarn**, with optional **maven / gradle** support coming.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![Status: MVP](https://img.shields.io/badge/Status-MVP-yellow.svg)]()

`guardep` audits a JavaScript project's resolved dependency graph against four finding sources (OSV.dev, npm registry intel, install scripts, Sigstore provenance) and refuses to forward to the real package manager when policy is violated. It is meant to sit between you and `npm install`, not to scan after the fact.

## What it actually does today (be honest)

| Capability                            | Status                                                                                     |
| ------------------------------------- | ------------------------------------------------------------------------------------------ |
| Audit existing lockfile               | Works. npm/pnpm/yarn lockfiles parsed, four evaluators run in parallel.                    |
| OSV.dev advisory matching             | Works. Batch endpoint, SQLite cache, semver range matching, per-major fix selection.       |
| Postinstall script heuristic          | String-match heuristic (~10 regex rules) on the shell command, plus **AST-based static analysis** of any referenced JS file (`node X.js` pattern). AST rules cover process spawn calls, credential-path file reads, dynamic code execution, base64-decode→eval chains, dynamic require/import, network calls. AST results promote the regex severity (never demote). |
| npm registry risk scoring             | Works. Maintainer count, version count, fresh-publish, abandonment, typosquat detection.   |
| Sigstore provenance                   | Presence + identity + **full crypto verification** (Fulcio cert chain, DSSE signature, SCT). Falls back to presence + identity when the trust root cannot be initialised (offline). Rekor inclusion proof check is not yet implemented (TODO upstream in `sigstore-rs`). |
| Pre-install gate (`npm ci`)           | Works when invoked through the shim AND lockfile is up-to-date.                            |
| Pre-install gate (`npm install foo`)  | **Limited.** Currently reads existing lockfile, so brand-new packages bypass until lockfile updates. See "Threat model" below. |
| Maven                                 | Resolves transitive graph via `mvn dependency:tree -DoutputType=tgf`. OSV ranges use a Maven-correct version comparator (qualifier ordering, snapshot/sp semantics). No shim yet. |
| Gradle                                | Not implemented. Shim passes through.                                                      |
| Bypass via `/usr/local/bin/npm`       | **Possible.** PATH-based shim is not airtight.                                             |

## Why this exists

`npm audit`, Trivy, OSV-Scanner all run **after** the package is on disk and `postinstall` has executed. By then a compromised package has already had its `postinstall` hook fire. The 2025 Shai-Hulud worm and the April 2026 Mini Shai-Hulud TanStack/SAP/axios compromises both worked because that window stays open.

guardep tries to close it for the most common path (`npm install` with an up-to-date lockfile, invoked through the shim).

## Install

```bash
git clone https://github.com/aroussi/guardep
cd guardep
cargo build --release

./target/release/guardep audit --path ./my-project

# Install shims and wire PATH in your shell rc files
./target/release/guardep install-shims
```

`install-shims` does two things:

1. Creates symlinks in `~/.guardep/bin/{npm,pnpm,yarn}` that point at the guardep binary.
2. Edits your shell rc files (`~/.zshrc`, `~/.bashrc`, `~/.bash_profile`, `~/.config/fish/config.fish` on Unix; `$PROFILE` on Windows PowerShell) to prepend `~/.guardep/bin` to `PATH`.

Each rc file is backed up to `<file>.guardep.bak` once before the first edit, and changes sit between marker comments (`# >>> guardep-shim >>>` / `# <<< guardep-shim <<<`) so removal is exact. On a tty the command asks before editing; in CI / piped input it proceeds.

Flags:
- `--no-wire-path` — symlink only, you add to `PATH` yourself.
- `--yes` / `-y` — skip the interactive prompt.
- `--force` — overwrite existing symlinks and re-inject the rc block.

Restart your shell (or `source ~/.zshrc`) to activate. To revert:

```bash
./target/release/guardep uninstall-shims
```

Removes the symlinks and strips the marker block from every rc file. Backups stay in place.

## Use

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

Severity levels (high → low): `critical`, `high`, `medium`, `low` (default), `info`.
Findings are sorted Critical → Info, then alphabetically by package within each tier.

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
> separate "trust this script hash" knob — finding IDs already
> include the script hash and are scoped to a specific package, so
> a malicious version of the same package wouldn't match the same
> ID.

## Architecture

```
crates/
  guardep-core/   Finding model, Evaluator trait, EvaluatorRegistry,
                  OSV / Postinstall / Intel / Provenance evaluators,
                  SQLite cache, semver matcher, policy engine,
                  lockfile resolvers
  guardep-cli/    Binary + shim dispatch (busybox argv0 pattern) +
                  commands (audit, install-shims, info, fix)
```

All four evaluators implement one trait and run concurrently. Findings are merged, deduped, and rendered together.

## Threat model (be honest)

guardep is intended to defend against:
- **Compromised package publishes** that depend on a `postinstall` hook firing
- **Known CVEs** in dependencies, gated by severity per policy
- **Suspicious install scripts**, via heuristic scoring of script bodies
- **Typosquats** of popular packages, with reputation cross-check to suppress legit lookalikes
- **Missing or mismatched provenance** for packages flagged in policy

guardep does **not** currently defend against:
- **Targeted attacks against guardep itself.** A malicious shell rc, modified shim binary, or PATH manipulation defeats it.
- **Bypass via absolute path.** `/usr/local/bin/npm` skips the shim entirely.
- **`--no-package-lock`.** Without a lockfile, the shim runs npm first and audits after, which is exactly what we are trying to avoid. Mitigation: in-progress (true dry-run resolution).
- **Yarn lockfiles, pre-pre-Berry.** Currently parses package-lock.json only.
- **Forged Sigstore attestations.** We verify presence, identity, the Fulcio certificate chain, the SCT, and the DSSE signature. We do NOT yet verify the Rekor inclusion proof (Merkle witness): the implementation [merged upstream](https://github.com/sigstore/sigstore-rs/pull/543) in Jan 2026 but isn't in a published `sigstore` crate version yet. Without the inclusion proof, an attacker who forges a bundle and bypasses public Rekor logging can still defeat the check. We pin to released crates.io versions only (no `git` deps for crypto code) and will bump as soon as the next sigstore release ships.
- **Zero-day malware not yet in OSV** that also passes the postinstall heuristic and risk scoring.
- **Vulnerabilities in code your team writes.** Use SAST/DAST.
- **Container base image vulnerabilities.** Use Trivy.

## How it compares

|                              | npm audit | OSV-Scanner | Trivy        | Socket / Phylum  | **guardep**          |
| ---------------------------- | --------- | ----------- | ------------ | ---------------- | -------------------- |
| Pre-install gate             | no        | no          | no           | yes (paid)       | **partial (npm/pnpm/yarn lockfile)** |
| Multi-source intel           | partial   | no          | no           | yes              | **yes**              |
| Malware-class policy         | no        | no          | indirect     | yes              | **yes**              |
| Postinstall script analysis  | no        | no          | no           | yes (paid)       | **heuristic only**   |
| Risk scoring                 | no        | no          | no           | yes (paid)       | **yes**              |
| Provenance enforcement       | no        | no          | no           | partial          | **full crypto verification** |
| Open source                  | yes       | yes         | yes          | no               | **yes (MIT)**        |
| Container / IaC scan         | no        | no          | yes          | no               | no                   |

## Known limitations and roadmap

- [ ] **True pre-install resolution.** Use `npm install --dry-run --json` to audit the *intended* graph instead of the existing lockfile. Eliminates the "new package bypasses audit" gap.
- [x] **AST-based postinstall analysis** of referenced JS files via `swc_ecma_parser`. Distinguishes literal-arg process-spawn calls from dynamic ones. Cross-file dataflow analysis is still future work.
- [x] **Sigstore crypto verification.** Fulcio cert chain, DSSE signature, SCT, Identity policy bound to GitHub Actions OIDC issuer.
- [ ] **Rekor inclusion proof.** Implementation merged upstream in [sigstore-rs#543](https://github.com/sigstore/sigstore-rs/pull/543) (Jan 2026) but not yet released to crates.io. We're pinned to `sigstore = "0.13"` (the latest release) which still skips the proof. Will bump to 0.14 (or whatever ships the merge) and flip `offline=false` once it's published.
- [x] **Maven resolver** (`mvn dependency:tree -DoutputType=tgf`) with Apache version-order comparator
- [ ] **Maven shim** (intercept install-equivalent invocations)
- [ ] **Gradle resolver.**
- [ ] **GitHub Action wrapper.**
- [ ] **SARIF output.**
- [ ] **Cargo dist / Homebrew release pipeline.** Currently `cargo install` from source only.

## Development

```bash
cargo build
cargo test
cargo run -- audit --path /path/to/project --collapse

# Bust caches to force fresh fetches
rm -f ~/Library/Caches/dev.guardep.guardep/*.db    # macOS
rm -f ~/.cache/guardep/*.db                         # Linux
```

## Acknowledgements

- [OSV.dev](https://osv.dev/) for the unified advisory database
- [GitHub Advisory Database](https://github.com/advisories)
- [Sigstore](https://www.sigstore.dev/) and the npm provenance team
- [Aqua Security Trivy](https://github.com/aquasecurity/trivy) and [OSV-Scanner](https://github.com/google/osv-scanner) for proving the model

## License

MIT, see [LICENSE](LICENSE).

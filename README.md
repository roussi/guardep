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
| Postinstall script heuristic          | Works as a string-match heuristic, not AST analysis. ~10 rules, scored 0-100.              |
| npm registry risk scoring             | Works. Maintainer count, version count, fresh-publish, abandonment, typosquat detection.   |
| Sigstore provenance                   | Presence + identity + **full crypto verification** (Fulcio cert chain, DSSE signature, SCT). Falls back to presence + identity when the trust root cannot be initialised (offline). Rekor inclusion proof check is not yet implemented (TODO upstream in `sigstore-rs`). |
| Pre-install gate (`npm ci`)           | Works when invoked through the shim AND lockfile is up-to-date.                            |
| Pre-install gate (`npm install foo`)  | **Limited.** Currently reads existing lockfile, so brand-new packages bypass until lockfile updates. See "Threat model" below. |
| Maven / Gradle                        | Not implemented. Shim passes through.                                                      |
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

# Install shims (creates ~/.guardep/bin/{npm,pnpm,yarn,mvn,gradle})
./target/release/guardep install-shims
export PATH="$HOME/.guardep/bin:$PATH"
```

## Use

### Audit a project

```bash
guardep audit --path ./frontend
guardep audit --path ./frontend --collapse                 # one row per package
guardep audit --path ./frontend --collapse --format json   # CI-friendly
guardep audit --path ./frontend --info                     # surface info-tier signals
guardep audit --path ./frontend --fail-on warn             # CI: exit 1 on warnings too
```

### Use as a shim

```bash
guardep install-shims
export PATH="$HOME/.guardep/bin:$PATH"

cd ./my-project
npm install      # audited; blocks if malware/critical
pnpm install     # audited
yarn install     # audited
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
postinstall_suspicious = "block"
postinstall_critical   = "block"
allowed_script_hashes  = []        # SHA-256 of pre-approved scripts

# Risk scoring policy
block_if_risk_score_above  = 85
warn_if_risk_score_above   = 60
warn_if_unmaintained_days  = 730
warn_if_fresh_publish_days = 7
block_typosquats           = true
report_single_maintainer   = false   # surface as Info when true

# Provenance policy (presence + identity check only)
require_provenance   = []           # globs: ["@*/*", "chalk", "react"]
missing_provenance   = "block"
provenance_mismatch  = "block"

# Cache TTL (hours)
cache_refresh_hours = 6

# Allowlists
allowlist = []                                # blanket: "axios@1.13.2"
[policy.finding_allowlist]                    # surgical
# "axios@1.13.2" = ["GHSA-43fc-jf86-j433"]
```

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
- **Forged Sigstore attestations.** We verify presence, identity, the Fulcio certificate chain, and the DSSE signature. We do NOT yet verify the Rekor inclusion proof (Merkle witness) — sigstore-rs has a TODO for this upstream. An attacker who can mint a valid Fulcio cert via a real GitHub Actions workflow with a matching repository identity could still bypass guardep, which is the same threat model as the upstream Sigstore tools.
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
- [ ] **AST-based postinstall analysis.** Replace regex heuristic with `swc_ecma_parser`. Real comment / string-literal awareness.
- [x] **Sigstore crypto verification.** Fulcio cert chain, DSSE signature, SCT, Identity policy bound to GitHub Actions OIDC issuer.
- [ ] **Rekor inclusion proof.** Pending upstream support in `sigstore-rs`.
- [ ] **Maven resolver.**
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

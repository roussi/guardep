# guardep

> **OSV-Scanner with teeth.** Block compromised installs across **npm / maven / gradle** before `postinstall` runs.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![Status: MVP](https://img.shields.io/badge/Status-MVP-yellow.svg)]()

---

`guardep` is a transparent shim for `npm`, `pnpm`, `yarn`, `mvn`, and `gradle` that resolves your dependency graph against multiple finding sources and refuses to install compromised packages, *before* any `postinstall` script gets a chance to run.

When the next Shai-Hulud-style worm hits, `npm install` should refuse to proceed. Not warn. Not log. **Refuse.**

```bash
$ npm install
> guardep: pre-install audit (npm install)
> resolved 759 packages
[X] chalk@5.6.1                GHSA-xxxx-xxxx-xxxx   MALWARE   Critical   BLOCK
[X] npm install blocked by guardep policy
```

---

## Why this exists

`npm audit`, Trivy, OSV-Scanner are all great. All run **after** the package is on disk and `postinstall` has executed. By then a compromised package has already exfiltrated your `~/.npmrc`, your `~/.aws/credentials`, your CI secrets, and republished itself to other packages you maintain.

The 2025 **Shai-Hulud worm** and the April 2026 **Mini Shai-Hulud TanStack/SAP/axios** compromises both worked because that window stays open. `guardep` closes it.

|                            | Scanner (Trivy / OSV-Scanner / `npm audit`) | guardep                  |
| -------------------------- | ------------------------------------------- | ------------------------ |
| When does it run?          | After install                               | **Before install**       |
| `postinstall` already ran? | Yes, damage done                            | No, gate intercepts      |
| Workflow change?           | New command (`trivy fs .`)                  | None, just `npm install` |
| Threat focus               | CVE severity                                | **Malware-first** policy |
| Decision model             | Report                                      | **Block / warn / allow** |

---

## Features

### Defenses (multiple finding sources)

guardep runs several **evaluators** in parallel against your resolved dependency graph. Each one produces findings that the policy engine combines and gates on.

| Evaluator           | What it catches                                                                                                                              | Status      |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| **OSV advisories**  | Known CVEs and malware records across npm/Maven/cargo/PyPI                                                                                   | shipped     |
| **Postinstall**     | Suspicious or known-bad `preinstall` / `install` / `postinstall` scripts via heuristic detector (network calls, cred reads, base64+eval, etc) | shipped     |
| **Risk score**      | Single-maintainer packages, fresh publishes, abandoned packages, typosquats (Levenshtein vs top-30 npm packages), missing source repo        | shipped     |
| **Provenance**      | Missing or mismatched npm Sigstore provenance attestations for packages flagged in policy                                                    | shipped     |
| **Maven resolver**  | `mvn dependency:tree` parsing, run advisory matching against full transitive graph                                                           | roadmap     |
| **Gradle resolver** | Tooling API or dependency-locking plugin                                                                                                     | roadmap     |

### Engine

- **Drop-in shim** that symlinks `npm`/`pnpm`/`yarn`/`mvn`/`gradle` via PATH. Zero workflow change.
- **Pre-install gate** audits the resolved dependency graph before forwarding to the real binary. Blocks on policy violation, exits non-zero.
- **Unified Finding model**: vulnerability, malware, postinstall script, risk score, missing provenance, provenance mismatch. All routed through one policy engine.
- **Parallel evaluator registry** runs every enabled finding source concurrently, isolating failures (one evaluator failing does not kill the audit).
- **OSV.dev backend** unifies GHSA, NVD, RUSTSEC, PYSEC, MAL-* across npm / Maven / cargo / PyPI.
- **Smart batching** via `/v1/querybatch` (1000 pkgs/call). Full audit of a 759-package project: ~20s cold, ~25ms cached.
- **Per-evaluator SQLite cache** with TTL configurable via policy.
- **Actionable upgrades**: `Min` (cheapest patch) vs `Safe` (clears all CVEs). Counts shown: `1.13.5 (1/5)` vs `1.15.2 (5/5)`.
- **Cross-major detection** flags when no in-major fix exists and a breaking change is required.
- **Allowlist escape hatch** (blanket `pkg@version` or surgical per-finding-id).
- **JSON output** for CI, dashboards, SARIF conversion.
- **Single static binary**, Rust, ~5MB, no runtime deps.

---

## Install

```bash
git clone https://github.com/aroussi/guardep
cd guardep
cargo build --release

# Audit a project (read-only)
./target/release/guardep audit --path ./my-project

# Install shims globally (creates ~/.guardep/bin/{npm,pnpm,yarn,mvn,gradle})
./target/release/guardep install-shims
export PATH="$HOME/.guardep/bin:$PATH"
```

> Add the `export PATH=...` line to your shell rc to make it permanent.

---

## Usage

### Audit a project

```bash
guardep audit --path ./frontend
guardep audit --path ./frontend --collapse              # one row per package
guardep audit --path ./frontend --collapse --format json
```

**Sample output (collapsed):**

```
+---+-------------------------------+---+--------------+-------+----------+------------------+------------------+--------+
|   | Package                       | # | Findings     | Class | Severity | Min              | Safe             | Action |
+---+-------------------------------+---+--------------+-------+----------+------------------+------------------+--------+
| ! | axios@1.13.2                  | 5 | GHSA-..., .. | CVE   | High     | 1.13.5 (1/5)     | 1.15.2 (5/5)     | WARN   |
| ! | electron@39.2.6               | 5 | GHSA-..., .. | CVE   | High     | 39.8.0 (3/5)     | 39.8.1 (5/5)     | WARN   |
| ! | tar@6.2.1                     | 6 | GHSA-..., .. | CVE   | High     | 7.5.3 (breaking) | 7.5.3 (breaking) | WARN   |
| X | chalk@5.6.1                   | 1 | GHSA-...     | MALW. | Critical | 5.6.2 (1/1)      | 5.6.2 (1/1)      | BLOCK  |
| X | loadsh@1.0.0                  | 1 | risk:typo... | RISK  | High     |                  |                  | BLOCK  |
| X | evil-pkg@2.0.0                | 1 | script:po... | SCRIPT| Critical |                  |                  | BLOCK  |
+---+-------------------------------+---+--------------+-------+----------+------------------+------------------+--------+

[X] 3 block(s), 16 warning(s), 1 malware finding(s) across 19 unique findings, 14 affected packages (98 raw)
```

Read the columns:

- **`#`**: number of findings matched against this `pkg@version`
- **`Min`**: smallest in-major bump and how many findings it clears (`1/5` = clears 1 of 5). Empty for non-version-fixable findings (script, risk).
- **`Safe`**: smallest in-major bump that clears **all** matched findings. `breaking` if a major upgrade is required.

### Use as a shim

```bash
guardep install-shims
export PATH="$HOME/.guardep/bin:$PATH"

cd ./my-project
npm install      # audited first; blocked if malware/critical
pnpm add lodash  # audited
yarn install     # audited
```

When the audit blocks, exit code is `2`. When clean, the real `npm`'s exit code is propagated.

### CI / JSON

```bash
guardep audit --path . --collapse --format json | tee guardep.json
jq '.summary' guardep.json
```

---

## Configuration

Drop a `guardep.toml` at your project root:

```toml
[policy]
# === OSV advisory policy ===
malware       = "block"
critical_cve  = "block"
high_cve      = "warn"
medium_cve    = "allow"
low_cve       = "allow"

# === Postinstall script policy ===
postinstall_default    = "warn"     # benign-looking script (score 0)
postinstall_suspicious = "block"    # heuristic flagged risky patterns
postinstall_critical   = "block"    # clear malware pattern (always block)
allowed_script_hashes  = [
  # "abc123...",   # pre-approved sha256 hash of a known-good script
]

# === Risk scoring policy ===
block_if_risk_score_above  = 85
warn_if_risk_score_above   = 60
warn_if_unmaintained_days  = 730
warn_if_fresh_publish_days = 7
block_typosquats           = true

# === Provenance policy ===
require_provenance   = []           # globs: ["@*/*", "chalk", "react"]
missing_provenance   = "block"
provenance_mismatch  = "block"

# === Cache TTL (hours) ===
cache_refresh_hours = 6

# === Allowlists ===
allowlist = [
  # "axios@1.13.2",   # blanket suppress all findings on this pkg@version
]

[policy.finding_allowlist]
# surgical: suppress one specific finding ID for one pkg@version
# "axios@1.13.2" = ["GHSA-43fc-jf86-j433"]
```

`Action` precedence: `block` > `warn` > `allow`. Allowlist downgrades to `allow` regardless of class.

---

## Architecture

```
crates/
  guardep-core/        Finding model, Evaluator trait, EvaluatorRegistry,
                       OSV client, Postinstall heuristic detector,
                       npm registry intel scoring, Sigstore provenance
                       verifier, SQLite caches, semver matcher,
                       policy engine, lockfile resolvers
  guardep-cli/         Binary + shim dispatch (busybox argv0 pattern) +
                       commands (audit, install-shims, info)
```

**Argv0 dispatch:** one binary, multiple symlinks. The shim inspects `argv[0]` to know whether it was invoked as `npm`, `mvn`, etc., and routes accordingly. Original tool is located via PATH (excluding the shim dir to avoid recursion) and forwarded to.

**Decision flow:**

```
user > npm install > ~/.guardep/bin/npm (shim)
                         |
                         + parse subcommand
                         + if not install-class -> passthrough
                         + resolve package-lock.json
                         + run all enabled evaluators in parallel:
                         |    OsvEvaluator (cache + batch fetch)
                         |    PostinstallEvaluator (read scripts, score)
                         |    IntelEvaluator (npm registry, risk score)
                         |    ProvenanceEvaluator (Sigstore attestations)
                         + merge findings, apply policy, dedup
                         |
                         + block? -> exit 2, no install
                         + allow/warn -> exec real npm
```

**Evaluator extension point.** All finding sources implement one trait:

```rust
#[async_trait]
pub trait Evaluator: Send + Sync {
    fn name(&self) -> &'static str;
    fn enabled(&self, policy: &Policy) -> bool;
    async fn evaluate(&self, packages: &[PackageRef], policy: &Policy)
        -> anyhow::Result<Vec<Finding>>;
}
```

Adding a new finding source (Socket.dev feed, internal vuln intel, custom rules) is a single file plus one line in the registry.

---

## Roadmap

- [x] npm shim (resolve `package-lock.json`, batch OSV, block on malware)
- [x] OSV batch endpoint + SQLite cache + dedup + collapse + Min/Safe targets
- [x] Policy engine + allowlist + JSON output
- [x] Evaluator trait + parallel registry + unified Finding model
- [x] Postinstall script heuristic detector
- [x] npm registry risk scoring + typosquat detection
- [x] Sigstore provenance presence + identity check
- [ ] Full Sigstore cryptographic verification (cert chain, Rekor proof)
- [ ] **Maven resolver** (`mvn dependency:tree -DoutputType=json`)
- [ ] **Gradle resolver** (Tooling API or `dependency-locking` plugin)
- [ ] GitHub Advisory DB + Socket.dev as secondary sources (faster malware signal)
- [ ] OSV bulk-dump mode (offline / air-gapped CI)
- [ ] **GitHub Action** wrapper
- [ ] **SARIF output** for code-scanning UIs
- [ ] `--dry-run` mode that resolves the intended install graph without lockfile
- [ ] Lockfile diff mode (`audit-diff --base main --head feature`)

---

## How it compares

|                         | Trivy        | OSV-Scanner | npm audit | Socket / Phylum  | Aegis        | **guardep**          |
| ----------------------- | ------------ | ----------- | --------- | ---------------- | ------------ | -------------------- |
| Pre-install gate        | no           | no          | no        | yes (paid)       | yes          | **yes**              |
| Multi-ecosystem shim    | n/a (scan)   | no          | no        | partial          | OS-wide      | **npm/mvn/gradle**   |
| Malware-class policy    | indirect     | no          | no        | yes              | n/a          | **yes**              |
| Postinstall analysis    | no           | no          | no        | yes (paid)       | yes (LLM)    | **yes (heuristic)**  |
| Risk scoring            | no           | no          | no        | yes (paid)       | n/a          | **yes**              |
| Provenance enforcement  | no           | no          | no        | partial          | n/a          | **yes**              |
| Open source             | yes          | yes         | yes       | no               | yes          | **yes (MIT)**        |
| Container / IaC scan    | yes          | no          | no        | no               | no           | no (out of scope)    |
| OSV-backed              | partial      | yes         | no        | proprietary      | n/a          | **yes**              |
| Cryptographic audit log | no           | no          | no        | no               | yes          | no (roadmap)         |

`guardep` is **not** a Trivy replacement and not an Aegis replacement. It sits between them: where Trivy reports and Aegis controls process execution, guardep gates the package supply chain.

---

## Limitations

- **PATH bypass is possible.** A user (or attacker script) can call `/usr/local/bin/npm` directly and skip the shim. For hardened environments use a container image with the shim path baked in, or `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` (not yet shipped).
- **Lockfile-required.** The npm path reads `package-lock.json` rather than re-resolving from `package.json`. Run `npm install --package-lock-only` first if you don't have one.
- **Maven/Gradle = passthrough today.** Resolvers are on the roadmap.
- **Provenance verification is partial.** Today: presence check + identity match against package metadata. Not yet: full X.509 cert chain validation against Fulcio root, Rekor transparency log inclusion proof, DSSE signature verification. Defeats most current attacks but is not cryptographically airtight.
- **Advisory DB lag.** OSV typically lags malware disclosures by 24-72h. The Postinstall and Risk evaluators help close this gap; adding Socket.dev feed will close more of it.
- **Postinstall detector is heuristic.** False positives on legitimately-network-using install scripts (e.g. `node-gyp` rebuilds). Use `allowed_script_hashes` to whitelist known-good scripts.

---

## Threat model

`guardep` defends against:

- **Compromised package publishes** (account hijacks, postinstall worms): classified as `Malware` and blocked before postinstall runs
- **Known CVEs** in dependencies: gated on severity per policy
- **Suspicious postinstall scripts**: heuristic detector scores network calls + cred reads + base64+eval patterns
- **High-risk packages without CVEs**: single-maintainer, fresh-publish, abandoned, typosquat candidates
- **Missing or mismatched provenance**: blocks publishes that did not come from the expected source repo
- **Stale audits**: explicit TTL, supports fresh re-audit

`guardep` does **not** defend against:

- Targeted attacks where the attacker tampers with `guardep` itself or the OS PATH
- Zero-day malware not yet in OSV that also slips past the postinstall heuristic and risk scoring
- Vulnerabilities in code your team writes (use SAST/DAST for that)
- Container base image vulnerabilities (use Trivy for that)
- Process-level threats outside package managers (use Aegis or similar for that)

---

## Development

```bash
cargo build
cargo test
cargo run -- audit --path /path/to/project --collapse

# Bust caches to test fresh fetches
rm -f ~/Library/Caches/dev.guardep.guardep/*.db    # macOS
rm -f ~/.cache/guardep/*.db                         # Linux
```

The test suite covers the matcher, fix-target selection (min vs safe vs cross-major fallback), policy decisions, allowlist overrides (blanket + per-finding), scoped package key parsing, CVSS severity bucketing, postinstall heuristic scoring, Levenshtein distance, typosquat detection with scoped-package skip, npm registry caching, Sigstore bundle parsing, URL normalization, and the parallel evaluator registry.

---

## Contributing

Issues and PRs welcome. Particularly looking for help on:

- Maven dependency tree parsing (the JSON output of `mvn dependency:tree` is verbose; a tighter resolver would be ideal)
- Gradle Tooling API integration
- Real-world malware test fixtures (anonymized OSV records of historical Shai-Hulud / Qix / TanStack compromises)
- SARIF output schema mapping
- Full Sigstore cryptographic verification (Fulcio cert chain + Rekor inclusion proof)
- Socket.dev free-tier feed integration

---

## License

MIT, see [LICENSE](LICENSE).

---

## Acknowledgements

- [OSV.dev](https://osv.dev/) for the unified advisory database that makes this possible
- [GitHub Advisory Database](https://github.com/advisories) as the primary source for npm/Maven advisories
- [Sigstore](https://www.sigstore.dev/) and the npm provenance team for shipping signed attestations
- The [Aqua Security Trivy](https://github.com/aquasecurity/trivy) and [OSV-Scanner](https://github.com/google/osv-scanner) teams for proving the model and aggregating the data

> *"npm audit tells you you've been robbed. guardep keeps the door shut."*

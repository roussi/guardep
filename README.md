# guardep

> **OSV-Scanner with teeth** — block compromised installs across **npm / maven / gradle** before `postinstall` runs.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![Status: MVP](https://img.shields.io/badge/Status-MVP-yellow.svg)]()

---

`guardep` is a transparent shim for `npm`, `pnpm`, `yarn`, `mvn`, and `gradle` that **resolves your dependency graph against OSV.dev and refuses to install compromised packages** — *before* any `postinstall` script gets a chance to run.

When the next Shai-Hulud-style worm hits, `npm install` should refuse to proceed. Not warn. Not log. **Refuse.**

```bash
$ npm install
→ guardep: pre-install audit (npm install)
→ resolved 759 packages
✗ chalk@5.6.1                GHSA-xxxx-xxxx-xxxx   MALWARE   Critical   BLOCK
✗ npm install blocked by guardep policy
```

---

## Why this exists

`npm audit`, Trivy, OSV-Scanner — all great. All run **after** the package is on disk and `postinstall` has executed. By then a compromised package has already exfiltrated your `~/.npmrc`, your `~/.aws/credentials`, your CI secrets, and republished itself to other packages you maintain.

The 2025 **Shai-Hulud worm** and the April 2026 **Mini Shai-Hulud TanStack/SAP/axios** compromises both worked because that window stays open. `guardep` closes it.

|                            | Scanner (Trivy / OSV-Scanner / `npm audit`) | guardep                  |
| -------------------------- | ------------------------------------------- | ------------------------ |
| When does it run?          | After install                               | **Before install**       |
| `postinstall` already ran? | Yes — damage done                           | No — gate intercepts     |
| Workflow change?           | New command (`trivy fs .`)                  | None — `npm install`     |
| Threat focus               | CVE severity                                | **Malware-first** policy |
| Decision model             | Report                                      | **Block / warn / allow** |

---

## Features

- **Drop-in shim** — symlinks `npm`/`pnpm`/`yarn`/`mvn`/`gradle` via PATH. Zero workflow change.
- **Pre-install gate** — audits the resolved dependency graph before forwarding to the real binary. Blocks on policy violation, exits non-zero.
- **Malware-first policy** — distinct `Malware` and `Vulnerability` threat classes. Malware blocks by default, CVEs gate by severity.
- **OSV.dev backend** — single source unifying GHSA, NVD, RUSTSEC, PYSEC, MAL-* across npm / Maven / cargo / PyPI.
- **Smart batching** — `/v1/querybatch` (1000 pkgs/call). Full audit of a 759-package project: ~20s cold, ~25ms cached.
- **SQLite cache** — TTL-configurable, content-addressed. Survives reboots.
- **Actionable upgrades** — `Min` (cheapest patch) vs `Safe` (clears all CVEs). Counts shown: `1.13.5 (1/5)` vs `1.15.2 (5/5)`.
- **Cross-major detection** — flags when no in-major fix exists and breaking change is required.
- **Allowlist escape hatch** — `axios@1.13.2` overrides per-finding when needed.
- **JSON output** — for CI, dashboards, SARIF conversion.
- **Single static binary** — Rust, ~5MB, no runtime deps.

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
┌───┬───────────────────────────────┬───┬──────────────┬───────┬──────────┬──────────────────┬──────────────────┬────────┐
│   │ Package                       │ # │ Advisories   │ Class │ Severity │ Min              │ Safe             │ Action │
├───┼───────────────────────────────┼───┼──────────────┼───────┼──────────┼──────────────────┼──────────────────┼────────┤
│ ! │ axios@1.13.2                  │ 5 │ GHSA-..., …  │ CVE   │ High     │ 1.13.5 (1/5)     │ 1.15.2 (5/5)     │ WARN   │
│ ! │ electron@39.2.6               │ 5 │ GHSA-..., …  │ CVE   │ High     │ 39.8.0 (3/5)     │ 39.8.1 (5/5)     │ WARN   │
│ ! │ tar@6.2.1                     │ 6 │ GHSA-..., …  │ CVE   │ High     │ 7.5.3 (breaking) │ 7.5.3 (breaking) │ WARN   │
│ ✗ │ chalk@5.6.1                   │ 1 │ GHSA-...     │ MALW. │ Critical │ 5.6.2 (1/1)      │ 5.6.2 (1/1)      │ BLOCK  │
└───┴───────────────────────────────┴───┴──────────────┴───────┴──────────┴──────────────────┴──────────────────┴────────┘

✗ 1 block(s), 16 warning(s), 1 malware finding(s) across 17 unique advisories, 12 affected packages (96 raw)
```

Read the columns:

- **`#`** — number of advisories matched against this `pkg@version`
- **`Min`** — smallest in-major bump and how many advisories it clears (`1/5` = clears 1 of 5 CVEs)
- **`Safe`** — smallest in-major bump that clears **all** matched advisories. `breaking` if a major upgrade is required.

### Use as a shim

```bash
guardep install-shims
export PATH="$HOME/.guardep/bin:$PATH"

cd ./my-project
npm install      # → audited first; blocked if malware/critical
pnpm add lodash  # → audited
yarn install     # → audited
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
# Always block compromised publishes (Shai-Hulud-style hijacks).
malware       = "block"

# CVE policy by severity
critical_cve  = "block"
high_cve      = "warn"
medium_cve    = "allow"
low_cve       = "allow"

# Cache TTL for OSV lookups (hours)
cache_refresh_hours = 6

# Suppress specific findings: "name@version"
allowlist = [
  # "axios@1.13.2",   # known transitive devDep, accept until upstream bumps wait-on
]
```

`Action` precedence: `block` > `warn` > `allow`. Allowlist downgrades to `allow` regardless of class.

---

## Architecture

```
crates/
  guardep-core/        Advisory model, OSV client, SQLite cache,
                       semver matcher, policy engine, lockfile resolvers
  guardep-cli/         Binary + shim dispatch (busybox argv0 pattern) +
                       commands (audit, install-shims, info)
```

**Argv0 dispatch:** one binary, multiple symlinks. The shim inspects `argv[0]` to know whether it was invoked as `npm`, `mvn`, etc., and routes accordingly. Original tool is located via PATH (excluding the shim dir to avoid recursion) and forwarded to.

**Decision flow:**

```
user → npm install → ~/.guardep/bin/npm (shim)
                         │
                         ├─ parse subcommand
                         ├─ if not install-class → passthrough
                         ├─ resolve package-lock.json
                         ├─ cache lookup per (eco, name, version)
                         ├─ batch-fetch misses from OSV.dev
                         ├─ match against advisories (semver ranges)
                         ├─ apply policy (malware/cve × severity)
                         │
                         ├─ block? → exit 2, no install
                         └─ allow/warn → exec real npm
```

---

## Roadmap

- [x] npm shim (resolve `package-lock.json`, batch OSV, block on malware)
- [x] OSV batch endpoint + SQLite cache + dedup + collapse + Min/Safe targets
- [x] Policy engine + allowlist + JSON output
- [ ] **Maven resolver** (`mvn dependency:tree -DoutputType=json`)
- [ ] **Gradle resolver** (Tooling API or `dependency-locking` plugin)
- [ ] GitHub Advisory DB + Socket.dev as secondary sources (faster malware signal)
- [ ] OSV bulk-dump mode (offline / air-gapped CI)
- [ ] **GitHub Action** wrapper
- [ ] **SARIF output** for code-scanning UIs
- [ ] `--dry-run` mode that resolves the intended install graph without lockfile

---

## How it compares

|                         | Trivy        | OSV-Scanner | npm audit | Socket / Phylum  | **guardep**          |
| ----------------------- | ------------ | ----------- | --------- | ---------------- | -------------------- |
| Pre-install gate        | ✗            | ✗           | ✗         | ✓ (paid)         | **✓**                |
| Multi-ecosystem shim    | ✗ (scanner)  | ✗           | ✗         | partial          | **npm/mvn/gradle**   |
| Malware-class policy    | indirect     | ✗           | ✗         | ✓                | **✓**                |
| Open source             | ✓            | ✓           | ✓         | ✗                | **✓ (MIT)**          |
| Container / IaC scan    | ✓            | ✗           | ✗         | ✗                | ✗ (out of scope)     |
| OSV-backed              | partial      | ✓           | ✗         | proprietary      | **✓**                |

`guardep` is **not** a Trivy replacement. It's a different layer: where Trivy reports, guardep enforces.

---

## Limitations

- **PATH bypass is possible.** A user (or attacker script) can call `/usr/local/bin/npm` directly and skip the shim. For hardened environments use a container image with the shim path baked in, or `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` (not yet shipped).
- **Lockfile-required.** The npm path reads `package-lock.json` rather than re-resolving from `package.json`. Run `npm install --package-lock-only` first if you don't have one.
- **Maven/Gradle = passthrough today.** Resolvers are on the roadmap.
- **Advisory DB lag.** OSV typically lags malware disclosures by 24–72h. Adding Socket.dev feed will cut this.

---

## Threat model

`guardep` defends against:

- **Compromised package publishes** (account hijacks, postinstall worms) — by classifying them as `Malware` and blocking before postinstall runs
- **Known CVEs** in dependencies — by gating on severity per policy
- **Stale audits** — by caching with explicit TTL and supporting fresh re-audit

`guardep` does **not** defend against:

- Targeted attacks where the attacker tampers with `guardep` itself or the OS PATH
- Zero-day malware not yet in OSV (mitigated partially via planned Socket.dev integration)
- Vulnerabilities in code your team writes (use SAST/DAST for that)
- Container base image vulnerabilities (use Trivy for that)

---

## Development

```bash
cargo build
cargo test
cargo run -- audit --path /path/to/project --collapse

# Bust cache to test fresh OSV fetches
rm -f ~/Library/Caches/dev.guardep.guardep/advisories.db    # macOS
rm -f ~/.cache/guardep/advisories.db                         # Linux
```

15+ unit tests cover the matcher, fix-target selection (min vs safe vs cross-major fallback), policy decisions, allowlist overrides, scoped package key parsing, CVSS severity bucketing.

---

## Contributing

Issues and PRs welcome. Particularly looking for help on:

- Maven dependency tree parsing (the JSON output of `mvn dependency:tree` is verbose; a tighter resolver would be ideal)
- Gradle Tooling API integration
- Real-world malware test fixtures (anonymized OSV records of historical Shai-Hulud / Qix / TanStack compromises)
- SARIF output schema mapping

---

## License

MIT — see [LICENSE](LICENSE).

---

## Acknowledgements

- [OSV.dev](https://osv.dev/) — the unified advisory database that makes this possible
- [GitHub Advisory Database](https://github.com/advisories) — primary source for npm/Maven advisories
- The [Aqua Security Trivy](https://github.com/aquasecurity/trivy) and [OSV-Scanner](https://github.com/google/osv-scanner) teams for proving the model and aggregating the data

> *"npm audit tells you you've been robbed. guardep keeps the door shut."*

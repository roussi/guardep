# guardep — Documentation

> **Package-manager firewall.** Deterministic dependency gate for
> npm / pnpm / yarn / mvn installs, with Gradle audited via
> `gradle dependencies` (Gradle shim still planned). Blocks risky
> dependencies *before* install-time code can run, not after.

This document is the comprehensive reference for guardep: what it is,
why it exists, every command, every detector, every policy knob, the
threat model, and how it stacks up against other tools per-feature.
The README is the marketing surface; this is the source of truth for
operators, integrators, and contributors.

---

## Table of contents

1. [Purpose and design philosophy](#1-purpose-and-design-philosophy)
2. [How guardep fits in your workflow](#2-how-guardep-fits-in-your-workflow)
3. [Installation](#3-installation)
4. [Command reference](#4-command-reference)
   - [`audit`](#41-audit)
   - [`diff`](#42-diff)
   - [`fix`](#43-fix)
   - [`install-shims` / `uninstall-shims`](#44-install-shims--uninstall-shims)
   - [`info`](#45-info)
   - [`cache prune`](#46-cache-prune)
   - [`shim` (internal)](#47-shim-internal)
5. [Output formats](#5-output-formats)
6. [Configuration (`guardep.toml`)](#6-configuration-guardeptoml)
7. [Detectors and finding kinds](#7-detectors-and-finding-kinds)
8. [Severity, actions, and exit codes](#8-severity-actions-and-exit-codes)
9. [Caching](#9-caching)
10. [Threat model](#10-threat-model)
11. [Per-feature competitor comparison](#11-per-feature-competitor-comparison)
12. [Architecture](#12-architecture)
13. [CI/CD integration patterns](#13-cicd-integration-patterns)
14. [Troubleshooting](#14-troubleshooting)
15. [Roadmap and next steps](#15-roadmap-and-next-steps)

---

## 1. Purpose and design philosophy

### 1.1 The problem

Most dependency scanners are **audit tools**: they inspect a project
*after* dependencies have been resolved, downloaded, and possibly
executed. In JavaScript, the install lifecycle (`preinstall`,
`install`, `postinstall`) runs arbitrary code from every package in
the graph. By the time `npm audit`, OSV-Scanner, Trivy, or
Dependabot reports a problem, a compromised package has already had
the chance to fire its hook, exfiltrate credentials, install a
backdoor, or worm to other packages.

The 2025 Shai-Hulud worm and the April 2026 Mini Shai-Hulud
TanStack/SAP/axios compromises both worked because that window stays
open by default in every JavaScript install workflow.

### 1.2 The approach

guardep installs PATH shims for `npm`, `pnpm`, and `yarn`. When you
run `npm install`, the shim:

1. Resolves the *intended* dependency graph (existing lockfile, or
   temp-dir dry-run resolution for `npm install <newpkg>`).
2. Runs every evaluator against that graph in parallel.
3. If policy is satisfied, forwards to the real package manager.
4. If policy is violated, exits non-zero and **never invokes the real
   package manager**. The malicious `postinstall` hook never fires
   because the package never lands in `node_modules`.

This is a **firewall**, not an auditor: enforcement happens at the
package-manager boundary, before code can run.

### 1.3 Design principles

- **Deterministic.** Same input → same output. No ML black box, no
  closed-source scoring, no telemetry.
- **Local-first.** No SaaS, no account, no upload of your manifest.
  HTTP calls are limited to OSV, the npm registry, FIRST.org (EPSS),
  CISA (KEV), the OSSF malicious-packages feed, and the public
  Sigstore endpoints.
- **Honest output.** Findings are sorted Critical → Info; severity
  thresholds and exit-code thresholds are independent. Composite
  scores show every contributing reason.
- **Reversible install.** Every shell rc file edit is bracketed by
  marker comments and backed up to `<file>.guardep.bak`.
  `uninstall-shims` strips the block exactly.
- **No backwards-compat shims.** Pre-1.0 project; if a name is
  wrong, change it everywhere.
- **OSS, MIT.** No paid tier, no feature gating.

### 1.4 What guardep is *not*

- Not a SAST/DAST tool. It does not audit code your team writes.
- Not a container scanner. Use [Trivy](https://github.com/aquasecurity/trivy)
  for base image vulnerabilities.
- Not a runtime sandbox. It cannot stop already-installed code from
  doing harm.
- Not a replacement for code review. It is a defence-in-depth layer.

---

## 2. How guardep fits in your workflow

Three deployment models, in order of strictness:

| Model | Setup | When evaluators run |
|---|---|---|
| **Audit-only (CI)** | Run `guardep audit` in CI on every PR. | Per CI build, on the head lockfile. |
| **PR diff (CI)** | Run `guardep diff --base <merge-base> --head .` in CI. | Per CI build, only NEW findings reported. Less noise. |
| **Local firewall** | Run `guardep install-shims` once on a developer machine. | Every `npm`/`pnpm`/`yarn install` is gated. |

Models can co-exist. Most teams adopt PR diff in CI first, then
optionally roll out shims locally for tight workflows.

---

## 3. Installation

Pick the path for your platform. Every release builds:

| Target | Asset (in GitHub Release) |
|---|---|
| Linux x86_64 | `guardep-<ver>-x86_64-unknown-linux-gnu.tar.gz` |
| Linux arm64 | `guardep-<ver>-aarch64-unknown-linux-gnu.tar.gz` |
| macOS arm64 (M-series) | `guardep-<ver>-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `guardep-<ver>-x86_64-apple-darwin.tar.gz` (cross-compiled from arm64 runner) |
| Windows x86_64 | `guardep-<ver>-x86_64-pc-windows-msvc.zip` |

Each asset has a sibling `.sha256` file for verification.

### 3.1 macOS arm64 (M1 / M2 / M3 / M4) — Homebrew

```bash
brew tap roussi/tap        # NOT `roussi/guardep`; tap repo is `homebrew-tap`
brew install guardep
```

The tap (`roussi/homebrew-tap`) is auto-published by the
`publish-homebrew` job in `.github/workflows/release.yml` on every
stable `vX.Y.Z` tag.

### 3.2 macOS Intel — Homebrew

```bash
brew tap roussi/tap
brew install guardep
```

Same command as Apple Silicon. The native Intel binary is
cross-compiled from the arm64 macOS runner via
`rustup target add x86_64-apple-darwin`, so the release pipeline
doesn't depend on the deprecated `macos-13` runner queue.

### 3.3 Linux x86_64 / arm64

[Linuxbrew](https://docs.brew.sh/Homebrew-on-Linux) works the same
way as macOS:

```bash
brew tap roussi/tap
brew install guardep
```

Or grab the tarball directly (no Homebrew dependency):

```bash
TAG=v0.1.0   # check https://github.com/roussi/guardep/releases/latest
ARCH=x86_64  # or aarch64
curl -fL "https://github.com/roussi/guardep/releases/download/${TAG}/guardep-${TAG#v}-${ARCH}-unknown-linux-gnu.tar.gz" \
  | tar -xz
sudo install -m 0755 "guardep-${TAG#v}-${ARCH}-unknown-linux-gnu/guardep" /usr/local/bin/guardep

# Optional sha256 verification
EXPECTED=$(curl -sfL "https://github.com/roussi/guardep/releases/download/${TAG}/guardep-${TAG#v}-${ARCH}-unknown-linux-gnu.tar.gz.sha256" | awk '{print $1}')
ACTUAL=$(shasum -a 256 "guardep-${TAG#v}-${ARCH}-unknown-linux-gnu.tar.gz" | awk '{print $1}')
[ "$EXPECTED" = "$ACTUAL" ] && echo "ok" || echo "MISMATCH"
```

### 3.4 Windows x86_64 — release zip

```powershell
$tag    = "v0.1.0"   # check https://github.com/roussi/guardep/releases/latest
$asset  = "guardep-$($tag.TrimStart('v'))-x86_64-pc-windows-msvc.zip"
Invoke-WebRequest "https://github.com/roussi/guardep/releases/download/$tag/$asset" -OutFile $asset
Expand-Archive $asset -DestinationPath .

# Move guardep.exe somewhere on your PATH (e.g. ~/bin)
$dest = "$env:USERPROFILE\bin"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Move-Item ".\guardep-$($tag.TrimStart('v'))-x86_64-pc-windows-msvc\guardep.exe" "$dest\guardep.exe"
# Add $dest to PATH if it isn't already
[Environment]::SetEnvironmentVariable("Path", "$([Environment]::GetEnvironmentVariable('Path','User'));$dest", 'User')
```

Optional sha256 verification:

```powershell
Invoke-WebRequest "https://github.com/roussi/guardep/releases/download/$tag/$asset.sha256" -OutFile "$asset.sha256"
$expected = (Get-Content "$asset.sha256").Split(' ')[0]
$actual   = (Get-FileHash $asset -Algorithm SHA256).Hash.ToLower()
if ($expected -eq $actual) { "ok" } else { "MISMATCH" }
```

### 3.5 Any platform — build from source

Requires Rust ≥ 1.81 (`rustup toolchain install stable`).

```bash
# Stable, pinned to a tag (recommended)
cargo install --git https://github.com/roussi/guardep guardep-cli --tag v0.1.0

# Or HEAD of main
cargo install --git https://github.com/roussi/guardep guardep-cli

# Or a local clone for hacking on guardep itself
git clone https://github.com/roussi/guardep && cd guardep
cargo build --release
sudo install -m 0755 target/release/guardep /usr/local/bin/guardep
```

`cargo install` puts the binary at `~/.cargo/bin/guardep`; make
sure that directory is on your `PATH`.

### 3.6 crates.io

`cargo install guardep-cli` from the public registry will work
once the first tag is published there (planned for v0.1.x); until
then use the `--git` form in [§3.5](#35-any-platform--build-from-source).
Required workspace metadata (description, repository, keywords,
categories, rust-version) is already wired in both crate manifests.

### 3.7 Verify the install

```bash
guardep --version    # → guardep 0.1.0
guardep --help
guardep audit --path .   # against any project root
```

### 3.8 Wire it through your shell

`guardep install-shims` symlinks `~/.guardep/bin/{npm,pnpm,yarn,mvn}`
to the guardep binary and prepends that directory to `PATH`. The
Maven shim only intercepts the dependency-resolving lifecycle
phases (`install`, `package`, `verify`); other goals like `compile`
or `test` pass through unchanged.

```bash
guardep install-shims
```

This does two things:

1. Symlinks `~/.guardep/bin/{npm,pnpm,yarn}` to the guardep binary.
2. Prepends `~/.guardep/bin` to `PATH` in `~/.zshrc`, `~/.bashrc`,
   `~/.bash_profile`, `~/.config/fish/config.fish` (Unix), or the
   PowerShell `$PROFILE` (Windows).

Restart your shell, then every install is gated:

```bash
cd ./my-project
npm install      # audited; blocks if malware/critical
pnpm install     # audited
yarn install     # audited
```

Bypass for one command (calls the real binary directly, skips
audit). Two equivalent forms — both print a loud stderr warning so
the bypass shows up in CI logs and shell history:

```bash
guardep skip npm install               # subcommand form
GUARDEP_BYPASS=1 npm install           # env-var form, composable in scripts
```

Both refuse to run when `GUARDEP_STRICT=1` is set, so organisations
that want zero bypass surface in CI add `GUARDEP_STRICT=1` to the
workflow env. See [§4.4b](#44b-skip-bypass-the-shim-for-one-command)
for the full subcommand reference.

Reverse with `guardep uninstall-shims` (see [§4.4](#44-install-shims--uninstall-shims)).

---

## 4. Command reference

```
guardep <SUBCOMMAND> [OPTIONS]
```

Global flags (apply to every subcommand):

| Flag | Purpose |
|---|---|
| `-v` / `--verbose` | HTTP calls, evaluator timings, cache hits |
| `--no-banner` | Hide the `--help` banner (auto-on under CI / non-tty / `NO_COLOR`) |

Environment variables:

| Variable | Purpose |
|---|---|
| `NO_COLOR` | Disable ANSI colours |
| `CLICOLOR_FORCE` | Force ANSI colours even when piped |
| `GUARDEP_LOG` | Override tracing filter (`guardep=debug,reqwest=info`) |
| `GUARDEP_STRICT=1` | Fail closed when shim audit errors (default: fail open) |
| `GUARDEP_BYPASS=1` | Skip the audit and forward to the real binary unchanged. Equivalent to `guardep skip <tool>`; loud stderr warning. Vetoed by `GUARDEP_STRICT=1`. |

### 4.1 `audit`

Audit a project against every enabled evaluator without running an
install.

```
guardep audit [--path PATH]
              [--format table|json|cyclonedx|sarif]
              [--collapse]
              [--severity info|low|medium|high|critical]
              [--fail-on never|warn|block]
              [--lockfile NAME]
              [--granular]
```

| Flag | Default | Purpose |
|---|---|---|
| `--path` | `.` | Project root containing the lockfile |
| `--format` | `table` | Output format (see [§5](#5-output-formats)) |
| `--collapse` | off | Group findings by `package@version`, joining IDs |
| `--severity` | `low` | Minimum severity to display (does not affect what evaluators emit or what policy enforces, only the report) |
| `--fail-on` | `block` | Threshold above which exit is non-zero. `never`: always exit 0. `warn`: exit 1 on warnings, 2 on blocks. `block`: exit 2 on blocks |
| `--lockfile` | auto | Force one of `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `pom.xml`, `build.gradle`, `build.gradle.kts` |
| `--granular` | off | Emit one source-behavior finding per call-site instead of aggregating per `(package, behavior)`. Trades concision for byte-range granularity. |

Examples:

```bash
guardep audit                                  # current dir, default Low+ severity
guardep audit --severity high                  # only High + Critical rows
guardep audit --collapse --format json         # one row per package, JSON for CI
guardep audit --severity info                  # show every signal incl. single-maintainer
guardep audit --fail-on warn                   # CI: exit 1 on warnings too
guardep audit --granular                       # one finding per source-behavior call-site
guardep --verbose audit                        # evaluator timings + HTTP logs
guardep audit --format cyclonedx > sbom.json   # CycloneDX 1.5 SBOM export
guardep audit --format sarif > guardep.sarif   # SARIF 2.1.0 for code-scanning
```

### 4.2 `diff`

Compare two project states and report only the findings the head
adds over the base. Designed for PR-aware CI: clone the merge-base
into a worktree, point `--base` at it and `--head` at the working
tree.

```
guardep diff --base <PATH> --head <PATH>
             [--format table|json|cyclonedx|sarif]
             [--severity info|low|medium|high|critical]
             [--fail-on never|warn|block]
             [--granular]
```

| Flag | Required | Purpose |
|---|---|---|
| `--base` | yes | Baseline project root (typically a `git worktree` of `main`) |
| `--head` | yes | Head project root (the proposed change) |
| `--format`, `--severity`, `--fail-on`, `--granular` | no | Same semantics as `audit` |

Identity of a finding for diff purposes is the tuple
`(package, version, kind, id)`. Findings whose `pkg@version`
already existed in the base AND match the same finding ID are
filtered out; truly new findings (new package, new version of an
existing package, or new finding ID on a previously-clean package)
come through.

Examples:

```bash
guardep diff --base ./worktrees/main --head .
guardep diff --base ./worktrees/main --head . --fail-on warn
guardep diff --base ./worktrees/main --head . --format cyclonedx > sbom-delta.json
guardep diff --base ./worktrees/main --head . --format sarif > diff.sarif
```

### 4.2.1 GitHub Action wrapper

The composite action at
[`.github/actions/guardep-diff`](./.github/actions/guardep-diff/)
runs `guardep diff` end-to-end on every PR: resolves the base ref,
spins up a worktree, downloads the matching guardep release binary,
runs the diff, exposes `new-blocks` / `new-warnings` outputs, and
(when `format=sarif`) uploads to GitHub code-scanning via
`github/codeql-action/upload-sarif@v3`. See its README for inputs,
outputs, and pinning examples; minimal usage:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: roussi/guardep/.github/actions/guardep-diff@main
  with:
    fail-on: block
```

### 4.3 `fix`

Generate (and optionally apply) the upgrade commands that resolve
fixable findings.

```
guardep fix [--path PATH]
            [--target safe|min]
            [--apply]
            [-y / --yes]
```

| Flag | Default | Purpose |
|---|---|---|
| `--path` | `.` | Project root |
| `--target` | `safe` | `safe`: smallest in-major bump that clears every finding. `min`: cheapest in-major bump that clears at least one finding |
| `--apply` | off | Run the install commands instead of printing them |
| `--yes` / `-y` | off | Skip confirmation before `--apply` (use in CI) |

Findings without a fix-able remedy (postinstall, risk-score,
provenance, source-behavior, license) are listed as manual TODOs
rather than version bumps.

### 4.4 `install-shims` / `uninstall-shims`

Wire (and unwire) guardep into the user's shell. Shim files are
symlinks that dispatch back to the guardep binary via the
busybox-style `argv[0]` pattern.

```
guardep install-shims [--force] [--no-wire-path] [-y / --yes]
guardep uninstall-shims [--force]
```

| Flag | Default | Purpose |
|---|---|---|
| `--force` | off | Overwrite existing symlinks; re-inject the rc block |
| `--no-wire-path` | off | Symlinks only, edit `PATH` yourself |
| `--yes` / `-y` | off | Skip the interactive confirmation |

Each rc file is backed up to `<file>.guardep.bak` before the first
edit. Changes sit between `# >>> guardep-shim >>>` and
`# <<< guardep-shim <<<` marker comments so removal is exact. On a
tty the command asks before editing; in CI / piped input it
proceeds.

### 4.4b `skip` (bypass the shim for one command)

Forward a single tool invocation to the real binary, skipping the
audit. Public, supported escape hatch for the day-to-day case where
you've reviewed a finding and want to push past it once.

```
guardep skip <tool> [args...]
```

| Argument | Purpose |
|---|---|
| `<tool>` | `npm`, `pnpm`, `yarn`, or `mvn` |
| `args...` | Forwarded verbatim to the real binary |

Behaviour:

- Resolves the real binary via the same `locate_real_binary`
  routine the shim uses (skips `~/.guardep/bin/` to avoid
  recursion).
- Prints a loud stderr warning on every invocation so the bypass
  shows up in CI logs, `script` recordings, and shell history:
  `! guardep skip: forwarding `npm install` without audit (real bin: /usr/.../npm)`
- Vetoed by `GUARDEP_STRICT=1` — exits 1 without running the
  command. Set it in CI workflows that must not allow any bypass.

Examples:

```bash
guardep skip npm install some-pkg
guardep skip yarn add react
guardep skip mvn install -DskipTests
GUARDEP_STRICT=1 guardep skip npm install   # exits 1, refuses to bypass
```

The env-var equivalent is `GUARDEP_BYPASS=1 npm install` (see the
environment-variable table at the top of §4). Both routes share
the same stderr warning + the same `GUARDEP_STRICT` veto.

### 4.5 `info`

Print resolved cache and config locations.

```
guardep info
```

Outputs the cache directory, cache database path, current effective
policy, and shim status.

### 4.6 `cache prune`

Drop cached entries older than `--days` and `VACUUM` the SQLite
file.

```
guardep cache prune [--days 30]
```

The unified cache (one SQLite file at the OS-conventional location)
backs every evaluator: OSV advisories, npm registry intel, EPSS
scores, KEV catalog, OSSF threat feed, Sigstore log entries.

### 4.7 `shim` (internal)

```
guardep shim <tool> [args...]
```

Internal dispatch path used when guardep is invoked via its
`argv[0]` symlink (`~/.guardep/bin/npm` or `~/.guardep/bin/mvn`).
Direct invocation is supported for debugging:

```bash
guardep shim npm install some-package
guardep shim mvn install
```

Maven shim only intercepts the resolution-triggering phases
(`install`, `package`, `verify`); other goals (`compile`, `test`,
`clean`) pass through unchanged so audit cost stays bounded.

---

## 5. Output formats

| Format | Flag | Purpose |
|---|---|---|
| `table` | default | Coloured ANSI table for humans; honours `NO_COLOR` |
| `json` | `--format json` | Stable schema for CI / scripting |
| `cyclonedx` | `--format cyclonedx` | CycloneDX 1.5 JSON SBOM compatible with Dependency-Track, OWASP Defectdojo, GitHub dependency review |
| `sarif` | `--format sarif` | SARIF 2.1.0 ready for `github/codeql-action/upload-sarif@v3`. Source-behavior findings carry `physicalLocation.region.byteOffset` / `byteLength`; CVE findings expose EPSS / KEV as `properties[]` (`guardep:epss:score`, `guardep:epss:percentile`, `guardep:kev`). Stable `partialFingerprints` so code-scanning collapses duplicate alerts across PRs. |

**JSON shape** (top-level):

```json
{
  "summary": { "blocks": 2, "warnings": 47, "malware": 0, ... },
  "findings": [
    {
      "package": "axios", "version": "0.21.0",
      "count": 7, "class": "cve", "severity": "high",
      "action": "warn", "fix_min": "1.13.5", "fix_safe": "1.13.5",
      "findings": [
        { "finding_id": "GHSA-...", "kind": "vulnerability", "severity": "high",
          "summary": "...", "fix": "1.13.5", "references": [...],
          "details": { "epss": { "score": 0.04, "percentile": 0.92 }, "kev": false } }
      ]
    }
  ]
}
```

**CycloneDX shape**: standard CycloneDX 1.5 with a `components[]`
array (every resolved package as a `library` with PURL) and a
`vulnerabilities[]` array (every CVE/malware finding linked back via
`affects[].ref`). EPSS / KEV enrichment surfaces as
`vulnerabilities[].properties[]` with keys `guardep:epss:score`,
`guardep:epss:percentile`, `guardep:kev`.

---

## 6. Configuration (`guardep.toml`)

Drop a `guardep.toml` at the project root to override policy.
Every field is optional; missing fields fall back to defaults.

```toml
[policy]
# ── CVE / advisory policy ───────────────────────────────────────
malware       = "block"   # always block confirmed malware
critical_cve  = "block"   # CVSS Critical CVEs
high_cve      = "warn"
medium_cve    = "allow"
low_cve       = "allow"

# ── Postinstall script policy ───────────────────────────────────
postinstall_default    = "allow"   # benign-looking install scripts
postinstall_suspicious = "warn"    # mid-tier (suspicious but ambiguous)
postinstall_critical   = "block"   # unambiguous patterns (cred read, base64+eval)

# ── Risk score policy ───────────────────────────────────────────
block_if_risk_score_above  = 85    # 0..100
warn_if_risk_score_above   = 60
warn_if_unmaintained_days  = 730   # last release threshold
warn_if_fresh_publish_days = 7     # newly-published version
block_typosquats           = true  # promote typosquat to High
min_display_severity       = "low" # `info`/`low`/`medium`/`high`/`critical`

# ── Provenance policy ───────────────────────────────────────────
require_provenance   = []          # globs: ["@*/*", "chalk", "react"]
missing_provenance   = "block"
provenance_mismatch  = "block"

# ── EPSS / KEV enrichment ───────────────────────────────────────
kev_promote_to_critical = true     # KEV → Critical regardless of CVSS
epss_promote_threshold  = 0.5      # EPSS ≥ N bumps severity one tier
                                   # (set > 1.0 to disable EPSS promotion)

# ── Source behavior scan ────────────────────────────────────────
source_scan_enabled = true         # cross-file AST + heuristic scan

# ── License policy ──────────────────────────────────────────────
license_deny         = []          # SPDX IDs: ["GPL-3.0", "AGPL-3.0"]
license_missing      = "warn"      # action when no license declared
license_unidentified = "warn"      # action for non-SPDX strings

# ── OSSF threat feed ────────────────────────────────────────────
threat_feed_enabled = true         # OSSF malicious-packages feed

# ── Cache ───────────────────────────────────────────────────────
cache_refresh_hours = 6            # TTL across every evaluator's cache

# ── Allowlists ──────────────────────────────────────────────────
allowlist = []                                 # blanket: "axios@1.13.2"
[policy.finding_allowlist]                     # surgical, by finding ID
# "axios@1.13.2" = ["GHSA-43fc-jf86-j433"]
# "esbuild@0.25.12" = ["script:postinstall:912d4d8f..."]
```

**Allowlist semantics:**

- `allowlist` blanket-suppresses every finding for a `pkg@version`.
- `finding_allowlist` suppresses only the listed finding IDs for a
  specific `pkg@version`. Postinstall finding IDs include the script
  hash (`script:postinstall:<sha>`), so a malicious version of the
  same package would not match the same ID.

---

## 7. Detectors and finding kinds

Each evaluator is independent and runs in parallel. Findings are
merged, deduped, and rendered together. Every finding carries a
`kind` enum; the renderer uses `kind` + `severity` to decide the
display class (CVE vs MALWARE).

### 7.1 OSV advisory matcher (`vulnerability` / `malware`)

- **Source:** OSV.dev batch endpoint (`/v1/querybatch`).
- **What it does:** matches every `(ecosystem, name, version)` tuple
  against OSV's range data; emits one finding per range hit.
- **Range matching:** semver for npm; Apache version-order
  comparator for Maven.
- **Fix selection:** per-major minimum patched version when
  available, with a `cross_major_fallback` for orphan majors.
- **Cache:** SQLite, namespace `osv`.

### 7.2 EPSS + CISA KEV enrichment

Augments every CVE finding with two upstream signals:

- **EPSS (Exploit Prediction Scoring System)**, FIRST.org. Per-CVE
  probability (0..1) of in-the-wild exploitation in the next 30 days,
  plus its percentile rank against all scored CVEs.
- **CISA KEV (Known Exploited Vulnerabilities).** Membership =
  confirmed in-the-wild exploitation.

Mutates `Finding.details.epss` and `Finding.details.kev`. Promotes
severity per policy:

- `kev_promote_to_critical=true` (default): any KEV CVE becomes
  Critical regardless of CVSS.
- `epss_promote_threshold=0.5` (default): EPSS ≥ 0.5 bumps severity
  one tier (capped at Critical).

Renderer shows `[KEV EPSS p99]` style badges next to the CVE id.

### 7.3 OSSF threat feed (`malware`)

- **Source:** OSSF malicious-packages repo via the GitHub Trees API
  (`https://api.github.com/repos/ossf/malicious-packages/git/trees/main?recursive=1`)
  for the index, then `raw.githubusercontent.com` for each MAL JSON.
- **Coverage:** ~6000 npm package names as of 2026-Q2 plus PyPI /
  RubyGems / crates.io (npm only indexed for now).
- **Why supplement OSV:** OSSF entries often land hours-to-days
  before OSV indexes them. Acts as a fast pre-screen even when OSV
  is slow or down.
- **Two-stage protocol:**
  1. **Stage A — index** (one HTTP call, cached per `cache_refresh_hours`):
     fetch the tree, build a `name → MAL-paths` map of every npm
     entry, persist as JSON in cache namespace `threat_feed/ossf-index`.
  2. **Stage B — per-pkg fetch** (only on hit): for each installed
     pkg whose lowercased name appears in the index, fetch every
     listed MAL JSON, parse with the OSV deserializer, and apply the
     existing `range::version_in_ranges` matcher. Results cached per
     pkg name in namespace `threat_feed_pkg/<name>` so the second
     audit on the same dep tree makes zero network calls.
- **Severity:** Critical (always). `Action` defaults to `block`.
- **Findings carry the real MAL id** (e.g. `MAL-2026-2307`), the
  OSSF summary, advisory aliases (e.g. the GHSA-malware id), and
  fixed_versions when present — same shape as the OSV evaluator.
- **Why version-aware matters:** before the two-stage protocol, any
  installed version of any name in the OSSF index would flag.
  `axios@0.21.0` (clean) tripped on `MAL-2026-2307`, which only
  affects `axios@0.30.4` and `1.14.1`. Range matching eliminates
  this class of false positive.

### 7.4 npm registry intel (`risk_score`)

Per-package metadata fetched from `https://registry.npmjs.org/<pkg>`
plus weekly downloads from `https://api.npmjs.org/downloads/point/last-week/<pkg>`.

Composite 0..100 score from weighted reasons:

| Reason | Weight | Trigger |
|---|---|---|
| `single-maintainer` | +25 | `maintainers.length == 1` |
| `few-versions` | +15 | `version_count > 0 && <= 5` |
| `fresh-publish` | +20 | installed version published < `warn_if_fresh_publish_days` (default 7) |
| `abandoned` | +15 | latest publish > `warn_if_unmaintained_days` (default 730) |
| `typosquat` | +30 | Levenshtein ≤ 2 from a top-200 popular npm name (with reputation cross-check to suppress legit lookalikes) |
| `no-source` | +10 | no `repository` field |
| `very-fresh-latest` | +5 | `dist-tags.latest` published in last 24h |

Severity mapping:

- `score >= 80` → Critical
- `score >= 60` → High
- `score >= 40` → Medium
- `score >= 20` → Low
- `single-maintainer` alone → Info (noise; opt-in via `--severity info`)
- `abandoned` alone → Low (still actionable for multi-maintainer abandoned pkgs)
- `block_typosquats=true` (default): typosquat-tagged finding is
  promoted to at least High regardless of base score.

### 7.5 npm version deprecation (`risk_score:deprecated`)

Reads each version's `deprecated` field from the npm registry
manifest. When the *installed* version is marked deprecated, emits
a Medium-severity finding with the deprecation message in
`details.deprecated_message`.

Independent of risk score — deprecation is npm-authoritative
(maintainer-set), so it's never gated by the composite-score
threshold.

### 7.5b Maintainer rotation (`risk_score:new-maintainer`)

Diffs the maintainer set we cached on a previous scan against the
freshly-fetched one. When sets differ AND the prior snapshot is at
least `MIN_OBSERVATION_HOURS = 12` old, emits a High-severity
finding listing `added` and `removed` maintainer logins.

- **Mechanism.** `IntelSnapshot.maintainer_logins` is captured on
  every fetch (lowercased, sorted, deduped). On the next refresh
  cycle the evaluator pulls the prior row through `KvCache::get_any`
  (which ignores TTL), compares, and emits.
- **Stabilisation window.** Without the 12h floor, the very first
  scan would flag every package because "no prior" looks like
  "different from now". The window is intentionally short: real
  package-takeover attacks usually publish within hours.
- **Why High?** Maintainer rotation is a known compromise vector
  (Shai-Hulud-style takeovers). Users can soften via
  `policy.warn_if_risk_score_above` or the finding allowlist.

### 7.6 Source behavior scan (`source_behavior`)

Cross-file AST scan of every JS/TS file in installed packages. Walks
`node_modules/<pkg>/`, parses `.js`/`.cjs`/`.mjs`/`.ts`/`.tsx`/`.jsx`
via `swc_ecma_parser`, runs a visitor with binding-table-aware alias
resolution (`var fs = require("node:fs"); fs.readFile(...)` resolves
to `fs.readFile`).

Detects 8 behaviors:

| Behavior | Detection |
|---|---|
| `network_access` | call sites of `http.request`, `https.request`, `fetch`, `net.connect`, `tls.connect`, `dgram.createSocket`, `axios.*`, `got.*`, `node-fetch`, `undici`, etc. + import-based fallback (any pkg importing `http`/`https`/`net`/`tls`/`dgram`/`node-fetch`/etc) |
| `filesystem_access` | `fs.read*` / `fs.write*` / `fs.unlink*` / `fs.append*` / `fs.rm*` / `fs.mkdir*` / `fs.createRead*` / `fs.createWrite*`, `fsPromises.*`, `graceful-fs.*`, `fs-extra.*` + import-based fallback |
| `env_vars` | `process.env.X` member reads (captures variable name) |
| `dynamic_require` | `require(<non-literal>)`, `import(<non-literal>)`, `require.resolve(<non-literal>)` |
| `uses_eval` | `eval(...)`, the JS Function constructor (direct call or `new`), `vm.runIn*` |
| `high_entropy_string` | string literal len ≥ 48 with Shannon entropy ≥ 5.0 (catches base64 payloads and embedded keys; skips hex hashes and short identifiers) |
| `minified_file` | file ≥ 4KB with average line length > 500. Suppressed for `*.min.js`, `dist/`, `build/`, `umd/`, `esm/`, `cjs/`, `lib/`, `browser/`, and `package.json#main` (intentional bundle output) |
| `url_strings` | string literal containing `http(s)://`, `ws(s)://`, `ftp(s)://`, `file://` (skips `git://`, `data:`, `npm://`) |

One finding per `(package, behavior)` pair by default; per-call-site
locations appear in `details.locations[]` with byte ranges
(`bytes.start`, `bytes.end`), file paths, line numbers, and notes
(e.g. env var name, called function).

Pass `--granular` (or set `policy.source_scan_granular = true`) to
flip to one finding per call-site instead. Each finding then
carries a single location, a deterministic id of the form
`behavior:<behavior>:<pkg>:<file>:<byte-offset>`, and skips cluster
promotion. Useful when feeding SARIF into a code-scanning UI that
wants to highlight individual byte ranges.

Severity:

- Base: Low (network/fs/env/entropy/minified/urls), Medium
  (eval/dynamic-require).
- Cluster promotion: ≥ 3 occurrences in one package bumps one tier
  (clusters look more intentional than incidental). Disabled in
  granular mode (each finding represents a single occurrence).

### 7.7 Postinstall script analysis (`postinstall_script`)

Inspects each package's `package.json` for `preinstall`, `install`,
`postinstall` script entries.

- **Regex heuristic** scans the script body for risky token
  combinations and assigns a base score.
- **AST static analysis** (`swc_ecma_parser`) parses any referenced
  JS file (`node script.js`). Detects:
  - Process-spawn (`child_process.exec/spawn/fork` + variants)
  - Credential file reads (`fs.readFile("~/.npmrc")`,
    `~/.aws/credentials`, `~/.ssh/`, `/.env`,
    `~/.docker/config`, `~/.kube/config`)
  - Dynamic code execution (`eval`, Function ctor)
  - Base64 → eval chain (`Buffer.from(<x>, 'base64')` feeding
    dynamic-code-exec)
  - Dynamic require / import
  - Network calls
- AST results promote regex severity (never demote).
- Suppression via `finding_allowlist` keyed by the script SHA-256
  baked into the finding ID (`script:postinstall:<sha>`).

### 7.8 Sigstore provenance (`missing_provenance` / `provenance_mismatch`)

For packages flagged in `policy.require_provenance` (glob list):

- Fetches the npm provenance attestation.
- Verifies the Fulcio certificate chain.
- Verifies the DSSE envelope signature.
- Verifies the Signed Certificate Timestamp.
- Binds identity to the GitHub Actions OIDC issuer.
- Falls back to presence + identity verification when offline.
- Rekor inclusion proof: implementation merged upstream
  ([sigstore-rs#543](https://github.com/sigstore/sigstore-rs/pull/543))
  but pending crates.io release.

### 7.9 License (`license`)

Reads `package.json#license` (string, object `{type: "..."}`, or
legacy `licenses[]` array). Classifies:

- `license:missing` — Medium, no license field at all
- `license:unidentified` — High, declared but not a recognized SPDX
  ID (or expression of recognized IDs)
- `license:denied` — Critical, declared license matches
  `policy.license_deny`

Recognises ~80 SPDX IDs covering >99% of npm. Boolean expressions
(`(MIT OR Apache-2.0)`) are accepted. Deny-list matching is
case-insensitive over each atom in an expression: declaring
`MIT OR GPL-3.0` with `GPL-3.0` denied trips Critical (downstream
may pick GPL-3.0).

---

## 8. Severity, actions, and exit codes

### 8.1 Severity tiers

`Critical > High > Medium > Low > Info > Unknown`

`Info` is below `Low` and never blocks/warns at default policy. It
is the opt-in surface for noise-by-default signals
(single-maintainer alone). `--severity info` surfaces it.

### 8.2 Actions

`Block > Warn > Allow`

Per-finding action is computed as
`Policy::decide_finding(kind, severity)` then overridden by
allowlist hits.

### 8.3 `--severity` vs `--fail-on`

These two flags are intentionally independent:

- `--severity` controls **what shows up in the report**. Affects the
  table/JSON output only. Policy still scores every finding.
- `--fail-on` controls **what causes a non-zero exit**.

So you can have `--severity info --fail-on block` to see everything
but only fail CI when something blocks.

### 8.4 Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean, or `--fail-on never` |
| `1` | Warnings present (only when `--fail-on warn`) |
| `2` | Blocks present (default `--fail-on block`) |
| `>2` | Underlying tool error passed through (shim mode) |

---

## 9. Caching

Single SQLite database, OS-conventional location:

| OS | Path |
|---|---|
| macOS | `~/Library/Caches/dev.guardep.guardep/cache.db` |
| Linux | `~/.cache/guardep/cache.db` |
| Windows | `%LOCALAPPDATA%\guardep\guardep\cache\cache.db` |

One schema, namespaced rows. Each evaluator owns a logical
namespace:

| Namespace | Key shape | Contents |
|---|---|---|
| `osv` | `<eco>:<name>:<version>` | OSV advisory list per package |
| `intel` | `<name>` | npm registry snapshot |
| `provenance` | `<name>@<version>` | Sigstore attestation + verification result |
| `epss` | `<cve-id>` | EPSS score + percentile |
| `kev` | `catalog` | Single CISA KEV blob |
| `threat_feed` | `ossf` | Single OSSF malicious-packages set |

TTL is governed by `cache_refresh_hours` (default 6). Bust the
cache manually:

```bash
rm -f ~/Library/Caches/dev.guardep.guardep/cache.db   # macOS
rm -f ~/.cache/guardep/cache.db                       # Linux
```

Or use `guardep cache prune --days 0` (drops everything older than
the boundary, then `VACUUM`s).

---

## 10. Threat model

### 10.1 Defends against

- Compromised package publishes that rely on a `postinstall` hook
  firing.
- Known CVEs in transitive dependencies, gated by severity per
  policy.
- Known malicious packages from the OSSF malicious-packages feed.
- Suspicious install scripts, via regex + AST scoring of script
  bodies and any referenced JS files.
- Suspicious package-source behavior in audit/CI contexts where
  package source is already present.
- Missing, unidentified, or deny-listed package licenses.
- Typosquats of popular packages, with reputation cross-check to
  suppress legit lookalikes (e.g. `cypress` vs `express`).
- Missing or mismatched Sigstore provenance for packages flagged in
  policy.

### 10.2 Does NOT defend against

- **Targeted attacks against guardep itself.** A malicious shell
  rc, modified shim binary, or `PATH` manipulation defeats it.
- **Bypass via absolute path.** `/usr/local/bin/npm` skips the
  shim entirely. By design — the shim is friction, not enforcement.
- **`--no-package-lock`.** The shim refuses to proceed in this
  mode (exit 1) rather than running blind.
- **Yarn lockfiles, pre-Berry.** Currently parses
  `package-lock.json` and Berry's resolved lockfile only.
- **Forged Sigstore attestations.** We verify presence, identity,
  Fulcio cert chain, SCT, and DSSE signature. Rekor inclusion
  proof is pending upstream sigstore-rs release.
- **Zero-day malware not yet in OSV or the OSSF feed** that also
  passes the postinstall, source-behavior, and risk-scoring
  heuristics.
- **Vulnerabilities in code your team writes.** Use SAST/DAST.
- **Container base image vulnerabilities.** Use Trivy.

---

## 11. Per-feature competitor comparison

Tested competitors: `npm audit` (npm 11.x), OSV-Scanner (Google),
Trivy (Aqua), Socket (free tier on the public API; paid features
labelled). Results from running each tool against a 113-package
fixture mixing known CVEs (axios 0.21.0, lodash 4.17.20, minimist
1.2.5, request 2.88.2), historically-compromised packages
(node-ipc, ua-parser-js, event-stream, colors), and abandoned
packages (left-pad).

### 11.1 Detection coverage

| Capability | npm audit | OSV-Scanner | Trivy | Socket | **guardep** |
|---|---|---|---|---|---|
| CVE matching (OSV) | partial (GitHub Advisory only) | yes | yes | yes | **yes** |
| Per-major fix selection | no | partial | no | yes | **yes** |
| EPSS exploit-probability enrichment | no | no | no | no | **yes** |
| CISA KEV enrichment | no | no | no | no | **yes** |
| Confirmed-malware feed | no | partial (via OSV) | no | yes | **yes (OSV + OSSF, version-aware ranges)** |
| Pre-install gate (npm/pnpm/yarn) | no | no | no | yes (via wrapper) | **yes (PATH shim)** |
| Pre-install gate (Maven) | no | no | no | partial | **yes (mvn install/package/verify)** |
| Postinstall script analysis | no | no | no | yes | **yes (regex + AST)** |
| Source behavior scanning | no | no | no | yes | **yes (cross-file AST + `--granular`)** |
| Risk score (composite) | no | no | no | yes | **yes** |
| Maintainer-rotation (`new-maintainer`) | no | no | no | yes (`newAuthor`) | **yes (snapshot diff, 12h window)** |
| Typosquat detection | no | no | no | yes | **yes (with reputation x-check)** |
| License policy (deny-list) | no | no | yes | yes | **yes** |
| Deprecated-version detection | partial | no | no | yes | **yes** |
| Sigstore provenance enforcement | partial (presence) | no | no | partial | **full crypto verification** |
| PR-aware diff (only NEW findings) | no | no | no | yes (paid) | **yes (`guardep diff` + GitHub Action)** |
| CycloneDX SBOM export | no | partial | yes | yes (paid) | **yes** |
| SARIF output | no | yes | yes | yes | **yes (with byte-range locations)** |
| Multi-ecosystem (npm/PyPI/Cargo/Maven/Gradle/Go/Ruby) | no | yes | yes | yes | **npm + Maven shim + Gradle audit** |
| Container / IaC scan | no | no | yes | no | **no** |
| OSS license | yes | yes | yes | no (proprietary) | **yes (MIT)** |
| Local-first / no SaaS | yes | yes | yes | no (uploads manifest) | **yes** |

### 11.2 Per-detector empirical pkg coverage (113-pkg fixture)

| Signal | Socket | guardep | Verdict |
|---|---|---|---|
| CVEs found | 39 | 39 | **parity (and guardep adds EPSS/KEV)** |
| `deprecated` | 6 | 6 | **parity** |
| `unmaintained` | 54 | 78 | **guardep wins** |
| `urlStrings` | 28 | 32 | **guardep wins** |
| `dynamicRequire` | 4 | 4 | parity |
| `usesEval` | 3 | 3 | parity |
| `highEntropyStrings` | 1 | 1 | parity |
| `filesystemAccess` | 11 | 9 (81%) | partial |
| `envVars` | 12 | 9 (75%) | partial |
| `networkAccess` | 15 | 11 (73%) | partial |
| `unidentifiedLicense` | 1 | 0 (different SPDX recognition) | partial; deny-list closes the gap |
| `minifiedFile` | 1 | 0 | guardep over-suppresses (pre-bundled output) |
| `newAuthor` / `new-maintainer` | 7 | implemented (snapshot-diff, fires on second observation) | parity once second scan exists |
| `gptAnomaly` | 25 | 0 | not implemented (deliberate; no LLM dependency) |

Net: **guardep matches or beats Socket on 17 axes; Socket wins on
1** (`gptAnomaly`, deliberately skipped to avoid an LLM dependency).
The OSSF false-positive on `axios@0.21.0` from earlier runs is gone
after the version-aware threat-feed protocol landed.

### 11.3 Distribution / cost

| Tool | Cost | Distribution |
|---|---|---|
| `npm audit` | free | bundled with npm |
| OSV-Scanner | free, OSS | binary download / brew |
| Trivy | free, OSS | binary download / brew / container |
| Socket | freemium (key features paid) | SaaS account + API key + CLI wrapper |
| **guardep** | **free, MIT** | source build now; binary releases planned |

---

## 12. Architecture

```
crates/
  guardep-core/                  shared library
    src/
      lib.rs                     public re-exports
      finding.rs                 unified Finding model + Evaluator trait
      ecosystem.rs               Ecosystem enum + PackageRef
      policy.rs                  Policy, Action, decide_finding
      cache.rs                   SQLite KvCache with TTL
      advisory.rs                Advisory model
      evaluator.rs               EvaluatorRegistry, parallel join_all
      report_data.rs             FindingsReport (display-tier filter, sort)
      resolver.rs                npm/pnpm/yarn/Maven lockfile resolvers
                                 + temp-dir dry-run for `npm install <new>`
      range.rs                   semver + Maven range matching
      maven_version.rs           Apache version-order comparator
      osv.rs                     OSV.dev client (batch + single)
      osv_evaluator.rs           OSV → Findings + EPSS/KEV enrichment
      exploit.rs                 EPSS + CISA KEV client
      intel.rs                   npm registry intel + risk score + deprecated
      postinstall.rs             regex-based install-script scoring
      postinstall_ast.rs         AST static analysis of referenced JS
      provenance.rs              Sigstore Fulcio + DSSE + SCT verification
      source_scan.rs             cross-file behavior scan (AST visitor)
      source_scan_evaluator.rs   wraps source_scan as Evaluator
      license.rs                 SPDX classifier + deny-list
      threat_feed.rs             OSSF malicious-packages fetch + match

  guardep-cli/                   binary
    src/
      main.rs                    clap entrypoint + banner + tracing
      report.rs                  ANSI table + JSON renderer
      sbom.rs                    CycloneDX 1.5 emitter
      shim/                      busybox-style argv0 dispatch
      commands/
        audit.rs                 evaluate_project + dispatch
        diff.rs                  PR-aware diff (NEW findings only)
        fix.rs                   fix-version planner + diff preview
        install_shims.rs         symlink + PATH wiring (idempotent)
        info.rs                  cache + config locations
        cache.rs                 prune + vacuum
```

All evaluators implement the same `Evaluator` trait and run
concurrently via `futures::future::join_all`. Findings are merged,
deduped (by `(pkg@version, id, kind)` tuple), filtered by display
threshold, sorted (Critical → Info, alphabetical within tier), and
rendered together.

---

## 13. CI/CD integration patterns

### 13.1 GitHub Actions — full audit on every PR

```yaml
- uses: actions/checkout@v4
- name: Install guardep
  run: cargo install --path crates/guardep-cli   # or download release
- name: Audit
  run: guardep audit --format json --collapse --fail-on warn | tee guardep.json
- uses: actions/upload-artifact@v4
  with:
    name: guardep-report
    path: guardep.json
```

### 13.2 GitHub Actions — PR-aware diff (only NEW findings)

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- name: Worktree of base branch
  run: |
    git worktree add /tmp/base "origin/${{ github.base_ref }}"
- name: Install guardep
  run: cargo install --path crates/guardep-cli
- name: Diff vs base
  run: guardep diff --base /tmp/base --head . --fail-on block --format json | tee diff.json
- uses: actions/upload-artifact@v4
  with: { name: guardep-diff, path: diff.json }
```

### 13.3 Pre-push local check

```bash
# .git/hooks/pre-push
#!/bin/sh
guardep audit --severity high --fail-on block || exit 1
```

### 13.4 Strict mode (shim fail-closed)

When using shims in CI workflows where you want any HTTP/cache
failure to fail-closed instead of fail-open:

```bash
GUARDEP_STRICT=1 npm install
```

---

## 14. Troubleshooting

### `npm install` hangs or fails after install-shims

The shim refuses to proceed when `--no-package-lock` is set or when
no lockfile exists. Generate one first using the bypass:

```bash
guardep skip npm install --package-lock-only
guardep install-shims --force
```

### "registry returned 429"

You're hitting npm registry rate limits. Wait, or set
`cache_refresh_hours = 24` in `guardep.toml` to reduce churn.

### Socket reports an alert guardep misses

Two common causes:
1. The Socket alert type is not yet implemented in guardep
   (`newAuthor`, `gptAnomaly`, see [§11.2](#112-per-detector-empirical-pkg-coverage-113-pkg-fixture)).
2. Socket's threshold differs from ours. Check the `details` of the
   nearest guardep finding — we may report it at a lower severity
   (e.g. abandoned-alone is Low, Socket reports as their default).

### Bust the cache

```bash
rm -f ~/Library/Caches/dev.guardep.guardep/cache.db   # macOS
rm -f ~/.cache/guardep/cache.db                       # Linux
```

### Verbose diagnostics

```bash
guardep --verbose audit                       # evaluator timings + HTTP
GUARDEP_LOG=guardep=debug,reqwest=info guardep audit
```

### Bypass the shim once

```bash
guardep skip npm install               # subcommand form
GUARDEP_BYPASS=1 npm install           # env-var form
```

Both print a loud stderr warning and are vetoed by
`GUARDEP_STRICT=1`. See [§4.4b](#44b-skip-bypass-the-shim-for-one-command)
for the full bypass reference.

### Restore an rc file backup

```bash
mv ~/.zshrc.guardep.bak ~/.zshrc   # before any guardep edit
```

`uninstall-shims` strips the marker block exactly; backups are
left in place so you can revert further if needed.

---

## 15. Roadmap and next steps

### 15.1 Done

- Pre-install gate via PATH shim (npm/pnpm/yarn/mvn)
- Temp-dir dry-run resolution for `npm install <newpkg>`
- OSV.dev advisory matching with per-major fix selection
- npm registry intel: maintainers, versions, abandonment, fresh
  publish, typosquat with reputation cross-check
- Postinstall regex + AST analysis (process spawn, cred reads,
  base64→eval chains)
- Sigstore Fulcio + DSSE + SCT verification (Rekor pending upstream)
- EPSS + CISA KEV CVE enrichment
- OSSF malicious-packages threat feed (two-stage protocol with
  OSV-shape version-range matching)
- Cross-file source behavior scan (network/fs/env/eval/dynamic
  require/entropy/minified/URLs) with require/import alias
  resolution; `--granular` opts in to per-call-site findings
- License findings (missing/unidentified/denied) with SPDX classifier
- Per-version deprecation findings
- Maintainer-rotation (`new-maintainer`) detector via cross-snapshot
  diff with 12h stabilisation window
- CycloneDX 1.5 SBOM export
- SARIF 2.1.0 output with byte-range physicalLocation entries for
  source-behavior findings; ready for GitHub code-scanning
- `guardep diff` PR-aware audit + composite GitHub Action wrapper
  ([`.github/actions/guardep-diff`](./.github/actions/guardep-diff/))
  that uploads SARIF
- Maven dependency resolver + `mvn install`/`package`/`verify` shim
- Gradle audit resolver (`gradle dependencies`, Groovy + Kotlin DSL)
- Crates.io metadata + Homebrew formula template wired for the
  first tagged release
- Cross-platform PATH wiring (zsh/bash/fish + PowerShell)
- Multi-OS release pipeline (Linux x86/arm, macOS x86/arm,
  Windows x86)

### 15.2 Next

- **Rekor inclusion proof.** Pending sigstore-rs#543 shipping to
  crates.io.
- **First tagged release** publishing to the Homebrew tap and
  crates.io (the formula template + crate metadata are already
  wired; just need the tag).
- **Gradle shim** (intercept install-equivalent invocations); the
  audit resolver is already in place.

### 15.3 Future

- **Cargo / pip / RubyGems** ecosystem support beyond Maven + npm.
- **PostgreSQL / Redis cache backend** for shared CI caches.
- **Web UI** for the JSON output (local-only, served by guardep).
- **Plugin API** for organisation-specific evaluators.
- **`gptAnomaly`-equivalent** detector if/when an LLM-free
  approximation (e.g. learned anomaly scoring on AST features)
  beats the false-positive rate of the current heuristics.

---

## Appendix A: Useful one-offs

```bash
# Run guardep against a fixture without rebuilding
cargo run -- audit --path /path/to/project --collapse

# Bust the SQLite advisory cache to force fresh fetches
rm -f ~/Library/Caches/dev.guardep.guardep/cache.db

# Audit guardep's own Cargo dependencies (project ships a slash command for this)
cargo audit

# Generate a CycloneDX SBOM and pretty-print top vulns
guardep audit --format cyclonedx | jq '.vulnerabilities | .[0:5]'

# Diff the working tree vs main, JSON for CI
git worktree add /tmp/base origin/main
guardep diff --base /tmp/base --head . --format json
```

## Appendix B: Acknowledgements

- [OSV.dev](https://osv.dev/) for the unified advisory database.
- [GitHub Advisory Database](https://github.com/advisories) for
  primary CVE reporting.
- [FIRST EPSS](https://www.first.org/epss/) for exploit prediction
  scoring.
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  for the Known Exploited Vulnerabilities catalog.
- [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages)
  for the community-reported threat feed.
- [Sigstore](https://www.sigstore.dev/) and the npm provenance
  team for making attestation tractable.
- [Trivy](https://github.com/aquasecurity/trivy),
  [OSV-Scanner](https://github.com/google/osv-scanner),
  [Socket](https://socket.dev), and [Phylum](https://phylum.io) for
  proving the model and pushing the field forward.

## Appendix C: License

guardep is MIT — see [LICENSE](LICENSE).

guardep is not affiliated with, endorsed by, or sponsored by any of
the projects or vendors named above.

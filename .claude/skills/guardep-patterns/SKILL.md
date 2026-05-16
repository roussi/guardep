---
name: guardep-patterns
description: Architecture, conventions, and per-evaluator patterns for the guardep workspace. Use when adding or modifying any code in `crates/guardep-core` or `crates/guardep-cli`.
---

# guardep patterns

## Workspace shape

```
crates/
  guardep-core/     library: ecosystem types, advisory + finding models,
                    evaluators (osv, postinstall, intel, provenance),
                    resolvers, policy engine, cache
  guardep-cli/      bin `guardep`: clap CLI, audit/fix/shims
                    (install/uninstall/list/enable/disable)/info/cache
                    subcommands, npm shim via busybox-style argv0 dispatch
```

## Cardinal rules

- **No backwards compatibility.** Pre-users project. If a name/shape is
  wrong, change it everywhere. No deprecated aliases, no kept-for-old-
  callers wrappers. The README + git log are the only changelog.
- **No emojis in code, docs, or commit messages** unless the user
  explicitly asks.
- **Comments only when WHY is non-obvious.** No restating the code in
  English. No "// added for X" or "// used by Y" - those rot.
- **Tests live with code.** `#[cfg(test)] mod tests { ... }` at the
  bottom of the file. Integration tests in `crates/*/tests/`.
- **No new dependency without justification.** Workspace deps are
  curated. Adding one means: name the use case, name the alternative
  considered, prefer std/an existing dep.

## Findings model

Every evaluator emits `Finding` (see `core/src/finding.rs`):

```rust
pub struct Finding {
    pub package: PackageRef,
    pub kind: FindingKind,        // Vulnerability | Malware | PostinstallScript
                                  // RiskScore | MissingProvenance | ProvenanceMismatch
    pub id: String,               // GHSA-*, CVE-*, MAL-*, risk:reason:pkg, etc.
    pub aliases: Vec<String>,
    pub summary: String,
    pub severity: FindingSeverity,// Unknown | Info | Low | Medium | High | Critical (Ord)
    pub fixed_versions: Vec<String>,
    pub references: Vec<String>,
    pub details: serde_json::Value,
}
```

`FindingSeverity` is `Ord` with `Critical > High > Medium > Low > Info > Unknown`.
The display threshold (`Policy::min_display_severity`, default `Low`) drops
rows below it from output but does not affect what the policy decides.

## Policy decisions

`policy.decide_finding(kind, severity) -> Action` returns `Allow | Warn | Block`.
Allowlists are checked first in `decide_action(policy, finding)`. The CLI's
`--severity` overrides `policy.min_display_severity` per-invocation. Action
mapping is by kind:

- `Malware`/`Vulnerability` -> `malware`/`{critical,high,medium,low}_cve` knob
- `PostinstallScript` -> `postinstall_{default,suspicious,critical}` knob
- `RiskScore` -> composite score thresholds (`block_if_risk_score_above`,
  `warn_if_risk_score_above`)
- `MissingProvenance`/`ProvenanceMismatch` -> `missing_provenance` /
  `provenance_mismatch` knob

## Resolvers

`Resolver::resolve(project_root) -> Vec<PackageRef>`. Implementations:

- `NpmLockResolver` - reads `package-lock.json` (v2/v3).
- `NpmDryRunResolver` - copies `package.json` (+ existing lock + `.npmrc`)
  to a `tempfile::tempdir()`, runs `npm install --package-lock-only
  --ignore-scripts` there with PATH scrubbed of `~/.guardep/bin`, parses
  the resulting lockfile via `NpmLockResolver`. Used by the shim when
  the user's lockfile is stale w.r.t. `npm install foo`.
- `MavenTreeResolver` - `mvn dependency:tree` -> tgf parser.

**Always scrub `~/.guardep/bin` from `PATH`** before spawning `npm`/`mvn`
in resolver code. Otherwise the shim re-enters itself and recurses.
Helper: `scrub_shim_from_path()` in `core/src/resolver.rs`.

## Shim dispatch (busybox pattern)

`crates/guardep-cli/src/main.rs` checks `argv[0]` first. If basename is
`npm`/`pnpm`/`yarn`, it routes to `shim::run` instead of clap.
`shims install` writes symlinks to `~/.guardep/bin/{npm,pnpm,yarn,mvn,cargo}`
-> `target/release/guardep` and injects `PATH=$HOME/.guardep/bin:$PATH`
into shell rc files (zsh/bash/fish/PowerShell), bracketed by
`# >>> guardep-shim >>>` ... `# <<< guardep-shim <<<` markers so
`shims uninstall` can strip them exactly. One-shot `*.guardep.bak`
backup before any rc edit.

Tty prompt before injection unless `--yes` or non-tty stdin.

## Risk-score composition (Socket-style)

`intel.rs` adds weighted reasons to a 0-100 composite. Severity buckets:
>=80 Critical, >=60 High, >=40 Medium, >=20 Low. Reason weights:

```
typosquat            30
single-maintainer    25
fresh-publish        20
abandoned            15
few-versions         15
no-source            10
very-fresh-latest     5
```

Single-maintainer alone always emits at `Info`. The display threshold
filters it out by default.

## CLI conventions

- `--severity {info,low,medium,high,critical}` - display threshold.
- `--fail-on {never,warn,block}` - exit-code threshold (separate from display).
- `-v`/`--verbose` (global) - bumps tracing filter from `warn` to `debug`.
- `--yes`/`-y` - skip interactive confirmation prompts (CI-friendly).
- Outputs honour `NO_COLOR` / `CLICOLOR_FORCE` / non-tty stdout via
  `init_color_support` in `main.rs`.

## Commit style

Conventional, lowercase imperative. No emoji. No Co-Authored-By unless
the user asks. Examples from real history:

```
feat: shim recursion fix, temp-dir resolver, auto PATH wiring with uninstall
fix: --info actually shows everything, multi-manifest warns, info is diagnostic
refactor: delete script-hash allowlist, calibrate AST severities for honesty
ci: add GitHub Actions workflows + apply rustfmt/clippy across workspace
```

Body: explain WHY, name the bug-fixed-or-feature-added, list non-obvious
side effects. Keep under ~80 columns per line.

## Quality gates (CI mirrors these)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
```

The local `Stop` hook runs these and prints a pass/fail summary.
Don't push if any gate is red.

## Adding a new evaluator

1. Implement `guardep_core::Evaluator` (async trait, `name()`,
   `enabled(policy)`, `evaluate(packages, policy) -> Vec<Finding>`).
2. Register in `EvaluatorRegistry` in `commands/audit.rs`.
3. Add a `FindingKind` variant + extend `policy.decide_finding`
   mapping.
4. Add unit tests next to the evaluator and an integration test in
   `crates/guardep-core/tests/` that runs against a fixture lockfile.
5. Update `display_class()` in `finding.rs` if the new kind has a
   non-obvious MALWARE/CVE bucketing.

## What NOT to do

- Don't add a `--debug` or `--trace` flag separate from `--verbose`.
  One verbosity axis (logs) and one display axis (`--severity`).
- Don't catch errors silently in evaluators. Either surface as a
  finding (`MissingProvenance` style "trust-root-unavailable") or
  bubble the error.
- Don't add a feature flag for behaviour you can flip at the CLI.
  Cargo features are for compile-time toggles (a target-OS gate, a
  vendored TLS swap), not user-facing behaviour.

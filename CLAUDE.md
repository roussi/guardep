# CLAUDE.md

Project-wide context loaded automatically by Claude Code.

## What this project is

`guardep` is a deterministic supply-chain audit and pre-install gate
for npm/pnpm/yarn (Maven/Gradle in progress). It blocks compromised
or vulnerable dependencies *before* they land in `node_modules`, by
intercepting the package-manager invocation via PATH shims and
running advisory + heuristic evaluators against the resolved
dependency graph.

Workspace layout, evaluator design, policy model, shim pattern, and
the project's hard rules (no backwards-compat, no emoji, comments
only when WHY is non-obvious) are documented in
[`.claude/skills/guardep-patterns/SKILL.md`](./.claude/skills/guardep-patterns/SKILL.md).
That skill is the source of truth - read it before non-trivial work.

## Daily workflow

1. Edit code. The `PostToolUse` hook auto-runs `cargo fmt --all`.
2. Before pushing, run `/pre-push` (mirrors CI: fmt, clippy,
   test, build, audit). Don't push on a red gate.
3. Cutting a release? `/release patch|minor|major` bumps the
   workspace version, commits, tags, and prints the push command.
   Push manually after review.
4. Suspect a CVE in our own deps? `/audit-self` runs `cargo audit`
   against the workspace lockfile.

## Authoritative gates (CI mirrors these locally)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
```

## House rules quick reference

- No `--no-verify`, no `git push --force` to `main`, no `cargo
  install` without `--locked`.
- New deps: justify in the commit message (use case + alternative
  considered + why std/existing dep doesn't fit).
- Tests live with code (`#[cfg(test)] mod tests` at file bottom)
  or in `crates/*/tests/` for integration.
- Conventional commit subjects, lowercase, imperative, no emoji,
  no Co-Authored-By unless explicitly requested.

## Things to avoid

- Don't add backwards-compat shims. If a name is wrong, change it
  everywhere. Pre-users project; readme + git log are the changelog.
- Don't catch errors silently in evaluators - surface as a
  `Finding` (e.g. `MissingProvenance` style "trust-root-unavailable")
  or bubble.
- Don't add a feature flag for behaviour you can flip at the CLI.
  Cargo features are for compile-time toggles only.

## Where things live

| Concern | File |
|--------|------|
| Workspace deps + lints | `Cargo.toml` |
| Findings model | `crates/guardep-core/src/finding.rs` |
| Policy + decisions | `crates/guardep-core/src/policy.rs` |
| Risk-score composition | `crates/guardep-core/src/intel.rs` |
| Resolvers (npm lock, dry-run, mvn) | `crates/guardep-core/src/resolver.rs` |
| Display threshold + sort | `crates/guardep-core/src/report_data.rs` |
| CLI surface | `crates/guardep-cli/src/main.rs` |
| Audit subcommand | `crates/guardep-cli/src/commands/audit.rs` |
| Fix subcommand + diff preview | `crates/guardep-cli/src/commands/fix.rs` |
| Install/uninstall shims + PATH wiring | `crates/guardep-cli/src/commands/install_shims.rs` |
| npm shim dispatch | `crates/guardep-cli/src/shim/npm.rs` |
| Table renderer | `crates/guardep-cli/src/report.rs` |

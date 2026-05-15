---
description: Cut a new release. Bumps the workspace version, commits, tags `vX.Y.Z`, and prints the push command. Does NOT push automatically.
argument-hint: "<patch|minor|major>"
---

Cut a release with bump `${ARGUMENTS:-patch}` (`patch`, `minor`, or
`major`). Steps:

1. Confirm the working tree is clean (`git status` empty).
2. Confirm we're on `main` and synced with `origin/main`.
3. Run `/pre-push` gates. Abort on any failure.
4. Read current version from `Cargo.toml` workspace package.
5. Compute next version per bump type.
6. Edit `Cargo.toml` → `[workspace.package]` `version = "X.Y.Z"`.
7. Run `cargo check --workspace` to update `Cargo.lock`.
8. Commit `release: vX.Y.Z` with the changelog excerpt.
9. Tag `vX.Y.Z` (annotated, signed if a signing key is configured).
10. Print: `git push origin main && git push origin vX.Y.Z`. The
    user runs the push when ready — `release.yml` will pick up the
    tag and produce the GitHub Release artifacts.

Never push automatically. The user pushes after a final review of
the commit + tag.

If `${ARGUMENTS}` isn't `patch`/`minor`/`major`, ask the user which
they meant before doing anything.

The version bump touches only `[workspace.package].version` —
individual crates inherit via `version.workspace = true` so no
per-crate edits.

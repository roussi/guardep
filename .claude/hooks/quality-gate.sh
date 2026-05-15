#!/usr/bin/env bash
# Stop hook: end-of-turn quality summary.
#
# Runs the same gates CI runs (fmt, clippy, test) and prints a
# concise pass/fail line per gate to stderr. Skipped entirely when
# `GUARDEP_SKIP_QUALITY_GATE=1` is set, or when no Rust files
# changed in the working tree (no point gating doc-only edits).
#
# Always exits 0. This is informational; CI is the authoritative
# enforcer. The model can react to the summary in its next turn if
# something is broken.

set -uo pipefail

[ "${GUARDEP_SKIP_QUALITY_GATE:-}" = "1" ] && exit 0

# Skip when the working tree has no Rust changes.
if command -v git >/dev/null 2>&1; then
  if ! git diff --name-only HEAD 2>/dev/null | grep -qE '\.rs$'; then
    exit 0
  fi
fi

if ! command -v cargo >/dev/null 2>&1; then
  exit 0
fi

echo "" >&2
echo "-- guardep quality gate -----------------------------" >&2

# fmt --check
if cargo fmt --all -- --check >/dev/null 2>&1; then
  echo "OK rustfmt" >&2
else
  echo "FAIL rustfmt: run \`cargo fmt --all\`" >&2
fi

# clippy
if cargo clippy --workspace --all-targets --all-features -- -D warnings >/dev/null 2>&1; then
  echo "OK clippy" >&2
else
  echo "FAIL clippy: run \`cargo clippy --workspace --all-targets --all-features -- -D warnings\`" >&2
fi

# test (only if the previous gates passed; tests are slow)
if cargo test --workspace --quiet >/dev/null 2>&1; then
  echo "OK tests" >&2
else
  echo "FAIL tests: run \`cargo test --workspace\`" >&2
fi

echo "--------------------------------------------------" >&2
exit 0

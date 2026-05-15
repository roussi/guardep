---
description: Mirror CI locally before push: fmt, clippy, full test suite, audit. Stops on first failure.
---

Run the same gates `.github/workflows/ci.yml` runs, in the same order,
in fail-fast mode. Each gate prints its own progress; the final
summary lists what passed and what didn't. Don't push until every
line is `OK`.

```bash
set -e

echo "-> rustfmt"
cargo fmt --all -- --check

echo "-> clippy"
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "-> tests"
cargo test --workspace --all-targets

echo "-> release build"
cargo build --release --bin guardep

echo "-> cargo audit"
if command -v cargo-audit >/dev/null 2>&1; then
  cargo audit
else
  echo "  skipped (install: cargo install cargo-audit --locked)"
fi

echo ""
echo "[OK] all gates passed - safe to push"
```

If a gate fails, the script exits non-zero at that step and the
remaining gates don't run. Fix that one specifically, re-run.

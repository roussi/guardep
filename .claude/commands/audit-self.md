---
description: Run guardep against its own Cargo dependency tree. Catches CVEs in our own supply chain.
---

Build the release binary if missing, then point `cargo audit` at the
workspace's `Cargo.lock` (RustSec advisory DB) and report any
findings. guardep itself doesn't yet handle Rust ecosystems — that's
why we use `cargo audit` here. Once Rust support lands in guardep,
swap the command for `./target/release/guardep audit --path .`.

```bash
if ! [ -x ./target/release/guardep ]; then
  cargo build --release --bin guardep
fi
if ! command -v cargo-audit >/dev/null 2>&1; then
  cargo install cargo-audit --locked
fi
cargo audit
```

Exit code 1 from `cargo audit` means at least one advisory matched
the workspace lockfile. Triage:

1. Check whether the affected crate is reachable from `guardep-cli`
   or `guardep-core` (vs a dev-dep that only matters in tests).
2. Bump the offending dep in `Cargo.toml` if a fix version exists.
3. If no fix exists, document the rationale in `.cargo/audit.toml`
   under `[advisories.ignore]` with a date-stamped reason.

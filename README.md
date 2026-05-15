# guardep

Drop-in shim for `npm` / `pnpm` / `yarn` / `mvn` / `gradle` that **blocks installs of compromised dependencies** before they hit your machine.

> Status: **MVP scaffold**. npm path works end-to-end against OSV.dev. Maven/Gradle = passthrough placeholders.

## Why

Recent supply-chain attacks (Shai-Hulud worm, Mini Shai-Hulud TanStack/SAP/axios compromises) prove that `npm install` can pull malicious code published from hijacked maintainer accounts within minutes. `npm audit` runs *after* install and is weak on malware. guardep runs *before*, with malware-first policy.

## Architecture

```
crates/
  guardep-core/    # advisory model, OSV client, SQLite cache, matcher, policy
  guardep-cli/     # binary + shim dispatch (argv0 busybox pattern)
```

- **OSV.dev** primary advisory source — unified across npm / Maven / cargo / PyPI.
- **SQLite cache** keyed by `(ecosystem, name, version)`, TTL configurable.
- **Two threat classes:** `Malware` (always block by default) vs `Vulnerability` (severity-graded).
- **Policy file:** `guardep.toml` per-project, with allowlist escape hatch.

## Build

```bash
cargo build --release
./target/release/guardep info
```

## Use

```bash
# Audit a project (read-only)
guardep audit --path ./my-project

# Install shims (creates ~/.guardep/bin/{npm,pnpm,yarn,mvn,gradle})
guardep install-shims
export PATH="$HOME/.guardep/bin:$PATH"

# Now this triggers a pre-install audit; blocks if malware/critical match
npm install
```

## Roadmap

- [ ] Maven resolver (`mvn dependency:tree -DoutputType=json`)
- [ ] Gradle resolver (Tooling API or lockfile parse)
- [ ] GitHub Advisory DB + Socket.dev as secondary sources (faster malware signal)
- [ ] OSV bulk-dump mode (offline / air-gapped CI)
- [ ] GitHub Action wrapper
- [ ] `--dry-run` mode that resolves intended install graph without lockfile

## Bypass model

PATH-based shim. Sophisticated users (or attackers in scripts) can call `/usr/local/bin/npm` directly. For hardened environments use container base image with the shim path baked in.

# Security Policy

guardep is a package-manager firewall whose entire job is gating
risky dependencies. Holding the same bar on guardep itself is
non-negotiable.

## Supported versions

guardep is pre-1.0 and ships from a single `main` branch. Only the
latest released tag receives security fixes.

| Version | Supported |
|---------|-----------|
| 0.1.x   | yes       |
| < 0.1   | no        |

## Reporting a vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Email: **roussi.abdelghani@gmail.com**
Subject line: `[security] guardep <short description>`

Include in the report:

- guardep version (`guardep --version`)
- Operating system and architecture
- Reproduction steps (minimum repro is gold)
- Impact assessment (what an attacker gains)
- Suggested fix or mitigation, if you have one
- Whether you would like credit in the release notes

If you prefer encrypted communication, ask for a PGP key in your
first message and we will exchange one.

## Response SLA

| Stage | Target |
|-------|--------|
| Acknowledgment that the report was received | within 72 hours |
| Triage and confirmed severity | within 7 days |
| Fix or documented mitigation plan | within 30 days for High/Critical |
| Coordinated public disclosure | after fix is released, in agreement with reporter |

## Disclosure preference

Coordinated disclosure preferred. We aim to publish a release with
the fix before any public write-up, and to credit the reporter in
the release notes unless they prefer anonymity.

## Scope

In scope:

- guardep binary and CLI (any subcommand)
- Shim dispatch (`shim/*`)
- Resolvers and evaluators in `guardep-core`
- GitHub release artifacts and Homebrew formula
- Workflow security (token permissions, action pinning, supply chain)

Out of scope:

- Issues in upstream sources we query (OSV, npm registry, EPSS,
  CISA KEV, OSSF malicious-packages, Sigstore). Please report those
  to the upstream project.
- Findings that depend on the user explicitly bypassing the gate
  (`guardep skip`, `GUARDEP_BYPASS=1`). Bypass is a documented
  escape hatch.
- Local-machine attacks that already have shell access.

## Hall of fame

Security researchers who report valid vulnerabilities will be listed
here (with their consent) once the first report is resolved.

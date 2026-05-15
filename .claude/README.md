# `.claude/` - guardep project setup for Claude Code

Tracked configuration that makes Claude Code productive on this
repository: project-level skill, slash commands, hooks, and a
permissions allowlist.

## What's here

```
.claude/
├── settings.json                   # hooks, permissions
├── skills/
│   └── guardep-patterns/
│       └── SKILL.md                # architecture, conventions, evaluator patterns
├── commands/
│   ├── audit-self.md               # /audit-self - RustSec advisory scan on our deps
│   ├── pre-push.md                 # /pre-push - local mirror of CI gates
│   └── release.md                  # /release patch|minor|major - bump + tag (no push)
└── hooks/
    ├── format-rust.sh              # PostToolUse: cargo fmt after Rust edits
    └── quality-gate.sh             # Stop: end-of-turn fmt+clippy+test summary
```

## Hooks

- **`PostToolUse` -> `format-rust.sh`** runs `cargo fmt --all` whenever
  Claude edits a `*.rs` file. Silent on success. Never blocks the
  tool call (CI's `cargo fmt --check` is the authoritative gate).
- **`Stop` -> `quality-gate.sh`** runs the same three gates as CI
  (fmt, clippy, test) at end of turn and prints a `[OK]`/`[X]` summary
  per gate. Skipped when no Rust files changed or when
  `GUARDEP_SKIP_QUALITY_GATE=1`. Always exits 0 - informational
  only, never blocks.

## Permissions

`settings.json` allows read-only Cargo/git/search commands and the
local `guardep` binary by default, so common operations don't
prompt. Denies network downloads, destructive git ops, and reads of
common secret paths (`.env*`, `~/.aws`, `~/.ssh`, `**/secrets/**`).

User-level `~/.claude/settings.json` and runtime `--allow`/`--deny`
flags compose on top.

## Why these conventions

The skill at `skills/guardep-patterns/SKILL.md` codifies the
project's invariants: no backwards compatibility, no emojis, no rot-
prone callsite comments, composite risk scoring, the busybox shim
pattern, the rationale for the temp-dir resolver, etc. Read it once
when picking up a new task.

## Adapting for your fork

- Update `settings.json` if you want different permission lists or
  hooks. Anything not committed to git stays local.
- Hooks are POSIX shell. If you don't want them, delete
  `.claude/hooks/` and the corresponding `hooks` block in
  `settings.json`.
- Slash commands are plain markdown with YAML frontmatter - copy,
  rename, edit.

## What is NOT here (intentionally)

- No secrets, API keys, or personal info. This directory is
  committed to git and public.
- No machine-specific paths.
- No user-level settings (model, theme, etc.) - those live in
  `~/.claude/settings.json`.

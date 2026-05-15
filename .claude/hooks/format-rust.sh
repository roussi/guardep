#!/usr/bin/env bash
# PostToolUse hook: auto-format Rust code after Edit/Write.
#
# Reads the tool invocation JSON from stdin, extracts the file path,
# runs `cargo fmt` on the workspace if and only if the touched file
# is a Rust source file. Silent on success. Prints rustfmt's stderr
# only when formatting fails so the model sees the diagnostic.
#
# Exit 0 always: never block tool execution from a formatter. CI
# rustfmt --check is the authoritative gate.

set -euo pipefail

# Drain stdin into a variable so we can grep without re-reading the
# pipe. The harness sends a JSON object describing the tool call.
payload="$(cat || true)"

# Extract the file path; tolerate missing key (e.g. when the matched
# tool didn't act on a file).
file=""
if command -v jq >/dev/null 2>&1; then
  file="$(printf '%s' "$payload" | jq -r '.tool_input.file_path // empty' 2>/dev/null || true)"
fi

case "$file" in
  *.rs) ;;
  *) exit 0 ;;
esac

if ! command -v cargo >/dev/null 2>&1; then
  exit 0
fi

# Format the whole workspace; cheap and ensures the edited file
# plus any incidentally touched ones stay aligned.
if ! cargo fmt --all 2>/tmp/guardep-fmt-err.log; then
  echo "rustfmt failed:" >&2
  cat /tmp/guardep-fmt-err.log >&2
fi

exit 0

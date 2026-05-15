# guardep-diff GitHub Action

PR-aware dependency audit. Reports only the findings the head adds
over the base branch, optionally uploading SARIF to GitHub
code-scanning.

## Usage

```yaml
name: dependency-review
on:
  pull_request:
permissions:
  contents: read
  security-events: write   # required only for SARIF upload
  actions: read
jobs:
  guardep-diff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0    # required so we can resolve the base ref
      - uses: aroussi/guardep/.github/actions/guardep-diff@main
        with:
          fail-on: block    # exit 2 if the PR adds any blocking finding
```

## Inputs

| Input | Default | Purpose |
|---|---|---|
| `base-ref` | PR base / repo default | Git ref to diff against (`origin/main`, `v1.2.0`, ...) |
| `head-path` | `.` | Path to the head project root |
| `severity` | `low` | Minimum severity shown (`info`/`low`/`medium`/`high`/`critical`) |
| `fail-on` | `block` | Exit threshold (`never`/`warn`/`block`) |
| `format` | `sarif` | `table` / `json` / `cyclonedx` / `sarif` |
| `upload-sarif` | `true` | When `format=sarif`, upload to code-scanning |
| `guardep-version` | `latest` | Release tag (`v0.2.0`, ...) |

## Outputs

| Output | Description |
|---|---|
| `report-path` | Path to the rendered guardep diff report file |
| `new-blocks` | Number of new findings at action `block` |
| `new-warnings` | Number of new findings at action `warn` |

## Examples

### Block PRs that add critical CVEs

```yaml
- uses: aroussi/guardep/.github/actions/guardep-diff@main
  with:
    severity: critical
    fail-on: block
```

### Comment on the PR with the diff

```yaml
- id: diff
  uses: aroussi/guardep/.github/actions/guardep-diff@main
  with:
    format: json
    fail-on: never
- name: Comment
  if: ${{ steps.diff.outputs.new-blocks != '0' || steps.diff.outputs.new-warnings != '0' }}
  uses: actions/github-script@v7
  with:
    script: |
      const fs = require('fs');
      const body = '## guardep diff\n\nNew blocks: ${{ steps.diff.outputs.new-blocks }}, new warnings: ${{ steps.diff.outputs.new-warnings }}';
      github.rest.issues.createComment({
        issue_number: context.issue.number,
        owner: context.repo.owner,
        repo: context.repo.repo,
        body
      });
```

### Pin a specific guardep version

```yaml
- uses: aroussi/guardep/.github/actions/guardep-diff@main
  with:
    guardep-version: v0.2.0
```

## Requirements

- `actions/checkout@v4` with `fetch-depth: 0` so the base ref is
  available locally.
- `permissions.security-events: write` only when uploading SARIF.
- `gh` CLI is preinstalled on GitHub-hosted runners; the action uses
  it to resolve `latest` and download release artifacts.

# Packaging

This directory holds distribution-time templates the release pipeline
fills in on each tag.

## Homebrew (`packaging/homebrew/guardep.rb`)

Source-of-truth for the `roussi/homebrew-tap` formula. The release
workflow does this end-to-end on each `v*` tag push (job
`publish-homebrew` in `.github/workflows/release.yml`):

1. Builds the cross-platform tarballs (job `build`).
2. Publishes the GitHub Release with the tarballs (job `publish`).
3. Computes sha256 of each tarball (job `publish-homebrew`).
4. Rewrites this template's `version` / `url` / `sha256`
   placeholders.
5. Commits + pushes the result to `roussi/homebrew-tap`'s
   `Formula/guardep.rb`.

The `publish-homebrew` job needs a `HOMEBREW_TAP_TOKEN` secret on
this repo: a fine-grained PAT with **Contents: Read and write** on
`roussi/homebrew-tap`. Generate at
<https://github.com/settings/personal-access-tokens/new>, restrict
to that single repo, set expiry to taste, then add via
`gh secret set HOMEBREW_TAP_TOKEN -R roussi/guardep`.

Once the tap is published end users install with:

```bash
brew tap roussi/tap
brew install guardep
```

Manual install path while the tap is being set up (only works once
the release artifacts exist and the placeholder sha256 values are
filled in by hand):

```bash
brew install --formula https://raw.githubusercontent.com/roussi/guardep/main/packaging/homebrew/guardep.rb
```

## crates.io

`cargo install guardep-cli` will install the binary as `guardep`
once the workspace ships its first tagged release. Required workspace
metadata (description, repository, keywords, categories,
rust-version) lives in the root `Cargo.toml` `[workspace.package]`
block and is inherited by every crate.

Publish order (only run after a successful tag build + cargo audit):

```bash
cargo publish -p guardep-core
cargo publish -p guardep-cli
```

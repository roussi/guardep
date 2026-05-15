# Packaging

This directory holds distribution-time templates the release pipeline
fills in on each tag.

## Homebrew (`packaging/homebrew/guardep.rb`)

Source-of-truth for the `aroussi/homebrew-tap` formula. The release
workflow:

1. Builds the cross-platform tarballs (already wired in
   `.github/workflows/release.yml`).
2. Computes sha256 of each tarball.
3. Rewrites this template's `url` / `sha256` placeholders.
4. Pushes the result to the tap repo.

Manual install path while the tap is being set up:

```bash
brew install --formula https://raw.githubusercontent.com/aroussi/guardep/main/packaging/homebrew/guardep.rb
```

(only works once the release artifacts exist and the placeholder
sha256 values are filled in by hand)

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

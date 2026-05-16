# Homebrew formula for guardep.
#
# Intended to live in a tap repo (roussi/homebrew-tap) once the first
# tagged release ships. Until then this template is the source of
# truth; the release pipeline rewrites the version + sha256 fields
# and pushes the result to the tap.
#
# To install once the tap is published:
#   brew tap roussi/tap
#   brew install guardep
#
class Guardep < Formula
  desc "Package-manager firewall: blocks risky npm/pnpm/yarn/mvn installs before postinstall runs"
  homepage "https://github.com/roussi/guardep"
  license "MIT"
  version "0.1.0"

  # Release pipeline (`publish-homebrew` job in
  # `.github/workflows/release.yml`) regenerates this file end-to-end
  # on each `vX.Y.Z` tag, computing sha256 from the per-platform
  # tarballs and pushing to `roussi/homebrew-tap`. The template
  # checked into the source repo is for reference; the tap repo is
  # the source of truth users install from.
  on_macos do
    on_arm do
      url "https://github.com/roussi/guardep/releases/download/v#{version}/guardep-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_SHA256_AT_RELEASE_TIME"
    end
    on_intel do
      url "https://github.com/roussi/guardep/releases/download/v#{version}/guardep-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_SHA256_AT_RELEASE_TIME"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/roussi/guardep/releases/download/v#{version}/guardep-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_SHA256_AT_RELEASE_TIME"
    end
    on_intel do
      url "https://github.com/roussi/guardep/releases/download/v#{version}/guardep-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_SHA256_AT_RELEASE_TIME"
    end
  end

  def install
    # Tarball top-level dir is `guardep-<ver>-<target>/`. Homebrew
    # strips it because the prefix matches the formula name, so the
    # binary lands at the buildpath root.
    bin.install "guardep"
  end

  def caveats
    <<~EOS
      To enforce the package-manager firewall locally:

        guardep shims install

      This wires npm/pnpm/yarn/mvn/cargo through guardep via PATH shims placed in
      ~/.guardep/bin. Reverse with `guardep shims uninstall`.
    EOS
  end

  test do
    assert_match "guardep #{version}", shell_output("#{bin}/guardep --version")
    # Audit an empty project to confirm the binary works end-to-end
    # without external network calls (no lockfile present, exits 0).
    (testpath/"empty").mkpath
    system bin/"guardep", "audit", "--path", testpath/"empty", "--fail-on", "never"
  end
end

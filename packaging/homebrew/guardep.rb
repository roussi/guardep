# Homebrew formula for guardep.
#
# Intended to live in a tap repo (e.g. aroussi/homebrew-tap) once the
# first tagged release ships. Until then this template is the source
# of truth; the release pipeline rewrites the version + sha256 fields
# and pushes the result to the tap.
#
# To install once the tap is published:
#   brew tap aroussi/tap
#   brew install guardep
#
class Guardep < Formula
  desc "Package-manager firewall: blocks risky npm/pnpm/yarn installs before postinstall runs"
  homepage "https://github.com/aroussi/guardep"
  license "MIT"
  version "0.1.0"

  # Release pipeline rewrites the URL + sha256 per platform on each
  # tag push. Manual installs from `cargo build --release` remain the
  # OSS-friendly fallback documented in the README.
  on_macos do
    on_arm do
      url "https://github.com/aroussi/guardep/releases/download/v#{version}/guardep-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_SHA256_AT_RELEASE_TIME"
    end
    on_intel do
      url "https://github.com/aroussi/guardep/releases/download/v#{version}/guardep-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_SHA256_AT_RELEASE_TIME"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/aroussi/guardep/releases/download/v#{version}/guardep-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_SHA256_AT_RELEASE_TIME"
    end
    on_intel do
      url "https://github.com/aroussi/guardep/releases/download/v#{version}/guardep-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_SHA256_AT_RELEASE_TIME"
    end
  end

  def install
    bin.install "guardep"
  end

  def caveats
    <<~EOS
      To enforce the package-manager firewall locally:

        guardep install-shims

      This wires npm/pnpm/yarn through guardep via PATH shims placed in
      ~/.guardep/bin. Reverse with `guardep uninstall-shims`.
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

//! Single-command bypass: forward to the real binary without auditing.
//!
//! Public, supported escape hatch for the day-to-day case where you've
//! reviewed a finding and just want to push past it once. Equivalent
//! to `$(which -a npm | grep -v guardep | head -1) install` but
//! discoverable in `--help`, greppable in CI logs, and safer than
//! permanently removing the shim.
//!
//! Loud by design: prints a warning to stderr on every invocation so
//! the bypass shows up in CI output / `script` recordings / shell
//! history. `GUARDEP_STRICT=1` disables this command entirely; orgs
//! that want zero bypass set it in the workflow env.

use crate::shim::locate_real_binary;
use anyhow::Result;
use owo_colors::OwoColorize;

pub async fn run(tool: &str, args: &[String]) -> Result<()> {
    if strict_mode_enabled() {
        eprintln!(
            "{} guardep strict mode (GUARDEP_STRICT=1) refuses to honour `guardep skip`",
            "X".red().bold()
        );
        std::process::exit(1);
    }

    let real = locate_real_binary(tool)?;
    eprintln!(
        "{} guardep skip: forwarding `{tool} {}` without audit (real bin: {})",
        "!".yellow(),
        args.join(" "),
        real.display()
    );

    let status = std::process::Command::new(real).args(args).status()?;
    std::process::exit(status.code().unwrap_or(1));
}

/// True when `GUARDEP_STRICT=1` is set in the process env. Split out
/// so the strict-mode predicate is testable without the side-effects
/// of `run()` (which spawns a child process and exits on success).
pub(crate) fn strict_mode_enabled() -> bool {
    std::env::var("GUARDEP_STRICT").ok().as_deref() == Some("1")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `set_var` mutates global state; restore prior value on the way
    /// out so the test is repeatable and doesn't leak into siblings.
    fn with_env<F: FnOnce()>(key: &str, value: Option<&str>, f: F) {
        let prev = std::env::var(key).ok();
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        f();
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn strict_mode_enabled_only_for_literal_one() {
        with_env("GUARDEP_STRICT", Some("1"), || {
            assert!(strict_mode_enabled());
        });
    }

    #[test]
    fn strict_mode_disabled_for_other_values() {
        // `GUARDEP_STRICT=true` should NOT enable strict mode — only
        // `1` does. Documents the contract narrowly so we don't drift.
        for v in ["0", "true", "yes", "on", ""] {
            with_env("GUARDEP_STRICT", Some(v), || {
                assert!(!strict_mode_enabled(), "value {v:?} unexpectedly strict");
            });
        }
    }

    #[test]
    fn strict_mode_disabled_when_unset() {
        with_env("GUARDEP_STRICT", None, || {
            assert!(!strict_mode_enabled());
        });
    }
}

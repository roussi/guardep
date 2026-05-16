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
    if std::env::var("GUARDEP_STRICT").ok().as_deref() == Some("1") {
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

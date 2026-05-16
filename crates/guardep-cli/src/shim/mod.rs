use anyhow::Result;
use owo_colors::OwoColorize;
use std::path::Path;

mod cargo;
mod mvn;
mod npm;

/// Tools we currently install shims for. Gradle is intentionally
/// excluded for now: no pre-install gate yet, and a passthrough shim
/// creates false confidence. When the Gradle shim ships, add it here
/// AND to `install_shims::TOOLS`.
pub fn detect_invocation() -> Option<String> {
    let arg0 = std::env::args().next()?;
    let name = Path::new(&arg0).file_name()?.to_str()?.to_string();
    match name.as_str() {
        "npm" | "pnpm" | "yarn" | "mvn" | "cargo" => Some(name),
        _ => None,
    }
}

pub async fn run(tool: &str, args: &[String]) -> Result<()> {
    // GUARDEP_BYPASS=1 is the env-var equivalent of `guardep skip`.
    // Loud on stderr so the bypass shows up in CI / shell history /
    // `script` recordings. GUARDEP_STRICT=1 vetoes the bypass for
    // organisations that want zero escape hatches in CI.
    if std::env::var("GUARDEP_BYPASS").ok().as_deref() == Some("1") {
        if std::env::var("GUARDEP_STRICT").ok().as_deref() == Some("1") {
            eprintln!(
                "{} guardep strict mode (GUARDEP_STRICT=1) refuses to honour GUARDEP_BYPASS",
                "X".red().bold()
            );
            std::process::exit(1);
        }
        eprintln!(
            "{} guardep bypassed via GUARDEP_BYPASS=1: forwarding `{tool} {}` without audit",
            "!".yellow(),
            args.join(" ")
        );
        return passthrough(tool, args);
    }

    match tool {
        "npm" | "pnpm" | "yarn" => npm::dispatch(tool, args).await,
        "mvn" => mvn::dispatch(tool, args).await,
        "cargo" => cargo::dispatch(tool, args).await,
        // Stale shim from a prior install. Tell the user explicitly
        // that we're NOT auditing, then forward.
        "gradle" | "gradlew" => {
            eprintln!(
                "{} guardep does not yet intercept {tool}. \
                 Use `guardep audit --path .` to scan the project. \
                 Forwarding to the real binary unchanged.",
                "!".yellow()
            );
            passthrough(tool, args)
        }
        other => anyhow::bail!("unknown shim target: {other}"),
    }
}

pub fn passthrough(tool: &str, args: &[String]) -> Result<()> {
    let real = locate_real_binary(tool)?;
    let status = std::process::Command::new(real).args(args).status()?;
    std::process::exit(status.code().unwrap_or(1));
}

pub fn locate_real_binary(tool: &str) -> Result<std::path::PathBuf> {
    // Skip our own shim dir to avoid infinite recursion.
    let shim_dir = crate::commands::install_shims::shim_dir().ok();
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        if shim_dir.as_deref() == Some(dir.as_path()) {
            continue;
        }
        let candidate = dir.join(tool);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    anyhow::bail!("could not locate real `{tool}` on PATH (excluding shim dir)")
}

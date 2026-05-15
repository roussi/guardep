use anyhow::Result;
use owo_colors::OwoColorize;
use std::path::Path;

mod npm;

/// Tools we currently install shims for. Maven/Gradle are intentionally
/// excluded: they have no pre-install gate yet, and installing a
/// passthrough shim creates false confidence that guardep is auditing
/// invocations when in reality it isn't doing anything beyond logging.
/// When the Maven shim is implemented, add `mvn` here AND to
/// `install_shims::TOOLS`.
pub fn detect_invocation() -> Option<String> {
    let arg0 = std::env::args().next()?;
    let name = Path::new(&arg0).file_name()?.to_str()?.to_string();
    match name.as_str() {
        "npm" | "pnpm" | "yarn" => Some(name),
        _ => None,
    }
}

pub async fn run(tool: &str, args: &[String]) -> Result<()> {
    match tool {
        "npm" | "pnpm" | "yarn" => npm::dispatch(tool, args).await,
        // Stale shim from a prior install. Tell the user explicitly
        // that we're NOT auditing, then forward.
        "mvn" | "gradle" | "gradlew" => {
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

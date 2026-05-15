use anyhow::Result;
use std::path::Path;

mod npm;

pub fn detect_invocation() -> Option<String> {
    let arg0 = std::env::args().next()?;
    let name = Path::new(&arg0).file_name()?.to_str()?.to_string();
    match name.as_str() {
        "npm" | "pnpm" | "yarn" | "mvn" | "gradle" | "gradlew" => Some(name),
        _ => None,
    }
}

pub async fn run(tool: &str, args: &[String]) -> Result<()> {
    match tool {
        "npm" | "pnpm" | "yarn" => npm::dispatch(tool, args).await,
        "mvn" => {
            tracing::warn!("maven shim not implemented yet — passthrough");
            passthrough(tool, args)
        }
        "gradle" | "gradlew" => {
            tracing::warn!("gradle shim not implemented yet — passthrough");
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
    let shim_dir = crate::commands::install_shims::shim_dir().ok().map(|p| p);
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

use anyhow::Result;
use owo_colors::OwoColorize;

/// `guardep info` is the diagnostic command users run when something
/// is wrong. It should help them figure out what — version, paths,
/// shim status, cache state, etc. Strictly read-only; no fetches.
pub fn run() -> Result<()> {
    let dirs = directories::ProjectDirs::from("dev", "guardep", "guardep")
        .ok_or_else(|| anyhow::anyhow!("no project dirs"))?;

    println!("{}", "guardep diagnostic info".bold());
    println!("  version:        {}", env!("CARGO_PKG_VERSION"));
    println!("  cache dir:      {}", dirs.cache_dir().display());
    println!("  config dir:     {}", dirs.config_dir().display());

    let shim_dir = crate::commands::install_shims::shim_dir()?;
    println!("  shim dir:       {}", shim_dir.display());

    // Shim install state — does the dir exist? does the binary actually
    // symlink to ours? Is the dir on PATH?
    if shim_dir.exists() {
        let installed: Vec<String> = std::fs::read_dir(&shim_dir)
            .ok()
            .map(|it| {
                it.filter_map(|e| e.ok())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .collect()
            })
            .unwrap_or_default();
        if installed.is_empty() {
            println!("  shims:          {} (no symlinks)", "not installed".yellow());
        } else {
            println!("  shims installed: {}", installed.join(", "));
        }
        let path_var = std::env::var_os("PATH").unwrap_or_default();
        let on_path = std::env::split_paths(&path_var).any(|p| p == shim_dir);
        if on_path {
            println!("  PATH:           shim dir is on PATH (active)");
        } else if !installed.is_empty() {
            println!(
                "  PATH:           {} shim dir not on PATH; add it with `export PATH=\"{}:$PATH\"`",
                "warning:".yellow(),
                shim_dir.display()
            );
        }
    } else {
        println!("  shims:          not installed (run `guardep install-shims`)");
    }

    // Cache file existence and size — quick health check.
    let cache_db = dirs.cache_dir().join("cache.db");
    if cache_db.exists() {
        let size = std::fs::metadata(&cache_db).map(|m| m.len()).unwrap_or(0);
        println!(
            "  cache.db:       exists ({:.1} KB)",
            size as f64 / 1024.0
        );
    } else {
        println!("  cache.db:       not yet created (will populate on first audit)");
    }

    // Shipped sigstore version. If the user complains "Rekor proof
    // doesn't work" we can confirm at a glance whether they're on a
    // version where it would be expected to.
    println!();
    println!("{}", "linked dependencies".bold());
    println!("  sigstore:       {}", "0.13.x (Rekor inclusion proof not yet implemented)".dimmed());
    println!("  swc_ecma_parser: {}", "39.x".dimmed());
    println!("  rusqlite:       {}", "bundled".dimmed());

    println!();
    println!(
        "{} no-op command, no network access. For an actual audit, run `guardep audit`.",
        "i".cyan()
    );
    Ok(())
}

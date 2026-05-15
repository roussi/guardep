use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use std::path::PathBuf;

const TOOLS: &[&str] = &["npm", "pnpm", "yarn", "mvn", "gradle"];

pub fn shim_dir() -> Result<PathBuf> {
    let home = directories::BaseDirs::new()
        .ok_or_else(|| anyhow::anyhow!("no home dir"))?
        .home_dir()
        .to_path_buf();
    Ok(home.join(".guardep").join("bin"))
}

pub fn run(force: bool) -> Result<()> {
    let dir = shim_dir()?;
    std::fs::create_dir_all(&dir).context("create shim dir")?;
    let exe = std::env::current_exe()?;

    for tool in TOOLS {
        let link = dir.join(tool);
        if link.exists() {
            if !force {
                eprintln!("{} {tool} already linked — use --force to overwrite", "•".dimmed());
                continue;
            }
            std::fs::remove_file(&link)?;
        }
        symlink(&exe, &link)?;
        println!("{} {tool} → {}", "✓".green(), exe.display());
    }
    println!("\nAdd to your shell rc:");
    println!("  export PATH=\"{}:$PATH\"", dir.display());
    Ok(())
}

#[cfg(unix)]
fn symlink(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    std::os::unix::fs::symlink(src, dst)?;
    Ok(())
}

#[cfg(windows)]
fn symlink(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    std::os::windows::fs::symlink_file(src, dst)?;
    Ok(())
}

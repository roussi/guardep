use anyhow::Result;

pub fn run() -> Result<()> {
    let dirs = directories::ProjectDirs::from("dev", "guardep", "guardep")
        .ok_or_else(|| anyhow::anyhow!("no project dirs"))?;
    println!("guardep v{}", env!("CARGO_PKG_VERSION"));
    println!("cache:  {}", dirs.cache_dir().display());
    println!("config: {}", dirs.config_dir().display());
    println!("shims:  {}", crate::commands::install_shims::shim_dir()?.display());
    Ok(())
}

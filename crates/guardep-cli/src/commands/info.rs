use anyhow::Result;
use owo_colors::OwoColorize;
use std::io::Write;
use std::path::{Path, PathBuf};

/// `guardep info` is the diagnostic command users run when something
/// is wrong. It should help them figure out what — version, paths,
/// shim status, cache state, etc. Strictly read-only; no fetches.
pub fn run() -> Result<()> {
    let dirs = directories::ProjectDirs::from("dev", "guardep", "guardep")
        .ok_or_else(|| anyhow::anyhow!("no project dirs"))?;
    let shim_dir = crate::commands::install_shims::shim_dir()?;
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    let snapshot = InfoSnapshot {
        version: env!("CARGO_PKG_VERSION"),
        cache_dir: dirs.cache_dir().to_path_buf(),
        config_dir: dirs.config_dir().to_path_buf(),
        shim_dir,
        path_entries: std::env::split_paths(&path_var).collect(),
    };
    print_info(&mut std::io::stdout(), &snapshot)?;
    Ok(())
}

/// Captures the resolved paths `run` would otherwise read from the
/// host env. Lifted so `print_info` is platform-agnostic and testable
/// against a tempdir, instead of whatever `~/.cache` the test runner
/// happens to expose.
pub(crate) struct InfoSnapshot {
    pub version: &'static str,
    pub cache_dir: PathBuf,
    pub config_dir: PathBuf,
    pub shim_dir: PathBuf,
    pub path_entries: Vec<PathBuf>,
}

/// Render the diagnostic block to `out`. Returns `Ok(())` on success;
/// IO errors propagate. `run()` calls this with `std::io::stdout()`,
/// tests with a `Vec<u8>`.
pub(crate) fn print_info(out: &mut dyn Write, s: &InfoSnapshot) -> Result<()> {
    writeln!(out, "{}", "guardep diagnostic info".bold())?;
    writeln!(out, "  version:        {}", s.version)?;
    writeln!(out, "  cache dir:      {}", s.cache_dir.display())?;
    writeln!(out, "  config dir:     {}", s.config_dir.display())?;
    writeln!(out, "  shim dir:       {}", s.shim_dir.display())?;

    // Shim install state — does the dir exist? Does the binary actually
    // symlink to ours? Is the dir on PATH?
    let installed = installed_shim_names(&s.shim_dir);
    if s.shim_dir.exists() {
        if installed.is_empty() {
            writeln!(
                out,
                "  shims:          {} (no symlinks)",
                "not installed".yellow()
            )?;
        } else {
            writeln!(out, "  shims installed: {}", installed.join(", "))?;
        }
        let on_path = s.path_entries.iter().any(|p| p == &s.shim_dir);
        if on_path {
            writeln!(out, "  PATH:           shim dir is on PATH (active)")?;
        } else if !installed.is_empty() {
            writeln!(
                out,
                "  PATH:           {} shim dir not on PATH; add it with `export PATH=\"{}:$PATH\"`",
                "warning:".yellow(),
                s.shim_dir.display()
            )?;
        }
    } else {
        writeln!(
            out,
            "  shims:          not installed (run `guardep shims install`)"
        )?;
    }

    // Cache file existence and size — quick health check.
    let cache_db = s.cache_dir.join("cache.db");
    if cache_db.exists() {
        let size = std::fs::metadata(&cache_db).map(|m| m.len()).unwrap_or(0);
        writeln!(
            out,
            "  cache.db:       exists ({:.1} KB)",
            size as f64 / 1024.0
        )?;
    } else {
        writeln!(
            out,
            "  cache.db:       not yet created (will populate on first audit)"
        )?;
    }

    writeln!(out)?;
    writeln!(out, "{}", "linked dependencies".bold())?;
    writeln!(
        out,
        "  sigstore:       {}",
        "0.13.x (Rekor inclusion proof not yet implemented)".dimmed()
    )?;
    writeln!(out, "  swc_ecma_parser: {}", "39.x".dimmed())?;
    writeln!(out, "  rusqlite:       {}", "bundled".dimmed())?;

    writeln!(out)?;
    writeln!(
        out,
        "{} no-op command, no network access. For an actual audit, run `guardep audit`.",
        "i".cyan()
    )?;
    Ok(())
}

/// Filenames inside `shim_dir`. Empty when the dir doesn't exist or
/// has no entries. Lifted out so the shim-install branch in
/// `print_info` stays linear instead of nested.
fn installed_shim_names(shim_dir: &Path) -> Vec<String> {
    std::fs::read_dir(shim_dir)
        .ok()
        .map(|it| {
            it.filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn snapshot_for(
        cache_dir: PathBuf,
        shim_dir: PathBuf,
        path_entries: Vec<PathBuf>,
    ) -> InfoSnapshot {
        InfoSnapshot {
            version: "0.0.0-test",
            cache_dir: cache_dir.clone(),
            config_dir: cache_dir,
            shim_dir,
            path_entries,
        }
    }

    fn render(s: &InfoSnapshot) -> String {
        // Disable ANSI so substring assertions are stable regardless
        // of whatever sibling test flipped owo_colors first.
        owo_colors::set_override(false);
        let mut buf = Vec::new();
        print_info(&mut buf, s).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn installed_shim_names_returns_empty_for_missing_dir() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("does-not-exist");
        assert!(installed_shim_names(&missing).is_empty());
    }

    #[test]
    fn installed_shim_names_lists_present_files() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("npm"), b"shim").unwrap();
        fs::write(dir.path().join("cargo"), b"shim").unwrap();
        let mut names = installed_shim_names(dir.path());
        names.sort();
        assert_eq!(names, vec!["cargo".to_string(), "npm".to_string()]);
    }

    #[test]
    fn print_info_reports_missing_shim_dir() {
        let dir = TempDir::new().unwrap();
        let cache = dir.path().join("cache");
        let shim = dir.path().join("nope");
        fs::create_dir_all(&cache).unwrap();
        let out = render(&snapshot_for(cache, shim, vec![]));
        assert!(out.contains("guardep diagnostic info"));
        assert!(out.contains("not installed"));
        assert!(out.contains("0.0.0-test"));
    }

    #[test]
    fn print_info_reports_active_shims_when_on_path() {
        let dir = TempDir::new().unwrap();
        let cache = dir.path().join("cache");
        let shim = dir.path().join("bin");
        fs::create_dir_all(&cache).unwrap();
        fs::create_dir_all(&shim).unwrap();
        fs::write(shim.join("npm"), b"shim").unwrap();
        let out = render(&snapshot_for(cache, shim.clone(), vec![shim]));
        assert!(out.contains("shims installed: npm"));
        assert!(out.contains("on PATH (active)"));
    }

    #[test]
    fn print_info_warns_when_shims_present_but_not_on_path() {
        let dir = TempDir::new().unwrap();
        let cache = dir.path().join("cache");
        let shim = dir.path().join("bin");
        fs::create_dir_all(&cache).unwrap();
        fs::create_dir_all(&shim).unwrap();
        fs::write(shim.join("npm"), b"shim").unwrap();
        // Unrelated PATH entries — shim dir is NOT among them.
        let out = render(&snapshot_for(
            cache,
            shim,
            vec![PathBuf::from("/usr/local/bin")],
        ));
        assert!(out.contains("not on PATH"));
    }

    #[test]
    fn print_info_reports_cache_db_size() {
        let dir = TempDir::new().unwrap();
        let cache = dir.path().to_path_buf();
        fs::write(cache.join("cache.db"), vec![0u8; 2048]).unwrap();
        let shim = dir.path().join("bin-missing");
        let out = render(&snapshot_for(cache, shim, vec![]));
        assert!(out.contains("cache.db:       exists"));
        // 2048 bytes = 2.0 KB after the {:.1} format.
        assert!(out.contains("2.0 KB"), "output was: {out}");
    }

    #[test]
    fn print_info_announces_missing_cache_db() {
        let dir = TempDir::new().unwrap();
        let cache = dir.path().to_path_buf();
        let shim = dir.path().join("bin-missing");
        let out = render(&snapshot_for(cache, shim, vec![]));
        assert!(out.contains("not yet created"));
    }
}

//! `guardep shims` — manage the package-manager shims after the
//! initial `install-shims` run. Three actions: list, enable, disable.
//!
//! These commands deliberately leave PATH wiring alone. `install-shims`
//! is the entry point that edits shell rc files; `shims enable/disable`
//! only flips symlinks under `~/.guardep/bin/`, so a user can adjust
//! the gated tool set without re-running the wiring prompt.

use crate::commands::install_shims::{ensure_shim, shim_dir, ALL_TOOLS};
use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use std::fs;
use std::path::Path;

pub fn list() -> Result<()> {
    let dir = shim_dir()?;
    let exists = dir.exists();
    println!("shims dir: {}", dir.display());
    println!();
    for tool in ALL_TOOLS {
        let active = exists && dir.join(tool).exists();
        let (mark, label) = if active {
            ("✓".green().to_string(), "active".green().to_string())
        } else {
            ("·".dimmed().to_string(), "disabled".dimmed().to_string())
        };
        println!("  {mark} {tool:<8} {label}");
    }
    if !exists {
        println!();
        println!(
            "{} {} does not exist — run `guardep install-shims` first.",
            "i".cyan(),
            dir.display()
        );
    }
    Ok(())
}

pub fn enable(tools: &[String]) -> Result<()> {
    let resolved = validate_tools(tools)?;
    let dir = shim_dir()?;
    if !dir.exists() {
        anyhow::bail!(
            "{} does not exist — run `guardep install-shims` first to wire PATH, \
             then `guardep shims enable` to add tools.",
            dir.display()
        );
    }
    let exe = std::env::current_exe().context("locate current guardep binary")?;
    for tool in resolved {
        ensure_shim(&dir, tool, &exe, false)?;
    }
    Ok(())
}

pub fn disable(tools: &[String]) -> Result<()> {
    let resolved = validate_tools(tools)?;
    let dir = shim_dir()?;
    for tool in resolved {
        remove_shim(&dir, tool)?;
    }
    Ok(())
}

fn remove_shim(dir: &Path, tool: &str) -> Result<()> {
    let link = dir.join(tool);
    if !link.exists() {
        println!("{} {tool} already disabled", "·".dimmed());
        return Ok(());
    }
    fs::remove_file(&link).with_context(|| format!("remove {}", link.display()))?;
    println!("{} disabled {tool}", "✓".green());
    Ok(())
}

fn validate_tools(tools: &[String]) -> Result<Vec<&'static str>> {
    if tools.is_empty() {
        anyhow::bail!(
            "no tool specified (expected one of: {})",
            ALL_TOOLS.join(", ")
        );
    }
    let mut out: Vec<&'static str> = Vec::with_capacity(tools.len());
    for raw in tools {
        let name = raw.trim();
        let known = ALL_TOOLS
            .iter()
            .find(|t| t.eq_ignore_ascii_case(name))
            .copied();
        match known {
            Some(t) if !out.contains(&t) => out.push(t),
            Some(_) => {}
            None => anyhow::bail!(
                "unknown tool `{name}` (expected one of: {})",
                ALL_TOOLS.join(", ")
            ),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_empty_list() {
        let err = validate_tools(&[]).unwrap_err();
        assert!(format!("{err}").contains("no tool specified"));
    }

    #[test]
    fn validate_accepts_known_tools_case_insensitive() {
        let out = validate_tools(&["NPM".into(), "Cargo".into()]).unwrap();
        assert_eq!(out, vec!["npm", "cargo"]);
    }

    #[test]
    fn validate_dedups() {
        let out = validate_tools(&["npm".into(), "npm".into()]).unwrap();
        assert_eq!(out, vec!["npm"]);
    }

    #[test]
    fn validate_rejects_unknown() {
        let err = validate_tools(&["bogus".into()]).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("bogus"), "msg should mention offender: {msg}");
    }

    #[test]
    fn remove_shim_noop_when_missing() {
        let dir = tempfile::TempDir::new().unwrap();
        // Should not error even though `npm` shim does not exist.
        remove_shim(dir.path(), "npm").unwrap();
    }

    #[test]
    fn remove_shim_deletes_existing_symlink() {
        let dir = tempfile::TempDir::new().unwrap();
        let link = dir.path().join("npm");
        fs::write(&link, b"placeholder").unwrap();
        assert!(link.exists());
        remove_shim(dir.path(), "npm").unwrap();
        assert!(!link.exists());
    }
}

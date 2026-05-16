use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const ALL_TOOLS: &[&str] = &["npm", "pnpm", "yarn", "mvn", "cargo"];

/// Map (lockfile / manifest filename in cwd) → tool whose shim is
/// useful. Order mirrors `ALL_TOOLS` so detect_project_tools yields
/// stable output across runs.
const LOCKFILE_TO_TOOL: &[(&str, &str)] = &[
    ("package-lock.json", "npm"),
    ("pnpm-lock.yaml", "pnpm"),
    ("yarn.lock", "yarn"),
    ("pom.xml", "mvn"),
    ("Cargo.lock", "cargo"),
];

const MARKER_BEGIN: &str = "# >>> guardep-shim >>>";
const MARKER_END: &str = "# <<< guardep-shim <<<";
const MARKER_BEGIN_PS: &str = "# >>> guardep-shim PS >>>";
const MARKER_END_PS: &str = "# <<< guardep-shim PS <<<";

pub fn shim_dir() -> Result<PathBuf> {
    let home = directories::BaseDirs::new()
        .ok_or_else(|| anyhow::anyhow!("no home dir"))?
        .home_dir()
        .to_path_buf();
    Ok(home.join(".guardep").join("bin"))
}

pub fn run(
    force: bool,
    wire_path: bool,
    assume_yes: bool,
    requested_tools: Option<Vec<String>>,
) -> Result<()> {
    let dir = shim_dir()?;
    fs::create_dir_all(&dir).context("create shim dir")?;
    let exe = std::env::current_exe()?;

    let cwd = std::env::current_dir()?;
    let detected = detect_project_tools(&cwd);
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
    let selected = select_tools(requested_tools, &detected, assume_yes, is_tty)?;

    if selected.is_empty() {
        eprintln!("{} no tools selected — nothing to install.", "i".cyan());
        return Ok(());
    }

    for tool in &selected {
        ensure_shim(&dir, tool, &exe, force)?;
    }

    if !wire_path {
        println!("\n{} PATH wiring skipped (--no-wire-path).", "i".cyan());
        println!("Add manually:");
        println!("  export PATH=\"{}:$PATH\"", dir.display());
        return Ok(());
    }

    let targets = detect_rc_files();
    if targets.is_empty() {
        eprintln!(
            "\n{} no shell rc files found — add this to your shell init:",
            "!".yellow()
        );
        eprintln!("  export PATH=\"{}:$PATH\"", dir.display());
        return Ok(());
    }

    if !confirm_path_wiring(&targets, assume_yes)? {
        println!("\n{} PATH wiring declined.", "i".cyan());
        println!("Add manually:");
        println!("  export PATH=\"{}:$PATH\"", dir.display());
        return Ok(());
    }

    wire_path_in_shells(&dir, &targets, force)?;
    Ok(())
}

fn confirm_path_wiring(targets: &[RcTarget], assume_yes: bool) -> Result<bool> {
    if assume_yes {
        return Ok(true);
    }
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        // Non-interactive (CI, pipe). Default to yes — user opted into
        // `install-shims` explicitly; refusing silently here would leave
        // them with a half-installed gate.
        return Ok(true);
    }
    println!();
    println!("guardep wants to add `~/.guardep/bin` to your PATH by editing:");
    for t in targets {
        println!("  {}", t.path.display());
    }
    println!(
        "Each file is backed up to `<file>.guardep.bak` before any change. \
         Edits sit between marker comments so `guardep uninstall-shims` can \
         remove them cleanly."
    );
    print!("Proceed? [Y/n] ");
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut answer = String::new();
    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut answer)?;
    let trimmed = answer.trim().to_ascii_lowercase();
    Ok(matches!(trimmed.as_str(), "" | "y" | "yes"))
}

pub fn uninstall(force: bool) -> Result<()> {
    let dir = shim_dir()?;

    if dir.exists() {
        for tool in ALL_TOOLS {
            let link = dir.join(tool);
            if link.exists() {
                fs::remove_file(&link).with_context(|| format!("remove {}", link.display()))?;
                println!("{} removed shim {}", "✓".green(), link.display());
            }
        }
        // Try to remove the (now empty) bin dir; ignore failure if other
        // files were placed there manually.
        let _ = fs::remove_dir(&dir);
    }

    unwire_path_from_shells(force)?;

    println!(
        "\n{} guardep shims uninstalled. Restart your shell to pick up PATH changes.",
        "✓".green()
    );
    Ok(())
}

#[cfg(unix)]
fn symlink(src: &Path, dst: &Path) -> Result<()> {
    std::os::unix::fs::symlink(src, dst)?;
    Ok(())
}

#[cfg(windows)]
fn symlink(src: &Path, dst: &Path) -> Result<()> {
    std::os::windows::fs::symlink_file(src, dst)?;
    Ok(())
}

// ── Tool selection ───────────────────────────────────────────────────────

/// Create or refresh the symlink for `tool` in `dir`. Idempotent.
pub(crate) fn ensure_shim(dir: &Path, tool: &str, exe: &Path, force: bool) -> Result<()> {
    let link = dir.join(tool);
    if link.exists() {
        if !force {
            eprintln!(
                "{} {tool} already linked — use --force to overwrite",
                "•".dimmed()
            );
            return Ok(());
        }
        fs::remove_file(&link)?;
    }
    symlink(exe, &link)?;
    println!("{} {tool} → {}", "✓".green(), exe.display());
    Ok(())
}

/// Walk `cwd` for known lockfile/manifest names and return the
/// matching tools in `ALL_TOOLS` order. No recursion — only the
/// immediate cwd, since shim install is a one-time setup decision,
/// not a build-time scan.
pub fn detect_project_tools(cwd: &Path) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for (file, tool) in LOCKFILE_TO_TOOL {
        if cwd.join(file).exists() && !out.contains(tool) {
            out.push(*tool);
        }
    }
    out
}

/// Decide which tools to wire based on (a) explicit `--tools`, (b)
/// detected lockfiles in cwd, (c) interactive prompt, and (d) whether
/// we're attached to a TTY. CI / piped invocations preserve the v0
/// behaviour: install every tool when no flag is given.
pub fn select_tools(
    requested: Option<Vec<String>>,
    detected: &[&'static str],
    assume_yes: bool,
    is_tty: bool,
) -> Result<Vec<&'static str>> {
    if let Some(list) = requested {
        return resolve_requested(&list);
    }

    if !is_tty || assume_yes {
        // Non-interactive / -y: trust detection or fall back to all.
        // Falling back to `ALL_TOOLS` mirrors the prior behaviour for
        // users running `guardep install-shims` globally outside any
        // project directory.
        if detected.is_empty() {
            return Ok(ALL_TOOLS.to_vec());
        }
        return Ok(detected.to_vec());
    }

    interactive_pick(detected)
}

fn resolve_requested(list: &[String]) -> Result<Vec<&'static str>> {
    let mut out: Vec<&'static str> = Vec::new();
    for raw in list {
        let name = raw.trim();
        if name.is_empty() {
            continue;
        }
        if name.eq_ignore_ascii_case("all") {
            return Ok(ALL_TOOLS.to_vec());
        }
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

fn interactive_pick(detected: &[&'static str]) -> Result<Vec<&'static str>> {
    println!();
    if detected.is_empty() {
        println!("No lockfiles detected in cwd — defaulting to all tools.");
    } else {
        println!("Detected in cwd: {}", detected.join(", "));
    }
    println!();
    println!("Tools that can be gated:");
    for tool in ALL_TOOLS {
        let mark = if detected.contains(tool) { "x" } else { " " };
        println!("  [{mark}] {tool}");
    }
    println!();
    print!("Accept selection? [Y/n/edit] ");
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut answer = String::new();
    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut answer)?;
    let trimmed = answer.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "" | "y" | "yes" => {
            if detected.is_empty() {
                Ok(ALL_TOOLS.to_vec())
            } else {
                Ok(detected.to_vec())
            }
        }
        "n" | "no" => Ok(vec![]),
        "e" | "edit" => prompt_custom_list(),
        // Any other input is treated as a comma list to keep one-shot
        // selection ergonomic (`npm,cargo` + Enter just works).
        _ => resolve_requested(
            &answer
                .trim()
                .split(',')
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        ),
    }
}

fn prompt_custom_list() -> Result<Vec<&'static str>> {
    print!("Enter comma-separated tools to enable (e.g. npm,cargo): ");
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut answer = String::new();
    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut answer)?;
    let list: Vec<String> = answer
        .trim()
        .split(',')
        .map(|s| s.to_string())
        .filter(|s| !s.trim().is_empty())
        .collect();
    resolve_requested(&list)
}

// ── PATH wiring ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum RcKind {
    PosixShell,
    Fish,
    PowerShell,
}

struct RcTarget {
    path: PathBuf,
    kind: RcKind,
}

fn wire_path_in_shells(shim_dir: &Path, targets: &[RcTarget], force: bool) -> Result<()> {
    println!();
    for target in targets {
        match inject_into(target, shim_dir, force) {
            Ok(InjectionResult::Inserted) => {
                println!("{} wired PATH in {}", "✓".green(), target.path.display());
            }
            Ok(InjectionResult::AlreadyPresent) => {
                println!(
                    "{} PATH already wired in {}",
                    "•".dimmed(),
                    target.path.display()
                );
            }
            Err(e) => {
                eprintln!(
                    "{} could not wire {}: {e}",
                    "!".yellow(),
                    target.path.display()
                );
            }
        }
    }

    println!(
        "\n{} restart your shell or `source` the rc file to activate.",
        "i".cyan()
    );
    Ok(())
}

fn unwire_path_from_shells(_force: bool) -> Result<()> {
    let targets = detect_rc_files();
    println!();
    for target in &targets {
        match remove_from(target) {
            Ok(true) => {
                println!(
                    "{} removed guardep PATH block from {}",
                    "✓".green(),
                    target.path.display()
                );
            }
            Ok(false) => {
                // Quiet — file simply didn't have the block.
            }
            Err(e) => {
                eprintln!(
                    "{} could not edit {}: {e}",
                    "!".yellow(),
                    target.path.display()
                );
            }
        }
    }
    Ok(())
}

fn detect_rc_files() -> Vec<RcTarget> {
    let home = match directories::BaseDirs::new() {
        Some(b) => b.home_dir().to_path_buf(),
        None => return vec![],
    };

    let mut out = vec![];

    if cfg!(target_os = "windows") {
        if let Some(profile) = powershell_profile_path(&home) {
            out.push(RcTarget {
                path: profile,
                kind: RcKind::PowerShell,
            });
        }
    } else {
        let candidates: &[(PathBuf, RcKind)] = &[
            (home.join(".zshrc"), RcKind::PosixShell),
            (home.join(".bashrc"), RcKind::PosixShell),
            (home.join(".bash_profile"), RcKind::PosixShell),
            (home.join(".config/fish/config.fish"), RcKind::Fish),
        ];
        for (path, kind) in candidates {
            if path.exists() {
                out.push(RcTarget {
                    path: path.clone(),
                    kind: *kind,
                });
            }
        }
    }
    out
}

fn powershell_profile_path(home: &Path) -> Option<PathBuf> {
    // Default $PROFILE for PowerShell 7+ on Windows. Older Windows
    // PowerShell 5.1 uses `WindowsPowerShell` instead, but PS 7 is the
    // shipped default since Windows 11 / Server 2022.
    let p = home
        .join("Documents")
        .join("PowerShell")
        .join("Microsoft.PowerShell_profile.ps1");
    Some(p)
}

#[derive(Debug)]
enum InjectionResult {
    Inserted,
    AlreadyPresent,
}

fn inject_into(target: &RcTarget, shim_dir: &Path, force: bool) -> Result<InjectionResult> {
    let existing = fs::read_to_string(&target.path).unwrap_or_default();
    let begin = match target.kind {
        RcKind::PowerShell => MARKER_BEGIN_PS,
        _ => MARKER_BEGIN,
    };
    if existing.contains(begin) && !force {
        return Ok(InjectionResult::AlreadyPresent);
    }
    if existing.contains(begin) && force {
        // --force: strip old block first so the file can't accumulate
        // duplicate guardep blocks across re-installs.
        remove_from(target)?;
    }

    backup_once(&target.path)?;

    let snippet = render_snippet(target.kind, shim_dir);
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&target.path)
        .with_context(|| format!("open {} for append", target.path.display()))?;

    if let Some(parent) = target.path.parent() {
        fs::create_dir_all(parent).ok();
    }

    if !existing.is_empty() && !existing.ends_with('\n') {
        file.write_all(b"\n")?;
    }
    file.write_all(snippet.as_bytes())?;
    Ok(InjectionResult::Inserted)
}

fn remove_from(target: &RcTarget) -> Result<bool> {
    let existing = match fs::read_to_string(&target.path) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    let (begin, end) = match target.kind {
        RcKind::PowerShell => (MARKER_BEGIN_PS, MARKER_END_PS),
        _ => (MARKER_BEGIN, MARKER_END),
    };
    if !existing.contains(begin) {
        return Ok(false);
    }

    let stripped = strip_block(&existing, begin, end);
    backup_once(&target.path)?;
    fs::write(&target.path, stripped)
        .with_context(|| format!("write {}", target.path.display()))?;
    Ok(true)
}

fn strip_block(content: &str, begin: &str, end: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut skipping = false;
    for line in content.split_inclusive('\n') {
        if !skipping && line.trim_end_matches(['\r', '\n']) == begin {
            skipping = true;
            continue;
        }
        if skipping {
            if line.trim_end_matches(['\r', '\n']) == end {
                skipping = false;
            }
            continue;
        }
        out.push_str(line);
    }
    out
}

fn render_snippet(kind: RcKind, shim_dir: &Path) -> String {
    let dir = shim_dir.display();
    match kind {
        RcKind::PosixShell => format!(
            "{MARKER_BEGIN}\n# Added by `guardep install-shims`. Remove with `guardep uninstall-shims`.\ncase \":$PATH:\" in\n  *\":{dir}:\"*) ;;\n  *) export PATH=\"{dir}:$PATH\" ;;\nesac\n{MARKER_END}\n"
        ),
        RcKind::Fish => format!(
            "{MARKER_BEGIN}\n# Added by `guardep install-shims`. Remove with `guardep uninstall-shims`.\nif not contains \"{dir}\" $PATH\n    set -gx PATH \"{dir}\" $PATH\nend\n{MARKER_END}\n"
        ),
        RcKind::PowerShell => format!(
            "{MARKER_BEGIN_PS}\n# Added by `guardep install-shims`. Remove with `guardep uninstall-shims`.\n$guardepBin = \"{dir}\"\nif (-not (($env:PATH -split [IO.Path]::PathSeparator) -contains $guardepBin)) {{\n    $env:PATH = \"$guardepBin$([IO.Path]::PathSeparator)$env:PATH\"\n}}\n{MARKER_END_PS}\n"
        ),
    }
}

fn backup_once(rc: &Path) -> Result<()> {
    let mut backup = rc.as_os_str().to_owned();
    backup.push(".guardep.bak");
    let backup_path = PathBuf::from(backup);
    if !backup_path.exists() && rc.exists() {
        fs::copy(rc, &backup_path)
            .with_context(|| format!("backup {} to {}", rc.display(), backup_path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_removes_marker_block() {
        let input = "before\n# >>> guardep-shim >>>\ninner\n# <<< guardep-shim <<<\nafter\n";
        let out = strip_block(input, MARKER_BEGIN, MARKER_END);
        assert_eq!(out, "before\nafter\n");
    }

    #[test]
    fn strip_no_block_returns_input() {
        let input = "before\nafter\n";
        let out = strip_block(input, MARKER_BEGIN, MARKER_END);
        assert_eq!(out, input);
    }

    #[test]
    fn strip_multiple_blocks_removes_all() {
        let input = "a\n# >>> guardep-shim >>>\nx\n# <<< guardep-shim <<<\nb\n# >>> guardep-shim >>>\ny\n# <<< guardep-shim <<<\nc\n";
        let out = strip_block(input, MARKER_BEGIN, MARKER_END);
        assert_eq!(out, "a\nb\nc\n");
    }

    #[test]
    fn render_posix_uses_case_guard() {
        let snippet = render_snippet(RcKind::PosixShell, Path::new("/home/u/.guardep/bin"));
        assert!(snippet.contains("case \":$PATH:\""));
        assert!(snippet.contains("export PATH=\"/home/u/.guardep/bin:$PATH\""));
        assert!(snippet.contains(MARKER_BEGIN));
        assert!(snippet.contains(MARKER_END));
    }

    #[test]
    fn render_fish_uses_contains_guard() {
        let snippet = render_snippet(RcKind::Fish, Path::new("/home/u/.guardep/bin"));
        assert!(snippet.contains("if not contains"));
        assert!(snippet.contains("set -gx PATH"));
    }

    #[test]
    fn render_powershell_uses_path_separator() {
        let snippet = render_snippet(RcKind::PowerShell, Path::new("C:\\Users\\u\\.guardep\\bin"));
        assert!(snippet.contains("$env:PATH"));
        assert!(snippet.contains(MARKER_BEGIN_PS));
        assert!(snippet.contains(MARKER_END_PS));
    }

    fn touch(dir: &Path, name: &str) {
        fs::write(dir.join(name), b"").unwrap();
    }

    #[test]
    fn detect_returns_empty_for_blank_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        assert_eq!(detect_project_tools(dir.path()), Vec::<&'static str>::new());
    }

    #[test]
    fn detect_finds_npm_only() {
        let dir = tempfile::TempDir::new().unwrap();
        touch(dir.path(), "package-lock.json");
        assert_eq!(detect_project_tools(dir.path()), vec!["npm"]);
    }

    #[test]
    fn detect_finds_npm_and_cargo_in_stable_order() {
        let dir = tempfile::TempDir::new().unwrap();
        touch(dir.path(), "Cargo.lock");
        touch(dir.path(), "package-lock.json");
        // npm comes first because LOCKFILE_TO_TOOL lists it first.
        assert_eq!(detect_project_tools(dir.path()), vec!["npm", "cargo"]);
    }

    #[test]
    fn select_with_explicit_list_returns_those() {
        let got = select_tools(Some(vec!["npm".into(), "cargo".into()]), &[], false, true).unwrap();
        assert_eq!(got, vec!["npm", "cargo"]);
    }

    #[test]
    fn select_with_all_keyword_returns_all_tools() {
        let got = select_tools(Some(vec!["all".into()]), &[], false, true).unwrap();
        assert_eq!(got, ALL_TOOLS.to_vec());
    }

    #[test]
    fn select_rejects_unknown_tool() {
        let err = select_tools(Some(vec!["bogus".into()]), &[], false, true).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("bogus"),
            "msg should mention offending tool: {msg}"
        );
    }

    #[test]
    fn select_non_tty_no_detection_returns_all_tools() {
        let got = select_tools(None, &[], false, false).unwrap();
        assert_eq!(got, ALL_TOOLS.to_vec());
    }

    #[test]
    fn select_non_tty_with_detection_returns_detected() {
        let got = select_tools(None, &["npm", "cargo"], false, false).unwrap();
        assert_eq!(got, vec!["npm", "cargo"]);
    }

    #[test]
    fn select_assume_yes_uses_detection_even_on_tty() {
        let got = select_tools(None, &["mvn"], true, true).unwrap();
        assert_eq!(got, vec!["mvn"]);
    }
}

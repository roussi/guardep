use crate::commands::audit;
use crate::shim::{locate_real_binary, passthrough};
use anyhow::Result;
use owo_colors::OwoColorize;
use std::path::PathBuf;

const INTERCEPTED: &[&str] = &["install", "i", "add", "ci", "update", "upgrade"];

pub async fn dispatch(tool: &str, args: &[String]) -> Result<()> {
    let subcommand = args.iter().find(|a| !a.starts_with('-')).map(|s| s.as_str());

    let should_intercept = subcommand
        .map(|s| INTERCEPTED.contains(&s))
        .unwrap_or(false);

    if !should_intercept {
        return passthrough(tool, args);
    }

    eprintln!("{} guardep: pre-install audit ({tool} {})", "→".cyan(), subcommand.unwrap_or(""));

    let project_root = std::env::current_dir()?;
    let lock_path = project_root.join("package-lock.json");
    if !lock_path.exists() {
        eprintln!(
            "{} no package-lock.json — running install then post-audit",
            "!".yellow()
        );
        run_real(tool, args)?;
        return audit::run(&project_root, audit::Format::Table, false, false).await;
    }

    let verdict = audit::evaluate_project(&project_root, false).await?;
    if verdict.should_block() {
        crate::report::print_verdict(&verdict, false);
        eprintln!(
            "\n{} {} install blocked by guardep policy",
            "✗".red().bold(),
            tool.bold()
        );
        std::process::exit(2);
    }
    if verdict.has_warnings() {
        crate::report::print_verdict(&verdict, false);
    }

    run_real(tool, args)
}

fn run_real(tool: &str, args: &[String]) -> Result<()> {
    let real: PathBuf = locate_real_binary(tool)?;
    let status = std::process::Command::new(real).args(args).status()?;
    std::process::exit(status.code().unwrap_or(1));
}

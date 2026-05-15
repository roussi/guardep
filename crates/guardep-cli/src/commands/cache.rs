//! `guardep cache prune` — drop entries older than N days.
//!
//! The cache is keyed by `(ecosystem, name, version)`. As packages
//! get bumped over time, old version rows accumulate and the file
//! grows monotonically. Pruning removes anything not refreshed in
//! the last N days, then VACUUMs.

use anyhow::Result;
use guardep_core::cache::KvCache;
use owo_colors::OwoColorize;

pub fn prune(days: i64) -> Result<()> {
    let dirs = directories::ProjectDirs::from("dev", "guardep", "guardep")
        .ok_or_else(|| anyhow::anyhow!("no project dirs"))?;
    let cache_db = dirs.cache_dir().join("cache.db");

    if !cache_db.exists() {
        eprintln!("{} cache.db doesn't exist; nothing to prune.", "i".cyan());
        return Ok(());
    }

    let size_before = std::fs::metadata(&cache_db).map(|m| m.len()).unwrap_or(0);
    // TTL on KvCache governs reads, not the prune cutoff. Use a short
    // TTL here so we can immediately read stats afterwards.
    let cache = KvCache::open(&cache_db, 24)?;
    let stats_before = cache.stats()?;

    let spinner = indicatif::ProgressBar::new_spinner();
    spinner.set_style(
        indicatif::ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap_or_else(|_| indicatif::ProgressStyle::default_spinner()),
    );
    spinner.set_message(format!("pruning rows older than {days} days…"));
    spinner.enable_steady_tick(std::time::Duration::from_millis(80));
    let removed = cache.prune_older_than(days);
    spinner.set_message("vacuuming…");
    let stats_after = cache.stats()?;
    drop(cache);
    spinner.finish_and_clear();
    let removed = removed?;

    let size_after = std::fs::metadata(&cache_db).map(|m| m.len()).unwrap_or(0);

    println!(
        "{} pruned {} row(s) older than {} days",
        "OK".green().bold(),
        removed,
        days
    );
    println!(
        "  rows:  {} -> {}",
        stats_before.row_count, stats_after.row_count
    );
    println!(
        "  size:  {:.1} KB -> {:.1} KB",
        size_before as f64 / 1024.0,
        size_after as f64 / 1024.0
    );
    Ok(())
}

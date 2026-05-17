//! `guardep cache prune` — drop entries older than N days.
//!
//! The cache is keyed by `(ecosystem, name, version)`. As packages
//! get bumped over time, old version rows accumulate and the file
//! grows monotonically. Pruning removes anything not refreshed in
//! the last N days, then VACUUMs.

use anyhow::Result;
use guardep_core::cache::KvCache;
use owo_colors::OwoColorize;
use std::path::Path;

pub fn prune(days: i64) -> Result<()> {
    let dirs = directories::ProjectDirs::from("dev", "guardep", "guardep")
        .ok_or_else(|| anyhow::anyhow!("no project dirs"))?;
    let cache_db = dirs.cache_dir().join("cache.db");
    prune_at(&cache_db, days).map(|_| ())
}

/// Pure prune entrypoint: takes the cache db path explicitly so the
/// `directories::ProjectDirs` lookup (which depends on `$HOME` and
/// platform-specific dirs) lives in `prune`. Tests can drive this
/// against a tempdir without polluting the user's real cache.
pub fn prune_at(cache_db: &Path, days: i64) -> Result<usize> {
    if !cache_db.exists() {
        eprintln!("{} cache.db doesn't exist; nothing to prune.", "i".cyan());
        return Ok(0);
    }

    let size_before = std::fs::metadata(cache_db).map(|m| m.len()).unwrap_or(0);
    // TTL on KvCache governs reads, not the prune cutoff. Use a short
    // TTL here so we can immediately read stats afterwards.
    let cache = KvCache::open(cache_db, 24)?;
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

    let size_after = std::fs::metadata(cache_db).map(|m| m.len()).unwrap_or(0);

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
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Force a row's `fetched_at` to `now - age_seconds`. KvCache::put
    /// always stamps `now`, so we backdate via a raw UPDATE against the
    /// connection the test owns. Avoids `sleep`-based fixtures.
    fn put_backdated(db: &Path, namespace: &str, key: &str, age_seconds: i64) {
        let cache = KvCache::open(db, 24).unwrap();
        cache.put(namespace, key, "{}").unwrap();
        drop(cache);
        let now = chrono::Utc::now().timestamp();
        let conn = rusqlite::Connection::open(db).unwrap();
        conn.execute(
            "UPDATE kv_cache SET fetched_at = ?1 WHERE namespace = ?2 AND key = ?3",
            rusqlite::params![now - age_seconds, namespace, key],
        )
        .unwrap();
    }

    #[test]
    fn prune_at_returns_zero_when_db_missing() {
        let dir = TempDir::new().unwrap();
        let removed = prune_at(&dir.path().join("nonexistent.db"), 30).unwrap();
        assert_eq!(removed, 0);
    }

    #[test]
    fn prune_at_drops_only_stale_rows() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("cache.db");

        let day = 86_400;
        put_backdated(&db, "osv", "fresh", day); // 1 day old
        put_backdated(&db, "osv", "borderline", 30 * day - 10); // just inside the 30-day window
        put_backdated(&db, "osv", "stale1", 31 * day);
        put_backdated(&db, "osv", "stale2", 90 * day);

        let removed = prune_at(&db, 30).unwrap();
        assert_eq!(removed, 2, "expected both stale rows to be pruned");

        let cache = KvCache::open(&db, 24).unwrap();
        assert_eq!(cache.stats().unwrap().row_count, 2);
    }

    #[test]
    fn prune_at_is_no_op_when_nothing_stale() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("cache.db");
        let cache = KvCache::open(&db, 24).unwrap();
        cache.put("ns", "fresh", "{}").unwrap();
        drop(cache);

        let removed = prune_at(&db, 30).unwrap();
        assert_eq!(removed, 0);

        let cache = KvCache::open(&db, 24).unwrap();
        assert_eq!(cache.stats().unwrap().row_count, 1);
    }
}

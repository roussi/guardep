//! Unified SQLite cache shared across all evaluators.
//!
//! One file (`cache.db`), one schema, namespaced rows. Each evaluator
//! gets a logical "namespace" (e.g. `"osv"`, `"intel"`, `"provenance"`).
//! Within a namespace, rows are keyed by an opaque string the caller
//! defines (`"<eco>:<name>:<version>"` for OSV; `"<name>"` for intel;
//! `"<name>@<version>"` for provenance).

use crate::advisory::Advisory;
use crate::ecosystem::PackageRef;
use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS kv_cache (
    namespace  TEXT NOT NULL,
    key        TEXT NOT NULL,
    fetched_at INTEGER NOT NULL,
    payload    TEXT NOT NULL,
    PRIMARY KEY (namespace, key)
);
CREATE INDEX IF NOT EXISTS idx_kv_namespace ON kv_cache (namespace);
"#;

/// Generic key/value cache with TTL. Thread-safe via internal mutex
/// because `rusqlite::Connection` is not `Sync`.
pub struct KvCache {
    conn: Mutex<Connection>,
    ttl_hours: i64,
}

impl KvCache {
    pub fn open(path: &Path, ttl_hours: u64) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path).context("open cache db")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Mutex::new(conn),
            ttl_hours: ttl_hours as i64,
        })
    }

    pub fn get(&self, namespace: &str, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().expect("kv cache mutex poisoned");
        let row = conn
            .query_row(
                "SELECT fetched_at, payload FROM kv_cache WHERE namespace = ?1 AND key = ?2",
                params![namespace, key],
                |r| {
                    let ts: i64 = r.get(0)?;
                    let payload: String = r.get(1)?;
                    Ok((ts, payload))
                },
            )
            .ok();
        let Some((ts, payload)) = row else {
            return Ok(None);
        };
        let cutoff = (Utc::now() - Duration::hours(self.ttl_hours)).timestamp();
        if ts < cutoff {
            return Ok(None);
        }
        Ok(Some(payload))
    }

    /// Fetch the raw payload regardless of TTL. Useful for diff-style
    /// detectors (e.g. new-maintainer) that want to compare a fresh
    /// upstream snapshot against the previously cached one even when
    /// the TTL has expired.
    pub fn get_any(&self, namespace: &str, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().expect("kv cache mutex poisoned");
        let row = conn
            .query_row(
                "SELECT payload FROM kv_cache WHERE namespace = ?1 AND key = ?2",
                params![namespace, key],
                |r| r.get::<_, String>(0),
            )
            .ok();
        Ok(row)
    }

    pub fn put(&self, namespace: &str, key: &str, payload: &str) -> Result<()> {
        let conn = self.conn.lock().expect("kv cache mutex poisoned");
        conn.execute(
            "INSERT OR REPLACE INTO kv_cache (namespace, key, fetched_at, payload)
             VALUES (?1, ?2, ?3, ?4)",
            params![namespace, key, Utc::now().timestamp(), payload],
        )?;
        Ok(())
    }

    /// Delete rows older than `days` and VACUUM the file. Used by
    /// `guardep cache prune` to keep the cache from growing
    /// monotonically as old package versions accumulate.
    pub fn prune_older_than(&self, days: i64) -> Result<usize> {
        let cutoff = (Utc::now() - Duration::days(days)).timestamp();
        let conn = self.conn.lock().expect("kv cache mutex poisoned");
        let removed = conn.execute(
            "DELETE FROM kv_cache WHERE fetched_at < ?1",
            params![cutoff],
        )?;
        // VACUUM reclaims space from deleted rows. Cheap on a few-MB
        // file; we'd skip it on multi-GB caches but we're not there.
        conn.execute_batch("VACUUM")?;
        Ok(removed)
    }

    /// Total row count + on-disk size estimate. Used by `guardep info`
    /// to surface cache health.
    pub fn stats(&self) -> Result<CacheStats> {
        let conn = self.conn.lock().expect("kv cache mutex poisoned");
        let rows: i64 = conn.query_row("SELECT COUNT(*) FROM kv_cache", [], |r| r.get(0))?;
        Ok(CacheStats {
            row_count: rows as usize,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CacheStats {
    pub row_count: usize,
}

/// Backwards-compatible advisory cache wrapper for the OSV evaluator.
/// Keeps the existing `get(&PackageRef) -> Vec<Advisory>` shape so
/// `OsvEvaluator` doesn't need to know about JSON serialization.
pub struct Cache<'a> {
    inner: &'a KvCache,
    namespace: &'static str,
}

impl<'a> Cache<'a> {
    pub fn new(inner: &'a KvCache) -> Self {
        Self {
            inner,
            namespace: "osv",
        }
    }

    pub fn get(&self, pkg: &PackageRef) -> Result<Option<Vec<Advisory>>> {
        let key = key_for(pkg);
        let Some(payload) = self.inner.get(self.namespace, &key)? else {
            return Ok(None);
        };
        let advisories: Vec<Advisory> = serde_json::from_str(&payload)?;
        Ok(Some(advisories))
    }

    pub fn put(&self, pkg: &PackageRef, advisories: &[Advisory]) -> Result<()> {
        let key = key_for(pkg);
        let payload = serde_json::to_string(advisories)?;
        self.inner.put(self.namespace, &key, &payload)
    }
}

fn key_for(pkg: &PackageRef) -> String {
    format!("{}:{}:{}", pkg.ecosystem.as_osv(), pkg.name, pkg.version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn kv_roundtrip() {
        let dir = TempDir::new().unwrap();
        let kv = KvCache::open(&dir.path().join("cache.db"), 24).unwrap();
        kv.put("ns", "k", "value").unwrap();
        assert_eq!(kv.get("ns", "k").unwrap().as_deref(), Some("value"));
    }

    #[test]
    fn kv_namespace_isolation() {
        let dir = TempDir::new().unwrap();
        let kv = KvCache::open(&dir.path().join("cache.db"), 24).unwrap();
        kv.put("a", "k", "alpha").unwrap();
        kv.put("b", "k", "beta").unwrap();
        assert_eq!(kv.get("a", "k").unwrap().as_deref(), Some("alpha"));
        assert_eq!(kv.get("b", "k").unwrap().as_deref(), Some("beta"));
    }

    #[test]
    fn kv_ttl_expires() {
        let dir = TempDir::new().unwrap();
        let kv = KvCache::open(&dir.path().join("cache.db"), 0).unwrap();
        kv.put("ns", "k", "v").unwrap();
        // ttl_hours == 0 means cutoff equals now; the row is exactly at
        // cutoff and considered stale.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(kv.get("ns", "k").unwrap().is_none());
    }
}

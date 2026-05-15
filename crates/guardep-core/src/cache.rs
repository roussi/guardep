use crate::advisory::Advisory;
use crate::ecosystem::PackageRef;
use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use rusqlite::{params, Connection};
use std::path::Path;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS advisory_cache (
    ecosystem TEXT NOT NULL,
    package   TEXT NOT NULL,
    version   TEXT NOT NULL,
    fetched_at INTEGER NOT NULL,
    payload   TEXT NOT NULL,
    PRIMARY KEY (ecosystem, package, version)
);
"#;

pub struct Cache {
    conn: Connection,
    ttl_hours: i64,
}

impl Cache {
    pub fn open(path: &Path, ttl_hours: u64) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path).context("open cache db")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn,
            ttl_hours: ttl_hours as i64,
        })
    }

    pub fn get(&self, pkg: &PackageRef) -> Result<Option<Vec<Advisory>>> {
        let mut stmt = self.conn.prepare(
            "SELECT fetched_at, payload FROM advisory_cache
             WHERE ecosystem = ?1 AND package = ?2 AND version = ?3",
        )?;
        let row = stmt
            .query_row(
                params![pkg.ecosystem.as_osv(), pkg.name, pkg.version],
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
        let advisories: Vec<Advisory> = serde_json::from_str(&payload)?;
        Ok(Some(advisories))
    }

    pub fn put(&self, pkg: &PackageRef, advisories: &[Advisory]) -> Result<()> {
        let payload = serde_json::to_string(advisories)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO advisory_cache
             (ecosystem, package, version, fetched_at, payload)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                pkg.ecosystem.as_osv(),
                pkg.name,
                pkg.version,
                Utc::now().timestamp(),
                payload
            ],
        )?;
        Ok(())
    }
}

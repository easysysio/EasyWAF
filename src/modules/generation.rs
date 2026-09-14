// =========================================================
// modules/generation.rs — EasyWAF
// When inspection's configuration last changed, and a cache
// of each site's configuration that forgets everything the
// moment it does.
//
// Reading a site's policy, rules and exclusions was three
// queries on every request, and at 138 rules it was 95% of
// what inspection cost. None of it changes except when an
// administrator clicks something.
//
// The difficulty was never the cache; it was knowing when to
// empty it. Those rows are written from about thirty places,
// so the database keeps a counter that triggers move on every
// write (migration 025), and this module compares it at most
// once a second. No handler takes part, so none can forget
// to.
// =========================================================

use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

/// How stale a module's view of the configuration may become.
///
/// One second: short enough that disabling a rule to stop it blocking somebody
/// has taken effect before they have finished reloading the page, and long
/// enough that the check is at most one small read a second however much
/// traffic is arriving.
pub const MAX_AGE: Duration = Duration::from_secs(1);

// ─── The generation ──────────────────────────────────────

struct Seen {
    value:   u64,
    checked: Option<Instant>,
}

/// One value for the process. There is one database, and a module that read a
/// different number from another would cache against a different version of
/// the same configuration.
static SEEN: OnceLock<Mutex<Seen>> = OnceLock::new();

fn seen() -> &'static Mutex<Seen> {
    SEEN.get_or_init(|| Mutex::new(Seen { value: 0, checked: None }))
}

/// The configuration generation, read from the database at most once per
/// [`MAX_AGE`].
pub async fn current(db: &SqlitePool) -> u64 {
    if let Ok(s) = seen().lock()
        && let Some(at) = s.checked
        && at.elapsed() < MAX_AGE
    {
        return s.value;
    }

    // The lock is not held across this await: a std mutex held through a query
    // would stall a runtime thread for its duration. Two requests arriving as
    // the second expires may both read — a pair of tiny reads, not a problem.
    let read = sqlx::query_scalar!(
        r#"SELECT value as "value!: i64" FROM config_generation WHERE id = 1"#
    )
    .fetch_one(db)
    .await;

    let mut s = match seen().lock() {
        Ok(s)  => s,
        Err(p) => p.into_inner(),
    };
    match read {
        Ok(v)  => s.value = v as u64,
        // The last value is kept and the attempt still counts as a check, so a
        // database in trouble costs one read a second rather than one per
        // request, and inspection goes on using what it last knew — which beats
        // failing every request until the database recovers.
        Err(e) => tracing::warn!("Could not read the configuration generation: {e}"),
    }
    s.checked = Some(Instant::now());
    s.value
}

// ─── PerSite ─────────────────────────────────────────────

/// A value per site, valid for exactly one generation.
///
/// Held by each module that needs a site's configuration on every request. It
/// never serves an entry stored under a different generation, and moving to a
/// newer one forgets every site at once rather than site by site — a policy is
/// shared, so one write can change what many sites should see.
pub struct PerSite<T> {
    inner: RwLock<Entries<T>>,
}

struct Entries<T> {
    generation: u64,
    by_site:    HashMap<i64, Arc<T>>,
}

impl<T> PerSite<T> {
    pub fn new() -> Self {
        Self { inner: RwLock::new(Entries { generation: 0, by_site: HashMap::new() }) }
    }

    /// The value for this site if it was stored under this generation.
    pub fn get(&self, generation: u64, site_id: i64) -> Option<Arc<T>> {
        let e = self.inner.read().ok()?;
        if e.generation != generation {
            return None;
        }
        e.by_site.get(&site_id).cloned()
    }

    /// Store a value read at `generation`, and hand it back.
    ///
    /// A value read at an **older** generation than the cache already holds is
    /// returned but not kept. That happens when a slow read loses a race with a
    /// faster one that saw a newer write, and keeping it would put stale rows
    /// back after fresh ones had already replaced them.
    pub fn put(&self, generation: u64, site_id: i64, value: T) -> Arc<T> {
        let value = Arc::new(value);
        if let Ok(mut e) = self.inner.write() {
            if generation > e.generation {
                e.by_site.clear();
                e.generation = generation;
            }
            if generation == e.generation {
                e.by_site.insert(site_id, value.clone());
            }
        }
        value
    }
}

impl<T> Default for PerSite<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_is_served_only_for_the_generation_it_was_read_at() {
        let c: PerSite<&str> = PerSite::new();
        c.put(5, 1, "rules as of 5");
        assert_eq!(c.get(5, 1).as_deref(), Some(&"rules as of 5"));
        assert!(c.get(6, 1).is_none(), "a newer generation must not see the old rules");
        assert!(c.get(5, 2).is_none(), "another site has nothing cached");
    }

    #[test]
    fn a_newer_generation_forgets_every_site_at_once() {
        // A policy is shared: one write can change what several sites should
        // see, so moving on has to drop all of them, not only the one asked for.
        let c: PerSite<&str> = PerSite::new();
        c.put(5, 1, "site 1");
        c.put(5, 2, "site 2");
        c.put(6, 1, "site 1, newer");
        assert!(c.get(6, 2).is_none(), "site 2's entry from generation 5 survived");
        assert_eq!(c.get(6, 1).as_deref(), Some(&"site 1, newer"));
    }

    #[test]
    fn a_slow_read_from_an_older_generation_is_not_kept() {
        // Two requests race: the fast one reads after a write and stores 7; the
        // slow one started before the write and arrives with 6. Keeping it
        // would put the rules from before the write back.
        let c: PerSite<&str> = PerSite::new();
        c.put(7, 1, "after the write");
        let returned = c.put(6, 1, "before the write");
        assert_eq!(*returned, "before the write", "the caller still gets what it read");
        assert_eq!(c.get(7, 1).as_deref(), Some(&"after the write"),
                   "the stale read replaced the fresh one");
    }

    /// Every write to what inspection reads must move the counter — this is the
    /// whole of the invalidation, so it is checked table by table and operation
    /// by operation rather than trusted.
    #[tokio::test]
    async fn every_write_to_what_inspection_reads_moves_the_generation() {
        let path = std::env::temp_dir()
            .join(format!("easywaf-generation-{}.db", std::process::id()));
        for sfx in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{}{sfx}", path.display())); }
        let db = crate::db::init(&format!("sqlite://{}", path.display())).await;

        let value = || async {
            sqlx::query_scalar::<_, i64>("SELECT value FROM config_generation WHERE id = 1")
                .fetch_one(&db).await.unwrap()
        };

        let writes: &[(&str, &str)] = &[
            ("policies insert",   "INSERT INTO policies (name) VALUES ('g')"),
            ("policies update",   "UPDATE policies SET score_threshold = 11 WHERE name = 'g'"),
            ("sites insert",      "INSERT INTO sites (name, server_name, target, waf_policy_id)
                                   VALUES ('g', 'g.example', 'http://x', (SELECT id FROM policies WHERE name = 'g'))"),
            ("sites update",      "UPDATE sites SET enabled = 0 WHERE name = 'g'"),
            ("rules insert",      "INSERT INTO waf_rules (policy_id, name, pattern)
                                   VALUES ((SELECT id FROM policies WHERE name = 'g'), 'r', 'x')"),
            ("rules update",      "UPDATE waf_rules SET enabled = 0 WHERE name = 'r'"),
            ("exclusions insert", "INSERT INTO site_rule_exclusions (site_id, external_id)
                                   VALUES ((SELECT id FROM sites WHERE name = 'g'), 1)"),
            ("exclusions update", "UPDATE site_rule_exclusions SET path_prefix = '/x'"),
            ("exclusions delete", "DELETE FROM site_rule_exclusions"),
            ("rules delete",      "DELETE FROM waf_rules WHERE name = 'r'"),
            ("sites delete",      "DELETE FROM sites WHERE name = 'g'"),
            ("policies delete",   "DELETE FROM policies WHERE name = 'g'"),
        ];

        for (what, sql) in writes {
            let before = value().await;
            sqlx::raw_sql(sql).execute(&db).await.unwrap_or_else(|e| panic!("{what}: {e}"));
            assert!(value().await > before, "{what} did not move the generation");
        }

        // And the converse: traffic must not churn the cache. The IP lists are
        // unrelated to rule inspection and reload themselves.
        let before = value().await;
        sqlx::raw_sql("INSERT INTO ip_rules (ip, list_type) VALUES ('203.0.113.9', 'block')")
            .execute(&db).await.unwrap();
        assert_eq!(value().await, before, "an unrelated write moved the generation");

        db.close().await;
        for sfx in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{}{sfx}", path.display())); }
    }
}

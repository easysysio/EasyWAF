-- 031 — a site can have more than one upstream.
--
-- `sites.target` was a single URL formatted straight into the outgoing
-- request. If it stopped answering, every request for that site got a 502 for
-- as long as the backend was down, with nowhere else to send it — so EasyWAF
-- could not be the only thing in front of an application that runs more than
-- one copy of itself, which is most applications worth putting a WAF in front
-- of.
--
-- The column becomes a table. One row is written per existing site from its
-- current target, so nothing changes for anyone until they add a second: a
-- site with one upstream behaves exactly as it did, and the GUI shows one
-- field, not a pool with a policy and a health check to learn.
--
-- `weight` is for backends on unequal hardware, the common real case. Health
-- is deliberately **not** stored here: which upstreams are in rotation is a
-- local observation, not configuration, and must never be copied between
-- nodes when configuration sync arrives (0.15.0) — node A may reach a backend
-- node B cannot, and sharing that judgement would take a working backend out
-- of rotation everywhere because one node has a network problem.
--
-- Applied once, inside a transaction, by run_migration_031.

CREATE TABLE upstreams (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id    INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    url        TEXT    NOT NULL,
    -- Share of the round-robin. 1 unless somebody says otherwise.
    weight     INTEGER NOT NULL DEFAULT 1 CHECK (weight >= 1),
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (site_id, url)
);

CREATE INDEX idx_upstreams_site ON upstreams(site_id);

INSERT INTO upstreams (site_id, url, weight, enabled)
SELECT id, target, 1, 1 FROM sites;

-- The column goes rather than staying as a copy of the first row: two places
-- holding the same upstream is how one of them goes stale, and the request
-- path has to read one of them.
ALTER TABLE sites DROP COLUMN target;

-- Which upstream served a request. Without it, "this site is intermittently
-- slow" cannot be traced to one bad backend, which is the most common thing
-- load balancing is asked to help diagnose.
ALTER TABLE traffic_events ADD COLUMN upstream TEXT;

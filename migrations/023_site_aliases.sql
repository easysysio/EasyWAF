-- 023 — additional hostnames a site answers for.
--
-- A site matched one server_name exactly, so two names for one application
-- meant two site rows with duplicate settings kept in step by hand — and any
-- divergence was a bug that appeared on only one of the names.
--
-- A table rather than a column on sites: UNIQUE(name) is what stops two sites
-- claiming the same hostname, and a check in application code cannot promise
-- that. It is also what the proxy's lookup indexes on.

CREATE TABLE IF NOT EXISTS site_aliases (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    name    TEXT    NOT NULL,
    UNIQUE(name)
);

CREATE INDEX IF NOT EXISTS idx_site_aliases_site ON site_aliases(site_id);

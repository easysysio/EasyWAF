-- =========================================================
-- 045 — traffic indexed by site and by verdict, then by time
--
-- The dashboard and Traffic Monitor count one site's or one verdict's
-- requests within a window. Indexed by site_id or blocked alone, SQLite
-- reaches those rows through every request that site or verdict has ever
-- logged and discards all but the window's, so every view grew slower with
-- the whole of traffic history, which is kept indefinitely by default. With
-- the timestamp as the second column, the index holds each site's and each
-- verdict's requests in time order and a window is read as one range.
--
-- The new indexes answer everything the old ones did, a lookup by site_id
-- or by blocked alone included, so the old ones are dropped rather than kept
-- beside them: each index is written on every request.
--
-- Building them reads the whole table once, which on a long history takes a
-- while. Idempotent.
-- =========================================================

CREATE INDEX IF NOT EXISTS idx_traffic_site_ts    ON traffic_events(site_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_traffic_blocked_ts ON traffic_events(blocked, timestamp);
DROP INDEX IF EXISTS idx_traffic_site;
DROP INDEX IF EXISTS idx_traffic_blocked;

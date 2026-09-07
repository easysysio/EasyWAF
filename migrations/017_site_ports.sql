-- =========================================================
-- 017_site_ports.sql — EasyWAF
-- Extra ports a site answers on, beyond its primary pair.
--
-- A site had exactly two: listen_port for plain HTTP and an
-- optional tls_port. Those stay, and stay primary — the
-- HTTP-to-HTTPS redirect has to name one port, so one of
-- them has to be the answer.
--
-- This table holds the additional ones. Routing does not
-- change: lookup_site matches on server_name alone and never
-- looked at the port, so an extra listener reaches the same
-- site by the same path as the primary one.
-- =========================================================

CREATE TABLE IF NOT EXISTS site_ports (
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    port    INTEGER NOT NULL,
    -- 1 = serve HTTPS here (needs the site's certificate), 0 = plain HTTP.
    tls     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (site_id, port, tls)
);

CREATE INDEX IF NOT EXISTS idx_site_ports_site ON site_ports(site_id);

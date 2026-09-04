-- Migration 009 — per-site HTTPS
--
-- A site can now be reached over both plain HTTP and HTTPS at once:
-- listen_port keeps serving HTTP, tls_port serves HTTPS. Either may be used
-- alone, so "secure only" is tls_port set with the site's HTTP port left
-- unused by DNS, and "insecure only" is simply no tls_port.
--
-- tls_port NULL means the site has no HTTPS listener. cert_id already exists
-- and selects which stored certificate the site presents; a site with a
-- tls_port but no cert_id cannot be served over TLS and is skipped with a
-- warning rather than silently binding a port that would fail every handshake.
--
-- Certificate selection across sites sharing a TLS port is done by SNI at
-- handshake time, so many sites can share port 443 each with its own
-- certificate. The TLS version and cipher profile is not per-site: rustls
-- fixes those on the listener, so it is a single appliance-wide setting.

ALTER TABLE sites ADD COLUMN tls_port INTEGER;

-- Redirect plain HTTP to HTTPS for this site. Off by default: the request was
-- to allow both secure and insecure access, so enabling HTTPS must not
-- silently stop the HTTP port working.
ALTER TABLE sites ADD COLUMN tls_redirect INTEGER NOT NULL DEFAULT 0;

-- 037 — a site may reach an HTTPS backend without checking its certificate.
--
-- A backend that serves HTTPS with a certificate of its own — self-signed, or
-- from a private CA — fails verification, and the site answers 502. Internal
-- applications are often set up exactly that way.
--
-- Off by default, and that is the point: a certificate that is not checked is
-- encryption without identity, so whoever can answer on the backend's address
-- can be the backend. It is a per-site decision for a backend on a network the
-- operator trusts, not something an upgrade should switch on for anybody.
--
-- Idempotent: the column is added only when it is missing.

ALTER TABLE sites ADD COLUMN backend_tls_insecure INTEGER NOT NULL DEFAULT 0
    CHECK (backend_tls_insecure IN (0, 1));

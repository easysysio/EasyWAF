-- EasyWAF schema v2
-- Self-contained WAF/reverse proxy — no nginx dependency.

PRAGMA journal_mode=WAL;

-- ── Users ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── TLS Certificates ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS certs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    NOT NULL UNIQUE,
    domain       TEXT,
    not_before   TEXT,
    not_after    TEXT,
    cert_pem     TEXT,           -- full certificate chain PEM
    key_pem      TEXT,           -- private key PEM
    acme_domain  TEXT,           -- set when issued by Let's Encrypt
    acme_expires TEXT,           -- ISO-8601 expiry, for auto-renewal
    created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── WAF Policies ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS policies (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    rule_engine     TEXT    NOT NULL DEFAULT 'DetectionOnly', -- DetectionOnly | On | Off
    rules           TEXT    NOT NULL DEFAULT '',              -- comma-sep rule file stems
    score_threshold INTEGER NOT NULL DEFAULT 10,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Sites ────────────────────────────────────────────────
-- Each site is a virtual host routed by the Host: header.
CREATE TABLE IF NOT EXISTS sites (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT    NOT NULL UNIQUE,   -- friendly label
    server_name    TEXT    NOT NULL UNIQUE,   -- hostname used for routing (e.g. example.com)
    target         TEXT    NOT NULL,          -- upstream URL (e.g. http://127.0.0.1:3000)
    enabled        INTEGER NOT NULL DEFAULT 1,
    cert_id        INTEGER REFERENCES certs(id) ON DELETE SET NULL,
    acme_enabled   INTEGER NOT NULL DEFAULT 0,
    waf_policy_id  INTEGER REFERENCES policies(id) ON DELETE SET NULL,
    hsts           INTEGER NOT NULL DEFAULT 0,
    x_frame        INTEGER NOT NULL DEFAULT 0,
    x_content_type INTEGER NOT NULL DEFAULT 0,
    xss_protection INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Traffic Events ───────────────────────────────────────
-- One row per proxied request. Written asynchronously.
CREATE TABLE IF NOT EXISTS traffic_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id      INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    timestamp    TEXT    NOT NULL DEFAULT (datetime('now')),
    client_ip    TEXT,
    method       TEXT,
    host         TEXT,
    path         TEXT,
    status_code  INTEGER,
    response_ms  INTEGER,    -- round-trip latency to upstream
    blocked      INTEGER NOT NULL DEFAULT 0,
    block_reason TEXT,       -- 'WAF' | 'GeoIP' | 'Rules' | NULL
    waf_score    INTEGER,
    country      TEXT        -- ISO 3166-1 alpha-2, populated by GeoIP module
);

CREATE INDEX IF NOT EXISTS idx_traffic_ts      ON traffic_events(timestamp);
-- The indexes by site and by verdict are migration 045's, which builds them
-- with the timestamp as their second column.

-- ── GeoIP Rules ──────────────────────────────────────────
-- Per-site list of countries to block or allow.
CREATE TABLE IF NOT EXISTS geoip_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id    INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    mode       TEXT    NOT NULL DEFAULT 'block',  -- 'block' | 'allow'
    action     TEXT    NOT NULL DEFAULT 'drop',   -- 'drop' | 'alert'
    countries  TEXT    NOT NULL DEFAULT '',       -- comma-sep ISO-3166-1 alpha-2 codes
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── ACME Accounts ────────────────────────────────────────
-- Global Let's Encrypt account (one per installation).
CREATE TABLE IF NOT EXISTS acme_accounts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT NOT NULL,
    private_key TEXT NOT NULL,  -- PEM ACME account key
    directory   TEXT NOT NULL DEFAULT 'https://acme-v02.api.letsencrypt.org/directory',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

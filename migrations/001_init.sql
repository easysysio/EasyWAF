-- EasyWAF initial schema

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sites (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT    NOT NULL UNIQUE,
    server_name    TEXT    NOT NULL,
    target         TEXT    NOT NULL,
    port           INTEGER NOT NULL DEFAULT 80,
    waf_policy     TEXT,
    hsts           INTEGER NOT NULL DEFAULT 0,
    x_frame        INTEGER NOT NULL DEFAULT 0,
    x_content_type INTEGER NOT NULL DEFAULT 0,
    xss_protection INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS certs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    domain     TEXT,
    not_before TEXT,
    not_after  TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS policies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    rule_engine TEXT NOT NULL DEFAULT 'DetectionOnly',
    rules       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

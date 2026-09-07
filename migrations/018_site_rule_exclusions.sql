-- Rules a particular site does not apply, optionally only under a path.
--
-- A policy is shared: several sites use one, which is the point of a policy.
-- That leaves nowhere to say "this rule is wrong for this one site" without
-- either weakening the rule for everyone or giving the site a policy of its
-- own and losing the shared updates. This table is that missing place.
--
-- Why a rule is named twice over:
--
--   external_id is the catalogue number and is stable. Removing a set and
--   installing it again deletes every waf_rules row and writes new ones with
--   new ids, so an exclusion keyed on the row id would quietly stop applying
--   at exactly the moment the rule came back. This project has already shipped
--   that class of bug twice.
--
--   rule_id is for custom rules, which have no catalogue number. It cascades:
--   delete the rule and the exclusion has nothing left to mean.
--
-- Exactly one of the two is set, which the CHECK enforces rather than trusts.
CREATE TABLE IF NOT EXISTS site_rule_exclusions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id     INTEGER NOT NULL REFERENCES sites(id)     ON DELETE CASCADE,
    external_id INTEGER,
    rule_id     INTEGER          REFERENCES waf_rules(id) ON DELETE CASCADE,
    -- Empty means the whole site. Otherwise the request path must start with
    -- it. A prefix and not a regex: an exclusion turns a rule off, so a
    -- mistake in it is a hole, and a prefix is a thing you can read and be
    -- sure about.
    path_prefix TEXT    NOT NULL DEFAULT '',
    -- Why this exists. Not decoration: an exclusion outlives the incident that
    -- caused it, and an unexplained one is never safe to remove later.
    note        TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    CHECK ((external_id IS NULL) <> (rule_id IS NULL))
);

-- The engine's lookup is by site on every request.
CREATE INDEX IF NOT EXISTS idx_exclusions_site ON site_rule_exclusions(site_id);

-- One exclusion per rule per path per site. Two identical rows would be two
-- entries in the UI that cannot be told apart, and deleting "the" one would be
-- ambiguous.
CREATE UNIQUE INDEX IF NOT EXISTS idx_exclusions_unique
    ON site_rule_exclusions(site_id, IFNULL(external_id, -1), IFNULL(rule_id, -1), path_prefix);

-- Which clients an exclusion applies to.
--
-- A rule exclusion was scoped by site and optionally by path. That answers
-- "this rule is wrong for this application", but not the case that actually
-- arrives most often: a rule is right, and one client trips it — an office
-- range, a monitoring probe, a colleague whose password manager sends
-- something that looks like an injection.
--
-- Narrowing by client is the smallest exclusion that fixes such a case. The
-- rule keeps protecting the site from everyone else, which a site-wide or even
-- a path-wide exclusion does not.
--
-- NULL means every client, which is what every existing row means and what the
-- engine did before this column existed. A value is an address or a CIDR block
-- in the form `forwarded::Cidr` already parses for trusted proxies: 10.0.0.1,
-- 10.0.0.0/8, ::1, fd00::/8.
ALTER TABLE site_rule_exclusions ADD COLUMN client_cidr TEXT;

-- The same rule can now be excluded for two different clients on one site, so
-- the client has to be part of what makes a row unique. IFNULL('') rather than
-- IFNULL(-1) because this column is text, and an empty string cannot collide
-- with a real CIDR.
DROP INDEX IF EXISTS idx_exclusions_unique;
CREATE UNIQUE INDEX idx_exclusions_unique
    ON site_rule_exclusions(
        site_id,
        IFNULL(external_id, -1),
        IFNULL(rule_id, -1),
        path_prefix,
        IFNULL(client_cidr, '')
    );

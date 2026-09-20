-- 032 — session affinity, per site.
--
-- Requests go round a site's backends in turn, which is right until a backend
-- keeps something in memory: a PHP session, an in-process cache, an upload
-- being assembled. Then a client's next request lands somewhere that has never
-- heard of it, and the symptom is a user logged out at random rather than
-- anything that looks like a load balancer problem.
--
-- Off by default, because it costs something real: a backend that is pinned is
-- a backend whose share of the traffic cannot be given to another while its
-- clients are still holding their cookies.
--
-- Idempotent: the column is added only when it is missing.

ALTER TABLE sites ADD COLUMN affinity INTEGER NOT NULL DEFAULT 0
    CHECK (affinity IN (0, 1));

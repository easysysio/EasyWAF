-- 036 — Smart Protect, per policy.
--
-- Every request is judged alone, so a scanner firing two hundred probes gets
-- two hundred independent refusals and is free to carry on. With this on, an
-- address the policy's rules keep refusing is refused outright for a while.
--
-- A switch on the policy, because whether it applies is a decision about what
-- a policy's sites face; the numbers — how many refusals, in what window, for
-- how long — are tuning, and live in settings, set once.
--
-- Off by default: an upgrade must not start refusing addresses nobody decided
-- to refuse.
--
-- Idempotent: the column is added only when it is missing.

ALTER TABLE policies ADD COLUMN smart_protect INTEGER NOT NULL DEFAULT 0
    CHECK (smart_protect IN (0, 1));

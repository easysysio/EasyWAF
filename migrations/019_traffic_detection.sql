-- What the WAF would have done, when it did not do it.
--
-- `blocked` says whether the request was refused. It could not say that a
-- request was allowed *and* matched rules, so those records were
-- indistinguishable from clean traffic — which made DetectionOnly report
-- nothing, the one thing that mode exists to do.
--
-- Values:
--   NULL              nothing matched (or the request was blocked; `blocked`
--                     already says so)
--   'observed'        rules matched, allowed on its merits — under threshold
--   'would_challenge' DetectionOnly: enforcing would have challenged it
--   'would_block'     DetectionOnly: enforcing would have refused it
ALTER TABLE traffic_events ADD COLUMN detection TEXT;

-- The Traffic Monitor filters on it, and the dashboard counts it per window.
CREATE INDEX IF NOT EXISTS idx_traffic_detection
    ON traffic_events(detection, timestamp);

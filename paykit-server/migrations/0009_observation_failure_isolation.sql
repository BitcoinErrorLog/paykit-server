ALTER TABLE invoices
    ADD COLUMN integrity_failed BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN integrity_failure_count INTEGER NOT NULL DEFAULT 0
        CHECK (integrity_failure_count >= 0),
    ADD COLUMN integrity_failed_at TIMESTAMPTZ,
    ADD COLUMN integrity_last_logged_at TIMESTAMPTZ;

ALTER TABLE bitcoin_observation_candidates
    ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    ADD COLUMN last_attempt_at TIMESTAMPTZ,
    ADD COLUMN next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN last_error_kind TEXT,
    ADD COLUMN state TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'approved', 'unfetchable'));

CREATE INDEX bitcoin_observation_candidates_retry_index
    ON bitcoin_observation_candidates (state, next_attempt_at, confirmed_height, created_at);

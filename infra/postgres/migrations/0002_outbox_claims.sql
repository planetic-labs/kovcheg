ALTER TABLE kovcheg.outbox_events
  ADD COLUMN claim_token uuid,
  ADD COLUMN claim_expires_at timestamptz;

ALTER TABLE kovcheg.outbox_events
  ADD CONSTRAINT outbox_events_claim_shape_check CHECK (
    (claim_token IS NULL AND claim_expires_at IS NULL)
    OR (claim_token IS NOT NULL AND claim_expires_at IS NOT NULL)
  ) NOT VALID;

ALTER TABLE kovcheg.outbox_events
  VALIDATE CONSTRAINT outbox_events_claim_shape_check;

CREATE INDEX outbox_events_expired_claim_idx
  ON kovcheg.outbox_events (claim_expires_at, id)
  WHERE delivered_at IS NULL AND claim_token IS NOT NULL;

GRANT UPDATE (claim_token, claim_expires_at, attempt_count, delivered_at)
ON kovcheg.outbox_events TO kovcheg_runtime;

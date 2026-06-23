-- Migration 008: Election-official assurance events.
--
-- voter_contact_events records identity-side lifecycle metadata for election
-- administration: invitation issued, delivery/open telemetry, authentication,
-- credential consumption, and submission accepted.
--
-- This table is intentionally identity/admin-only. It has no ballot_id, choice,
-- payload commitment, or vote-direction column, so it can support turnout and
-- voter-support dashboards without recreating a voter-to-payload join.

CREATE TABLE IF NOT EXISTS voter_contact_events (
    id            BIGSERIAL   PRIMARY KEY,
    poll_id       TEXT        NOT NULL,
    identity_hash TEXT        NOT NULL,
    event_type    TEXT        NOT NULL,
    event_ref     TEXT,
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata      JSONB       NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT voter_contact_events_type_ck CHECK (
        event_type IN (
            'invited',
            'delivered',
            'opened',
            'authenticated',
            'credential_consumed',
            'submitted',
            'remediated'
        )
    )
);

CREATE INDEX IF NOT EXISTS idx_voter_contact_events_poll
  ON voter_contact_events(poll_id, event_type, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_voter_contact_events_identity
  ON voter_contact_events(identity_hash, poll_id, occurred_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_voter_contact_events_unique_ref
  ON voter_contact_events(poll_id, identity_hash, event_type, event_ref)
  WHERE event_ref IS NOT NULL;

COMMENT ON TABLE voter_contact_events IS
  'Identity-side election administration events. No ballot_id, choice, payload commitment, or direction column.';

COMMENT ON COLUMN voter_contact_events.metadata IS
  'Delivery/open/auth metadata only. Must not contain ballot payload, ballot_id, choice, or payload commitment.';

CREATE OR REPLACE VIEW voter_contact_assurance AS
SELECT
    poll_id,
    COUNT(DISTINCT identity_hash) FILTER (WHERE event_type = 'invited')             AS invited_count,
    COUNT(DISTINCT identity_hash) FILTER (WHERE event_type = 'delivered')           AS delivered_count,
    COUNT(DISTINCT identity_hash) FILTER (WHERE event_type = 'opened')              AS opened_count,
    COUNT(DISTINCT identity_hash) FILTER (WHERE event_type = 'authenticated')       AS authenticated_count,
    COUNT(DISTINCT identity_hash) FILTER (WHERE event_type = 'credential_consumed') AS credential_consumed_count,
    COUNT(DISTINCT identity_hash) FILTER (WHERE event_type = 'submitted')           AS submitted_count,
    COUNT(DISTINCT identity_hash) FILTER (WHERE event_type = 'remediated')          AS remediated_count
FROM voter_contact_events
GROUP BY poll_id;

COMMENT ON VIEW voter_contact_assurance IS
  'Aggregate election-admin lifecycle counts. Does not expose identity_hash values or ballot payload linkage.';

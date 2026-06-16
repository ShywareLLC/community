-- Migration 007: I Want Solicitations marketplace
--
-- solicitations_consent — voter opt-in keyed by identity_hash.
--   identity_hash is the same value that appears in voter_registry (List 2).
--   Opting in is a prerequisite for receiving marketplace solicitations.
--   Opting out nullifies matchability but preserves the audit record.
--
-- solicitations — marketplace listings posted by advocates/campaigns.
--   A sponsor may target all opted-in voters (poll_id IS NULL) or voters who
--   expressed a specific choice on a specific poll (poll_id + choice_filter).
--   The analytics layer never reveals identity_hash to sponsors; matching is
--   done server-side and delivery is push-notification or in-app only.

CREATE TABLE IF NOT EXISTS solicitations_consent (
    identity_hash TEXT        PRIMARY KEY,
    opted_in      BOOLEAN     NOT NULL DEFAULT false,
    opted_in_at   TIMESTAMP,                              -- when they first opted in
    updated_at    TIMESTAMP   NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE solicitations_consent IS
  'Voter opt-in for I Want Solicitations marketplace. '
  'identity_hash mirrors voter_registry. opted_in = false means opted-out.';

CREATE INDEX IF NOT EXISTS idx_sc_opted_in ON solicitations_consent(opted_in)
  WHERE opted_in = true;

-- solicitations marketplace listings
CREATE TABLE IF NOT EXISTS solicitations (
    id            BIGSERIAL   PRIMARY KEY,
    sponsor_id    TEXT        NOT NULL,   -- opaque sponsor identifier
    poll_id       TEXT,                   -- NULL = target all opted-in voters
    choice_filter TEXT,                   -- 'yes' | 'no' | NULL (any direction)
    message       TEXT        NOT NULL,
    active        BOOLEAN     NOT NULL DEFAULT true,
    created_at    TIMESTAMP   NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMP
);

COMMENT ON TABLE solicitations IS
  'I Want Solicitations marketplace. Sponsors post messages; the analytics '
  'service matches them to opted-in voters by poll_id + choice_filter.';

CREATE INDEX IF NOT EXISTS idx_sol_active ON solicitations(active, poll_id);
CREATE INDEX IF NOT EXISTS idx_sol_sponsor ON solicitations(sponsor_id);

-- Migration 006: Add didit_proof_hash to voter_registry.
--
-- didit_proof_hash = H(didit_journey_id || poll_id)
--
-- This column binds each voter registry entry to a specific Didit identity
-- verification journey without exposing the journey ID on-chain. It is
-- poll-scoped so the same voter produces a different hash per poll, preventing
-- cross-poll tracking via this field alone.
--
-- Auditors with Didit record access can verify the full chain:
--   identity_hash → didit_proof_hash → Didit journey → real identity
--
-- The column is NOT NULL for all new entries. Existing rows (if any) must be
-- backfilled or removed before applying this migration in production.

ALTER TABLE voter_registry
    ADD COLUMN IF NOT EXISTS didit_proof_hash TEXT NOT NULL DEFAULT '';

-- Remove the temporary default once backfill is complete:
-- ALTER TABLE voter_registry ALTER COLUMN didit_proof_hash DROP DEFAULT;

CREATE INDEX IF NOT EXISTS idx_voter_registry_didit_proof
    ON voter_registry(didit_proof_hash);

COMMENT ON COLUMN voter_registry.didit_proof_hash IS
    'H(didit_journey_id || poll_id) — on-chain KYC commitment, poll-scoped';

-- Refresh the count-check view (no schema change needed, but refresh to pick
-- up any underlying table changes).
CREATE OR REPLACE VIEW ballot_count_check AS
SELECT
    poll_id,
    (SELECT COUNT(*) FROM vote_directions vd WHERE vd.poll_id = bcc.poll_id) AS vote_count,
    (SELECT COUNT(*) FROM voter_registry  vr WHERE vr.poll_id = bcc.poll_id) AS voter_count,
    (SELECT COUNT(*) FROM vote_directions vd WHERE vd.poll_id = bcc.poll_id) =
    (SELECT COUNT(*) FROM voter_registry  vr WHERE vr.poll_id = bcc.poll_id) AS counts_match
FROM (SELECT DISTINCT poll_id FROM vote_directions) bcc;

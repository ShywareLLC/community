-- Migration 005: Split ballots_view into two unjoined tables.
--
-- Replaces the single ballots_view (which linked voter_tag + choice) with:
--   vote_directions  — List 1: anonymous vote directions, no identity column
--   voter_registry   — List 2: voter participation, no choice column
--
-- Trustless count-match invariant:
--   SELECT COUNT(*) FROM vote_directions WHERE poll_id = $1
--   must equal
--   SELECT COUNT(*) FROM voter_registry  WHERE poll_id = $1
--
-- The two tables have no foreign key or shared non-poll column between them.
-- The only record linking them is in Firestore (users/{uid}/votes/{poll_id}),
-- which is private and not validated by any consensus node.

-- Drop the old joined view
DROP MATERIALIZED VIEW IF EXISTS ballots_view CASCADE;

-- List 1: anonymous vote directions
-- Sourced from "ballot_cast" events (no identity_hash attribute in this event type)
CREATE TABLE IF NOT EXISTS vote_directions (
    ballot_id       TEXT        NOT NULL,
    poll_id         TEXT        NOT NULL,
    choice          TEXT        NOT NULL,
    included_height BIGINT,
    included_at     TIMESTAMPTZ,
    tx_hash         TEXT,
    PRIMARY KEY (ballot_id)
);

CREATE INDEX IF NOT EXISTS idx_vote_directions_poll_id ON vote_directions(poll_id);
CREATE INDEX IF NOT EXISTS idx_vote_directions_height  ON vote_directions(included_height);

-- List 2: voter participation — who voted, no choice
-- Sourced from "voter_registered" events (no choice attribute in this event type)
CREATE TABLE IF NOT EXISTS voter_registry (
    identity_hash   TEXT        NOT NULL,
    poll_id         TEXT        NOT NULL,
    included_height BIGINT,
    included_at     TIMESTAMPTZ,
    tx_hash         TEXT,
    PRIMARY KEY (poll_id, identity_hash)
);

CREATE INDEX IF NOT EXISTS idx_voter_registry_poll_id ON voter_registry(poll_id);
CREATE INDEX IF NOT EXISTS idx_voter_registry_height  ON voter_registry(included_height);

-- Count-match verification view (read-only audit tool — never joins the two tables)
CREATE OR REPLACE VIEW ballot_count_check AS
SELECT
    poll_id,
    (SELECT COUNT(*) FROM vote_directions vd WHERE vd.poll_id = bcc.poll_id) AS vote_count,
    (SELECT COUNT(*) FROM voter_registry  vr WHERE vr.poll_id = bcc.poll_id) AS voter_count,
    (SELECT COUNT(*) FROM vote_directions vd WHERE vd.poll_id = bcc.poll_id) =
    (SELECT COUNT(*) FROM voter_registry  vr WHERE vr.poll_id = bcc.poll_id) AS counts_match
FROM (SELECT DISTINCT poll_id FROM vote_directions) bcc;

COMMENT ON TABLE vote_directions  IS 'List 1: anonymous vote directions — no identity column';
COMMENT ON TABLE voter_registry   IS 'List 2: voter participation — no choice column';
COMMENT ON VIEW  ballot_count_check IS 'Audit: vote_count must equal voter_count per poll';

-- Update tallies_view to include both Merkle roots
DROP MATERIALIZED VIEW IF EXISTS tallies_view CASCADE;

CREATE MATERIALIZED VIEW IF NOT EXISTS tallies_view AS
SELECT
    attrs_poll_id.value         AS poll_id,
    attrs_total_votes.value::BIGINT AS total_votes,
    attrs_vote_root.value       AS vote_merkle_root,
    attrs_voter_root.value      AS voter_merkle_root,
    attrs_finalized_at.value::BIGINT AS finalized_at,
    tx.height                   AS closing_height,
    b.block_time                AS closed_at,
    tx.tx_hash,
    tx.success
FROM tx_results tx
JOIN blocks b ON tx.height = b.height
JOIN events e ON e.tx_hash = tx.tx_hash
JOIN attributes attrs_poll_id
    ON attrs_poll_id.event_id = e.id AND attrs_poll_id.key = 'poll_id'
LEFT JOIN attributes attrs_total_votes
    ON attrs_total_votes.event_id = e.id AND attrs_total_votes.key = 'total_votes'
LEFT JOIN attributes attrs_vote_root
    ON attrs_vote_root.event_id = e.id AND attrs_vote_root.key = 'vote_merkle_root'
LEFT JOIN attributes attrs_voter_root
    ON attrs_voter_root.event_id = e.id AND attrs_voter_root.key = 'voter_merkle_root'
LEFT JOIN attributes attrs_finalized_at
    ON attrs_finalized_at.event_id = e.id AND attrs_finalized_at.key = 'finalized_at'
WHERE e.type = 'poll_closed'
    AND tx.success = true
ORDER BY tx.height DESC;

CREATE UNIQUE INDEX IF NOT EXISTS idx_tallies_view_poll_id  ON tallies_view(poll_id);
CREATE        INDEX IF NOT EXISTS idx_tallies_view_height   ON tallies_view(closing_height);

CREATE OR REPLACE FUNCTION refresh_tallies_view()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY tallies_view;
END;
$$ LANGUAGE plpgsql;

COMMENT ON MATERIALIZED VIEW tallies_view IS
    'Poll tallies with both vote_merkle_root (List 1) and voter_merkle_root (List 2)';

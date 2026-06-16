-- Materialized view for queryable ballots
-- Denormalizes ballot events for efficient lookups

CREATE MATERIALIZED VIEW IF NOT EXISTS ballots_view AS
SELECT
    attrs_ballot_id.value AS ballot_id,
    attrs_poll_id.value AS poll_id,
    attrs_voter_tag.value AS voter_tag,
    attrs_choice.value AS choice,
    attrs_timestamp.value::BIGINT AS ballot_timestamp,
    tx.height AS included_height,
    b.block_time AS included_at,
    tx.tx_hash,
    tx.success
FROM tx_results tx
JOIN blocks b ON tx.height = b.height
JOIN events e ON e.tx_hash = tx.tx_hash
JOIN attributes attrs_ballot_id ON attrs_ballot_id.event_id = e.id AND attrs_ballot_id.key = 'ballot_id'
JOIN attributes attrs_poll_id ON attrs_poll_id.event_id = e.id AND attrs_poll_id.key = 'poll_id'
JOIN attributes attrs_voter_tag ON attrs_voter_tag.event_id = e.id AND attrs_voter_tag.key = 'voter_tag'
JOIN attributes attrs_choice ON attrs_choice.event_id = e.id AND attrs_choice.key = 'choice'
LEFT JOIN attributes attrs_timestamp ON attrs_timestamp.event_id = e.id AND attrs_timestamp.key = 'timestamp'
WHERE e.type = 'ballot_cast'
    AND tx.success = true
ORDER BY tx.height DESC;

-- Unique index for concurrent refresh
CREATE UNIQUE INDEX IF NOT EXISTS idx_ballots_view_ballot_id ON ballots_view(ballot_id);
CREATE INDEX IF NOT EXISTS idx_ballots_view_poll_id ON ballots_view(poll_id);
CREATE INDEX IF NOT EXISTS idx_ballots_view_voter_tag ON ballots_view(voter_tag);
CREATE INDEX IF NOT EXISTS idx_ballots_view_height ON ballots_view(included_height);
CREATE INDEX IF NOT EXISTS idx_ballots_view_poll_voter ON ballots_view(poll_id, voter_tag);

-- Refresh function
CREATE OR REPLACE FUNCTION refresh_ballots_view()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY ballots_view;
END;
$$ LANGUAGE plpgsql;

COMMENT ON MATERIALIZED VIEW ballots_view IS 'Queryable ballots with denormalized attributes';

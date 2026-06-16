-- Materialized view for queryable poll tallies
-- Denormalizes poll close events and final tallies

CREATE MATERIALIZED VIEW IF NOT EXISTS tallies_view AS
SELECT
    attrs_poll_id.value AS poll_id,
    attrs_total_votes.value::BIGINT AS total_votes,
    attrs_merkle_root.value AS merkle_root,
    attrs_finalized_at.value::BIGINT AS finalized_at,
    tx.height AS closing_height,
    b.block_time AS closed_at,
    tx.tx_hash,
    tx.success
FROM tx_results tx
JOIN blocks b ON tx.height = b.height
JOIN events e ON e.tx_hash = tx.tx_hash
JOIN attributes attrs_poll_id ON attrs_poll_id.event_id = e.id AND attrs_poll_id.key = 'poll_id'
LEFT JOIN attributes attrs_total_votes ON attrs_total_votes.event_id = e.id AND attrs_total_votes.key = 'total_votes'
LEFT JOIN attributes attrs_merkle_root ON attrs_merkle_root.event_id = e.id AND attrs_merkle_root.key = 'merkle_root'
LEFT JOIN attributes attrs_finalized_at ON attrs_finalized_at.event_id = e.id AND attrs_finalized_at.key = 'finalized_at'
WHERE e.type = 'poll_closed'
    AND tx.success = true
ORDER BY tx.height DESC;

-- Unique index for concurrent refresh
CREATE UNIQUE INDEX IF NOT EXISTS idx_tallies_view_poll_id ON tallies_view(poll_id);
CREATE INDEX IF NOT EXISTS idx_tallies_view_height ON tallies_view(closing_height);
CREATE INDEX IF NOT EXISTS idx_tallies_view_closed_at ON tallies_view(closed_at);

-- Refresh function
CREATE OR REPLACE FUNCTION refresh_tallies_view()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY tallies_view;
END;
$$ LANGUAGE plpgsql;

-- Combined view: polls with their tallies
CREATE VIEW polls_with_tallies AS
SELECT
    p.poll_id,
    p.poll_hash,
    p.question,
    p.start_time,
    p.end_time,
    p.created_at,
    p.created_height,
    t.total_votes,
    t.merkle_root,
    t.finalized_at,
    t.closing_height,
    t.closed_at,
    CASE
        WHEN t.poll_id IS NOT NULL THEN 'closed'
        WHEN EXTRACT(EPOCH FROM NOW()) >= p.end_time THEN 'ended'
        WHEN EXTRACT(EPOCH FROM NOW()) >= p.start_time THEN 'open'
        ELSE 'pending'
    END AS status
FROM polls_view p
LEFT JOIN tallies_view t ON p.poll_id = t.poll_id
ORDER BY p.created_at DESC;

COMMENT ON MATERIALIZED VIEW tallies_view IS 'Queryable poll tallies';
COMMENT ON VIEW polls_with_tallies IS 'Polls joined with their tallies and computed status';

-- Materialized view for queryable polls
-- This denormalizes the canonical blockchain data for efficient queries

CREATE MATERIALIZED VIEW IF NOT EXISTS polls_view AS
SELECT
    attrs_scoping_id.value AS poll_id,
    attrs_poll_hash.value AS poll_hash,
    attrs_question.value AS question,
    attrs_start_time.value::BIGINT AS start_time,
    attrs_end_time.value::BIGINT AS end_time,
    tx.height AS created_height,
    b.block_time AS created_at,
    tx.tx_hash,
    tx.success
FROM tx_results tx
JOIN blocks b ON tx.height = b.height
JOIN events e ON e.tx_hash = tx.tx_hash
JOIN attributes attrs_scoping_id ON attrs_scoping_id.event_id = e.id AND attrs_scoping_id.key = 'scoping_id'
LEFT JOIN attributes attrs_poll_hash ON attrs_poll_hash.event_id = e.id AND attrs_poll_hash.key = 'poll_hash'
LEFT JOIN attributes attrs_question ON attrs_question.event_id = e.id AND attrs_question.key = 'question'
LEFT JOIN attributes attrs_start_time ON attrs_start_time.event_id = e.id AND attrs_start_time.key = 'start_time'
LEFT JOIN attributes attrs_end_time ON attrs_end_time.event_id = e.id AND attrs_end_time.key = 'end_time'
WHERE e.type = 'poll_created'
    AND tx.success = true
ORDER BY tx.height DESC;

-- Unique index for concurrent refresh
CREATE UNIQUE INDEX IF NOT EXISTS idx_polls_view_poll_id ON polls_view(poll_id);
CREATE INDEX IF NOT EXISTS idx_polls_view_created_at ON polls_view(created_at);
CREATE INDEX IF NOT EXISTS idx_polls_view_height ON polls_view(created_height);

-- Refresh function (called by projector after each block)
CREATE OR REPLACE FUNCTION refresh_polls_view()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY polls_view;
END;
$$ LANGUAGE plpgsql;

COMMENT ON MATERIALIZED VIEW polls_view IS 'Queryable polls with denormalized attributes';

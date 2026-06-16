-- Initial schema for Populist canonical voting protocol indexer
-- Stores raw blockchain data from CometBFT

-- Blocks table
CREATE TABLE IF NOT EXISTS blocks (
    height BIGINT PRIMARY KEY,
    chain_id TEXT NOT NULL,
    block_time TIMESTAMP NOT NULL,
    proposer_address TEXT,
    num_txs INT NOT NULL DEFAULT 0,
    total_gas BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_blocks_chain_id ON blocks(chain_id);
CREATE INDEX idx_blocks_block_time ON blocks(block_time);

-- Transaction results table
CREATE TABLE IF NOT EXISTS tx_results (
    tx_hash TEXT PRIMARY KEY,
    height BIGINT NOT NULL REFERENCES blocks(height) ON DELETE CASCADE,
    index INT NOT NULL,
    tx_type TEXT NOT NULL,
    gas_wanted BIGINT,
    gas_used BIGINT,
    success BOOLEAN NOT NULL,
    log TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tx_results_height ON tx_results(height);
CREATE INDEX idx_tx_results_tx_type ON tx_results(tx_type);
CREATE INDEX idx_tx_results_created_at ON tx_results(created_at);
CREATE INDEX idx_tx_results_success ON tx_results(success);

-- Events table (for ABCI events)
CREATE TABLE IF NOT EXISTS events (
    id BIGSERIAL PRIMARY KEY,
    tx_hash TEXT REFERENCES tx_results(tx_hash) ON DELETE CASCADE,
    height BIGINT NOT NULL,
    type TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_events_tx_hash ON events(tx_hash);
CREATE INDEX idx_events_height ON events(height);
CREATE INDEX idx_events_type ON events(type);
CREATE INDEX idx_events_created_at ON events(created_at);

-- Event attributes table
CREATE TABLE IF NOT EXISTS attributes (
    id BIGSERIAL PRIMARY KEY,
    event_id BIGINT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    index BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX idx_attributes_event_id ON attributes(event_id);
CREATE INDEX idx_attributes_key ON attributes(key);
CREATE INDEX idx_attributes_key_value ON attributes(key, value);
CREATE INDEX idx_attributes_composite_event_type_key ON attributes(event_id, key);

-- Comments
COMMENT ON TABLE blocks IS 'Raw CometBFT blocks';
COMMENT ON TABLE tx_results IS 'Transaction execution results';
COMMENT ON TABLE events IS 'ABCI events emitted by transactions';
COMMENT ON TABLE attributes IS 'Key-value attributes for events';

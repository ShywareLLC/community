package projector

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ShywareLLC/community/analytics/types"
)

// Projector processes blocks and writes them to PostgreSQL.
type Projector struct {
	db *pgxpool.Pool
}

// New creates a new Projector.
func New(db *pgxpool.Pool) *Projector {
	return &Projector{db: db}
}

// ProcessBlock persists a block and all its transaction results / events to the DB.
func (p *Projector) ProcessBlock(ctx context.Context, block *types.Block) error {
	tx, err := p.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO blocks (height, chain_id, block_time, proposer_address, num_txs, total_gas)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (height) DO NOTHING
	`, block.Height, block.ChainID, block.Time, block.ProposerAddress, block.NumTxs, block.TotalGas)
	if err != nil {
		return fmt.Errorf("failed to insert block: %w", err)
	}

	for _, txResult := range block.TxResults {
		if err := p.processTxResult(ctx, tx, block.Height, txResult); err != nil {
			return fmt.Errorf("failed to process tx %s: %w", txResult.TxHash, err)
		}
	}

	if _, err := tx.Exec(ctx, "REFRESH MATERIALIZED VIEW CONCURRENTLY polls_view"); err != nil {
		fmt.Printf("⚠️  Failed to refresh polls_view: %v\n", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

func (p *Projector) processTxResult(ctx context.Context, tx pgx.Tx, height int64, txResult *types.TxResult) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO tx_results (tx_hash, height, index, tx_type, gas_wanted, gas_used, success, log, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
		ON CONFLICT (tx_hash) DO NOTHING
	`, txResult.TxHash, height, txResult.Index, txResult.TxType,
		txResult.GasWanted, txResult.GasUsed, txResult.Success, txResult.Log)
	if err != nil {
		return fmt.Errorf("failed to insert tx_result: %w", err)
	}

	for _, event := range txResult.Events {
		if err := p.processEvent(ctx, tx, txResult.TxHash, height, event); err != nil {
			return fmt.Errorf("failed to process event: %w", err)
		}
	}
	return nil
}

func (p *Projector) processEvent(ctx context.Context, tx pgx.Tx, txHash string, height int64, event *types.Event) error {
	var eventID int64
	err := tx.QueryRow(ctx, `
		INSERT INTO events (tx_hash, height, type, created_at)
		VALUES ($1, $2, $3, NOW())
		RETURNING id
	`, txHash, height, event.Type).Scan(&eventID)
	if err != nil {
		return fmt.Errorf("failed to insert event: %w", err)
	}

	for _, attr := range event.Attributes {
		_, err := tx.Exec(ctx, `
			INSERT INTO attributes (event_id, key, value, index)
			VALUES ($1, $2, $3, $4)
		`, eventID, attr.Key, attr.Value, attr.Index)
		if err != nil {
			return fmt.Errorf("failed to insert attribute: %w", err)
		}
	}
	return nil
}

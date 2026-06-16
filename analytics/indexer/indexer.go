package indexer

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ShywareLLC/community/analytics/types"
)

// Subscriber drives block ingestion.
type Subscriber interface {
	Start(ctx context.Context) error
}

// Projector processes individual blocks.
type Projector interface {
	ProcessBlock(ctx context.Context, block *types.Block) error
}

// Indexer coordinates the subscriber and projector.
type Indexer struct {
	subscriber Subscriber
	projector  Projector
	db         *pgxpool.Pool
}

// New creates a new Indexer.
func New(subscriber Subscriber, projector Projector, db *pgxpool.Pool) *Indexer {
	return &Indexer{subscriber: subscriber, projector: projector, db: db}
}

// Start begins block ingestion.
func (idx *Indexer) Start(ctx context.Context) error {
	return idx.subscriber.Start(ctx)
}

// Stop performs a graceful shutdown.
func (idx *Indexer) Stop() {}

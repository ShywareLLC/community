package app

import (
	"context"
	"encoding/hex"
	"fmt"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/libs/log"
	dbm "github.com/cometbft/cometbft-db"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ShywareLLC/community/services/identity"
	"github.com/ShywareLLC/community/domain/state"
	"github.com/ShywareLLC/community/services/telemetry"
	"github.com/ShywareLLC/community/protocol/tx"
)

// Config parametrizes a protocol App deployment.
type Config struct {
	ChainID    string // CometBFT chain ID (e.g. "populist-1", "seda-haqq-1")
	DBPath     string // Directory for LevelDB state files
	DBName     string // LevelDB database name (e.g. "populist", "seda-haqq")
	AppName    string // Human-readable name returned in Info() response
	TracerName string // OpenTelemetry tracer name (e.g. "populist-abci")
	KMSKeyID   string // AWS KMS key ID for tally signing (empty = SHA-256 stub)

	// Verifier is the IDV attestation verifier for this deployment.
	// Required — startup fails if nil. Build the appropriate implementation
	// from the shyconfig identity_binding_mode:
	//   identity.DiditVerifier  — preferred (Didit device attestation)
	//   identity.ZKVerifier     — high-assurance (Groth16 nullifier + Didit)
	//   identity.IdentusVerifier — DAO governance (offline VC)
	//   identity.WalletVerifier  — EVM wallet (shyshares-v1)
	Verifier identity.IdentityVerifier
}

// App implements the CometBFT v0.38 ABCI 2.0 application interface for the
// two-list anonymous voting protocol. Shared across all deployments.
type App struct {
	abcitypes.BaseApplication

	logger  log.Logger
	state   *state.State
	chainID string
	appName string
	tracer  trace.Tracer
}

// New constructs and initializes the shared ABCI application.
// cfg.Verifier is required — startup fails fast if nil.
func New(ctx context.Context, cfg Config, logger log.Logger) (*App, error) {
	if cfg.Verifier == nil {
		return nil, fmt.Errorf("Config.Verifier is required: set an identity.IdentityVerifier appropriate for the shyconfig identity_binding_mode")
	}

	db, err := dbm.NewGoLevelDB(cfg.DBName, cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	st, err := state.NewState(ctx, db, cfg.KMSKeyID, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize state: %w", err)
	}

	st.SetIdentityVerifier(cfg.Verifier)
	logger.Info("Identity verifier configured", "type", fmt.Sprintf("%T", cfg.Verifier))

	return &App{
		logger:  logger,
		state:   st,
		chainID: cfg.ChainID,
		appName: cfg.AppName,
		tracer:  telemetry.Tracer(cfg.TracerName),
	}, nil
}

// Info returns information about the application state.
// Called by CometBFT on startup to sync block height and app hash.
func (app *App) Info(_ context.Context, _ *abcitypes.RequestInfo) (*abcitypes.ResponseInfo, error) {
	height, appHash := app.state.GetInfo()
	return &abcitypes.ResponseInfo{
		Data:             app.appName,
		Version:          "0.1.0",
		AppVersion:       1,
		LastBlockHeight:  height,
		LastBlockAppHash: appHash,
	}, nil
}

// CheckTx validates a transaction before adding it to the mempool.
// Called concurrently; only performs stateless + stateful validation (no state mutation).
func (app *App) CheckTx(_ context.Context, req *abcitypes.RequestCheckTx) (*abcitypes.ResponseCheckTx, error) {
	transaction, err := tx.DecodeTx(req.Tx)
	if err != nil {
		return &abcitypes.ResponseCheckTx{Code: 1, Log: fmt.Sprintf("invalid tx encoding: %v", err)}, nil
	}
	if err := transaction.Validate(); err != nil {
		return &abcitypes.ResponseCheckTx{Code: 2, Log: fmt.Sprintf("invalid tx: %v", err)}, nil
	}
	if err := app.state.ValidateTx(transaction); err != nil {
		return &abcitypes.ResponseCheckTx{Code: 3, Log: fmt.Sprintf("tx validation failed: %v", err)}, nil
	}
	return &abcitypes.ResponseCheckTx{Code: 0}, nil
}

// FinalizeBlock processes all transactions in a decided block.
// In ABCI 2.0 this replaces the old BeginBlock/DeliverTx/EndBlock sequence.
//
// PII guardrail: span attributes must NOT include poll_id, ballot_id, or identity_hash.
func (app *App) FinalizeBlock(ctx context.Context, req *abcitypes.RequestFinalizeBlock) (*abcitypes.ResponseFinalizeBlock, error) {
	ctx, span := app.tracer.Start(ctx, "FinalizeBlock",
		trace.WithAttributes(
			attribute.Int64("block.height", req.Height),
			attribute.Int("block.tx_count", len(req.Txs)),
			attribute.String("chain.id", app.chainID),
		),
	)
	defer span.End()

	// Record the canonical block hash in the beacon window so that submission
	// validators can prove nonce independence from publicly-committed BFT entropy.
	app.state.RecordBeacon(req.Height, hex.EncodeToString(req.Hash))

	txResults := make([]*abcitypes.ExecTxResult, len(req.Txs))
	successCount, failCount := 0, 0

	for i, txBytes := range req.Txs {
		transaction, err := tx.DecodeTx(txBytes)
		if err != nil {
			txResults[i] = &abcitypes.ExecTxResult{Code: 1, Log: fmt.Sprintf("invalid tx encoding: %v", err)}
			failCount++
			span.AddEvent("tx_decode_error", trace.WithAttributes(attribute.Int("tx.index", i)))
			continue
		}

		events, err := app.state.ExecuteTx(transaction)
		if err != nil {
			txResults[i] = &abcitypes.ExecTxResult{Code: 4, Log: fmt.Sprintf("tx execution failed: %v", err)}
			failCount++
			span.AddEvent("tx_exec_error", trace.WithAttributes(
				attribute.Int("tx.index", i),
				attribute.Int("tx.type", int(transaction.Type)),
				// Do NOT add poll_id, ballot_id, or identity_hash — PII guardrail.
			))
			continue
		}

		txResults[i] = &abcitypes.ExecTxResult{Code: 0, Events: events}
		successCount++
	}

	span.SetAttributes(
		attribute.Int("block.tx_success", successCount),
		attribute.Int("block.tx_fail", failCount),
	)

	validatorUpdates := app.state.GetPendingValidatorUpdates()
	if len(validatorUpdates) > 0 {
		app.logger.Info("FinalizeBlock: applying validator updates", "count", len(validatorUpdates))
		span.AddEvent("validator_updates", trace.WithAttributes(attribute.Int("count", len(validatorUpdates))))
	}

	appHash, err := app.state.Commit()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "commit failed")
		return nil, fmt.Errorf("commit failed: %v", err)
	}

	span.SetStatus(codes.Ok, "")
	return &abcitypes.ResponseFinalizeBlock{
		TxResults:        txResults,
		ValidatorUpdates: validatorUpdates,
		AppHash:          appHash,
	}, nil
}

// Commit signals that the block has been committed. State is persisted in FinalizeBlock.
func (app *App) Commit(_ context.Context, _ *abcitypes.RequestCommit) (*abcitypes.ResponseCommit, error) {
	return &abcitypes.ResponseCommit{}, nil
}

// Query handles queries for application state.
// Supported paths: /poll/{id}, /tally/{id}, /votes/{id}, /voter_count/{id}, /confirms/{id}
func (app *App) Query(ctx context.Context, req *abcitypes.RequestQuery) (*abcitypes.ResponseQuery, error) {
	_, span := app.tracer.Start(ctx, "Query",
		trace.WithAttributes(attribute.String("query.path", req.Path)),
	)
	defer span.End()

	result, err := app.state.Query(req.Path, req.Data, req.Height, req.Prove)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return &abcitypes.ResponseQuery{Code: 5, Log: fmt.Sprintf("query failed: %v", err)}, nil
	}

	span.SetStatus(codes.Ok, "")
	return &abcitypes.ResponseQuery{Code: 0, Value: result}, nil
}

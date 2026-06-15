package app

import (
	"context"
	"encoding/base64"
	"fmt"

	dbm "github.com/cometbft/cometbft-db"
	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/libs/log"

	"github.com/ShywareLLC/community/shywire/state"
	"github.com/ShywareLLC/community/shywire/tx"
)

// Config parametrizes a shyware deployment.
type Config struct {
	ChainID                         string // e.g. "shyware-1"
	DBPath                          string
	DBName                          string
	AppName                         string
	EnrollmentAuthorityPubKeyBase64 string
}

// App implements CometBFT ABCI 2.0 for the shyware anonymous transfer protocol.
type App struct {
	abcitypes.BaseApplication

	logger  log.Logger
	state   *state.State
	chainID string
	appName string
}

func New(ctx context.Context, cfg Config, logger log.Logger) (*App, error) {
	db, err := dbm.NewGoLevelDB(cfg.DBName, cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	var opts state.Options
	if cfg.EnrollmentAuthorityPubKeyBase64 != "" {
		pubKeyBytes, err := base64.StdEncoding.DecodeString(cfg.EnrollmentAuthorityPubKeyBase64)
		if err != nil {
			return nil, fmt.Errorf("invalid enrollment authority pubkey: %w", err)
		}
		opts.EnrollmentAuthorityPubKey = pubKeyBytes
	}

	st, err := state.NewStateWithOptions(db, logger, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize state: %w", err)
	}

	return &App{
		logger:  logger,
		state:   st,
		chainID: cfg.ChainID,
		appName: cfg.AppName,
	}, nil
}

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

func (app *App) FinalizeBlock(ctx context.Context, req *abcitypes.RequestFinalizeBlock) (*abcitypes.ResponseFinalizeBlock, error) {
	txResults := make([]*abcitypes.ExecTxResult, len(req.Txs))

	for i, txBytes := range req.Txs {
		transaction, err := tx.DecodeTx(txBytes)
		if err != nil {
			txResults[i] = &abcitypes.ExecTxResult{Code: 1, Log: fmt.Sprintf("decode error: %v", err)}
			continue
		}
		events, err := app.state.ExecuteTx(transaction)
		if err != nil {
			txResults[i] = &abcitypes.ExecTxResult{Code: 4, Log: fmt.Sprintf("exec error: %v", err)}
			continue
		}
		txResults[i] = &abcitypes.ExecTxResult{Code: 0, Events: events}
	}

	validatorUpdates := app.state.GetPendingValidatorUpdates()

	appHash, err := app.state.Commit()
	if err != nil {
		return nil, fmt.Errorf("commit failed: %w", err)
	}

	return &abcitypes.ResponseFinalizeBlock{
		TxResults:        txResults,
		ValidatorUpdates: validatorUpdates,
		AppHash:          appHash,
	}, nil
}

func (app *App) Commit(_ context.Context, _ *abcitypes.RequestCommit) (*abcitypes.ResponseCommit, error) {
	return &abcitypes.ResponseCommit{}, nil
}

func (app *App) Query(_ context.Context, req *abcitypes.RequestQuery) (*abcitypes.ResponseQuery, error) {
	result, err := app.state.Query(req.Path, req.Data, req.Height, req.Prove)
	if err != nil {
		return &abcitypes.ResponseQuery{Code: 5, Log: fmt.Sprintf("query failed: %v", err)}, nil
	}
	return &abcitypes.ResponseQuery{Code: 0, Value: result}, nil
}

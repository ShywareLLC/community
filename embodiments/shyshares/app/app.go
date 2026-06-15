// Package app provides the combined ABCI application for shyshares — the
// composition of the shyvoting (anonymous ballot) and shywire (anonymous token)
// protocols running on a single CometBFT chain.
//
// # Architecture
//
// shyshares is not a new protocol. It is one mechanism applied twice:
//
//	shywire L2 (anonymous holder registry) — who holds governance tokens, anonymously
//	shyvoting L1/L2 (anonymous ballot) — who voted which way, anonymously
//
// The two-list invariant holds independently in each sub-state machine.
// The app hash is sha256(voting_app_hash || wire_app_hash), committing both
// sub-states atomically per block.
//
// # Cross-protocol eligibility
//
// When Config.GovAssetID is set, BallotCast transactions are additionally
// validated against the shywire account state: the voter's account commitment
// must hold at least Config.MinVoteBalance units of the governance asset.
// This implements anonymous token-weighted governance without revealing which
// account voted for what.
//
// # Tx routing
//
// Every tx submitted to a shyshares chain is wrapped in a shyshares Envelope
// ({protocol, payload}). The ABCI app decodes the envelope and dispatches to
// the appropriate sub-state machine. See shyshares/tx for the envelope format.
package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/libs/log"
	dbm "github.com/cometbft/cometbft-db"

	"github.com/ShywareLLC/community/services/identity"
	votingstate "github.com/ShywareLLC/community/domain/state"
	votingtx "github.com/ShywareLLC/community/protocol/tx"

	wirestate "github.com/ShywareLLC/community/shywire/state"
	wiretx "github.com/ShywareLLC/community/shywire/tx"

	sstx "github.com/ShywareLLC/community/shyshares/tx"
)

// Config parametrizes a shyshares chain deployment.
type Config struct {
	ChainID string
	AppName string

	// Voting sub-state configuration.
	VotingDBPath   string                 // directory for voting LevelDB files
	VotingDBName   string                 // voting database name (e.g. "dao-voting")
	VotingKMSKeyID string                 // AWS KMS key for tally attestation (empty = SHA-256 stub)
	Verifier       identity.IdentityVerifier // IDV verifier — WalletVerifier for DAO governance

	// Token sub-state configuration.
	WireDBPath string // directory for wire LevelDB files
	WireDBName string // wire database name (e.g. "dao-wire")

	// Cross-protocol: governance token eligibility gate.
	// When GovAssetID is non-empty, BallotCast txs are rejected unless the
	// voter's account commitment holds at least MinVoteBalance units.
	// Set MinVoteBalance = 0 to allow any token holder (balance > 0).
	GovAssetID     string
	MinVoteBalance uint64

	// AuthorityKeys tags PollCreate txs from consortium board/coordinator keys.
	// Polls signed by these keys emit creator_type = "authority".
	AuthorityKeys []ed25519.PublicKey

	// HouseKeys tags PollCreate txs from warehouse/vault owner keys.
	// The house is the legal owner of the physical premises — a person,
	// partnership, or verified entity. May operate multiple warehouse locations.
	// Polls signed by these keys emit creator_type = "house".
	// Checked before AuthorityKeys; a key may appear in only one list.
	HouseKeys []ed25519.PublicKey
}

// App is the combined ABCI application for a shyshares chain.
// It holds two independent sub-state machines that commit atomically.
type App struct {
	abcitypes.BaseApplication

	logger  log.Logger
	voting  *votingstate.State
	wire    *wirestate.State
	chainID string
	appName string
	cfg     Config
}

// New constructs a ShySharesApp from cfg.
// Opens two LevelDB databases and initialises both sub-state machines.
func New(ctx context.Context, cfg Config, logger log.Logger) (*App, error) {
	if cfg.Verifier == nil {
		return nil, fmt.Errorf("Config.Verifier is required for the voting sub-state machine")
	}

	vDB, err := dbm.NewGoLevelDB(cfg.VotingDBName, cfg.VotingDBPath)
	if err != nil {
		return nil, fmt.Errorf("open voting db: %w", err)
	}

	vs, err := votingstate.NewState(ctx, vDB, cfg.VotingKMSKeyID, logger)
	if err != nil {
		return nil, fmt.Errorf("init voting state: %w", err)
	}
	vs.SetIdentityVerifier(cfg.Verifier)

	wDB, err := dbm.NewGoLevelDB(cfg.WireDBName, cfg.WireDBPath)
	if err != nil {
		return nil, fmt.Errorf("open wire db: %w", err)
	}

	ws, err := wirestate.NewState(wDB, logger)
	if err != nil {
		return nil, fmt.Errorf("init wire state: %w", err)
	}

	logger.Info("ShySharesApp initialised",
		"chain_id", cfg.ChainID,
		"verifier", fmt.Sprintf("%T", cfg.Verifier),
		"gov_asset_id", cfg.GovAssetID,
		"min_vote_balance", cfg.MinVoteBalance,
	)

	return &App{
		logger:  logger,
		voting:  vs,
		wire:    ws,
		chainID: cfg.ChainID,
		appName: cfg.AppName,
		cfg:     cfg,
	}, nil
}

// Info returns the combined chain state for CometBFT handshake.
// Height = max(voting_height, wire_height).
// AppHash = sha256(voting_app_hash || wire_app_hash).
func (a *App) Info(_ context.Context, _ *abcitypes.RequestInfo) (*abcitypes.ResponseInfo, error) {
	vHeight, vHash := a.voting.GetInfo()
	wHeight, wHash := a.wire.GetInfo()

	height := vHeight
	if wHeight > height {
		height = wHeight
	}

	h := sha256.New()
	h.Write(vHash)
	h.Write(wHash)

	return &abcitypes.ResponseInfo{
		Data:             a.appName,
		Version:          "0.1.0",
		AppVersion:       1,
		LastBlockHeight:  height,
		LastBlockAppHash: h.Sum(nil),
	}, nil
}

// CheckTx validates a transaction before mempool admission.
func (a *App) CheckTx(_ context.Context, req *abcitypes.RequestCheckTx) (*abcitypes.ResponseCheckTx, error) {
	env, err := sstx.DecodeEnvelope(req.Tx)
	if err != nil {
		return &abcitypes.ResponseCheckTx{Code: 1, Log: fmt.Sprintf("invalid envelope: %v", err)}, nil
	}

	switch env.Protocol {
	case sstx.ProtocolVoting:
		t, err := votingtx.DecodeTx(env.Payload)
		if err != nil {
			return &abcitypes.ResponseCheckTx{Code: 1, Log: fmt.Sprintf("invalid voting tx: %v", err)}, nil
		}
		if err := t.Validate(); err != nil {
			return &abcitypes.ResponseCheckTx{Code: 2, Log: fmt.Sprintf("invalid tx: %v", err)}, nil
		}
		if err := a.voting.ValidateTx(t); err != nil {
			return &abcitypes.ResponseCheckTx{Code: 3, Log: fmt.Sprintf("voting validation failed: %v", err)}, nil
		}

	case sstx.ProtocolWire:
		t, err := wiretx.DecodeTx(env.Payload)
		if err != nil {
			return &abcitypes.ResponseCheckTx{Code: 1, Log: fmt.Sprintf("invalid wire tx: %v", err)}, nil
		}
		if err := a.wire.ValidateTx(t); err != nil {
			return &abcitypes.ResponseCheckTx{Code: 3, Log: fmt.Sprintf("wire validation failed: %v", err)}, nil
		}
	}

	return &abcitypes.ResponseCheckTx{Code: 0}, nil
}

// FinalizeBlock processes all txs in a decided block, routing each to the
// appropriate sub-state machine and committing both atomically.
func (a *App) FinalizeBlock(ctx context.Context, req *abcitypes.RequestFinalizeBlock) (*abcitypes.ResponseFinalizeBlock, error) {
	txResults := make([]*abcitypes.ExecTxResult, len(req.Txs))
	var allValidatorUpdates []abcitypes.ValidatorUpdate

	for i, txBytes := range req.Txs {
		env, err := sstx.DecodeEnvelope(txBytes)
		if err != nil {
			txResults[i] = &abcitypes.ExecTxResult{Code: 1, Log: fmt.Sprintf("invalid envelope: %v", err)}
			continue
		}

		switch env.Protocol {
		case sstx.ProtocolVoting:
			t, err := votingtx.DecodeTx(env.Payload)
			if err != nil {
				txResults[i] = &abcitypes.ExecTxResult{Code: 1, Log: fmt.Sprintf("invalid voting tx: %v", err)}
				continue
			}
			events, err := a.voting.ExecuteTx(t)
			if err != nil {
				txResults[i] = &abcitypes.ExecTxResult{Code: 4, Log: fmt.Sprintf("voting execution failed: %v", err)}
				continue
			}
			if ct := a.pollCreatorType(t); ct != "" {
				events = append(events, abcitypes.Event{
					Type: "poll_create",
					Attributes: []abcitypes.EventAttribute{
						{Key: "creator_type", Value: ct, Index: false},
					},
				})
			}
			txResults[i] = &abcitypes.ExecTxResult{Code: 0, Events: events}

		case sstx.ProtocolWire:
			t, err := wiretx.DecodeTx(env.Payload)
			if err != nil {
				txResults[i] = &abcitypes.ExecTxResult{Code: 1, Log: fmt.Sprintf("invalid wire tx: %v", err)}
				continue
			}
			events, err := a.wire.ExecuteTx(t)
			if err != nil {
				txResults[i] = &abcitypes.ExecTxResult{Code: 4, Log: fmt.Sprintf("wire execution failed: %v", err)}
				continue
			}
			txResults[i] = &abcitypes.ExecTxResult{Code: 0, Events: events}

		default:
			txResults[i] = &abcitypes.ExecTxResult{Code: 1, Log: fmt.Sprintf("unknown protocol: %q", env.Protocol)}
		}
	}

	allValidatorUpdates = append(allValidatorUpdates, a.voting.GetPendingValidatorUpdates()...)
	allValidatorUpdates = append(allValidatorUpdates, a.wire.GetPendingValidatorUpdates()...)

	vHash, err := a.voting.Commit()
	if err != nil {
		return nil, fmt.Errorf("voting commit failed: %w", err)
	}
	wHash, err := a.wire.Commit()
	if err != nil {
		return nil, fmt.Errorf("wire commit failed: %w", err)
	}

	combined := sha256.New()
	combined.Write(vHash)
	combined.Write(wHash)

	return &abcitypes.ResponseFinalizeBlock{
		TxResults:        txResults,
		ValidatorUpdates: allValidatorUpdates,
		AppHash:          combined.Sum(nil),
	}, nil
}

// pollCreatorType returns "authority" if the PollCreate tx was signed by a known
// authority key (operator/board), or "holder" otherwise. Any eligible holder may
// create a poll — this tag is informational only, used in event attributes so the
// API and frontend can distinguish official polls from community-raised ones.
// Returns "" for non-PollCreate txs.
func (a *App) pollCreatorType(t *votingtx.Tx) string {
	if t.Type != votingtx.TxTypePollCreate {
		return ""
	}
	for _, pub := range a.cfg.HouseKeys {
		if ed25519.Verify(pub, t.Data, t.Signature) {
			return "house"
		}
	}
	for _, pub := range a.cfg.AuthorityKeys {
		if ed25519.Verify(pub, t.Data, t.Signature) {
			return "authority"
		}
	}
	return "holder"
}

// Commit signals block commit. State is persisted in FinalizeBlock.
func (a *App) Commit(_ context.Context, _ *abcitypes.RequestCommit) (*abcitypes.ResponseCommit, error) {
	return &abcitypes.ResponseCommit{}, nil
}

// Query routes state queries to the appropriate sub-state machine.
//
// Path prefix routing:
//
//	/voting/* → voting sub-state (strip /voting prefix)
//	/wire/*   → wire sub-state (strip /wire prefix)
//	anything else → try voting first, then wire
func (a *App) Query(_ context.Context, req *abcitypes.RequestQuery) (*abcitypes.ResponseQuery, error) {
	var (
		result []byte
		err    error
	)

	const votingPrefix = "/voting"
	const wirePrefix = "/wire"

	switch {
	case len(req.Path) >= len(votingPrefix) && req.Path[:len(votingPrefix)] == votingPrefix:
		subPath := req.Path[len(votingPrefix):]
		if subPath == "" {
			subPath = "/"
		}
		result, err = a.voting.Query(subPath, req.Data, req.Height, req.Prove)

	case len(req.Path) >= len(wirePrefix) && req.Path[:len(wirePrefix)] == wirePrefix:
		subPath := req.Path[len(wirePrefix):]
		if subPath == "" {
			subPath = "/"
		}
		result, err = a.wire.Query(subPath, req.Data, req.Height, req.Prove)

	default:
		// Unqualified path: try voting, then wire.
		result, err = a.voting.Query(req.Path, req.Data, req.Height, req.Prove)
		if err != nil {
			result, err = a.wire.Query(req.Path, req.Data, req.Height, req.Prove)
		}
	}

	if err != nil {
		return &abcitypes.ResponseQuery{Code: 5, Log: fmt.Sprintf("query failed: %v", err)}, nil
	}
	return &abcitypes.ResponseQuery{Code: 0, Value: result}, nil
}

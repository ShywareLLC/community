package state

import (
	"encoding/base64"
	"fmt"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	cmtcrypto "github.com/cometbft/cometbft/proto/tendermint/crypto"

	"github.com/ShywareLLC/community/protocol/tx"
)

// ValidatorRecord holds the registered state of a consensus validator.
type ValidatorRecord struct {
	PubKeyBase64 string `json:"pub_key_base64"` // base64 raw 32-byte Ed25519 key
	Power        int64  `json:"power"`
	Name         string `json:"name"`
	Height       int64  `json:"height"` // block height at which the record was last updated
}

// validateValidatorRegister performs stateful validation of a RegisterValidator tx.
// Currently stateless (no duplicate-key rejection) — the execute path handles upserts.
func (s *State) validateValidatorRegister(transaction *tx.Tx) error {
	var data tx.ValidatorRegistrationData
	if err := transaction.UnmarshalData(&data); err != nil {
		return fmt.Errorf("invalid validator registration data: %w", err)
	}
	// Stateless checks already ran in tx.Validate(); nothing extra to check here.
	return nil
}

// executeValidatorRegister applies a RegisterValidator tx to the in-memory state.
// Power > 0 upserts the validator; Power == 0 removes it.
// In both cases a ValidatorUpdate is queued for EndBlock.
func (s *State) executeValidatorRegister(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var data tx.ValidatorRegistrationData
	if err := transaction.UnmarshalData(&data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal validator registration data: %w", err)
	}

	raw, err := base64.StdEncoding.DecodeString(data.PubKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("pub_key_base64 decode failed: %w", err)
	}

	if data.Power == 0 {
		delete(s.validators, data.PubKeyBase64)
	} else {
		s.validators[data.PubKeyBase64] = &ValidatorRecord{
			PubKeyBase64: data.PubKeyBase64,
			Power:        data.Power,
			Name:         data.Name,
			Height:       s.height,
		}
	}

	s.pendingValidatorUpdates = append(s.pendingValidatorUpdates, abcitypes.ValidatorUpdate{
		PubKey: cmtcrypto.PublicKey{
			Sum: &cmtcrypto.PublicKey_Ed25519{Ed25519: raw},
		},
		Power: data.Power,
	})

	s.dirty = true

	return []abcitypes.Event{
		{
			Type: "validator_registered",
			Attributes: []abcitypes.EventAttribute{
				{Key: "pub_key", Value: data.PubKeyBase64},
				{Key: "power", Value: fmt.Sprintf("%d", data.Power)},
				{Key: "name", Value: data.Name},
			},
		},
	}, nil
}

// GetPendingValidatorUpdates returns all queued ValidatorUpdates and clears the slice.
// Called once per block by EndBlock.
func (s *State) GetPendingValidatorUpdates() []abcitypes.ValidatorUpdate {
	updates := s.pendingValidatorUpdates
	s.pendingValidatorUpdates = nil
	return updates
}

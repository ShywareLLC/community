package state

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/ed25519"

	"github.com/ShywareLLC/community/shywire/tx"
)

// ValidatorRecord mirrors the protocol equivalent.
type ValidatorRecord struct {
	PubKeyBase64 string `json:"pub_key_base64"`
	Power        int64  `json:"power"`
	Name         string `json:"name"`
}

func (s *State) executeRegisterValidator(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.ValidatorRegistrationData
	if err := json.Unmarshal(transaction.Data, &d); err != nil {
		return nil, fmt.Errorf("invalid validator registration data: %w", err)
	}

	raw, err := base64.StdEncoding.DecodeString(d.PubKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid pub_key_base64: %w", err)
	}

	pubKey := ed25519.PubKey(raw)
	update := abcitypes.UpdateValidator(pubKey.Bytes(), d.Power, "ed25519")

	s.validators[d.PubKeyBase64] = &ValidatorRecord{
		PubKeyBase64: d.PubKeyBase64,
		Power:        d.Power,
		Name:         d.Name,
	}
	s.pendingValidatorUpdates = append(s.pendingValidatorUpdates, update)
	s.dirty = true

	return []abcitypes.Event{
		{Type: "validator_update", Attributes: []abcitypes.EventAttribute{
			{Key: "name", Value: d.Name},
			{Key: "power", Value: fmt.Sprintf("%d", d.Power)},
		}},
	}, nil
}

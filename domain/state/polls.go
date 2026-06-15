package state

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/ShywareLLC/community/protocol/tx"
	"github.com/ShywareLLC/community/protocol/types"
)

// validatePollCreate validates a poll creation transaction
func (s *State) validatePollCreate(transaction *tx.Tx) error {
	var data tx.PollCreateData
	if err := transaction.UnmarshalData(&data); err != nil {
		return fmt.Errorf("invalid poll create data: %w", err)
	}

	// Check if poll already exists
	if _, exists := s.polls[data.PollID]; exists {
		return &types.ErrorInvalidPoll{Message: fmt.Sprintf("poll %s already exists", data.PollID)}
	}

	// Validate poll times
	now := time.Now().Unix()
	if data.StartTime < now {
		return &types.ErrorInvalidPoll{Message: "start time must be in the future"}
	}
	if data.EndTime <= data.StartTime {
		return &types.ErrorInvalidPoll{Message: "end time must be after start time"}
	}

	// Validate voting method
	switch data.VotingMethod {
	case "", types.VotingMethodPlurality, types.VotingMethodApproval, types.VotingMethodRanked:
		// valid (empty defaults to plurality)
	default:
		return &types.ErrorInvalidPoll{Message: fmt.Sprintf("unknown voting_method: %q", data.VotingMethod)}
	}

	// Validate options
	if len(data.Options) < 2 {
		return &types.ErrorInvalidPoll{Message: "poll must have at least 2 options"}
	}
	if len(data.Options) > 10 {
		return &types.ErrorInvalidPoll{Message: "poll cannot have more than 10 options"}
	}

	// Check for duplicate options
	optionSet := make(map[string]bool)
	for _, option := range data.Options {
		if option == "" {
			return &types.ErrorInvalidPoll{Message: "option cannot be empty"}
		}
		if optionSet[option] {
			return &types.ErrorInvalidPoll{Message: fmt.Sprintf("duplicate option: %s", option)}
		}
		optionSet[option] = true
	}

	// Two-party rescission keys: both or neither, count-match deployments only.
	hasElig := data.EligibilityAuthorityPubKeyBase64 != ""
	hasReconcile := data.ReconcilingAuthorityPubKeyBase64 != ""
	if hasElig != hasReconcile {
		return &types.ErrorInvalidPoll{Message: "eligibility_authority_pub_key_base64 and reconciling_authority_pub_key_base64 must both be provided or both omitted"}
	}
	if hasElig && data.EligibilityAuthorityPubKeyBase64 == data.ReconcilingAuthorityPubKeyBase64 {
		return &types.ErrorInvalidPoll{Message: "eligibility_authority_pub_key_base64 and reconciling_authority_pub_key_base64 must be distinct keys; identical keys collapse the two-party threshold to a single-party threshold"}
	}
	for label, val := range map[string]string{
		"eligibility_authority_pub_key_base64":  data.EligibilityAuthorityPubKeyBase64,
		"reconciling_authority_pub_key_base64": data.ReconcilingAuthorityPubKeyBase64,
	} {
		if val == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(val)
		if err != nil {
			return &types.ErrorInvalidPoll{Message: fmt.Sprintf("%s is not valid base64: %v", label, err)}
		}
		if len(raw) != 32 {
			return &types.ErrorInvalidPoll{Message: fmt.Sprintf("%s must decode to 32 bytes (Ed25519), got %d", label, len(raw))}
		}
	}

	return nil
}

// executePollCreate executes a poll creation transaction
func (s *State) executePollCreate(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var data tx.PollCreateData
	if err := transaction.UnmarshalData(&data); err != nil {
		return nil, fmt.Errorf("invalid poll create data: %w", err)
	}

	// Compute poll hash (deterministic)
	pollHash := s.computePollHash(&data)

	method := data.VotingMethod
	if method == "" {
		method = types.VotingMethodPlurality
	}

	// Create poll
	poll := &types.Poll{
		PollID:       data.PollID,
		PollHash:     pollHash,
		Question:     data.Question,
		Options:      data.Options,
		VotingMethod: method,
		StartTime:    data.StartTime,
		EndTime:      data.EndTime,
		Status:       "pending",
		CreatedAt:    time.Now().Unix(),
		// Two-party rescission keys — stored as-is (base64); immutable after creation.
		EligibilityAuthorityPubKey: data.EligibilityAuthorityPubKeyBase64,
		ReconcilingAuthorityPubKey: data.ReconcilingAuthorityPubKeyBase64,
	}

	// Store poll
	s.polls[data.PollID] = poll
	s.dirty = true

	s.logger.Info("Poll created",
		"scoping_id", data.PollID,
		"question", data.Question,
		"options", len(data.Options),
	)

	// Emit event for indexer
	events := []abcitypes.Event{
		{
			Type: "poll_created",
			Attributes: []abcitypes.EventAttribute{
				{Key: "scoping_id", Value: data.PollID, Index: true},
				{Key: "poll_hash", Value: pollHash, Index: true},
				{Key: "question", Value: data.Question, Index: false},
				{Key: "start_time", Value: fmt.Sprintf("%d", data.StartTime), Index: false},
				{Key: "end_time", Value: fmt.Sprintf("%d", data.EndTime), Index: false},
			},
		},
	}

	return events, nil
}

// computePollHash computes a deterministic hash of poll parameters
func (s *State) computePollHash(data *tx.PollCreateData) string {
	h := sha256.New()
	h.Write([]byte(data.PollID))
	h.Write([]byte(data.Question))
	for _, option := range data.Options {
		h.Write([]byte(option))
	}
	h.Write([]byte(data.VotingMethod))
	h.Write([]byte(fmt.Sprintf("%d", data.StartTime)))
	h.Write([]byte(fmt.Sprintf("%d", data.EndTime)))
	return hex.EncodeToString(h.Sum(nil))
}

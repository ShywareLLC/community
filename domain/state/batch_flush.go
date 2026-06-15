package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/ShywareLLC/community/protocol/tx"
	"github.com/ShywareLLC/community/protocol/types"
)

type batchCandidate struct {
	transaction  *tx.Tx
	data         tx.BallotCastData
	ballotID     string
	identityHash string
}

func (s *State) validateBatchFlush(transaction *tx.Tx) error {
	var data tx.BatchFlushData
	if err := transaction.UnmarshalData(&data); err != nil {
		return fmt.Errorf("invalid batch flush data: %w", err)
	}

	poll, exists := s.polls[data.PollID]
	if !exists {
		return &types.ErrorInvalidPoll{Message: fmt.Sprintf("poll %s does not exist", data.PollID)}
	}
	if poll.Status == "closed" {
		return &types.ErrorInvalidPoll{Message: "poll is closed"}
	}

	seenBallotIDs := make(map[string]struct{}, len(data.Submissions))
	seenRegistryKeys := make(map[string]struct{}, len(data.Submissions))

	for i := range data.Submissions {
		submission := data.Submissions[i]
		if submission.Type != tx.TxTypeBallotCast {
			return fmt.Errorf("batch flush submission %d must be ballot cast", i)
		}
		if err := s.validateBallotCast(&submission); err != nil {
			return fmt.Errorf("batch flush submission %d invalid: %w", i, err)
		}

		var castData tx.BallotCastData
		if err := submission.UnmarshalData(&castData); err != nil {
			return fmt.Errorf("batch flush submission %d data invalid: %w", i, err)
		}
		if castData.PollID != data.PollID {
			return fmt.Errorf("batch flush submission %d poll mismatch: %s != %s", i, castData.PollID, data.PollID)
		}

		ballotID := deriveBallotIDWithBeacon(castData.BeaconBlockHash, castData.BallotNonce, castData.Choices, castData.SubmissionIdentifierDerivation)
		if _, exists := seenBallotIDs[ballotID]; exists {
			return fmt.Errorf("duplicate ballot nonce in batch for poll %s", data.PollID)
		}
		seenBallotIDs[ballotID] = struct{}{}

		identityHash, err := s.verifier.VerifyAndIdentify(&castData)
		if err != nil {
			return fmt.Errorf("batch flush submission %d identity verification failed: %w", i, err)
		}
		registryKey := data.PollID + ":" + identityHash
		if _, exists := seenRegistryKeys[registryKey]; exists {
			return fmt.Errorf("duplicate participant identity in batch for poll %s", data.PollID)
		}
		seenRegistryKeys[registryKey] = struct{}{}
	}

	return nil
}

func (s *State) executeBatchFlush(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var data tx.BatchFlushData
	if err := transaction.UnmarshalData(&data); err != nil {
		return nil, fmt.Errorf("invalid batch flush data: %w", err)
	}

	candidates := make([]batchCandidate, 0, len(data.Submissions))
	for i := range data.Submissions {
		submission := data.Submissions[i]
		var castData tx.BallotCastData
		if err := submission.UnmarshalData(&castData); err != nil {
			return nil, fmt.Errorf("batch flush submission %d data invalid: %w", i, err)
		}
		identityHash, err := s.verifier.VerifyAndIdentify(&castData)
		if err != nil {
			return nil, fmt.Errorf("batch flush submission %d identity verification failed: %w", i, err)
		}
		candidates = append(candidates, batchCandidate{
			transaction:  &submission,
			data:         castData,
			ballotID:     deriveBallotIDWithBeacon(castData.BeaconBlockHash, castData.BallotNonce, castData.Choices, castData.SubmissionIdentifierDerivation),
			identityHash: identityHash,
		})
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].ballotID < candidates[j].ballotID
	})

	for _, candidate := range candidates {
		registryKey := candidate.data.PollID + ":" + candidate.identityHash
		voteKey := voteStoreKey(candidate.data.PollID, candidate.ballotID)

		migrationAuthInput := "partition-migration-auth:" + candidate.data.VoterPubKey + ":" + candidate.data.PollID
		migrationAuthHash := sha256.Sum256([]byte(migrationAuthInput))
		s.voteDirections[voteKey] = &types.VoteRecord{
			BallotID:        candidate.ballotID,
			Choices:         candidate.data.Choices,
			VoterPubKeyHash: hex.EncodeToString(migrationAuthHash[:]),
		}
		s.voterRegistry[registryKey] = &types.VoterRecord{
			IdentityHash: candidate.identityHash,
		}
	}

	// Increment IDVCastCount by the number of candidates flushed. Each candidate
	// passed IDV attestation during validateBatchFlush. Batch flushes share the
	// same IDV-attested-cast semantic as individual executeBallotCast calls.
	if len(candidates) > 0 {
		if p, exists := s.polls[data.PollID]; exists {
			p.IDVCastCount += int64(len(candidates))
		}
	}

	s.dirty = true

	var checkpointEvents []abcitypes.Event
	if s.attestationMode == "rolling" && s.rollingThreshold > 0 {
		s.submissionCounts[data.PollID] += len(candidates)
		for s.submissionCounts[data.PollID] >= s.rollingThreshold {
			s.submissionCounts[data.PollID] -= s.rollingThreshold
			cpEvents, err := s.commitRollingAttestation(context.Background(), data.PollID)
			if err != nil {
				return nil, fmt.Errorf("rolling attestation failed for flushed batch: %w", err)
			}
			checkpointEvents = append(checkpointEvents, cpEvents...)
		}
	}

	batchID := computeBatchID(data.PollID, candidateBallotIDs(candidates))
	s.logger.Info("Submission batch flushed",
		"scoping_id", data.PollID,
		"batch_id", batchID,
		"submission_count", len(candidates),
	)

	events := []abcitypes.Event{{
		Type: "submission_batch_flushed",
		Attributes: []abcitypes.EventAttribute{
			{Key: "scoping_id", Value: data.PollID, Index: true},
			{Key: "batch_id", Value: batchID, Index: true},
			{Key: "submission_count", Value: fmt.Sprintf("%d", len(candidates)), Index: false},
		},
	}}

	events = append(events, checkpointEvents...)
	return events, nil
}

func candidateBallotIDs(candidates []batchCandidate) []string {
	ids := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		ids = append(ids, candidate.ballotID)
	}
	return ids
}

func computeBatchID(pollID string, ballotIDs []string) string {
	h := sha256.New()
	h.Write([]byte(pollID))
	for _, ballotID := range ballotIDs {
		h.Write([]byte{0})
		h.Write([]byte(ballotID))
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)
}

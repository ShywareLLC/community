package state

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/ShywareLLC/community/protocol/tx"
	"github.com/ShywareLLC/community/protocol/types"
	"github.com/ShywareLLC/community/verify"
)

// validatePollClose validates a poll close transaction
func (s *State) validatePollClose(transaction *tx.Tx) error {
	var data tx.PollCloseData
	if err := transaction.UnmarshalData(&data); err != nil {
		return fmt.Errorf("invalid poll close data: %w", err)
	}

	poll, exists := s.polls[data.PollID]
	if !exists {
		return &types.ErrorInvalidPoll{Message: fmt.Sprintf("poll %s does not exist", data.PollID)}
	}

	if poll.Status == "closed" {
		return &types.ErrorInvalidPoll{Message: "poll is already closed"}
	}

	now := time.Now().Unix()
	if now < poll.EndTime {
		return &types.ErrorInvalidPoll{Message: "poll end time has not been reached"}
	}

	if _, exists := s.tallies[data.PollID]; exists {
		return &types.ErrorInvalidPoll{Message: "tally already exists for this poll"}
	}

	return nil
}

// collectPollLists returns the sorted ballot IDs, identity hashes, and vote
// counts for a poll. Shared by executePollClose and commitRollingAttestation.
func (s *State) collectPollLists(pollID string, method string, options []string) (
	ballotIDs []string, identityHashes []string, counts map[string]int64,
) {
	counts = make(map[string]int64)
	for _, option := range options {
		counts[option] = 0
	}
	prefix := pollID + ":"
	for key, vote := range s.voteDirections {
		if strings.HasPrefix(key, prefix) {
			// Count all votes except sealed (not yet revealed) and superseded.
			// Empty PartitionID means no partition — counts normally.
			// PartitionID "public" means explicitly revealed — also counts.
			// PartitionID "sealed" means encrypted payload not yet revealed — skip.
			if vote.PartitionID == "sealed" || vote.Superseded {
				continue
			}
			switch method {
			case types.VotingMethodApproval:
				for _, c := range vote.Choices {
					counts[c]++
				}
			default:
				if len(vote.Choices) > 0 {
					counts[vote.Choices[0]]++
				}
			}
			ballotIDs = append(ballotIDs, vote.BallotID)
		}
	}
	for key, voter := range s.voterRegistry {
		if strings.HasPrefix(key, prefix) {
			identityHashes = append(identityHashes, voter.IdentityHash)
		}
	}
	return
}

// commitRollingAttestation commits a cryptographic attestation checkpoint over
// the current two-list state for a poll without closing it. Called automatically
// after every rollingThreshold ballot casts when attestationMode == "rolling".
func (s *State) commitRollingAttestation(ctx context.Context, pollID string) ([]abcitypes.Event, error) {
	poll := s.polls[pollID]
	method := poll.VotingMethod
	if method == "" {
		method = types.VotingMethodPlurality
	}

	ballotIDs, identityHashes, _ := s.collectPollLists(pollID, method, poll.Options)
	total := int64(len(ballotIDs))

	if int64(len(identityHashes)) != total {
		return nil, fmt.Errorf(
			"count-match invariant violated at rolling attestation for poll %s: l1=%d l2=%d",
			pollID, total, len(identityHashes),
		)
	}

	l1Commitment := computeMerkleRoot(ballotIDs)
	l2Commitment := computeMerkleRoot(identityHashes)

	// Sign with an empty counts map — directional counts are not revealed at checkpoints.
	signature, degraded, err := s.signTallyPayload(ctx, pollID, nil, l1Commitment, l2Commitment, total)
	if err != nil {
		return nil, fmt.Errorf("rolling attestation signing failed for poll %s: %w", pollID, err)
	}

	var pubKeyDER []byte
	if s.signer != nil && !degraded {
		pubKeyDER = s.signer.PublicKeyDER()
	}

	seq := len(s.checkpoints[pollID])
	cp := &types.AttestationCheckpoint{
		PollID:              pollID,
		SequenceNumber:      seq,
		TotalSubmissions:    total,
		L1Commitment:        l1Commitment,
		L2Commitment:        l2Commitment,
		Signature:           signature,
		PublicKey:           pubKeyDER,
		AttestationDegraded: degraded,
		CommittedAt:         time.Now().Unix(),
		Height:              s.height + 1,
	}
	s.checkpoints[pollID] = append(s.checkpoints[pollID], cp)
	s.dirty = true

	s.logger.Info("Rolling attestation committed",
		"scoping_id", pollID,
		"sequence", seq,
		"total_submissions", total,
	)

	return []abcitypes.Event{{
		Type: "rolling_attestation",
		Attributes: []abcitypes.EventAttribute{
			{Key: "scoping_id", Value: pollID, Index: true},
			{Key: "sequence", Value: fmt.Sprintf("%d", seq), Index: false},
			{Key: "total_submissions", Value: fmt.Sprintf("%d", total), Index: false},
			{Key: "l1_commitment", Value: fmt.Sprintf("%x", l1Commitment), Index: false},
			{Key: "l2_commitment", Value: fmt.Sprintf("%x", l2Commitment), Index: false},
		},
	}}, nil
}

// executePollClose computes the final tally and enforces the count-match invariant.
// When attestationMode is "none", the poll is closed without a signed attestation.
func (s *State) executePollClose(transaction *tx.Tx) ([]abcitypes.Event, error) {
	var data tx.PollCloseData
	if err := transaction.UnmarshalData(&data); err != nil {
		return nil, fmt.Errorf("invalid poll close data: %w", err)
	}

	poll := s.polls[data.PollID]
	method := poll.VotingMethod
	if method == "" {
		method = types.VotingMethodPlurality
	}

	ballotIDs, identityHashes, counts := s.collectPollLists(data.PollID, method, poll.Options)
	totalVotes := int64(len(ballotIDs))

	if int64(len(identityHashes)) != totalVotes {
		return nil, fmt.Errorf(
			"count-match invariant violated for poll %s: vote_directions=%d voter_registry=%d",
			data.PollID, totalVotes, len(identityHashes),
		)
	}

	l1Commitment := computeMerkleRoot(ballotIDs)
	l2Commitment := computeMerkleRoot(identityHashes)

	var signature, pubKeyDER []byte
	var degraded bool

	if s.attestationMode != "none" {
		var err error
		signature, degraded, err = s.signTallyPayload(context.Background(), data.PollID, counts, l1Commitment, l2Commitment, totalVotes)
		if err != nil {
			return nil, fmt.Errorf("tally signing failed for poll %s: %w", data.PollID, err)
		}
		if s.signer != nil && !degraded {
			pubKeyDER = s.signer.PublicKeyDER()
		}
	}

	tally := &types.Tally{
		PollID:              data.PollID,
		VotingMethod:        method,
		Counts:              counts,
		TotalVotes:          totalVotes,
		ConfirmedCount:      s.confirmedCountForPoll(data.PollID),
		VoteMerkleRoot:      l1Commitment,
		VoterMerkleRoot:     l2Commitment,
		Signature:           signature,
		PublicKey:           pubKeyDER,
		AttestationDegraded: degraded,
		FinalizedAt:         time.Now().Unix(),
		Height:              s.height + 1,
	}

	poll.Status = "closed"
	s.tallies[data.PollID] = tally
	s.dirty = true

	s.logger.Info("Poll closed",
		"scoping_id", data.PollID,
		"total_votes", totalVotes,
		"attestation_mode", s.attestationMode,
	)

	return []abcitypes.Event{{
		Type: "poll_closed",
		Attributes: []abcitypes.EventAttribute{
			{Key: "scoping_id", Value: data.PollID, Index: true},
			{Key: "total_votes", Value: fmt.Sprintf("%d", totalVotes), Index: false},
			{Key: "l1_commitment", Value: fmt.Sprintf("%x", l1Commitment), Index: false},
			{Key: "l2_commitment", Value: fmt.Sprintf("%x", l2Commitment), Index: false},
			{Key: "finalized_at", Value: fmt.Sprintf("%d", tally.FinalizedAt), Index: false},
		},
	}}, nil
}

// computeMerkleRoot builds a binary Merkle tree over a set of string leaves
// (ballot_ids or identity_hashes). Leaves are sorted for determinism.
func computeMerkleRoot(items []string) []byte {
	if len(items) == 0 {
		return make([]byte, 32)
	}

	sort.Strings(items)

	leaves := make([][]byte, len(items))
	for i, item := range items {
		h := sha256.Sum256([]byte(item))
		leaves[i] = h[:]
	}

	for len(leaves) > 1 {
		var next [][]byte
		for i := 0; i < len(leaves); i += 2 {
			if i+1 < len(leaves) {
				combined := append(leaves[i], leaves[i+1]...)
				h := sha256.Sum256(combined)
				next = append(next, h[:])
			} else {
				next = append(next, leaves[i])
			}
		}
		leaves = next
	}

	return leaves[0]
}

// signTallyPayload builds the canonical signing payload via verify.BuildSigningPayload
// and signs it. Returns the signature and a degraded flag.
//
//   - degraded=false: KMS/HSM signed the payload (auditable by the public key).
//   - degraded=true:  KMS was unavailable at close time; SHA-256 stub used.
//     Canonical writes are preserved; attestation cannot be verified by third parties.
//
// In local development (no KMS key configured) the stub path is the default and
// degraded is false — indicating expected dev behaviour, not an HSM failure.
func (s *State) signTallyPayload(
	ctx context.Context,
	pollID string,
	counts map[string]int64,
	voteMerkleRoot, voterMerkleRoot []byte,
	totalVotes int64,
) (sig []byte, degraded bool, err error) {
	payload := verify.BuildSigningPayload(voteMerkleRoot, voterMerkleRoot, totalVotes, counts)

	if s.signer != nil {
		sig, err = s.signer.Sign(ctx, payload)
		if err != nil {
			// HSM/KMS unavailable at runtime: fall back to SHA-256 stub so that
			// the canonical tally write is not blocked (Claim 6 — canonical writes
			// preserved during HSM-unavailability fallback).
			s.logger.Error("KMS signer unavailable — HSM-unavailability fallback to SHA-256 stub",
				"scoping_id", pollID,
				"error", err,
			)
			return payload, true, nil
		}
		s.logger.Info("Tally signed",
			"scoping_id", pollID,
			"payload_prefix", fmt.Sprintf("%x", payload[:8]),
		)
		return sig, false, nil
	}

	// Local dev: no KMS key configured — stub signature, not a degraded condition.
	s.logger.Info("Tally signed (SHA-256 stub — no KMS key configured)",
		"scoping_id", pollID,
		"sig_prefix", fmt.Sprintf("%x", payload[:8]),
	)
	return payload, false, nil
}

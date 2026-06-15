// Package shyshares implements the weighted anonymous governance embodiment
// of the two-list shyware protocol.
//
// The two-list structural invariant (|L1| == |L2|, count-match, HSM tally
// attestation) is inherited from the shyware core. shyshares extends it with:
//   - wallet/delegation membership snapshots
//   - delegated-stake vote weighting
//   - canonical queued governance actions after proposal passage
//   - adapter-driven execution (shywire, byodao, internal_queue)
//
// A voter's wallet address and effective weight are never jointly visible
// in public outputs. The anonymous two-list layer hides direction; the
// membership snapshot hides which wallets participated in any given vote.
//
// First product surface: bigglom.com / quorum.bigglom.com (Co-Mission DAO).
package shyshares

import "time"

// Organization is a DAO or governance group using the shyshares protocol.
type Organization struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Slug          string   `json:"slug"`
	Description   string   `json:"description"`
	TokenSymbol   string   `json:"token_symbol"`
	TreasuryRail  string   `json:"treasury_rail"`
	Adapters      []string `json:"adapters"`
	MemberCount   int      `json:"member_count"`
	ProposalCount int      `json:"proposal_count"`
}

// MembershipSnapshot records a voter's eligibility at a governance snapshot point.
// account_commitment is SHA-256(lowercase(wallet_address)) — never the raw address.
type MembershipSnapshot struct {
	OrganizationID    string   `json:"organization_id"`
	SnapshotID        string   `json:"snapshot_id"`
	AccountCommitment string   `json:"account_commitment"`
	WalletAddress     string   `json:"wallet_address"`
	Roles             []string `json:"roles"`
	VotingWeight      uint64   `json:"voting_weight"`
	DelegatedWeight   uint64   `json:"delegated_weight"`
	EffectiveWeight   uint64   `json:"effective_weight"`
}

// EffectiveWeight returns the member's total voting power.
func (m MembershipSnapshot) EffectiveVotingWeight() uint64 {
	if m.EffectiveWeight > 0 {
		return m.EffectiveWeight
	}
	return m.VotingWeight + m.DelegatedWeight
}

// HasRole returns true if the membership snapshot includes the given role.
func (m MembershipSnapshot) HasRole(role string) bool {
	for _, r := range m.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// GovernanceProposal is a discrete governance question within an organization.
type GovernanceProposal struct {
	ID               string         `json:"id"`
	OrganizationID   string         `json:"organization_id"`
	Title            string         `json:"title"`
	Summary          string         `json:"summary"`
	ProposalClass    string         `json:"proposal_class"`
	Status           string         `json:"status"` // "active" | "passed" | "failed"
	SnapshotID       string         `json:"snapshot_id"`
	SnapshotMode     string         `json:"snapshot_mode"`
	SnapshotRef      string         `json:"snapshot_ref"`
	CreatedBy        string         `json:"created_by"`
	CreatedAt        time.Time      `json:"created_at"`
	ClosesAt         time.Time      `json:"closes_at"`
	QuorumBPS        uint64         `json:"quorum_bps"`    // basis points; e.g. 4000 = 40%
	ApprovalBPS      uint64         `json:"approval_bps"`  // basis points required for passage
	EligibleWeight   uint64         `json:"eligible_weight"`
	ExecutionAdapter string         `json:"execution_adapter"`
	Payload          map[string]any `json:"payload"`
	QueuedActionIDs  []string       `json:"queued_action_ids"`
}

// WeightedBallot is an anonymous ballot cast against a governance proposal.
// AccountCommitment is the anonymous identity token; Direction is "yes"/"no"/"abstain".
// The wallet address that produced the commitment is never stored alongside it.
type WeightedBallot struct {
	ProposalID        string    `json:"proposal_id"`
	AccountCommitment string    `json:"account_commitment"`
	Direction         string    `json:"direction"`
	SubmittedAt       time.Time `json:"submitted_at"`
}

// GovernanceTally is the computed weighted vote tally for a proposal.
type GovernanceTally struct {
	ProposalID     string `json:"proposal_id"`
	YesWeight      uint64 `json:"yes_weight"`
	NoWeight       uint64 `json:"no_weight"`
	AbstainWeight  uint64 `json:"abstain_weight"`
	EligibleWeight uint64 `json:"eligible_weight"`
	QuorumReached  bool   `json:"quorum_reached"`
	ApprovalBPS    uint64 `json:"approval_bps"` // actual approval basis points achieved
	Status         string `json:"status"`
}

// QueuedGovernanceAction is a canonical action queued after a proposal passes.
type QueuedGovernanceAction struct {
	ID             string         `json:"id"`
	OrganizationID string         `json:"organization_id"`
	ProposalID     string         `json:"proposal_id"`
	ActionType     string         `json:"action_type"`
	Adapter        string         `json:"adapter"`
	Status         string         `json:"status"` // "queued" | "dispatched"
	Payload        map[string]any `json:"payload"`
	CreatedAt      time.Time      `json:"created_at"`
	DispatchedAt   *time.Time     `json:"dispatched_at,omitempty"`
	Dispatch       map[string]any `json:"dispatch,omitempty"`
}

// Adapter constants for queued action execution.
const (
	AdapterShywire      = "shywire"
	AdapterByodao       = "byodao"
	AdapterInternalQueue = "internal_queue"
)

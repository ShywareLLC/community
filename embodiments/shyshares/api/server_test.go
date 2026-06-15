package api

import (
	"testing"
	"time"

	"github.com/ShywareLLC/community/shyshares"
)

// seedStore builds a minimal store fixture: one org, two members, one active
// proposal. Weights are chosen so both votes together meet 40% quorum.
func seedStore() *Store {
	s := NewStore()

	adminWallet := "0x1111111111111111111111111111111111111111"
	memberWallet := "0x2222222222222222222222222222222222222222"
	adminCommitment := shyshares.AccountCommitment(adminWallet)
	memberCommitment := shyshares.AccountCommitment(memberWallet)

	s.organizations["test-org"] = shyshares.Organization{
		ID:          "test-org",
		Name:        "Test Org",
		TokenSymbol: "TEST",
	}

	seed := func(wallet string, weight uint64, roles ...string) {
		c := shyshares.AccountCommitment(wallet)
		s.memberships[c] = append(s.memberships[c], shyshares.MembershipSnapshot{
			OrganizationID:    "test-org",
			SnapshotID:        "snap-1",
			AccountCommitment: c,
			WalletAddress:     wallet,
			Roles:             roles,
			VotingWeight:      weight,
			EffectiveWeight:   weight,
		})
	}
	seed(adminWallet, 6000, "member", "admin")
	seed(memberWallet, 4000, "member")

	proposal := shyshares.GovernanceProposal{
		ID:             "prop-1",
		OrganizationID: "test-org",
		Status:         "active",
		SnapshotID:     "snap-1",
		CreatedBy:      adminCommitment,
		CreatedAt:      time.Now().UTC(),
		ClosesAt:       time.Now().UTC().Add(72 * time.Hour),
		QuorumBPS:      4000,
		ApprovalBPS:    5000,
		EligibleWeight: 10000,
	}
	s.proposals[proposal.ID] = proposal
	s.ballots[proposal.ID] = map[string]shyshares.WeightedBallot{
		adminCommitment:  {ProposalID: proposal.ID, AccountCommitment: adminCommitment, Direction: "yes"},
		memberCommitment: {ProposalID: proposal.ID, AccountCommitment: memberCommitment, Direction: "yes"},
	}
	return s
}

func TestAccountCommitmentIsDeterministic(t *testing.T) {
	const wallet = "0x1111111111111111111111111111111111111111"
	first := shyshares.AccountCommitment(wallet)
	second := shyshares.AccountCommitment(wallet)
	if first == "" {
		t.Fatal("expected non-empty commitment")
	}
	if first != second {
		t.Fatalf("expected deterministic commitment, got %q and %q", first, second)
	}
}

func TestComputeTallyMeetsQuorum(t *testing.T) {
	s := seedStore()
	proposal := s.proposals["prop-1"]
	tally := s.computeTally(proposal)

	// Both members voted yes — 10000/10000 = 100% quorum, 100% approval.
	if !tally.QuorumReached {
		t.Fatal("expected quorum to be reached")
	}
	if tally.YesWeight != 10000 {
		t.Fatalf("expected yes_weight=10000, got %d", tally.YesWeight)
	}
}

func TestCloseProposalQueuesActionOnPass(t *testing.T) {
	s := seedStore()
	proposal := s.proposals["prop-1"]

	tally := s.computeTally(proposal)
	if !tally.QuorumReached {
		t.Fatal("expected tally to meet quorum")
	}

	action := s.ensureQueuedAction(&proposal)
	s.proposals[proposal.ID] = proposal

	if action.ID == "" {
		t.Fatal("expected queued action id")
	}
	if len(s.proposals[proposal.ID].QueuedActionIDs) != 1 {
		t.Fatal("expected proposal to reference queued action")
	}
}

func TestEnsureQueuedActionDoesNotMutateStatus(t *testing.T) {
	s := seedStore()
	proposal := s.proposals["prop-1"]
	s.ensureQueuedAction(&proposal)
	// ensureQueuedAction must not change proposal.Status — the caller does that.
	if proposal.Status != "active" {
		t.Fatalf("ensureQueuedAction should not mutate proposal status, got %q", proposal.Status)
	}
}

func TestBuildActionDispatchUsesAdapterSpecificStatus(t *testing.T) {
	action := shyshares.QueuedGovernanceAction{
		ID:         "act-001",
		ProposalID: "prop-001",
		Adapter:    shyshares.AdapterShywire,
	}
	dispatch := shyshares.BuildActionDispatch(action, "acct-001")
	if dispatch["status"] != "queued_for_shywire" {
		t.Fatalf("expected shywire dispatch status, got %#v", dispatch["status"])
	}

	action.Adapter = shyshares.AdapterByodao
	dispatch = shyshares.BuildActionDispatch(action, "acct-001")
	if dispatch["status"] != "queued_for_byodao" {
		t.Fatalf("expected byodao dispatch status, got %#v", dispatch["status"])
	}
}

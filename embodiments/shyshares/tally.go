package shyshares

// ComputeTally computes the weighted governance tally for a proposal.
//
// ballots maps accountCommitment → direction ("yes" | "no" | "abstain").
// memberWeight maps accountCommitment → effective voting weight for the
// proposal's organization at the snapshot block. The caller is responsible
// for resolving membership weights from the snapshot store.
//
// The anonymous two-list layer ensures that ballot direction and wallet
// identity are never jointly visible in public outputs. ComputeTally
// operates on commitments only — the raw wallet addresses are not needed.
func ComputeTally(proposal GovernanceProposal, ballots map[string]string, memberWeight map[string]uint64) GovernanceTally {
	tally := GovernanceTally{
		ProposalID:     proposal.ID,
		EligibleWeight: proposal.EligibleWeight,
		Status:         proposal.Status,
	}

	for commitment, direction := range ballots {
		weight, ok := memberWeight[commitment]
		if !ok {
			continue
		}
		switch direction {
		case "yes":
			tally.YesWeight += weight
		case "no":
			tally.NoWeight += weight
		default:
			tally.AbstainWeight += weight
		}
	}

	castWeight := tally.YesWeight + tally.NoWeight + tally.AbstainWeight
	if proposal.EligibleWeight > 0 {
		tally.QuorumReached = castWeight*10000 >= proposal.EligibleWeight*proposal.QuorumBPS
	}
	if decisive := tally.YesWeight + tally.NoWeight; decisive > 0 {
		tally.ApprovalBPS = (tally.YesWeight * 10000) / decisive
	}

	return tally
}

// TotalEligibleWeight sums the effective voting weight of all members
// belonging to organizationID across the provided snapshots.
func TotalEligibleWeight(snapshots []MembershipSnapshot, organizationID string) uint64 {
	var total uint64
	for _, s := range snapshots {
		if s.OrganizationID == organizationID {
			total += s.EffectiveVotingWeight()
		}
	}
	return total
}

// MemberWeightMap builds the accountCommitment → effective weight lookup
// needed by ComputeTally from a slice of membership snapshots.
func MemberWeightMap(snapshots []MembershipSnapshot, organizationID string) map[string]uint64 {
	m := make(map[string]uint64, len(snapshots))
	for _, s := range snapshots {
		if s.OrganizationID == organizationID {
			m[s.AccountCommitment] = s.EffectiveVotingWeight()
		}
	}
	return m
}

// Package api provides the HTTP API server for shyshares governance deployments.
//
// In production, replace the in-memory Store with a CockroachDB-backed
// implementation. The Store interface is intentionally narrow so the swap
// is mechanical.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"

	"github.com/ShywareLLC/community/shyshares"
)

// Store is the in-memory state for the shyshares API.
// Production deployments replace this with a CockroachDB-backed store.
type Store struct {
	mu            sync.RWMutex
	organizations map[string]shyshares.Organization
	memberships   map[string][]shyshares.MembershipSnapshot
	proposals     map[string]shyshares.GovernanceProposal
	ballots       map[string]map[string]shyshares.WeightedBallot
	actions       map[string]shyshares.QueuedGovernanceAction
}

// NewStore returns an empty Store.
func NewStore() *Store {
	return &Store{
		organizations: map[string]shyshares.Organization{},
		memberships:   map[string][]shyshares.MembershipSnapshot{},
		proposals:     map[string]shyshares.GovernanceProposal{},
		ballots:       map[string]map[string]shyshares.WeightedBallot{},
		actions:       map[string]shyshares.QueuedGovernanceAction{},
	}
}

// Router returns a configured mux.Router for the shyshares API.
func Router(store *Store) http.Handler {
	r := mux.NewRouter()

	r.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": "shyshares-api"})
	}).Methods(http.MethodGet)

	r.HandleFunc("/organizations", listOrganizations(store)).Methods(http.MethodGet)
	r.HandleFunc("/organizations/{id}", getOrganization(store)).Methods(http.MethodGet)
	r.HandleFunc("/memberships/{account_commitment}", getMemberships(store)).Methods(http.MethodGet)
	r.HandleFunc("/proposals", listProposals(store)).Methods(http.MethodGet)
	r.HandleFunc("/proposals", createProposal(store)).Methods(http.MethodPost)
	r.HandleFunc("/proposals/{id}", getProposal(store)).Methods(http.MethodGet)
	r.HandleFunc("/proposals/{id}/close", closeProposal(store)).Methods(http.MethodPost)
	r.HandleFunc("/ballots", submitBallot(store)).Methods(http.MethodPost)
	r.HandleFunc("/tallies/{proposal_id}", getTally(store)).Methods(http.MethodGet)
	r.HandleFunc("/actions", listActions(store)).Methods(http.MethodGet)
	r.HandleFunc("/actions/{id}", getAction(store)).Methods(http.MethodGet)
	r.HandleFunc("/actions/{id}/dispatch", dispatchAction(store)).Methods(http.MethodPost)

	return r
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(dst)
}

func (s *Store) refreshOrganizationStats() {
	for orgID, org := range s.organizations {
		memberCount := 0
		for _, snapshots := range s.memberships {
			for _, snapshot := range snapshots {
				if snapshot.OrganizationID == orgID {
					memberCount++
				}
			}
		}
		proposalCount := 0
		for _, proposal := range s.proposals {
			if proposal.OrganizationID == orgID {
				proposalCount++
			}
		}
		org.MemberCount = memberCount
		org.ProposalCount = proposalCount
		s.organizations[orgID] = org
	}
}

func (s *Store) getMembership(commitment, organizationID string) (shyshares.MembershipSnapshot, bool) {
	for _, snapshot := range s.memberships[commitment] {
		if snapshot.OrganizationID == organizationID {
			return snapshot, true
		}
	}
	return shyshares.MembershipSnapshot{}, false
}

func (s *Store) computeTally(proposal shyshares.GovernanceProposal) shyshares.GovernanceTally {
	ballots := map[string]string{}
	for commitment, b := range s.ballots[proposal.ID] {
		ballots[commitment] = b.Direction
	}
	return shyshares.ComputeTally(proposal, ballots, shyshares.MemberWeightMap(s.allMemberships(), proposal.OrganizationID))
}

func (s *Store) allMemberships() []shyshares.MembershipSnapshot {
	var all []shyshares.MembershipSnapshot
	for _, snapshots := range s.memberships {
		all = append(all, snapshots...)
	}
	return all
}

// ensureQueuedAction creates and stores the queued action for a passed proposal
// and updates proposal.QueuedActionIDs in place.
func (s *Store) ensureQueuedAction(proposal *shyshares.GovernanceProposal) shyshares.QueuedGovernanceAction {
	action := shyshares.NewQueuedAction(*proposal)
	s.actions[action.ID] = action
	proposal.QueuedActionIDs = []string{action.ID}
	return action
}

func listOrganizations(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		store.mu.RLock()
		defer store.mu.RUnlock()
		orgs := make([]shyshares.Organization, 0, len(store.organizations))
		for _, o := range store.organizations {
			orgs = append(orgs, o)
		}
		sort.Slice(orgs, func(i, j int) bool { return orgs[i].Name < orgs[j].Name })
		writeJSON(w, http.StatusOK, map[string]any{"organizations": orgs})
	}
}

func getOrganization(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store.mu.RLock()
		defer store.mu.RUnlock()
		org, ok := store.organizations[mux.Vars(r)["id"]]
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "Organization not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"organization": org})
	}
}

func getMemberships(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store.mu.RLock()
		defer store.mu.RUnlock()
		commitment := mux.Vars(r)["account_commitment"]
		memberships := append([]shyshares.MembershipSnapshot(nil), store.memberships[commitment]...)
		writeJSON(w, http.StatusOK, map[string]any{
			"account_commitment": commitment,
			"memberships":        memberships,
		})
	}
}

func listProposals(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store.mu.RLock()
		defer store.mu.RUnlock()
		orgID := strings.TrimSpace(r.URL.Query().Get("organization_id"))
		status := strings.TrimSpace(r.URL.Query().Get("status"))
		proposals := make([]shyshares.GovernanceProposal, 0, len(store.proposals))
		for _, p := range store.proposals {
			if orgID != "" && p.OrganizationID != orgID {
				continue
			}
			if status != "" && p.Status != status {
				continue
			}
			proposals = append(proposals, p)
		}
		sort.Slice(proposals, func(i, j int) bool { return proposals[i].CreatedAt.After(proposals[j].CreatedAt) })
		writeJSON(w, http.StatusOK, map[string]any{"proposals": proposals})
	}
}

func createProposal(store *Store) http.HandlerFunc {
	type request struct {
		OrganizationID   string         `json:"organization_id"`
		CreatedBy        string         `json:"created_by"`
		Title            string         `json:"title"`
		Summary          string         `json:"summary"`
		ProposalClass    string         `json:"proposal_class"`
		QuorumBPS        uint64         `json:"quorum_bps"`
		ApprovalBPS      uint64         `json:"approval_bps"`
		ClosesAt         string         `json:"closes_at"`
		ExecutionAdapter string         `json:"execution_adapter"`
		Payload          map[string]any `json:"payload"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var body request
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON payload"})
			return
		}
		store.mu.Lock()
		defer store.mu.Unlock()
		if _, ok := store.organizations[body.OrganizationID]; !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "Organization not found"})
			return
		}
		membership, ok := store.getMembership(body.CreatedBy, body.OrganizationID)
		if !ok || !membership.HasRole("admin") {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "Only organization admins may create proposals"})
			return
		}
		closesAt := time.Now().UTC().Add(72 * time.Hour)
		if strings.TrimSpace(body.ClosesAt) != "" {
			if parsed, err := time.Parse(time.RFC3339, body.ClosesAt); err == nil {
				closesAt = parsed.UTC()
			}
		}
		proposalID := fmt.Sprintf("prop-%s-%03d", body.OrganizationID, len(store.proposals)+1)
		proposal := shyshares.GovernanceProposal{
			ID:               proposalID,
			OrganizationID:   body.OrganizationID,
			Title:            strings.TrimSpace(body.Title),
			Summary:          strings.TrimSpace(body.Summary),
			ProposalClass:    strings.TrimSpace(body.ProposalClass),
			Status:           "active",
			SnapshotID:       membership.SnapshotID,
			SnapshotMode:     "delegated_stake_snapshot",
			SnapshotRef:      membership.SnapshotID,
			CreatedBy:        body.CreatedBy,
			CreatedAt:        time.Now().UTC(),
			ClosesAt:         closesAt,
			QuorumBPS:        maxUint64(body.QuorumBPS, 4000),
			ApprovalBPS:      maxUint64(body.ApprovalBPS, 5000),
			EligibleWeight:   shyshares.TotalEligibleWeight(store.allMemberships(), body.OrganizationID),
			ExecutionAdapter: defaultString(body.ExecutionAdapter, shyshares.AdapterInternalQueue),
			Payload:          body.Payload,
		}
		store.proposals[proposal.ID] = proposal
		store.ballots[proposal.ID] = map[string]shyshares.WeightedBallot{}
		store.refreshOrganizationStats()
		writeJSON(w, http.StatusOK, map[string]any{"proposal": proposal})
	}
}

func getProposal(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store.mu.RLock()
		defer store.mu.RUnlock()
		proposal, ok := store.proposals[mux.Vars(r)["id"]]
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "Proposal not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"proposal": proposal})
	}
}

func closeProposal(store *Store) http.HandlerFunc {
	type request struct {
		ClosedBy string `json:"closed_by"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var body request
		_ = decodeJSON(r, &body)
		store.mu.Lock()
		defer store.mu.Unlock()
		proposal, ok := store.proposals[mux.Vars(r)["id"]]
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "Proposal not found"})
			return
		}
		membership, ok := store.getMembership(body.ClosedBy, proposal.OrganizationID)
		if !ok || !membership.HasRole("admin") {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "Only organization admins may close proposals"})
			return
		}
		if proposal.Status != "active" {
			writeJSON(w, http.StatusOK, map[string]any{"proposal": proposal, "tally": store.computeTally(proposal)})
			return
		}
		tally := store.computeTally(proposal)
		if tally.QuorumReached && tally.ApprovalBPS >= proposal.ApprovalBPS {
			proposal.Status = "passed"
			action := store.ensureQueuedAction(&proposal)
			store.proposals[proposal.ID] = proposal
			tally.Status = proposal.Status
			writeJSON(w, http.StatusOK, map[string]any{"proposal": proposal, "tally": tally, "queued_action": action})
			return
		}
		proposal.Status = "failed"
		store.proposals[proposal.ID] = proposal
		tally.Status = proposal.Status
		writeJSON(w, http.StatusOK, map[string]any{"proposal": proposal, "tally": tally})
	}
}

func submitBallot(store *Store) http.HandlerFunc {
	type request struct {
		ProposalID        string `json:"proposal_id"`
		AccountCommitment string `json:"account_commitment"`
		Direction         string `json:"direction"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var body request
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON payload"})
			return
		}
		store.mu.Lock()
		defer store.mu.Unlock()
		proposal, ok := store.proposals[body.ProposalID]
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "Proposal not found"})
			return
		}
		if proposal.Status != "active" {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "Proposal is not active"})
			return
		}
		if _, ok := store.getMembership(body.AccountCommitment, proposal.OrganizationID); !ok {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "No eligible membership snapshot for this organization"})
			return
		}
		if _, exists := store.ballots[proposal.ID][body.AccountCommitment]; exists {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "Ballot already submitted for this proposal"})
			return
		}
		store.ballots[proposal.ID][body.AccountCommitment] = shyshares.WeightedBallot{
			ProposalID:        proposal.ID,
			AccountCommitment: body.AccountCommitment,
			Direction:         strings.TrimSpace(body.Direction),
			SubmittedAt:       time.Now().UTC(),
		}
		tally := store.computeTally(proposal)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "proposal": proposal.ID, "tally": tally})
	}
}

func getTally(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store.mu.RLock()
		defer store.mu.RUnlock()
		proposal, ok := store.proposals[mux.Vars(r)["proposal_id"]]
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "Proposal not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tally": store.computeTally(proposal)})
	}
}

func listActions(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store.mu.RLock()
		defer store.mu.RUnlock()
		orgID := strings.TrimSpace(r.URL.Query().Get("organization_id"))
		status := strings.TrimSpace(r.URL.Query().Get("status"))
		actions := make([]shyshares.QueuedGovernanceAction, 0, len(store.actions))
		for _, a := range store.actions {
			if orgID != "" && a.OrganizationID != orgID {
				continue
			}
			if status != "" && a.Status != status {
				continue
			}
			actions = append(actions, a)
		}
		sort.Slice(actions, func(i, j int) bool { return actions[i].CreatedAt.After(actions[j].CreatedAt) })
		writeJSON(w, http.StatusOK, map[string]any{"actions": actions})
	}
}

func getAction(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store.mu.RLock()
		defer store.mu.RUnlock()
		action, ok := store.actions[mux.Vars(r)["id"]]
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "Action not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"action": action})
	}
}

func dispatchAction(store *Store) http.HandlerFunc {
	type request struct {
		DispatchedBy string `json:"dispatched_by"`
		Adapter      string `json:"adapter"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var body request
		_ = decodeJSON(r, &body)
		store.mu.Lock()
		defer store.mu.Unlock()
		action, ok := store.actions[mux.Vars(r)["id"]]
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "Action not found"})
			return
		}
		membership, ok := store.getMembership(body.DispatchedBy, action.OrganizationID)
		if !ok || !membership.HasRole("admin") {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "Only organization admins may dispatch queued actions"})
			return
		}
		now := time.Now().UTC()
		action.Adapter = defaultString(body.Adapter, action.Adapter)
		action.DispatchedAt = &now
		action.Status = "dispatched"
		action.Dispatch = shyshares.BuildActionDispatch(action, body.DispatchedBy)
		store.actions[action.ID] = action
		writeJSON(w, http.StatusOK, map[string]any{"action": action})
	}
}

func maxUint64(value, fallback uint64) uint64 {
	if value == 0 {
		return fallback
	}
	return value
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

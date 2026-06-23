// Package server exposes materialized analytics data over HTTP.
// It is the query half of the analytics service; the indexer package is the
// ingestion half. Both run in the same binary (seda-haqq-analytics,
// populist-analytics) but are independently testable.
//
// Routes:
//
//	GET  /health
//	GET  /polls
//	GET  /polls/{poll_id}
//	GET  /polls/{poll_id}/tally
//	GET  /polls/{poll_id}/votes
//	GET  /polls/{poll_id}/voters
//	GET  /polls/{poll_id}/assurances
//	POST /polls/{poll_id}/contact-events — identity-side lifecycle events only
//	POST /consent                  — opt in/out of solicitations marketplace
//	GET  /solicitations            — active marketplace listings (opted-in only)
package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Server holds shared state for all HTTP handlers.
type Server struct {
	db  *pgxpool.Pool
	mux *http.ServeMux
}

// New creates a Server and registers all routes.
func New(db *pgxpool.Pool) *Server {
	s := &Server{db: db, mux: http.NewServeMux()}
	s.mux.HandleFunc("/health", s.health)
	s.mux.HandleFunc("/polls", s.polls)
	s.mux.HandleFunc("/polls/", s.pollsRouter)
	s.mux.HandleFunc("/consent", s.consent)
	s.mux.HandleFunc("/solicitations", s.solicitations)
	return s
}

// Handler returns the http.Handler for use with http.ListenAndServe.
func (s *Server) Handler() http.Handler { return s.mux }

// pollsRouter dispatches /polls/{id}, /polls/{id}/tally, /polls/{id}/votes,
// /polls/{id}/voters, /polls/{id}/assurances, and
// /polls/{id}/contact-events.
func (s *Server) pollsRouter(w http.ResponseWriter, r *http.Request) {
	// strip leading /polls/
	rest := strings.TrimPrefix(r.URL.Path, "/polls/")
	parts := strings.SplitN(rest, "/", 2)
	pollID := parts[0]
	if pollID == "" {
		http.NotFound(w, r)
		return
	}
	sub := ""
	if len(parts) == 2 {
		sub = parts[1]
	}
	switch sub {
	case "":
		s.getPoll(w, r, pollID)
	case "tally":
		s.getTally(w, r, pollID)
	case "votes":
		s.getVotes(w, r, pollID)
	case "voters":
		s.getVoters(w, r, pollID)
	case "assurances":
		s.getAssurances(w, r, pollID)
	case "contact-events":
		s.contactEvent(w, r, pollID)
	default:
		http.NotFound(w, r)
	}
}

// ---- handlers ---------------------------------------------------------------

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) polls(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := s.db.Query(ctx, `
		SELECT
			p.poll_id,
			p.poll_hash,
			p.question,
			p.start_time,
			p.end_time,
			CASE
				WHEN t.poll_id IS NOT NULL THEN 'closed'
				WHEN EXTRACT(EPOCH FROM NOW()) >= p.end_time THEN 'ended'
				WHEN EXTRACT(EPOCH FROM NOW()) >= p.start_time THEN 'open'
				ELSE 'pending'
			END AS status,
			p.created_at,
			p.created_height
		FROM polls_view p
		LEFT JOIN tallies_view t ON p.poll_id = t.poll_id
		ORDER BY created_at DESC
		LIMIT 100
	`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	type Poll struct {
		PollID        string `json:"poll_id"`
		PollHash      string `json:"poll_hash"`
		Question      string `json:"question"`
		StartTime     int64  `json:"start_time"`
		EndTime       int64  `json:"end_time"`
		Status        string `json:"status"`
		CreatedAt     string `json:"created_at"`
		CreatedHeight int64  `json:"created_height"`
	}
	polls := []Poll{}
	for rows.Next() {
		var p Poll
		var createdAt time.Time
		if err := rows.Scan(&p.PollID, &p.PollHash, &p.Question, &p.StartTime, &p.EndTime,
			&p.Status, &createdAt, &p.CreatedHeight); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		p.CreatedAt = createdAt.Format(time.RFC3339)
		polls = append(polls, p)
	}
	writeJSON(w, http.StatusOK, map[string]any{"polls": polls, "count": len(polls)})
}

func (s *Server) getPoll(w http.ResponseWriter, r *http.Request, pollID string) {
	ctx := r.Context()
	type Poll struct {
		PollID        string `json:"poll_id"`
		PollHash      string `json:"poll_hash"`
		Question      string `json:"question"`
		StartTime     int64  `json:"start_time"`
		EndTime       int64  `json:"end_time"`
		Status        string `json:"status"`
		CreatedAt     string `json:"created_at"`
		CreatedHeight int64  `json:"created_height"`
	}
	var p Poll
	var createdAt time.Time
	err := s.db.QueryRow(ctx, `
		SELECT
			p.poll_id,
			p.poll_hash,
			p.question,
			p.start_time,
			p.end_time,
			CASE
				WHEN t.poll_id IS NOT NULL THEN 'closed'
				WHEN EXTRACT(EPOCH FROM NOW()) >= p.end_time THEN 'ended'
				WHEN EXTRACT(EPOCH FROM NOW()) >= p.start_time THEN 'open'
				ELSE 'pending'
			END AS status,
			p.created_at,
			p.created_height
		FROM polls_view p
		LEFT JOIN tallies_view t ON p.poll_id = t.poll_id
		WHERE p.poll_id = $1
	`, pollID).Scan(&p.PollID, &p.PollHash, &p.Question, &p.StartTime, &p.EndTime,
		&p.Status, &createdAt, &p.CreatedHeight)
	if err != nil {
		writeError(w, http.StatusNotFound, "poll not found")
		return
	}
	p.CreatedAt = createdAt.Format(time.RFC3339)
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) getTally(w http.ResponseWriter, r *http.Request, pollID string) {
	ctx := r.Context()
	type Tally struct {
		PollID         string           `json:"poll_id"`
		Counts         map[string]int64 `json:"counts"`
		TotalVotes     int64            `json:"total_votes"`
		ConfirmedCount int64            `json:"confirmed_count"`
		L1Commitment   string           `json:"l1_commitment"`
		L2Commitment   string           `json:"l2_commitment"`
		FinalizedAt    int64            `json:"finalized_at"`
		ClosingHeight  int64            `json:"closing_height"`
		Status         string           `json:"status"`
		ClosedAt       string           `json:"closed_at,omitempty"`
	}
	var t Tally
	var closedAt *time.Time
	err := s.db.QueryRow(ctx, `
		SELECT poll_id, total_votes, l1_commitment, l2_commitment, finalized_at, closing_height, closed_at
		FROM tallies_view WHERE poll_id = $1
	`, pollID).Scan(
		&t.PollID,
		&t.TotalVotes,
		&t.L1Commitment,
		&t.L2Commitment,
		&t.FinalizedAt,
		&t.ClosingHeight,
		&closedAt,
	)
	if err != nil {
		writeError(w, http.StatusNotFound, "tally not found")
		return
	}
	countRows, err := s.db.Query(ctx, `
		SELECT choice, COUNT(*) FROM vote_directions
		WHERE poll_id = $1
		GROUP BY choice
		ORDER BY choice
	`, pollID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer countRows.Close()
	t.Counts = map[string]int64{}
	for countRows.Next() {
		var choice string
		var count int64
		if err := countRows.Scan(&choice, &count); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		t.Counts[choice] = count
	}
	if err := countRows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	err = s.db.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM events e
		JOIN attributes a ON a.event_id = e.id AND a.key = 'scoping_id' AND a.value = $1
		JOIN tx_results tx ON tx.tx_hash = e.tx_hash
		WHERE e.type = 'confirmation_processed'
			AND tx.success = true
	`, pollID).Scan(&t.ConfirmedCount)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	t.Status = "closed"
	if closedAt != nil {
		t.ClosedAt = closedAt.Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) getVotes(w http.ResponseWriter, r *http.Request, pollID string) {
	ctx := r.Context()
	rows, err := s.db.Query(ctx, `
		SELECT ballot_id, poll_id, choice, included_height, included_at
		FROM vote_directions WHERE poll_id = $1
		ORDER BY included_height DESC LIMIT 1000
	`, pollID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	type Vote struct {
		BallotID       string `json:"ballot_id"`
		PollID         string `json:"poll_id"`
		Choice         string `json:"choice"`
		IncludedHeight int64  `json:"included_height"`
		IncludedAt     string `json:"included_at"`
	}
	votes := []Vote{}
	for rows.Next() {
		var v Vote
		var includedAt time.Time
		if err := rows.Scan(&v.BallotID, &v.PollID, &v.Choice, &v.IncludedHeight, &includedAt); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		v.IncludedAt = includedAt.Format(time.RFC3339)
		votes = append(votes, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"votes": votes, "count": len(votes)})
}

func (s *Server) getVoters(w http.ResponseWriter, r *http.Request, pollID string) {
	ctx := r.Context()
	var count int64
	err := s.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM voter_registry WHERE poll_id = $1`, pollID,
	).Scan(&count)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"poll_id": pollID, "voter_count": count})
}

func (s *Server) getAssurances(w http.ResponseWriter, r *http.Request, pollID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	var a struct {
		VoteCount               int64
		VoterCount              int64
		CountMatch              bool
		ConfirmedCount          int64
		InvitedCount            int64
		DeliveredCount          int64
		OpenedCount             int64
		AuthenticatedCount      int64
		CredentialConsumedCount int64
		SubmittedCount          int64
		RemediatedCount         int64
	}
	err := s.db.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM vote_directions WHERE poll_id = $1) AS vote_count,
			(SELECT COUNT(*) FROM voter_registry  WHERE poll_id = $1) AS voter_count,
			(SELECT COUNT(*) FROM vote_directions WHERE poll_id = $1) =
			(SELECT COUNT(*) FROM voter_registry  WHERE poll_id = $1) AS count_match,
			(
				SELECT COUNT(*)
				FROM events e
				JOIN attributes attr ON attr.event_id = e.id AND attr.key = 'scoping_id' AND attr.value = $1
				JOIN tx_results tx ON tx.tx_hash = e.tx_hash
				WHERE e.type = 'confirmation_processed'
					AND tx.success = true
			) AS confirmed_count,
			COALESCE((SELECT invited_count FROM voter_contact_assurance WHERE poll_id = $1), 0) AS invited_count,
			COALESCE((SELECT delivered_count FROM voter_contact_assurance WHERE poll_id = $1), 0) AS delivered_count,
			COALESCE((SELECT opened_count FROM voter_contact_assurance WHERE poll_id = $1), 0) AS opened_count,
			COALESCE((SELECT authenticated_count FROM voter_contact_assurance WHERE poll_id = $1), 0) AS authenticated_count,
			COALESCE((SELECT credential_consumed_count FROM voter_contact_assurance WHERE poll_id = $1), 0) AS credential_consumed_count,
			COALESCE((SELECT submitted_count FROM voter_contact_assurance WHERE poll_id = $1), 0) AS submitted_count,
			COALESCE((SELECT remediated_count FROM voter_contact_assurance WHERE poll_id = $1), 0) AS remediated_count
	`, pollID).Scan(
		&a.VoteCount, &a.VoterCount, &a.CountMatch, &a.ConfirmedCount,
		&a.InvitedCount, &a.DeliveredCount, &a.OpenedCount, &a.AuthenticatedCount,
		&a.CredentialConsumedCount, &a.SubmittedCount, &a.RemediatedCount,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"poll_id": pollID,
		"canonical": map[string]any{
			"accepted_payload_count": a.VoteCount,
			"participant_count":      a.VoterCount,
			"count_match":            a.CountMatch,
			"confirmed_count":        a.ConfirmedCount,
		},
		"admin_lifecycle": map[string]int64{
			"invited":             a.InvitedCount,
			"delivered":           a.DeliveredCount,
			"opened":              a.OpenedCount,
			"authenticated":       a.AuthenticatedCount,
			"credential_consumed": a.CredentialConsumedCount,
			"submitted":           a.SubmittedCount,
			"remediated":          a.RemediatedCount,
		},
		"privacy_boundary": map[string]any{
			"identity_fields_exposed": false,
			"ballot_fields_exposed":   false,
			"join_fields_exposed":     false,
		},
	})
}

func (s *Server) contactEvent(w http.ResponseWriter, r *http.Request, pollID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	var req struct {
		IdentityHash string         `json:"identity_hash"`
		EventType    string         `json:"event_type"`
		EventRef     *string        `json:"event_ref,omitempty"`
		OccurredAt   *time.Time     `json:"occurred_at,omitempty"`
		Metadata     map[string]any `json:"metadata,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.IdentityHash == "" {
		writeError(w, http.StatusBadRequest, "identity_hash required")
		return
	}
	if !validContactEventType(req.EventType) {
		writeError(w, http.StatusBadRequest, "invalid event_type")
		return
	}
	if containsForbiddenContactMetadata(req.Metadata) {
		writeError(w, http.StatusBadRequest, "contact metadata must not contain ballot or payload linkage fields")
		return
	}
	if req.Metadata == nil {
		req.Metadata = map[string]any{}
	}
	metadataRaw, err := json.Marshal(req.Metadata)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid metadata")
		return
	}
	var eventRef any
	if req.EventRef != nil {
		eventRef = *req.EventRef
	}
	occurredAt := time.Now().UTC()
	if req.OccurredAt != nil {
		occurredAt = req.OccurredAt.UTC()
	}
	_, err = s.db.Exec(ctx, `
		INSERT INTO voter_contact_events
			(poll_id, identity_hash, event_type, event_ref, occurred_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb)
	`, pollID, req.IdentityHash, req.EventType, eventRef, occurredAt, string(metadataRaw))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"poll_id":    pollID,
		"event_type": req.EventType,
		"recorded":   true,
	})
}

// consent handles POST /consent — records an opt-in or opt-out.
//
// Request body:
//
//	{ "identity_hash": "<hex>", "opted_in": true }
//
// The identity_hash must exist in voter_registry for any poll; this prevents
// phantom consent records. The opted_in flag enables/disables participation
// in the I Want Solicitations marketplace.
func (s *Server) consent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()

	var req struct {
		IdentityHash string `json:"identity_hash"`
		OptedIn      bool   `json:"opted_in"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.IdentityHash == "" {
		writeError(w, http.StatusBadRequest, "identity_hash required")
		return
	}

	// Require identity_hash to be present in voter_registry (at least one poll).
	var exists bool
	_ = s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM voter_registry WHERE identity_hash = $1)`,
		req.IdentityHash,
	).Scan(&exists)
	if !exists {
		writeError(w, http.StatusUnprocessableEntity, "identity_hash not found in voter registry")
		return
	}

	var optedInAt *time.Time
	if req.OptedIn {
		now := time.Now().UTC()
		optedInAt = &now
	}

	_, err := s.db.Exec(ctx, `
		INSERT INTO solicitations_consent (identity_hash, opted_in, opted_in_at, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (identity_hash) DO UPDATE
		  SET opted_in    = EXCLUDED.opted_in,
		      opted_in_at = CASE WHEN EXCLUDED.opted_in THEN EXCLUDED.opted_in_at
		                         ELSE solicitations_consent.opted_in_at END,
		      updated_at  = NOW()
	`, req.IdentityHash, req.OptedIn, optedInAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"identity_hash": req.IdentityHash,
		"opted_in":      req.OptedIn,
	})
}

// solicitations handles GET /solicitations — returns active marketplace listings.
// No auth in Tier 2a; auth will be added when the marketplace backend is built.
func (s *Server) solicitations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := s.db.Query(ctx, `
		SELECT id, sponsor_id, poll_id, choice_filter, message, created_at, expires_at
		FROM solicitations
		WHERE active = true AND (expires_at IS NULL OR expires_at > NOW())
		ORDER BY created_at DESC
		LIMIT 50
	`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	type Solicitation struct {
		ID           int64   `json:"id"`
		SponsorID    string  `json:"sponsor_id"`
		PollID       *string `json:"poll_id,omitempty"`
		ChoiceFilter *string `json:"choice_filter,omitempty"`
		Message      string  `json:"message"`
		CreatedAt    string  `json:"created_at"`
		ExpiresAt    *string `json:"expires_at,omitempty"`
	}
	list := []Solicitation{}
	for rows.Next() {
		var s Solicitation
		var createdAt time.Time
		var expiresAt *time.Time
		if err := rows.Scan(&s.ID, &s.SponsorID, &s.PollID, &s.ChoiceFilter,
			&s.Message, &createdAt, &expiresAt); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.CreatedAt = createdAt.Format(time.RFC3339)
		if expiresAt != nil {
			exp := expiresAt.Format(time.RFC3339)
			s.ExpiresAt = &exp
		}
		list = append(list, s)
	}
	writeJSON(w, http.StatusOK, map[string]any{"solicitations": list, "count": len(list)})
}

// ---- helpers ----------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func validContactEventType(eventType string) bool {
	switch eventType {
	case "invited", "delivered", "opened", "authenticated", "credential_consumed", "submitted", "remediated":
		return true
	default:
		return false
	}
}

func containsForbiddenContactMetadata(value any) bool {
	forbidden := map[string]bool{
		"ballot_id":          true,
		"ballotId":           true,
		"choice":             true,
		"choices":            true,
		"direction":          true,
		"payload":            true,
		"payload_commitment": true,
		"payloadCommitment":  true,
		"submission_id":      true,
		"submissionId":       true,
		"vote":               true,
	}
	switch v := value.(type) {
	case map[string]any:
		for key, nested := range v {
			if forbidden[key] || containsForbiddenContactMetadata(nested) {
				return true
			}
		}
	case []any:
		for _, nested := range v {
			if containsForbiddenContactMetadata(nested) {
				return true
			}
		}
	}
	return false
}

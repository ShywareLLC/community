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
// /polls/{id}/voters.
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
		SELECT poll_id, poll_hash, question, start_time, end_time, status, created_at, created_height
		FROM polls_view
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
		SELECT poll_id, poll_hash, question, start_time, end_time, status, created_at, created_height
		FROM polls_view WHERE poll_id = $1
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
		PollID         string `json:"poll_id"`
		YesVotes       int64  `json:"yes_votes"`
		NoVotes        int64  `json:"no_votes"`
		TotalVotes     int64  `json:"total_votes"`
		ConfirmedCount int64  `json:"confirmed_count"`
		Status         string `json:"status"`
		ClosedAt       string `json:"closed_at,omitempty"`
	}
	var t Tally
	var closedAt *time.Time
	err := s.db.QueryRow(ctx, `
		SELECT poll_id, yes_votes, no_votes, total_votes, confirmed_count, status, closed_at
		FROM tallies_view WHERE poll_id = $1
	`, pollID).Scan(&t.PollID, &t.YesVotes, &t.NoVotes, &t.TotalVotes, &t.ConfirmedCount, &t.Status, &closedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "tally not found")
		return
	}
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

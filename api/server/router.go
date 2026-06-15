// Package server provides the canonical protocol API — a stateless proxy to CometBFT RPC.
// No database. No auth. No sessions. Reads proxy to CometBFT ABCI query.
// Ballot submissions are forwarded to broadcast_tx_commit.
//
// Deployments wire this up with deployment-specific middleware (auth, rate limiting, etc.).
// Privacy: /voters returns only a count, never identity_hashes.
//
//	/votes  returns ballot_ids and choices — no identity information.
package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ShywareLLC/community/api/rpc"
	"github.com/ShywareLLC/community/protocol/config"
	"github.com/ShywareLLC/community/services/reconcile"
	"github.com/ShywareLLC/community/protocol/tx"
)

type Server struct {
	rpc            rpc.Broadcaster
	serviceName    string
	reconcileStore reconcile.Store       // nil when reconcileed ballot-update path is not configured
	attester       Attester              // nil when attestation is not required (NopVerifier equivalent)
	postureCfg     *config.PostureConfig // nil when no manifest has been loaded
	queueMu        sync.Mutex
	ballotQueue    map[string][]queuedBallot
}

type queuedBallot struct {
	txJSON       string
	envelope     tx.Tx
	data         tx.BallotCastData
	ballotID     string
	identityHash string
	allowReceipt bool
}

// Attester is the server-side device attestation interface.
// Wire in via WithAttester().  The full attest.Verifier type satisfies this.
type Attester interface {
	// Verify checks the token from X-Attest-Token and returns the verified
	// platform string and write-only flag.  Returns an error on invalid tokens.
	VerifyToken(ctx context.Context, platform, token string) (writeOnly bool, err error)
}

func NewServer(cometbftRPC, serviceName string) *Server {
	return &Server{
		rpc:         rpc.NewClient(cometbftRPC),
		serviceName: serviceName,
		ballotQueue: make(map[string][]queuedBallot),
	}
}

// NewServerWithBroadcaster creates a Server using any rpc.Broadcaster
// implementation — used in integration tests with an in-process broadcaster.
func NewServerWithBroadcaster(b rpc.Broadcaster, serviceName string) *Server {
	return &Server{
		rpc:         b,
		serviceName: serviceName,
		ballotQueue: make(map[string][]queuedBallot),
	}
}

// WithAttester enables server-side device attestation verification.
// When set, POST /ballots requires a valid X-Attest-Token header.
// Submissions without a token are either rejected (strict) or accepted at
// write-only posture when the attester returns writeOnly=true.
func (s *Server) WithAttester(a Attester) {
	s.attester = a
}

// WithReconcileStore enables the reconcileed ballot-update path (Claims 7 + 8).
// Call after NewServer for recoverable-posture deployments.
func (s *Server) WithReconcileStore(rs reconcile.Store) {
	s.reconcileStore = rs
}

// WithManifest validates a shyconfig manifest at server initialization time and
// stores the parsed posture configuration for runtime use (Claim 6 + Claim 9).
// Returns an error if any required field is missing or the contract_version is
// unsupported — enforcing the Claim 9 initialization gate at the server layer.
// After a successful call, the server evaluates runtime_fallbacks flags in
// submitBallot to decide whether to fall back to write-only posture.
func (s *Server) WithManifest(manifestJSON []byte) error {
	cfg, err := config.ParseManifest(manifestJSON)
	if err != nil {
		return err
	}
	s.postureCfg = cfg
	return nil
}

// Router returns an http.Handler. Callers may wrap with deployment-specific middleware
// (e.g. Firebase auth for blockchain/, Tor-aware rate limiting for seda-haqq/).
func (s *Server) Router() http.Handler {
	r := mux.NewRouter()

	r.Use(corsMiddleware)

	r.HandleFunc("/health", s.health).Methods("GET")
	r.HandleFunc("/polls", s.listPolls).Methods("GET")
	r.HandleFunc("/polls/{poll_id}", s.getPoll).Methods("GET")
	r.HandleFunc("/polls/{poll_id}/tally", s.getTally).Methods("GET")
	r.HandleFunc("/polls/{poll_id}/votes", s.getVotes).Methods("GET")
	r.HandleFunc("/polls/{poll_id}/voters", s.getVoterCount).Methods("GET")
	r.HandleFunc("/polls/{poll_id}/confirms", s.getConfirmedCount).Methods("GET")
	r.HandleFunc("/polls/{poll_id}/confirm", s.confirmReceipt).Methods("POST")
	r.HandleFunc("/polls/{poll_id}/flush", s.flushQueuedBallots).Methods("POST")
	r.HandleFunc("/ballots", s.submitBallot).Methods("POST")
	r.HandleFunc("/ballots/update", s.updateBallot).Methods("POST")


	return otelhttp.NewHandler(r, s.serviceName,
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			if route := mux.CurrentRoute(r); route != nil {
				if tmpl, err := route.GetPathTemplate(); err == nil {
					return r.Method + " " + tmpl
				}
			}
			return r.Method + " " + r.URL.Path
		}),
	)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	status, err := s.rpc.Status()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "node unreachable")
		return
	}
	writeJSON(w, status)
}

func (s *Server) listPolls(w http.ResponseWriter, r *http.Request) {
	data, err := s.rpc.ABCIQuery("/polls")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) getPoll(w http.ResponseWriter, r *http.Request) {
	pollID := mux.Vars(r)["scoping_id"]
	trace.SpanFromContext(r.Context()).SetAttributes(attribute.String("poll.id", pollID))
	data, err := s.rpc.ABCIQuery("/poll/" + pollID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) getTally(w http.ResponseWriter, r *http.Request) {
	pollID := mux.Vars(r)["scoping_id"]
	trace.SpanFromContext(r.Context()).SetAttributes(attribute.String("poll.id", pollID))
	data, err := s.rpc.ABCIQuery("/tally/" + pollID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) getVotes(w http.ResponseWriter, r *http.Request) {
	pollID := mux.Vars(r)["scoping_id"]
	data, err := s.rpc.ABCIQuery("/votes/" + pollID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) getVoterCount(w http.ResponseWriter, r *http.Request) {
	pollID := mux.Vars(r)["scoping_id"]
	data, err := s.rpc.ABCIQuery("/voter_count/" + pollID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) getConfirmedCount(w http.ResponseWriter, r *http.Request) {
	pollID := mux.Vars(r)["scoping_id"]
	data, err := s.rpc.ABCIQuery("/confirms/" + pollID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) submitBallot(w http.ResponseWriter, r *http.Request) {
	// Attestation check (Claim 4 + Claim 6).
	//
	// When an attester is configured, the client supplies X-Attest-Platform and
	// X-Attest-Token. The posture decision depends on the manifest runtime_fallbacks:
	//
	//   token absent + write_only_on_missing_play_integrity=true
	//     → write-only fallback (canonical write proceeds; no receipt written)
	//   token absent + write_only_on_missing_play_integrity=false (or no manifest)
	//     → 401 Unauthorized (strict mode)
	//   token present, attester returns writeOnly=true + write_only_on_untrusted_device_attestation=true
	//     → write-only fallback
	//   token present, attester returns error
	//     → 403 Forbidden
	//
	// permanent write-only posture (default_posture: coercion_resistant) overrides
	// all of the above: canonical write always proceeds; receipt never written.
	permanentWriteOnly := s.postureCfg != nil && s.postureCfg.WriteOnly

	if s.attester != nil {
		platform := r.Header.Get("X-Attest-Platform")
		token := r.Header.Get("X-Attest-Token")

		fallbacks := config.RuntimeFallbacks{}
		if s.postureCfg != nil {
			fallbacks = s.postureCfg.RuntimeFallbacks
		}

		if token == "" {
			if !permanentWriteOnly && fallbacks.WriteOnlyOnMissingPlayIntegrity {
				// Configured fallback: no token → write-only posture.
				// Canonical write proceeds; receipt store suppressed below.
				r = r.WithContext(withWriteOnly(r.Context()))
			} else if !permanentWriteOnly {
				writeError(w, http.StatusUnauthorized, "X-Attest-Token required")
				return
			}
		} else {
			writeOnly, err := s.attester.VerifyToken(r.Context(), platform, token)
			if err != nil {
				writeError(w, http.StatusForbidden, "attestation verification failed: "+err.Error())
				return
			}
			if writeOnly && fallbacks.WriteOnlyOnUntrustedDeviceAttestation {
				r = r.WithContext(withWriteOnly(r.Context()))
			}
		}
	}

	var body struct {
		Tx string `json:"tx"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Tx == "" {
		writeError(w, http.StatusBadRequest, "missing tx field")
		return
	}
	var envelope tx.Tx
	if err := json.Unmarshal([]byte(body.Tx), &envelope); err != nil {
		writeError(w, http.StatusBadRequest, "invalid tx JSON: "+err.Error())
		return
	}
	if err := envelope.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid tx: "+err.Error())
		return
	}
	if envelope.Type != tx.TxTypeBallotCast {
		writeError(w, http.StatusBadRequest, "tx.type must be TxTypeBallotCast")
		return
	}
	var data tx.BallotCastData
	if err := envelope.UnmarshalData(&data); err != nil {
		writeError(w, http.StatusBadRequest, "invalid ballot cast data: "+err.Error())
		return
	}

	ballotID, identityHash, err := s.deriveBallotIdentity(data)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Check the canonical state for a post-flush duplicate: the in-queue dedup
	// only catches duplicates within the current unflushed batch, but if the
	// participant already appears in voterRegistry (from a prior flush), the
	// state machine will reject their next ballot during batch validation. We
	// catch it here to return 409 immediately rather than silently queuing
	// a tx that will fail on broadcast.
	if regData, qErr := s.rpc.ABCIQuery("/voter_registered/" + data.PollID + "/" + identityHash); qErr == nil {
		var regResp struct {
			Registered bool `json:"registered"`
		}
		if jsonErr := json.Unmarshal(regData, &regResp); jsonErr == nil && regResp.Registered {
			writeError(w, http.StatusConflict, "participant already voted in poll "+data.PollID)
			return
		}
	}

	writeOnlyActive := permanentWriteOnly || isWriteOnly(r.Context())
	if err := s.enqueueBallot(queuedBallot{
		txJSON:       body.Tx,
		envelope:     envelope,
		data:         data,
		ballotID:     ballotID,
		identityHash: identityHash,
		allowReceipt: s.reconcileStore != nil && !writeOnlyActive,
	}); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	resp := map[string]any{
		"queued":        true,
		"scoping_id":       data.PollID,
		"submission_id": ballotID,
	}
	if writeOnlyActive {
		resp["write_only"] = true
		resp["message"] = "queued for canonical commit without receipt persistence"
	}
	writeJSONBody(w, http.StatusOK, resp)
}

// updateBallot handles POST /ballots/update.
//
// Two paths:
//
//  1. Device-receipt path — client holds the receipt (non-write-only posture,
//     receipt retained on device). Body: {"tx": "<json-encoded Tx>"}.
//     The client constructs the full BallotUpdateData (including old_ballot_id
//     from their receipt) and signs it. The server broadcasts as-is.
//
//  2. Reconcileed path — server looks up old_ballot_id from the CockroachDB
//     receipt store using the voter's identity_hash. Requires receiptStore to
//     be configured via WithReceiptStore. Body: all BallotUpdateData fields
//     except old_ballot_id, plus "identity_hash" for the CRDB lookup.
//     The server injects old_ballot_id, encodes the Tx, and broadcasts.
//     The outer Tx.Signature is set to a relay marker [0x01] since the voter's
//     device signature inside BallotUpdateData.VoterSig is the real authenticator.
func (s *Server) updateBallot(w http.ResponseWriter, r *http.Request) {
	// Peek: if body has a "tx" field, it's the device-receipt path.
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if txField, ok := raw["tx"]; ok {
		// Device-receipt path: pre-built signed tx, broadcast directly.
		var txStr string
		if err := json.Unmarshal(txField, &txStr); err != nil || txStr == "" {
			writeError(w, http.StatusBadRequest, "tx must be a non-empty string")
			return
		}
		result, err := s.rpc.BroadcastTx([]byte(txStr))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, result)
		return
	}

	// Reconcileed path: server fills old_ballot_id from receipt store.
	if s.reconcileStore == nil {
		writeError(w, http.StatusNotImplemented, "reconcileed ballot update not configured for this deployment")
		return
	}

	// Decode the partial update request — everything except old_ballot_id.
	var req struct {
		IdentityHash string `json:"identity_hash"` // used to look up old_ballot_id
		tx.BallotUpdateData
	}
	// Re-marshal the raw fields into a single JSON object for decoding.
	combined, err := json.Marshal(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := json.Unmarshal(combined, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid ballot update fields")
		return
	}
	if req.PollID == "" || req.IdentityHash == "" {
		writeError(w, http.StatusBadRequest, "poll_id and identity_hash are required for reconcileed update")
		return
	}

	oldBallotID, err := s.reconcileStore.GetSubmissionID(r.Context(), req.PollID, req.IdentityHash)
	if err != nil {
		writeError(w, http.StatusNotFound, "no receipt found for this voter on poll "+req.PollID)
		return
	}

	req.BallotUpdateData.OldBallotID = oldBallotID

	data, err := json.Marshal(req.BallotUpdateData)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to encode ballot update data")
		return
	}
	envelope := struct {
		Type      uint8           `json:"type"`
		Signature []byte          `json:"signature"`
		Data      json.RawMessage `json:"data"`
	}{
		Type:      tx.TxTypeUpdateBallot,
		Signature: []byte{0x01}, // relay marker; VoterSig inside Data is the real authenticator
		Data:      data,
	}
	txBytes, err := json.Marshal(envelope)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to encode tx")
		return
	}
	result, err := s.rpc.BroadcastTx(txBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Sync the off-chain receipt store after a successful canonical broadcast.
	// Errors are non-fatal: the canonical state transition already committed.
	if s.reconcileStore != nil {
		if len(req.NewChoices) == 0 {
			// Rescission: both L1 + L2 deleted on-chain — remove the dangling link.
			_ = s.reconcileStore.DeleteSubmission(r.Context(), req.PollID, req.IdentityHash)
		} else {
			// Replacement: L1 swapped on-chain — update link to new submission ID.
			rawID := sha256.Sum256([]byte(req.NewBallotNonce))
			newSubmissionID := hex.EncodeToString(rawID[:])
			_ = s.reconcileStore.RecordSubmission(r.Context(), req.PollID, req.IdentityHash, newSubmissionID)
		}
	}

	writeJSON(w, result)
}

func (s *Server) confirmReceipt(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Tx string `json:"tx"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Tx == "" {
		writeError(w, http.StatusBadRequest, "missing tx field")
		return
	}
	result, err := s.rpc.BroadcastTx([]byte(body.Tx))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, result)
}

func (s *Server) flushQueuedBallots(w http.ResponseWriter, r *http.Request) {
	pollID := mux.Vars(r)["scoping_id"]

	batch, batchID := s.dequeueBallotsForFlush(pollID)
	if len(batch) == 0 {
		writeError(w, http.StatusNotFound, "no queued submissions for poll")
		return
	}

	submissions := make([]tx.Tx, 0, len(batch))
	for _, item := range batch {
		submissions = append(submissions, item.envelope)
	}
	payload, err := json.Marshal(tx.BatchFlushData{
		PollID:      pollID,
		Submissions: submissions,
	})
	if err != nil {
		s.restoreQueuedBallots(pollID, batch)
		writeError(w, http.StatusInternalServerError, "failed to encode batch flush payload")
		return
	}
	flushTx := tx.Tx{
		Type:      tx.TxTypeBatchFlush,
		Signature: []byte{0x01},
		Data:      payload,
	}
	raw, err := json.Marshal(flushTx)
	if err != nil {
		s.restoreQueuedBallots(pollID, batch)
		writeError(w, http.StatusInternalServerError, "failed to encode batch flush tx")
		return
	}

	result, err := s.rpc.BroadcastTx(raw)
	if err != nil {
		s.restoreQueuedBallots(pollID, batch)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if txFailed(result) {
		s.restoreQueuedBallots(pollID, batch)
		writeJSONBody(w, http.StatusConflict, json.RawMessage(result))
		return
	}

	if s.reconcileStore != nil {
		for _, item := range batch {
			if !item.allowReceipt {
				continue
			}
			if err := s.storeReceiptForBallot(r.Context(), item.data, item.ballotID, item.identityHash); err != nil {
				trace.SpanFromContext(r.Context()).RecordError(err)
			}
		}
	}

	writeJSONBody(w, http.StatusOK, map[string]any{
		"flushed":          true,
		"scoping_id":          pollID,
		"batch_id":         batchID,
		"submission_count": len(batch),
		"result":           json.RawMessage(result),
	})
}

func (s *Server) enqueueBallot(item queuedBallot) error {
	s.queueMu.Lock()
	defer s.queueMu.Unlock()

	queue := s.ballotQueue[item.data.PollID]
	for _, existing := range queue {
		if existing.ballotID == item.ballotID {
			return fmt.Errorf("duplicate queued submission_id %s for poll %s", item.ballotID, item.data.PollID)
		}
		if existing.identityHash == item.identityHash {
			return fmt.Errorf("duplicate queued participant for poll %s", item.data.PollID)
		}
	}
	s.ballotQueue[item.data.PollID] = append(queue, item)
	return nil
}

func (s *Server) dequeueBallotsForFlush(pollID string) ([]queuedBallot, string) {
	s.queueMu.Lock()
	defer s.queueMu.Unlock()

	queue := append([]queuedBallot(nil), s.ballotQueue[pollID]...)
	if len(queue) == 0 {
		return nil, ""
	}
	delete(s.ballotQueue, pollID)
	return queue, computeServerBatchID(pollID, queue)
}

func (s *Server) restoreQueuedBallots(pollID string, batch []queuedBallot) {
	if len(batch) == 0 {
		return
	}
	s.queueMu.Lock()
	defer s.queueMu.Unlock()
	s.ballotQueue[pollID] = append(batch, s.ballotQueue[pollID]...)
}

func (s *Server) deriveBallotIdentity(data tx.BallotCastData) (string, string, error) {
	var ballotID string
	if data.SubmissionIdentifierDerivation == tx.SubmissionIdentifierDerivationNoncePlusPayload {
		payloadBytes, _ := json.Marshal(data.Choices)
		rawBallotID := sha256.Sum256([]byte(data.BallotNonce + ":" + string(payloadBytes)))
		ballotID = hex.EncodeToString(rawBallotID[:])
	} else {
		rawBallotID := sha256.Sum256([]byte(data.BallotNonce))
		ballotID = hex.EncodeToString(rawBallotID[:])
	}

	switch {
	case data.ZKNullifier != "":
		return ballotID, data.ZKNullifier, nil
	case data.IdentusSubjectDID != "":
		raw := sha256.Sum256([]byte(data.IdentusSubjectDID + data.VoterPubKey + data.PollID))
		return ballotID, hex.EncodeToString(raw[:]), nil
	case data.VoterPubKey != "":
		raw := sha256.Sum256([]byte(data.VoterPubKey + data.PollID))
		return ballotID, hex.EncodeToString(raw[:]), nil
	default:
		return "", "", fmt.Errorf("ballot queue requires derivable participant identity metadata")
	}
}

func (s *Server) storeReceiptForBallot(ctx context.Context, data tx.BallotCastData, ballotID, identityHash string) error {
	if s.reconcileStore == nil {
		return nil
	}
	// Retry up to 3 times with exponential backoff. RecordSubmission uses an
	// upsert (ON CONFLICT ... DO UPDATE), so retries are idempotent: a
	// transient failure after confirmed on-chain acceptance is recoverable
	// without violating the two-list structural invariant.
	const maxAttempts = 3
	delay := 50 * time.Millisecond
	var err error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			if ctx.Err() != nil {
				return err
			}
			time.Sleep(delay)
			delay *= 2
		}
		err = s.reconcileStore.RecordSubmission(ctx, data.PollID, identityHash, ballotID)
		if err == nil {
			return nil
		}
	}
	return err
}

func computeServerBatchID(pollID string, batch []queuedBallot) string {
	ids := make([]string, 0, len(batch))
	for _, item := range batch {
		ids = append(ids, item.ballotID)
	}
	sort.Strings(ids)
	h := sha256.New()
	h.Write([]byte(pollID))
	for _, id := range ids {
		h.Write([]byte(":"))
		h.Write([]byte(id))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func txFailed(raw []byte) bool {
	var body struct {
		Result struct {
			CheckTx struct {
				Code float64 `json:"code"`
			} `json:"check_tx"`
			TxResult struct {
				Code float64 `json:"code"`
			} `json:"tx_result"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return false
	}
	return body.Result.CheckTx.Code != 0 || body.Result.TxResult.Code != 0
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, traceparent, tracestate")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, data []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func writeJSONBody(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// writeOnlyKey is the context key used to propagate write-only posture within a
// single request. Set by withWriteOnly; read by isWriteOnly.
type writeOnlyKey struct{}

// withWriteOnly returns a copy of ctx carrying the write-only posture flag.
func withWriteOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, writeOnlyKey{}, true)
}

// isWriteOnly reports whether ctx carries the write-only posture flag.
func isWriteOnly(ctx context.Context) bool {
	v, _ := ctx.Value(writeOnlyKey{}).(bool)
	return v
}

// writeWriteOnlyFallback responds with HTTP 200 and a write_only posture indicator.
// Used when the server detects a hostile-network condition (Claim 6): the
// submission was received but the consensus node was unreachable. The client must
// suppress recovery receipt setup and operate write-only.
func writeWriteOnlyFallback(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"write_only": true,
		"message":    msg,
	})
}

// isNetworkError reports whether err is a network-level failure (connection
// refused, DNS failure, timeout, EOF) as opposed to a CometBFT validation
// rejection. Network errors trigger the hostile-network write-only fallback
// (Claim 6); validation errors are returned as-is to the caller.
func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "dial tcp") ||
		strings.Contains(msg, "EOF")
}

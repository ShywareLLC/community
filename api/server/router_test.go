package server_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	dbm "github.com/cometbft/cometbft-db"
	"github.com/cometbft/cometbft/libs/log"

	"github.com/ShywareLLC/community/api/server"
	"github.com/ShywareLLC/community/domain/state"
	"github.com/ShywareLLC/community/protocol/tx"
	statetypes "github.com/ShywareLLC/community/protocol/types"
	"github.com/ShywareLLC/community/services/attest"
	"github.com/ShywareLLC/community/services/identity"
)

// ── in-process broadcaster ────────────────────────────────────────────────────

// inProcessBroadcaster wires the HTTP API server directly to an in-process
// state machine, bypassing CometBFT entirely. This enables full HTTP
// integration tests without a running CometBFT node.
type inProcessBroadcaster struct {
	s *state.State
}

func (b *inProcessBroadcaster) ABCIQuery(path string) ([]byte, error) {
	return b.s.Query(path, nil, 0, false)
}

func (b *inProcessBroadcaster) BroadcastTx(txBytes []byte) ([]byte, error) {
	transaction, err := tx.DecodeTx(txBytes)
	if err != nil {
		return broadcastErrorJSON(fmt.Sprintf("decode tx: %v", err)), nil
	}
	if err := b.s.ValidateTx(transaction); err != nil {
		return broadcastErrorJSON(err.Error()), nil
	}
	if _, err := b.s.ExecuteTx(transaction); err != nil {
		return broadcastErrorJSON(err.Error()), nil
	}
	return broadcastOKJSON(), nil
}

func (b *inProcessBroadcaster) Status() ([]byte, error) {
	return []byte(`{"result":{"sync_info":{"latest_block_height":"1"}}}`), nil
}

func broadcastErrorJSON(msg string) []byte {
	r, _ := json.Marshal(map[string]any{
		"result": map[string]any{
			"check_tx":  map[string]any{"code": 1, "log": msg},
			"tx_result": map[string]any{"code": 1, "log": msg},
		},
	})
	return r
}

func broadcastOKJSON() []byte {
	r, _ := json.Marshal(map[string]any{
		"result": map[string]any{
			"check_tx":  map[string]any{"code": 0},
			"tx_result": map[string]any{"code": 0},
		},
	})
	return r
}

// ── test helpers ──────────────────────────────────────────────────────────────

func newIntegrationServer(t *testing.T) (*server.Server, *state.State, ed25519.PrivateKey) {
	t.Helper()
	s, err := state.NewState(context.Background(), dbm.NewMemDB(), "", nil, log.NewNopLogger())
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}
	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	s.SetIdentityVerifier(&identity.IdentusVerifier{IssuerPubKey: issuerPub})
	s.RecordBeacon(testBeaconHeight, testBeaconHash)
	srv := server.NewServerWithBroadcaster(&inProcessBroadcaster{s: s}, "test")
	return srv, s, issuerPriv
}

// postJSON is a convenience wrapper for POST requests with JSON body.
func postJSON(t *testing.T, url string, body any, headers map[string]string) *http.Response {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

// createPoll injects an already-open poll directly into the state machine,
// bypassing validatePollCreate (which requires StartTime in the future).
// StartTime is set 100 seconds in the past so ballots can be cast immediately.
func createPoll(t *testing.T, b *inProcessBroadcaster, pollID string) {
	t.Helper()
	now := time.Now().Unix()
	b.s.SetPollForTest(pollID, &statetypes.Poll{
		PollID:       pollID,
		Question:     "Integration test question?",
		Options:      []string{"yes", "no"},
		VotingMethod: "plurality",
		StartTime:    now - 100,
		EndTime:      now + 3600,
		Status:       "open",
		CreatedAt:    now - 100,
	})
}

// testNonce returns a deterministic valid 64-hex-char nonce for tests.
func testNonce(tag string) string {
	h := sha256.Sum256([]byte("test-nonce:" + tag))
	return hex.EncodeToString(h[:])
}

// testBeaconHeight / testBeaconHash are the canonical test beacon fields.
const testBeaconHeight int64 = 42

var testBeaconHash = func() string {
	h := sha256.Sum256([]byte("test-beacon-block"))
	return hex.EncodeToString(h[:])
}()

// buildIssuerBallotTx constructs a signed BallotCast tx using the current
// generic IDV attestation path.
func buildIssuerBallotTx(t *testing.T, pollID, nonce string,
	choices []string, voterPriv, issuerPriv ed25519.PrivateKey) string {
	t.Helper()
	voterPub := voterPriv.Public().(ed25519.PublicKey)
	voterPubHex := hex.EncodeToString(voterPub)

	deviceMsg := []byte(nonce + ":" + pollID)
	voterSig := ed25519.Sign(voterPriv, deviceMsg)

	h := sha256.New()
	h.Write([]byte(voterPubHex))
	h.Write([]byte(pollID))
	idvSig := ed25519.Sign(issuerPriv, h.Sum(nil))

	payload := tx.BallotCastData{
		PollID:            pollID,
		BallotNonce:       nonce,
		BeaconBlockHash:   testBeaconHash,
		BeaconBlockHeight: testBeaconHeight,
		Choices:           choices,
		Timestamp:         time.Now().Unix(),
		VoterPubKey:       voterPubHex,
		VoterSig:          voterSig,
		IdvAttestationSig: idvSig,
	}
	data, _ := json.Marshal(payload)
	envelope := &tx.Tx{Type: tx.TxTypeBallotCast, Signature: []byte{1}, Data: data}
	raw, _ := json.Marshal(envelope)
	return string(raw)
}

// ── tests ─────────────────────────────────────────────────────────────────────

// TestHealthEndpoint verifies GET /health returns 200 via the in-process stack.
func TestHealthEndpoint(t *testing.T) {
	srv, _, _ := newIntegrationServer(t)
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// TestSubmitBallotIntegration submits a valid ballot through HTTP →
// in-process state machine and verifies the voter count via GET /polls/{id}/voters.
func TestSubmitBallotIntegration(t *testing.T) {
	srv, s, issuerPriv := newIntegrationServer(t)
	b := &inProcessBroadcaster{s: s}
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	pollID := "poll-integ-1"
	createPoll(t, b, pollID)

	_, voterPriv, _ := ed25519.GenerateKey(nil)
	txStr := buildIssuerBallotTx(t, pollID, testNonce("integ-1"),
		[]string{"yes"}, voterPriv, issuerPriv)

	resp := postJSON(t, ts.URL+"/ballots", map[string]string{"tx": txStr}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("POST /ballots status = %d, want 200", resp.StatusCode)
	}
	var queueResult map[string]any
	json.NewDecoder(resp.Body).Decode(&queueResult)
	if queued, _ := queueResult["queued"].(bool); !queued {
		t.Fatalf("expected queued response, got %+v", queueResult)
	}

	votersResp, err := http.Get(ts.URL + "/polls/" + pollID + "/voters")
	if err != nil {
		t.Fatalf("GET /voters: %v", err)
	}
	if votersResp.StatusCode != http.StatusOK {
		t.Errorf("GET /voters status = %d, want 200", votersResp.StatusCode)
	}
	var voterBody struct {
		Count int `json:"count"`
	}
	if err := json.NewDecoder(votersResp.Body).Decode(&voterBody); err != nil {
		t.Fatalf("decode voters response: %v", err)
	}
	if voterBody.Count != 0 {
		t.Fatalf("voter count before flush = %d, want 0", voterBody.Count)
	}

	flushResp := postJSON(t, ts.URL+"/polls/"+pollID+"/flush", map[string]string{}, nil)
	if flushResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /flush status = %d, want 200", flushResp.StatusCode)
	}

	votersResp, err = http.Get(ts.URL + "/polls/" + pollID + "/voters")
	if err != nil {
		t.Fatalf("GET /voters after flush: %v", err)
	}
	if err := json.NewDecoder(votersResp.Body).Decode(&voterBody); err != nil {
		t.Fatalf("decode voters response after flush: %v", err)
	}
	if voterBody.Count != 1 {
		t.Errorf("voter count = %d, want 1", voterBody.Count)
	}
}

// TestDuplicateVoteRejected verifies that a second ballot from the same voter
// is rejected and the voter count stays at 1.
func TestDuplicateVoteRejected(t *testing.T) {
	srv, s, issuerPriv := newIntegrationServer(t)
	b := &inProcessBroadcaster{s: s}
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	pollID := "poll-dedup-1"
	createPoll(t, b, pollID)

	_, voterPriv, _ := ed25519.GenerateKey(nil)
	txStr1 := buildIssuerBallotTx(t, pollID, testNonce("d1"),
		[]string{"yes"}, voterPriv, issuerPriv)
	txStr2 := buildIssuerBallotTx(t, pollID, testNonce("d2"),
		[]string{"no"}, voterPriv, issuerPriv)

	postJSON(t, ts.URL+"/ballots", map[string]string{"tx": txStr1}, nil)
	postJSON(t, ts.URL+"/polls/"+pollID+"/flush", map[string]string{}, nil)

	resp2 := postJSON(t, ts.URL+"/ballots", map[string]string{"tx": txStr2}, nil)
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("second queued ballot status = %d, want 409", resp2.StatusCode)
	}
	var body map[string]any
	json.NewDecoder(resp2.Body).Decode(&body)
	if body["error"] == nil {
		t.Fatalf("expected queue rejection body, got %+v", body)
	}
}

// TestAttestationRequired verifies that POST /ballots returns 401 when an
// Attester is wired but no X-Attest-Token header is present.
func TestAttestationRequired(t *testing.T) {
	srv, s, issuerPriv := newIntegrationServer(t)
	b := &inProcessBroadcaster{s: s}
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	pollID := "poll-attest-1"
	createPoll(t, b, pollID)
	srv.WithAttester(&nopServerAttester{})

	_, voterPriv, _ := ed25519.GenerateKey(nil)
	txStr := buildIssuerBallotTx(t, pollID, testNonce("attest-1"),
		[]string{"yes"}, voterPriv, issuerPriv)

	// Without token — 401.
	resp := postJSON(t, ts.URL+"/ballots", map[string]string{"tx": txStr}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no-token status = %d, want 401", resp.StatusCode)
	}

	// With token — 200.
	resp2 := postJSON(t, ts.URL+"/ballots", map[string]string{"tx": txStr},
		map[string]string{
			"X-Attest-Platform": "android",
			"X-Attest-Token":    "test-token",
		})
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("with-token status = %d, want 200", resp2.StatusCode)
	}
}

// TestNopVerifierWriteOnly verifies that attest.NopVerifier{WriteOnly:true}
// surfaces degraded posture correctly.
func TestNopVerifierWriteOnly(t *testing.T) {
	v := &attest.NopVerifier{WriteOnly: true}
	result, err := v.Verify(context.Background(), "any-token")
	if err != nil {
		t.Fatalf("NopVerifier.Verify: %v", err)
	}
	if !result.WriteOnly {
		t.Error("NopVerifier{WriteOnly:true} should return WriteOnly=true")
	}
}

// ── nopServerAttester adapts attest.NopVerifier to server.Attester ──────────

type nopServerAttester struct{}

func (n *nopServerAttester) VerifyToken(ctx context.Context, platform, token string) (bool, error) {
	result, err := (&attest.NopVerifier{}).Verify(ctx, token)
	if err != nil {
		return false, err
	}
	return result.WriteOnly, nil
}

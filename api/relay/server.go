package relay

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/mux"

	"github.com/ShywareLLC/community/protocol/tx"
)

type queuedSubmission struct {
	TxJSON string
}

// Server is a non-canonical ingress relay that pools ballot submissions,
// shuffles them off-chain, forwards them to the canonical queue endpoint, and
// then triggers canonical batch flush.
type Server struct {
	upstreamBase string
	httpClient   *http.Client

	mu    sync.Mutex
	queue map[string][]queuedSubmission
}

func NewServer(upstreamBase string) *Server {
	return &Server{
		upstreamBase: strings.TrimRight(upstreamBase, "/"),
		httpClient:   &http.Client{},
		queue:        make(map[string][]queuedSubmission),
	}
}

func (s *Server) Router() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/health", s.health).Methods(http.MethodGet)
	r.HandleFunc("/relay/ballots", s.submitBallot).Methods(http.MethodPost)
	r.HandleFunc("/relay/polls/{poll_id}/flush", s.flushPoll).Methods(http.MethodPost)
	r.HandleFunc("/relay/polls/{poll_id}/count", s.getQueueCount).Methods(http.MethodGet)
	return r
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) submitBallot(w http.ResponseWriter, r *http.Request) {
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
	if data.PollID == "" {
		writeError(w, http.StatusBadRequest, "poll_id required")
		return
	}

	s.mu.Lock()
	s.queue[data.PollID] = append(s.queue[data.PollID], queuedSubmission{TxJSON: body.Tx})
	count := len(s.queue[data.PollID])
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"queued":      true,
		"scoping_id":     data.PollID,
		"queue_count": count,
	})
}

func (s *Server) flushPoll(w http.ResponseWriter, r *http.Request) {
	pollID := mux.Vars(r)["scoping_id"]
	batch := s.dequeue(pollID)
	if len(batch) == 0 {
		writeError(w, http.StatusNotFound, "no queued relay submissions for poll")
		return
	}

	if err := shuffle(batch); err != nil {
		s.restore(pollID, batch)
		writeError(w, http.StatusInternalServerError, "shuffle failed: "+err.Error())
		return
	}

	for i, item := range batch {
		res, err := s.postJSON(s.upstreamBase+"/ballots", map[string]string{"tx": item.TxJSON})
		if err != nil || responseHasErrorStatus(res) {
			s.restore(pollID, batch[i:])
			if err != nil {
				writeError(w, http.StatusBadGateway, "upstream queue submit failed: "+err.Error())
			} else {
				writeJSON(w, http.StatusConflict, json.RawMessage(res))
			}
			return
		}
	}

	result, err := s.postJSON(s.upstreamBase+"/polls/"+pollID+"/flush", map[string]string{})
	if err != nil {
		s.restore(pollID, nil)
		writeError(w, http.StatusBadGateway, "upstream flush failed: "+err.Error())
		return
	}
	if responseHasErrorStatus(result) {
		writeJSON(w, http.StatusConflict, json.RawMessage(result))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"relayed":          true,
		"scoping_id":          pollID,
		"submission_count": len(batch),
		"result":           json.RawMessage(result),
	})
}

func (s *Server) getQueueCount(w http.ResponseWriter, r *http.Request) {
	pollID := mux.Vars(r)["scoping_id"]
	s.mu.Lock()
	count := len(s.queue[pollID])
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"scoping_id":     pollID,
		"queue_count": count,
	})
}

func (s *Server) dequeue(pollID string) []queuedSubmission {
	s.mu.Lock()
	defer s.mu.Unlock()
	batch := append([]queuedSubmission(nil), s.queue[pollID]...)
	delete(s.queue, pollID)
	return batch
}

func (s *Server) restore(pollID string, batch []queuedSubmission) {
	if len(batch) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queue[pollID] = append(batch, s.queue[pollID]...)
}

func (s *Server) postJSON(url string, body any) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return raw, nil
	}
	return raw, nil
}

func shuffle(batch []queuedSubmission) error {
	for i := len(batch) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		j := int(n.Int64())
		batch[i], batch[j] = batch[j], batch[i]
	}
	return nil
}

func responseHasErrorStatus(raw []byte) bool {
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return false
	}
	if _, ok := body["error"]; ok {
		return true
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) String() string {
	return fmt.Sprintf("relay->%s", s.upstreamBase)
}

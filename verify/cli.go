package verify

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

// TallyResponse mirrors types.Tally for JSON decoding in verify tools.
// []byte fields are decoded from base64 by encoding/json automatically.
type TallyResponse struct {
	PollID          string           `json:"scoping_id"`
	Counts          map[string]int64 `json:"counts"`
	TotalVotes      int64            `json:"total_votes"`
	VoteMerkleRoot  []byte           `json:"vote_merkle_root"`
	VoterMerkleRoot []byte           `json:"voter_merkle_root"`
	Signature       []byte           `json:"signature"`
	PublicKey       []byte           `json:"public_key"`
	FinalizedAt     int64            `json:"finalized_at"`
	Height          int64            `json:"height"`
}

// VoterCountResponse is the shape of GET /polls/{id}/voters.
type VoterCountResponse struct {
	Count int64 `json:"count"`
}

// FetchTally calls GET {apiBase}/polls/{pollID}/tally and decodes the response.
// Exits with code 1 on any error.
func FetchTally(apiBase, pollID string) TallyResponse {
	url := apiBase + "/polls/" + pollID + "/tally"
	body := MustGET(url)
	var t TallyResponse
	if err := json.Unmarshal(body, &t); err != nil {
		Red("✗ Failed to parse tally response from %s: %v\n", url, err)
		fmt.Fprintf(os.Stderr, "Response body: %s\n", body)
		os.Exit(1)
	}
	if t.PollID == "" {
		Red("✗ Tally not found for poll %q — has the poll been closed yet?\n", pollID)
		os.Exit(1)
	}
	return t
}

// FetchVoterCount calls GET {apiBase}/polls/{pollID}/voters and returns the count.
// Exits with code 1 on any error.
func FetchVoterCount(apiBase, pollID string) int64 {
	url := apiBase + "/polls/" + pollID + "/voters"
	body := MustGET(url)
	var r VoterCountResponse
	if err := json.Unmarshal(body, &r); err != nil {
		Red("✗ Failed to parse voter count from %s: %v\n", url, err)
		os.Exit(1)
	}
	return r.Count
}

// MustGET performs an HTTP GET and returns the body, or exits on error.
func MustGET(url string) []byte {
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		Red("✗ HTTP GET %s failed: %v\n", url, err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		Red("✗ Failed to read response body from %s: %v\n", url, err)
		os.Exit(1)
	}
	if resp.StatusCode != http.StatusOK {
		Red("✗ HTTP %d from %s: %s\n", resp.StatusCode, url, body)
		os.Exit(1)
	}
	return body
}

// Green prints a green-coloured formatted line to stdout.
func Green(format string, args ...any) { fmt.Printf("\033[32m"+format+"\033[0m", args...) }

// Red prints a red-coloured formatted line to stderr.
func Red(format string, args ...any) { fmt.Fprintf(os.Stderr, "\033[31m"+format+"\033[0m", args...) }

// Package rpc wraps CometBFT JSON-RPC for use by shyware API handlers.
// All calls carry a 10-second timeout. BroadcastTx uses broadcast_tx_commit,
// blocking until the transaction is included in a block.
package rpc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client wraps CometBFT RPC calls for the shyware transfer layer.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// ABCIQuery queries the shyware state machine at the given path.
func (c *Client) ABCIQuery(path string) ([]byte, error) {
	u := fmt.Sprintf("%s/abci_query?path=%s", c.baseURL, url.QueryEscape(`"`+path+`"`))
	resp, err := c.httpClient.Get(u)
	if err != nil {
		return nil, fmt.Errorf("abci_query failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Result struct {
			Response struct {
				Code  int    `json:"code"`
				Log   string `json:"log"`
				Value string `json:"value"` // base64-encoded
			} `json:"response"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse abci_query response: %w", err)
	}
	if result.Result.Response.Code != 0 {
		return nil, fmt.Errorf("abci_query error (code %d): %s", result.Result.Response.Code, result.Result.Response.Log)
	}

	decoded, err := base64.StdEncoding.DecodeString(result.Result.Response.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response value: %w", err)
	}
	return decoded, nil
}

// BroadcastTx submits a transaction and waits for it to be committed.
func (c *Client) BroadcastTx(txBytes []byte) ([]byte, error) {
	encoded := base64.StdEncoding.EncodeToString(txBytes)
	u := fmt.Sprintf("%s/broadcast_tx_commit?tx=%s", c.baseURL, url.QueryEscape(`"`+encoded+`"`))
	resp, err := c.httpClient.Get(u)
	if err != nil {
		return nil, fmt.Errorf("broadcast_tx_commit failed: %w", err)
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// Status returns the node status.
func (c *Client) Status() ([]byte, error) {
	resp, err := c.httpClient.Get(c.baseURL + "/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

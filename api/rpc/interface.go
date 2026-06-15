package rpc

// Broadcaster is the interface the API server uses to talk to CometBFT.
// The concrete *Client implements it; tests supply an in-process mock.
type Broadcaster interface {
	ABCIQuery(path string) ([]byte, error)
	BroadcastTx(txBytes []byte) ([]byte, error)
	Status() ([]byte, error)
}

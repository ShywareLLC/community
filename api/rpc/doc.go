// Package rpc wraps CometBFT JSON-RPC for use by api/server handlers.
//
// All calls carry a 10-second timeout. BroadcastTx uses broadcast_tx_commit,
// blocking until the transaction is included in a block (or the timeout fires).
// ABCIQuery reads committed state; it does not hit the mempool.
package rpc

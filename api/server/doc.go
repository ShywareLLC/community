// Package server exposes the protocol state over HTTP.
//
// # Design
//
// The server is a thin proxy: every handler calls api/rpc.Client to query
// CometBFT ABCI state or broadcast transactions. No local state is kept.
//
// # Privacy contract
//
// GET /polls/{id}/voters returns only a count field. identity_hash values are
// never returned by any endpoint. GET /polls/{id}/votes returns ballot_ids and
// choices but no voter identity, preserving List 1 / List 2 separation at the
// API boundary.
//
// # CORS
//
// All endpoints include permissive CORS headers. Deployments that need tighter
// origin control should place a reverse proxy in front of the server.
package server

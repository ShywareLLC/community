// Package tx defines the combined transaction envelope for shyshares — the
// composition of the shyvoting (anonymous ballot) and shywire (anonymous token)
// protocols on one CometBFT chain.
//
// Every tx submitted to a shyshares chain is wrapped in Envelope so the ABCI
// app can route to the correct sub-state machine without ambiguity.
package tx

import (
	"encoding/json"
	"fmt"
)

// Protocol discriminators.
const (
	ProtocolVoting = "shyvoting" // route to the voting sub-state machine
	ProtocolWire   = "shywire"   // route to the token sub-state machine
)

// Envelope wraps any shyvoting or shywire tx for submission to a shyshares chain.
//
//	{
//	  "protocol": "shyvoting",
//	  "payload":  <raw shyvoting Tx JSON>
//	}
type Envelope struct {
	Protocol string          `json:"protocol"`
	Payload  json.RawMessage `json:"payload"`
}

// DecodeEnvelope decodes a shyshares tx envelope from raw bytes.
func DecodeEnvelope(raw []byte) (*Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("decode envelope: %w", err)
	}
	switch e.Protocol {
	case ProtocolVoting, ProtocolWire:
	default:
		return nil, fmt.Errorf("unknown protocol %q: must be %q or %q", e.Protocol, ProtocolVoting, ProtocolWire)
	}
	if len(e.Payload) == 0 {
		return nil, fmt.Errorf("envelope payload is empty")
	}
	return &e, nil
}

// WrapVoting wraps a shyvoting tx (already JSON-encoded) in a shyshares envelope.
func WrapVoting(payload []byte) ([]byte, error) {
	return json.Marshal(Envelope{Protocol: ProtocolVoting, Payload: payload})
}

// WrapWire wraps a shywire tx (already JSON-encoded) in a shyshares envelope.
func WrapWire(payload []byte) ([]byte, error) {
	return json.Marshal(Envelope{Protocol: ProtocolWire, Payload: payload})
}

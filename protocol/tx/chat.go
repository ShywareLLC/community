package tx

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Wire-format discriminators for shychat-v1 transactions.
// These constants are scoped to the shychat domain state machine; the same uint8
// values are reused independently in the shystore and shyvoting domains because
// each domain's ABCI app dispatches from its own type set.
const (
	ChatTxTypeMailboxCreate   uint8 = 1 // create a new mailbox (period open)
	ChatTxTypeMessageDispatch uint8 = 2 // dispatch a message — atomic List 1 + List 2 write
	ChatTxTypeMailboxClose    uint8 = 3 // close a mailbox and commit attested closure record
	ChatTxTypeMessageUpdate   uint8 = 4 // replace a previously dispatched message (recoverable posture only)
	ChatTxTypeMessageWithdraw uint8 = 5 // bilateral withdrawal from both lists (re-abstain equivalent)
	ChatTxTypeRegisterValidator uint8 = 6 // add or remove a consensus validator
)

// MailboxCreateData creates a new mailbox (the chat-domain equivalent of PollCreate).
//
// A mailbox is the period unit for shychat: it opens a submission window keyed by
// MailboxID and closes with an HSM-signed ClosureRecord over the two-list state.
// SurfaceModel governs the client UI affordance; the protocol is identical for both.
type MailboxCreateData struct {
	MailboxID    string `json:"mailbox_id"`
	Label        string `json:"label,omitempty"`
	Address      string `json:"address,omitempty"`     // recipient address / routing hint
	RouteHint    string `json:"route_hint,omitempty"`
	SurfaceModel string `json:"surface_model"` // "mail" | "chat"
	AccountLabel string `json:"account_label,omitempty"`
	EndTime      int64  `json:"end_time,omitempty"` // 0 = no expiry
}

// MessageDispatchData submits a message to a mailbox.
//
// The structural anonymity contract mirrors BallotCastData:
//   - MessageNonce is random; MessageID = H(MessageNonce) is unlinkable to IdentityHash.
//   - SenderSig = Ed25519.Sign(sk_s, MessageNonce + ":" + MailboxID) proves
//     only the submitting device could have produced this message.
//   - IDV attestation derives IdentityHash for List 2 dedup — the IDV cannot
//     forge a message because it never holds sk_s.
//   - SealedBody and SealedSubject are AES-GCM encrypted before the tx is broadcast;
//     the ABCI layer stores the ciphertext in List 1 and never sees plaintext.
type MessageDispatchData struct {
	MailboxID         string `json:"mailbox_id"`
	MessageNonce      string `json:"message_nonce"`       // random 32-byte hex; message_id = H(beacon || nonce), unlinkable to identity
	BeaconBlockHash   string `json:"beacon_block_hash"`   // hex-encoded hash of a recent canonical block
	BeaconBlockHeight int64  `json:"beacon_block_height"` // height of the beacon block
	Timestamp         int64  `json:"timestamp"`
	PartitionID       string `json:"partition_id,omitempty"` // "sealed" (default) | "public"

	// Sealed content — AES-GCM encrypted by the sender before broadcast.
	// The ABCI layer stores ciphertext verbatim in List 1. Payload is JSON-encoded
	// MessagePayload (subject + body + metadata sealed as one envelope).
	SealedPayload json.RawMessage `json:"sealed_payload"` // JSON-encoded sealed envelope

	// Device signature — oracle-forgery prevention.
	// SenderSig = Ed25519.Sign(sk_s, MessageNonce + ":" + MailboxID).
	// Proves only the submitting device could have produced this message.
	SenderPubKey string `json:"sender_pub_key"` // hex-encoded Ed25519 public key
	SenderSig    []byte `json:"sender_sig"`     // Ed25519 signature

	IdvAttestationSig []byte `json:"idv_attestation_sig,omitempty"`
}

// MailboxCloseData closes a mailbox and commits the period-close attestation.
// Equivalent to PollCloseData for the shychat domain.
type MailboxCloseData struct {
	MailboxID     string `json:"mailbox_id"`
	ClosingHeight int64  `json:"closing_height"`
}

// MessageUpdateData replaces a previously dispatched message (direction change).
//
// Preconditions match BallotUpdateData:
//   - Mailbox is open (not closed).
//   - OldMessageID exists in List 1.
//   - Identity attestation matches the registered List 2 entry.
//   - Mailbox is not in write-only posture.
//
// SenderSig = Ed25519.Sign(sk_s, "update:" + NewMessageNonce + ":" + MailboxID).
// The "update:" prefix prevents a dispatch signature from being replayed as an update.
type MessageUpdateData struct {
	MailboxID       string          `json:"mailbox_id"`
	OldMessageID      string          `json:"old_message_id"`      // H(old_beacon || old_nonce)
	NewMessageNonce   string          `json:"new_message_nonce"`   // random 32-byte hex; new_message_id = H(beacon || new_nonce)
	BeaconBlockHash   string          `json:"beacon_block_hash"`   // hex-encoded hash of a recent canonical block
	BeaconBlockHeight int64           `json:"beacon_block_height"` // height of the beacon block
	NewSealedPayload  json.RawMessage `json:"new_sealed_payload"`
	Timestamp         int64           `json:"timestamp"`

	SenderPubKey string `json:"sender_pub_key"`
	SenderSig    []byte `json:"sender_sig"` // signs "update:" + NewMessageNonce + ":" + MailboxID

	IdvAttestationSig []byte `json:"idv_attestation_sig,omitempty"`
}

// MessageWithdrawData performs a bilateral withdrawal from both lists.
// Equivalent to BallotUpdateData with empty NewChoices.
// Both |L1| and |L2| decrease by one; the count-match invariant is preserved.
// The sender's IdentityHash is no longer in List 2 after withdrawal; they may
// re-dispatch using the same attestation (new keypair, new message nonce).
type MessageWithdrawData struct {
	MailboxID    string `json:"mailbox_id"`
	MessageID    string `json:"message_id"` // H(nonce) — the message to withdraw
	Timestamp    int64  `json:"timestamp"`

	SenderPubKey string `json:"sender_pub_key"`
	SenderSig    []byte `json:"sender_sig"` // signs "withdraw:" + MessageID + ":" + MailboxID

	IdvAttestationSig []byte `json:"idv_attestation_sig,omitempty"`
}

// ValidateChatTx performs stateless validation of a shychat transaction.
// Called by the shychat state machine's ValidateTx before stateful checks.
func ValidateChatTx(t *Tx) error {
	validChatTypes := map[uint8]bool{
		ChatTxTypeMailboxCreate:    true,
		ChatTxTypeMessageDispatch:  true,
		ChatTxTypeMailboxClose:     true,
		ChatTxTypeMessageUpdate:    true,
		ChatTxTypeMessageWithdraw:  true,
		ChatTxTypeRegisterValidator: true,
	}
	if !validChatTypes[t.Type] {
		return fmt.Errorf("invalid shychat transaction type: %d", t.Type)
	}
	if len(t.Signature) == 0 {
		return fmt.Errorf("missing transaction signature")
	}
	if len(t.Data) == 0 {
		return fmt.Errorf("missing transaction data")
	}

	switch t.Type {
	case ChatTxTypeMailboxCreate:
		var d MailboxCreateData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid mailbox create data: %w", err)
		}
		if d.MailboxID == "" {
			return fmt.Errorf("missing mailbox_id")
		}
		if d.SurfaceModel != "mail" && d.SurfaceModel != "chat" {
			return fmt.Errorf("surface_model must be 'mail' or 'chat'")
		}

	case ChatTxTypeMessageDispatch:
		var d MessageDispatchData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid message dispatch data: %w", err)
		}
		if d.MailboxID == "" {
			return fmt.Errorf("missing mailbox_id")
		}
		if d.MessageNonce == "" {
			return fmt.Errorf("missing message_nonce")
		}
		if len(d.SealedPayload) == 0 {
			return fmt.Errorf("missing sealed_payload")
		}
		if d.SenderPubKey == "" {
			return fmt.Errorf("missing sender_pub_key")
		}
		if len(d.SenderSig) == 0 {
			return fmt.Errorf("missing sender_sig")
		}
		if len(d.IdvAttestationSig) == 0 {
			return fmt.Errorf("message dispatch must carry idv_attestation_sig")
		}

	case ChatTxTypeMailboxClose:
		var d MailboxCloseData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid mailbox close data: %w", err)
		}
		if d.MailboxID == "" {
			return fmt.Errorf("missing mailbox_id")
		}

	case ChatTxTypeMessageUpdate:
		var d MessageUpdateData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid message update data: %w", err)
		}
		if d.MailboxID == "" {
			return fmt.Errorf("missing mailbox_id")
		}
		if d.OldMessageID == "" {
			return fmt.Errorf("missing old_message_id")
		}
		if d.NewMessageNonce == "" {
			return fmt.Errorf("missing new_message_nonce")
		}
		if d.SenderPubKey == "" {
			return fmt.Errorf("missing sender_pub_key")
		}
		if len(d.SenderSig) == 0 {
			return fmt.Errorf("missing sender_sig")
		}
		if len(d.IdvAttestationSig) == 0 {
			return fmt.Errorf("message update must carry idv_attestation_sig")
		}

	case ChatTxTypeMessageWithdraw:
		var d MessageWithdrawData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid message withdraw data: %w", err)
		}
		if d.MailboxID == "" {
			return fmt.Errorf("missing mailbox_id")
		}
		if d.MessageID == "" {
			return fmt.Errorf("missing message_id")
		}
		if d.SenderPubKey == "" {
			return fmt.Errorf("missing sender_pub_key")
		}
		if len(d.SenderSig) == 0 {
			return fmt.Errorf("missing sender_sig")
		}
		if len(d.IdvAttestationSig) == 0 {
			return fmt.Errorf("message withdraw must carry idv_attestation_sig")
		}

	case ChatTxTypeRegisterValidator:
		var d ValidatorRegistrationData
		if err := json.Unmarshal(t.Data, &d); err != nil {
			return fmt.Errorf("invalid validator registration data: %w", err)
		}
		raw, err := base64.StdEncoding.DecodeString(d.PubKeyBase64)
		if err != nil {
			return fmt.Errorf("pub_key_base64 is not valid base64: %w", err)
		}
		if len(raw) != 32 {
			return fmt.Errorf("pub_key_base64 must decode to 32 bytes (Ed25519), got %d", len(raw))
		}
		if d.Name == "" {
			return fmt.Errorf("missing validator name")
		}
		if d.Power < 0 {
			return fmt.Errorf("power must be >= 0")
		}
	}

	return nil
}

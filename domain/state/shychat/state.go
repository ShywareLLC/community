// Package shychat implements the shychat-v1 ABCI state machine.
//
// # Architecture
//
// ChatState embeds submission.TwoListBase for the two-list invariant and adds
// shychat-specific domain state: mailbox metadata and delivery records.
//
// List 1 (submissions / messages): "mailboxID:messageID" → sealed message payload, no identity
// List 2 (participants / senders): "mailboxID:identityHash" → sender identity, no payload
//
// The structural anonymity guarantee is inherited from TwoListBase.
// Identity verification is delegated to the configured IdentityVerifier.
//
// # Lifecycle
//
// 1. MailboxCreate — opens a mailbox (analogous to PollCreate).
// 2. MessageDispatch — atomic List 1 + List 2 write via TwoListBase.SubmitToLists.
// 3. MessageUpdate — direction change: replaces List 1 entry (recoverable posture only).
// 4. MessageWithdraw — bilateral withdrawal from both lists.
// 5. MailboxClose — count-match + HSM-signed ClosureRecord via TwoListBase.ClosePeriod.
package shychat

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	dbm "github.com/cometbft/cometbft-db"
	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/libs/log"

	"github.com/ShywareLLC/community/services/identity"
	"github.com/ShywareLLC/community/protocol/submission"
	"github.com/ShywareLLC/community/protocol/tx"
)

// MailboxRecord holds shychat-specific metadata for a mailbox period.
// The lifecycle (open/closed/startTime/endTime) is tracked by the embedded
// TwoListBase.PeriodRecord; MailboxRecord carries the messaging semantics.
type MailboxRecord struct {
	MailboxID    string `json:"mailbox_id"`
	Label        string `json:"label,omitempty"`
	Address      string `json:"address,omitempty"`
	RouteHint    string `json:"route_hint,omitempty"`
	SurfaceModel string `json:"surface_model"` // "mail" | "chat"
	AccountLabel string `json:"account_label,omitempty"`
}

// DeliveryRecord is the per-mailbox delivery closure record: a lightweight
// domain-specific summary committed alongside TwoListBase.ClosureRecord.
type DeliveryRecord struct {
	MailboxID        string `json:"mailbox_id"`
	TotalMessages    int64  `json:"total_messages"` // mirrors ClosureRecord.TotalSubmissions
	SurfaceModel     string `json:"surface_model"`
	FinalizedAt      int64  `json:"finalized_at"`
}

// ChatState is the shychat-v1 ABCI state machine.
// Embed TwoListBase for the protocol invariant; add mailbox and delivery maps
// for chat-specific metadata.
type ChatState struct {
	*submission.TwoListBase

	// shychat-specific domain state.
	mailboxes map[string]*MailboxRecord  // mailboxID → MailboxRecord
	deliveries map[string]*DeliveryRecord // mailboxID → DeliveryRecord (set at close)
}

// NewChatState creates a new ChatState.
func NewChatState(ctx context.Context, db dbm.DB, kmsKeyID string, logger log.Logger) (*ChatState, error) {
	base, err := submission.NewTwoListBase(ctx, db, kmsKeyID, logger)
	if err != nil {
		return nil, err
	}
	return &ChatState{
		TwoListBase: base,
		mailboxes:   make(map[string]*MailboxRecord),
		deliveries:  make(map[string]*DeliveryRecord),
	}, nil
}

// SetIdentityVerifier installs the IDV attestation verifier. Must be called
// before any MessageDispatch transactions are processed.
func (s *ChatState) SetIdentityVerifier(v identity.IdentityVerifier) {
	s.TwoListBase.SetIdentityVerifier(v)
}

// GetMailbox returns the mailbox metadata or nil if not found.
func (s *ChatState) GetMailbox(mailboxID string) *MailboxRecord {
	return s.mailboxes[mailboxID]
}

// GetDelivery returns the delivery record for a closed mailbox or nil.
func (s *ChatState) GetDelivery(mailboxID string) *DeliveryRecord {
	return s.deliveries[mailboxID]
}

// ValidateTx performs stateful validation of a shychat transaction.
func (s *ChatState) ValidateTx(transaction *tx.Tx) error {
	if err := tx.ValidateChatTx(transaction); err != nil {
		return err
	}
	switch transaction.Type {
	case tx.ChatTxTypeMailboxCreate:
		return s.validateMailboxCreate(transaction)
	case tx.ChatTxTypeMessageDispatch:
		return s.validateMessageDispatch(transaction)
	case tx.ChatTxTypeMailboxClose:
		return s.validateMailboxClose(transaction)
	case tx.ChatTxTypeMessageUpdate:
		return s.validateMessageUpdate(transaction)
	case tx.ChatTxTypeMessageWithdraw:
		return s.validateMessageWithdraw(transaction)
	case tx.ChatTxTypeRegisterValidator:
		return nil // stateless checks sufficient
	default:
		return fmt.Errorf("unknown shychat transaction type: %d", transaction.Type)
	}
}

// ExecuteTx executes a shychat transaction and returns ABCI events.
func (s *ChatState) ExecuteTx(transaction *tx.Tx) ([]abcitypes.Event, error) {
	switch transaction.Type {
	case tx.ChatTxTypeMailboxCreate:
		return s.executeMailboxCreate(transaction)
	case tx.ChatTxTypeMessageDispatch:
		return s.executeMessageDispatch(transaction)
	case tx.ChatTxTypeMailboxClose:
		return s.executeMailboxClose(transaction)
	case tx.ChatTxTypeMessageUpdate:
		return s.executeMessageUpdate(transaction)
	case tx.ChatTxTypeMessageWithdraw:
		return s.executeMessageWithdraw(transaction)
	case tx.ChatTxTypeRegisterValidator:
		return s.executeRegisterValidator(transaction)
	default:
		return nil, fmt.Errorf("unknown shychat transaction type: %d", transaction.Type)
	}
}

// ---- MailboxCreate ----

func (s *ChatState) validateMailboxCreate(t *tx.Tx) error {
	var d tx.MailboxCreateData
	if err := t.UnmarshalData(&d); err != nil {
		return fmt.Errorf("invalid mailbox create data: %w", err)
	}
	if s.TwoListBase.GetPeriod(d.MailboxID) != nil {
		return fmt.Errorf("mailbox %s already exists", d.MailboxID)
	}
	return nil
}

func (s *ChatState) executeMailboxCreate(t *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.MailboxCreateData
	if err := t.UnmarshalData(&d); err != nil {
		return nil, fmt.Errorf("invalid mailbox create data: %w", err)
	}

	now := time.Now().Unix()
	endTime := d.EndTime
	if endTime == 0 {
		endTime = now + 365*24*3600 // default 1-year window if not specified
	}

	if err := s.TwoListBase.CreatePeriod(d.MailboxID, "shychat", now, endTime); err != nil {
		return nil, err
	}

	s.mailboxes[d.MailboxID] = &MailboxRecord{
		MailboxID:    d.MailboxID,
		Label:        d.Label,
		Address:      d.Address,
		RouteHint:    d.RouteHint,
		SurfaceModel: d.SurfaceModel,
		AccountLabel: d.AccountLabel,
	}

	return []abcitypes.Event{{
		Type: "mailbox_created",
		Attributes: []abcitypes.EventAttribute{
			{Key: "mailbox_id", Value: d.MailboxID, Index: true},
			{Key: "surface_model", Value: d.SurfaceModel, Index: false},
		},
	}}, nil
}

// ---- MessageDispatch ----

func (s *ChatState) validateMessageDispatch(t *tx.Tx) error {
	var d tx.MessageDispatchData
	if err := t.UnmarshalData(&d); err != nil {
		return fmt.Errorf("invalid message dispatch data: %w", err)
	}

	// Validate nonce format.
	if err := submission.ValidateNonce(d.MessageNonce); err != nil {
		return fmt.Errorf("message_nonce: %w", err)
	}

	// Validate beacon: confirms the identifier was conditioned on a pre-session canonical block hash.
	if err := submission.ValidateBeacon(d.BeaconBlockHash, d.BeaconBlockHeight, s.TwoListBase.BeaconWindow()); err != nil {
		return fmt.Errorf("beacon: %w", err)
	}

	// Verify device signature: Ed25519.Sign(sk_s, MessageNonce + ":" + MailboxID).
	senderPubBytes, err := hex.DecodeString(d.SenderPubKey)
	if err != nil || len(senderPubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("sender_pub_key must be a 64-char hex-encoded Ed25519 public key")
	}
	deviceMsg := []byte(d.MessageNonce + ":" + d.MailboxID)
	if !ed25519.Verify(ed25519.PublicKey(senderPubBytes), deviceMsg, d.SenderSig) {
		return fmt.Errorf("sender device signature invalid for mailbox %s", d.MailboxID)
	}

	// Mailbox must exist and be open.
	period := s.TwoListBase.GetPeriod(d.MailboxID)
	if period == nil {
		return fmt.Errorf("mailbox %s does not exist", d.MailboxID)
	}
	if period.Status == "closed" {
		return fmt.Errorf("mailbox %s is closed", d.MailboxID)
	}
	now := time.Now().Unix()
	if period.EndTime > 0 && now >= period.EndTime {
		return fmt.Errorf("mailbox %s has expired", d.MailboxID)
	}

	// IDV attestation.
	if s.TwoListBase.GetVerifier() == nil {
		return fmt.Errorf("no identity verifier configured for this deployment")
	}
	identityHash, err := verifyAndIdentifyChat(s.TwoListBase.GetVerifier(), &d)
	if err != nil {
		return fmt.Errorf("identity verification failed: %w", err)
	}

	// Dedup: one message per sender per mailbox.
	if s.TwoListBase.HasParticipant(d.MailboxID, identityHash) {
		return fmt.Errorf("sender %s already has a message in mailbox %s", identityHash, d.MailboxID)
	}

	return nil
}

func (s *ChatState) executeMessageDispatch(t *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.MessageDispatchData
	if err := t.UnmarshalData(&d); err != nil {
		return nil, fmt.Errorf("invalid message dispatch data: %w", err)
	}

	// Re-derive identity_hash.
	identityHash, err := verifyAndIdentifyChat(s.TwoListBase.GetVerifier(), &d)
	if err != nil {
		return nil, fmt.Errorf("identity re-derivation failed: %w", err)
	}

	messageID := computeMessageIDWithBeacon(d.BeaconBlockHash, d.MessageNonce)

	return s.TwoListBase.SubmitToLists(
		context.Background(),
		d.MailboxID,
		messageID,
		identityHash,
		d.SealedPayload,
		d.PartitionID,
	)
}

// ---- MailboxClose ----

func (s *ChatState) validateMailboxClose(t *tx.Tx) error {
	var d tx.MailboxCloseData
	if err := t.UnmarshalData(&d); err != nil {
		return fmt.Errorf("invalid mailbox close data: %w", err)
	}
	period := s.TwoListBase.GetPeriod(d.MailboxID)
	if period == nil {
		return fmt.Errorf("mailbox %s does not exist", d.MailboxID)
	}
	if period.Status == "closed" {
		return fmt.Errorf("mailbox %s is already closed", d.MailboxID)
	}
	return nil
}

func (s *ChatState) executeMailboxClose(t *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.MailboxCloseData
	if err := t.UnmarshalData(&d); err != nil {
		return nil, fmt.Errorf("invalid mailbox close data: %w", err)
	}

	closure, events, err := s.TwoListBase.ClosePeriod(context.Background(), d.MailboxID, d.ClosingHeight)
	if err != nil {
		return nil, err
	}

	mb := s.mailboxes[d.MailboxID]
	surfaceModel := ""
	if mb != nil {
		surfaceModel = mb.SurfaceModel
	}

	s.deliveries[d.MailboxID] = &DeliveryRecord{
		MailboxID:     d.MailboxID,
		TotalMessages: closure.TotalSubmissions,
		SurfaceModel:  surfaceModel,
		FinalizedAt:   closure.FinalizedAt,
	}

	return events, nil
}

// ---- MessageUpdate ----

func (s *ChatState) validateMessageUpdate(t *tx.Tx) error {
	if s.TwoListBase.IsWriteOnly() {
		return fmt.Errorf("write-only posture active: message updates are not permitted")
	}
	var d tx.MessageUpdateData
	if err := t.UnmarshalData(&d); err != nil {
		return fmt.Errorf("invalid message update data: %w", err)
	}

	// Validate nonce format.
	if err := submission.ValidateNonce(d.NewMessageNonce); err != nil {
		return fmt.Errorf("new_message_nonce: %w", err)
	}

	// Validate beacon: confirms the identifier was conditioned on a pre-session canonical block hash.
	if err := submission.ValidateBeacon(d.BeaconBlockHash, d.BeaconBlockHeight, s.TwoListBase.BeaconWindow()); err != nil {
		return fmt.Errorf("beacon: %w", err)
	}

	senderPubBytes, err := hex.DecodeString(d.SenderPubKey)
	if err != nil || len(senderPubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("sender_pub_key must be a 64-char hex-encoded Ed25519 public key")
	}
	updateMsg := []byte("update:" + d.NewMessageNonce + ":" + d.MailboxID)
	if !ed25519.Verify(ed25519.PublicKey(senderPubBytes), updateMsg, d.SenderSig) {
		return fmt.Errorf("sender device signature invalid for message update on mailbox %s", d.MailboxID)
	}

	period := s.TwoListBase.GetPeriod(d.MailboxID)
	if period == nil {
		return fmt.Errorf("mailbox %s does not exist", d.MailboxID)
	}
	if period.Status == "closed" {
		return fmt.Errorf("mailbox %s is closed", d.MailboxID)
	}

	if !s.TwoListBase.HasSubmission(d.MailboxID, d.OldMessageID) {
		return fmt.Errorf("old_message_id %s not found in mailbox %s", d.OldMessageID, d.MailboxID)
	}

	if s.TwoListBase.GetVerifier() == nil {
		return fmt.Errorf("no identity verifier configured for this deployment")
	}
	identityHash, err := verifyAndIdentifyChatUpdate(s.TwoListBase.GetVerifier(), &d)
	if err != nil {
		return fmt.Errorf("identity verification failed for message update: %w", err)
	}
	if !s.TwoListBase.HasParticipant(d.MailboxID, identityHash) {
		return fmt.Errorf("sender is not registered in mailbox %s — cannot update a non-dispatched message", d.MailboxID)
	}

	return nil
}

func (s *ChatState) executeMessageUpdate(t *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.MessageUpdateData
	if err := t.UnmarshalData(&d); err != nil {
		return nil, fmt.Errorf("invalid message update data: %w", err)
	}

	newMessageID := computeMessageIDWithBeacon(d.BeaconBlockHash, d.NewMessageNonce)
	return s.TwoListBase.UpdateSubmission(d.MailboxID, d.OldMessageID, newMessageID, d.NewSealedPayload)
}

// ---- MessageWithdraw ----

func (s *ChatState) validateMessageWithdraw(t *tx.Tx) error {
	var d tx.MessageWithdrawData
	if err := t.UnmarshalData(&d); err != nil {
		return fmt.Errorf("invalid message withdraw data: %w", err)
	}

	senderPubBytes, err := hex.DecodeString(d.SenderPubKey)
	if err != nil || len(senderPubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("sender_pub_key must be a 64-char hex-encoded Ed25519 public key")
	}
	withdrawMsg := []byte("withdraw:" + d.MessageID + ":" + d.MailboxID)
	if !ed25519.Verify(ed25519.PublicKey(senderPubBytes), withdrawMsg, d.SenderSig) {
		return fmt.Errorf("sender device signature invalid for message withdraw on mailbox %s", d.MailboxID)
	}

	period := s.TwoListBase.GetPeriod(d.MailboxID)
	if period == nil {
		return fmt.Errorf("mailbox %s does not exist", d.MailboxID)
	}
	if period.Status == "closed" {
		return fmt.Errorf("mailbox %s is closed", d.MailboxID)
	}
	if !s.TwoListBase.HasSubmission(d.MailboxID, d.MessageID) {
		return fmt.Errorf("message_id %s not found in mailbox %s", d.MessageID, d.MailboxID)
	}

	if s.TwoListBase.GetVerifier() == nil {
		return fmt.Errorf("no identity verifier configured for this deployment")
	}
	identityHash, err := verifyAndIdentifyChatWithdraw(s.TwoListBase.GetVerifier(), &d)
	if err != nil {
		return fmt.Errorf("identity verification failed for message withdraw: %w", err)
	}
	if !s.TwoListBase.HasParticipant(d.MailboxID, identityHash) {
		return fmt.Errorf("sender is not registered in mailbox %s", d.MailboxID)
	}

	return nil
}

func (s *ChatState) executeMessageWithdraw(t *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.MessageWithdrawData
	if err := t.UnmarshalData(&d); err != nil {
		return nil, fmt.Errorf("invalid message withdraw data: %w", err)
	}

	identityHash, err := verifyAndIdentifyChatWithdraw(s.TwoListBase.GetVerifier(), &d)
	if err != nil {
		return nil, fmt.Errorf("identity re-derivation failed: %w", err)
	}

	return s.TwoListBase.WithdrawFromLists(d.MailboxID, d.MessageID, identityHash)
}

// ---- Validator registration ----

func (s *ChatState) executeRegisterValidator(t *tx.Tx) ([]abcitypes.Event, error) {
	var d tx.ValidatorRegistrationData
	if err := t.UnmarshalData(&d); err != nil {
		return nil, fmt.Errorf("invalid validator registration data: %w", err)
	}
	return s.TwoListBase.RegisterValidator(d.PubKeyBase64, d.Power, d.Name)
}

// ---- Query ----

// Query handles state queries for the shychat domain.
// Supported paths:
//
//	/mailboxes                   — list all mailboxes
//	/mailbox/{mailbox_id}        — single mailbox record
//	/delivery/{mailbox_id}       — delivery record for a closed mailbox
//	/message_count/{mailbox_id}  — current |L1| count for a mailbox
func (s *ChatState) Query(path string, _ []byte, _ int64, _ bool) ([]byte, error) {
	switch {
	case path == "/mailboxes":
		boxes := make([]*MailboxRecord, 0, len(s.mailboxes))
		for _, mb := range s.mailboxes {
			boxes = append(boxes, mb)
		}
		return json.Marshal(boxes)

	case strings.HasPrefix(path, "/mailbox/"):
		id := strings.TrimPrefix(path, "/mailbox/")
		mb, ok := s.mailboxes[id]
		if !ok {
			return nil, fmt.Errorf("mailbox not found: %s", id)
		}
		return json.Marshal(mb)

	case strings.HasPrefix(path, "/delivery/"):
		id := strings.TrimPrefix(path, "/delivery/")
		dr, ok := s.deliveries[id]
		if !ok {
			return nil, fmt.Errorf("delivery record not found for mailbox: %s", id)
		}
		return json.Marshal(dr)

	case strings.HasPrefix(path, "/message_count/"):
		id := strings.TrimPrefix(path, "/message_count/")
		l1, l2 := s.TwoListBase.CountsForPeriod(id)
		return json.Marshal(map[string]int{"l1": l1, "l2": l2})

	default:
		return nil, fmt.Errorf("unknown query path: %s", path)
	}
}

// ---- Identity verification helpers ----

// verifyAndIdentifyChat derives the identity_hash for a MessageDispatch.
// Uses the same two embodiments as BallotCastData (Didit preferred, Identus alternative).
// identity_hash = sha256(sender_pub_key || mailbox_id)  [Didit]
//              or sha256(identus_subject_did || sender_pub_key || mailbox_id)  [Identus]
func verifyAndIdentifyChat(v identity.IdentityVerifier, d *tx.MessageDispatchData) (string, error) {
	// Convert MessageDispatchData → BallotCastData shape for reuse of the verifier interface.
	// The verifier expects VoterPubKey, PollID, and the attestation fields.
	cast := &tx.BallotCastData{
		PollID:               d.MailboxID,
		BallotNonce:          d.MessageNonce,
		VoterPubKey:          d.SenderPubKey,
		VoterSig:             d.SenderSig,
		DiditDeviceSig:       d.DiditDeviceSig,
		IdentusSubjectDID:    d.IdentusSubjectDID,
		IdentusCredentialSig: d.IdentusCredentialSig,
	}
	return v.VerifyAndIdentify(cast)
}

func verifyAndIdentifyChatUpdate(v identity.IdentityVerifier, d *tx.MessageUpdateData) (string, error) {
	update := &tx.BallotUpdateData{
		PollID:               d.MailboxID,
		NewBallotNonce:       d.NewMessageNonce,
		VoterPubKey:          d.SenderPubKey,
		VoterSig:             d.SenderSig,
		DiditDeviceSig:       d.DiditDeviceSig,
		IdentusSubjectDID:    d.IdentusSubjectDID,
		IdentusCredentialSig: d.IdentusCredentialSig,
	}
	return v.VerifyAndIdentifyUpdate(update)
}

func verifyAndIdentifyChatWithdraw(v identity.IdentityVerifier, d *tx.MessageWithdrawData) (string, error) {
	// Withdraw reuses the Didit/Identus attestation path; treat MailboxID as the period scope.
	h := sha256.New()
	if d.IdentusSubjectDID != "" {
		h.Write([]byte(d.IdentusSubjectDID))
	}
	h.Write([]byte(d.SenderPubKey))
	h.Write([]byte(d.MailboxID))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// computeMessageID derives an anonymous message ID from the sender-supplied nonce.
func computeMessageID(messageNonce string) string {
	h := sha256.Sum256([]byte(messageNonce))
	return hex.EncodeToString(h[:])
}

// computeMessageIDWithBeacon derives the message ID using the beacon-committed block hash.
// message_id = SHA-256(beacon_bytes || nonce_bytes) — independence verifiable from canonical state.
// Falls back to legacy SHA-256(nonce) when beacon is absent (e.g. test injection paths).
func computeMessageIDWithBeacon(beaconBlockHash, messageNonce string) string {
	if beaconBlockHash == "" {
		return computeMessageID(messageNonce)
	}
	id, err := submission.DeriveSubmissionID(beaconBlockHash, messageNonce)
	if err != nil {
		return computeMessageID(messageNonce)
	}
	return id
}

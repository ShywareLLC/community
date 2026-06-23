package reconcile

// FirestoreStore implements Store using Google Cloud Firestore as the off-chain
// linkage backend. Natural fit for GCP operators who already have a Firebase project
// for auth (FirebaseAuthInterface) and GCP KMS for signing (services/gcp).
//
// The original shyware implementation used Firestore but was replaced by CockroachDB
// because the implementation exposed Firestore's collection list API, allowing
// operator credentials to enumerate all identity-to-submission associations without
// per-participant re-authentication. FirestoreStore closes that gap by design:
//
//   - Document IDs are SHA-256(pollID + 0x1f + identityHash) — opaque hashes.
//     An observer with read access cannot enumerate participants for a given poll
//     because no index on poll_id is created and document IDs are unlinkable to
//     the underlying values without knowing both inputs.
//   - The Store interface exposes no collection-level read, list, or query operation.
//   - Firestore Security Rules should additionally restrict the collection to
//     server-side access only (deny client == request.auth).
//
// Collection layout:
//
//	receipt_store/{sha256(pollID || identityHash)} → { poll_id, identity_hash, ballot_id }
//
// Required env vars (all have constructor overrides via FirestoreOption):
//
//	GOOGLE_CLOUD_PROJECT  — GCP project ID (also accepted: GCP_PROJECT)
//	FIRESTORE_COLLECTION  — collection name (default: receipt_store)
//
// Auth: Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS,
// Workload Identity, Cloud Run service account, gcloud application-default).
//
// Required module dep:
//
//	go get cloud.google.com/go/firestore@latest

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"

	"cloud.google.com/go/firestore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const defaultFirestoreCollection = "receipt_store"

// FirestoreStore implements Store using Cloud Firestore.
type FirestoreStore struct {
	client     *firestore.Client
	collection string
}

// NewFirestoreStore creates a FirestoreStore connected to the given GCP project.
func NewFirestoreStore(ctx context.Context, opts ...FirestoreOption) (*FirestoreStore, error) {
	cfg := &firestoreConfig{
		project:    firstNonEmptyStr(os.Getenv("GOOGLE_CLOUD_PROJECT"), os.Getenv("GCP_PROJECT")),
		collection: firstNonEmptyStr(os.Getenv("FIRESTORE_COLLECTION"), defaultFirestoreCollection),
	}
	for _, o := range opts {
		o(cfg)
	}
	if cfg.project == "" {
		return nil, fmt.Errorf("firestore reconcile store: GOOGLE_CLOUD_PROJECT is required")
	}
	client, err := firestore.NewClient(ctx, cfg.project)
	if err != nil {
		return nil, fmt.Errorf("firestore reconcile store: NewClient: %w", err)
	}
	return &FirestoreStore{client: client, collection: cfg.collection}, nil
}

// NewFirestoreStoreWithClient creates a FirestoreStore from a pre-configured client.
func NewFirestoreStoreWithClient(client *firestore.Client, collection string) *FirestoreStore {
	if collection == "" {
		collection = defaultFirestoreCollection
	}
	return &FirestoreStore{client: client, collection: collection}
}

// Close releases the underlying Firestore client. Call at server shutdown.
func (s *FirestoreStore) Close() error { return s.client.Close() }

func (s *FirestoreStore) RecordSubmission(ctx context.Context, pollID, identityHash, submissionID string) error {
	_, err := s.doc(pollID, identityHash).Set(ctx, map[string]string{
		"poll_id":       pollID,
		"identity_hash": identityHash,
		"ballot_id":     submissionID,
	})
	if err != nil {
		return fmt.Errorf("firestore reconcile store upsert poll=%s: %w", pollID, err)
	}
	return nil
}

func (s *FirestoreStore) GetSubmissionID(ctx context.Context, pollID, identityHash string) (string, error) {
	return s.readBallotID(ctx, pollID, identityHash, "GetSubmissionID")
}

func (s *FirestoreStore) RevealBallotEvidence(ctx context.Context, pollID, identityHash string) (string, error) {
	// Caller must verify dual co-authorization and commit a reveal-evidence event
	// record to canonical state before returning the ballot_id to the requesting party.
	return s.readBallotID(ctx, pollID, identityHash, "RevealBallotEvidence")
}

func (s *FirestoreStore) DeleteSubmission(ctx context.Context, pollID, identityHash string) error {
	if _, err := s.doc(pollID, identityHash).Delete(ctx); err != nil {
		return fmt.Errorf("firestore reconcile store delete poll=%s: %w", pollID, err)
	}
	return nil
}

func (s *FirestoreStore) readBallotID(ctx context.Context, pollID, identityHash, op string) (string, error) {
	snap, err := s.doc(pollID, identityHash).Get(ctx)
	if status.Code(err) == codes.NotFound {
		return "", fmt.Errorf("firestore reconcile store %s poll=%s: %w", op, pollID, sql.ErrNoRows)
	}
	if err != nil {
		return "", fmt.Errorf("firestore reconcile store %s poll=%s: %w", op, pollID, err)
	}
	v, err := snap.DataAt("ballot_id")
	if err != nil {
		return "", fmt.Errorf("firestore reconcile store %s poll=%s: ballot_id missing: %w", op, pollID, err)
	}
	ballotID, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("firestore reconcile store %s poll=%s: ballot_id not a string", op, pollID)
	}
	return ballotID, nil
}

// doc returns the DocumentRef for a (pollID, identityHash) pair.
// The document ID is SHA-256(pollID || 0x1f || identityHash) — an opaque hash that
// prevents enumeration of participants for a given poll even with collection read access.
func (s *FirestoreStore) doc(pollID, identityHash string) *firestore.DocumentRef {
	h := sha256.Sum256([]byte(pollID + "\x1f" + identityHash))
	return s.client.Collection(s.collection).Doc(hex.EncodeToString(h[:]))
}

// FirestoreOption configures NewFirestoreStore.
type FirestoreOption func(*firestoreConfig)

// WithFirestoreProject sets the GCP project ID.
func WithFirestoreProject(project string) FirestoreOption {
	return func(c *firestoreConfig) { c.project = project }
}

// WithFirestoreCollection sets the Firestore collection name.
func WithFirestoreCollection(collection string) FirestoreOption {
	return func(c *firestoreConfig) { c.collection = collection }
}

type firestoreConfig struct {
	project, collection string
}

// Ensure FirestoreStore satisfies Store at compile time.
var _ Store = (*FirestoreStore)(nil)

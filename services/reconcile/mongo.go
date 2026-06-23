package reconcile

// MongoStore implements Store using any MongoDB-compatible database as the
// off-chain linkage backend (MongoDB Atlas, self-hosted, DocumentDB, Cosmos DB
// MongoDB API, Ferretdb, etc.).
//
// Collection schema (index — run once):
//
//	db.receipt_store.createIndex({ poll_id: 1, identity_hash: 1 }, { unique: true })
//
// Required env vars (all have constructor overrides via MongoOption):
//
//	MONGODB_URI                  — connection string (default: mongodb://localhost:27017)
//	MONGODB_DB                   — database name (default: shyware)
//	MONGODB_RECEIPT_COLLECTION   — collection name (default: receipt_store)
//
// Required module dep:
//
//	go get go.mongodb.org/mongo-driver/mongo@latest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// MongoStore implements Store using a MongoDB collection.
type MongoStore struct {
	coll *mongo.Collection
}

// NewMongoStore connects to MongoDB using the default env var config and returns a MongoStore.
// The caller is responsible for calling client.Disconnect(ctx) at shutdown if needed;
// pass the returned *mongo.Client to disconnect cleanly.
func NewMongoStore(ctx context.Context, opts ...MongoOption) (*MongoStore, *mongo.Client, error) {
	cfg := &mongoConfig{
		uri:        firstNonEmptyStr(os.Getenv("MONGODB_URI"), "mongodb://localhost:27017"),
		db:         firstNonEmptyStr(os.Getenv("MONGODB_DB"), "shyware"),
		collection: firstNonEmptyStr(os.Getenv("MONGODB_RECEIPT_COLLECTION"), "receipt_store"),
	}
	for _, o := range opts {
		o(cfg)
	}

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.uri))
	if err != nil {
		return nil, nil, fmt.Errorf("mongo reconcile store: Connect: %w", err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		return nil, nil, fmt.Errorf("mongo reconcile store: Ping: %w", err)
	}
	coll := client.Database(cfg.db).Collection(cfg.collection)
	return &MongoStore{coll: coll}, client, nil
}

// NewMongoStoreWithCollection creates a MongoStore from a pre-configured collection.
// Use this when the calling binary already owns the mongo.Client.
func NewMongoStoreWithCollection(coll *mongo.Collection) *MongoStore {
	return &MongoStore{coll: coll}
}

func (s *MongoStore) RecordSubmission(ctx context.Context, pollID, identityHash, submissionID string) error {
	filter := bson.D{{Key: "poll_id", Value: pollID}, {Key: "identity_hash", Value: identityHash}}
	update := bson.D{{Key: "$set", Value: bson.D{
		{Key: "poll_id", Value: pollID},
		{Key: "identity_hash", Value: identityHash},
		{Key: "ballot_id", Value: submissionID},
	}}}
	_, err := s.coll.UpdateOne(ctx, filter, update, options.Update().SetUpsert(true))
	if err != nil {
		return fmt.Errorf("mongo reconcile store upsert poll=%s: %w", pollID, err)
	}
	return nil
}

func (s *MongoStore) GetSubmissionID(ctx context.Context, pollID, identityHash string) (string, error) {
	return s.findBallotID(ctx, pollID, identityHash, "GetSubmissionID")
}

func (s *MongoStore) RevealBallotEvidence(ctx context.Context, pollID, identityHash string) (string, error) {
	// Caller must verify dual co-authorization and commit a reveal-evidence event
	// record to canonical state before returning the ballot_id to the requesting party.
	return s.findBallotID(ctx, pollID, identityHash, "RevealBallotEvidence")
}

func (s *MongoStore) DeleteSubmission(ctx context.Context, pollID, identityHash string) error {
	filter := bson.D{{Key: "poll_id", Value: pollID}, {Key: "identity_hash", Value: identityHash}}
	if _, err := s.coll.DeleteOne(ctx, filter); err != nil {
		return fmt.Errorf("mongo reconcile store delete poll=%s: %w", pollID, err)
	}
	return nil
}

func (s *MongoStore) findBallotID(ctx context.Context, pollID, identityHash, op string) (string, error) {
	filter := bson.D{{Key: "poll_id", Value: pollID}, {Key: "identity_hash", Value: identityHash}}
	proj := options.FindOne().SetProjection(bson.D{{Key: "ballot_id", Value: 1}, {Key: "_id", Value: 0}})

	var result struct {
		BallotID string `bson:"ballot_id"`
	}
	err := s.coll.FindOne(ctx, filter, proj).Decode(&result)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", fmt.Errorf("mongo reconcile store %s poll=%s: %w", op, pollID, sql.ErrNoRows)
	}
	if err != nil {
		return "", fmt.Errorf("mongo reconcile store %s poll=%s: %w", op, pollID, err)
	}
	return result.BallotID, nil
}

// MongoOption configures NewMongoStore.
type MongoOption func(*mongoConfig)

// WithMongoURI sets the MongoDB connection string.
func WithMongoURI(uri string) MongoOption { return func(c *mongoConfig) { c.uri = uri } }

// WithMongoDB sets the database name.
func WithMongoDB(db string) MongoOption { return func(c *mongoConfig) { c.db = db } }

// WithMongoCollection sets the collection name.
func WithMongoCollection(coll string) MongoOption { return func(c *mongoConfig) { c.collection = coll } }

type mongoConfig struct {
	uri, db, collection string
}

// Ensure MongoStore satisfies Store at compile time.
var _ Store = (*MongoStore)(nil)

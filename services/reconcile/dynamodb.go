package reconcile

// DynamoDBStore implements Store using AWS DynamoDB as the off-chain linkage backend.
// Designed for Lambda + DynamoDB deployments where a Postgres instance is out of place.
//
// Table layout (single table — create once with aws dynamodb create-table):
//
//	aws dynamodb create-table \
//	  --table-name shy_receipt_store \
//	  --attribute-definitions AttributeName=poll_id,AttributeType=S AttributeName=identity_hash,AttributeType=S \
//	  --key-schema AttributeName=poll_id,KeyType=HASH AttributeName=identity_hash,KeyType=RANGE \
//	  --billing-mode PAY_PER_REQUEST
//
// Required env vars (all have constructor overrides):
//
//	AWS_REGION              — DynamoDB region (default: us-east-1)
//	DYNAMODB_RECEIPT_TABLE  — table name (default: shy_receipt_store)
//
// Auth: standard AWS credential chain (env vars, instance/task role, Lambda execution role, etc.)
//
// Required module deps:
//
//	go get github.com/aws/aws-sdk-go-v2/config@latest
//	go get github.com/aws/aws-sdk-go-v2/service/dynamodb@latest
//	go get github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue@latest

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

const defaultReceiptTable = "shy_receipt_store"

// DynamoDBStore implements Store using DynamoDB.
type DynamoDBStore struct {
	client *dynamodb.Client
	table  string
}

// NewDynamoDBStore creates a DynamoDBStore using the default AWS credential chain.
func NewDynamoDBStore(ctx context.Context) (*DynamoDBStore, error) {
	region := firstNonEmptyStr(os.Getenv("AWS_REGION"), os.Getenv("CLOUD_REGION"), "us-east-1")
	table := firstNonEmptyStr(os.Getenv("DYNAMODB_RECEIPT_TABLE"), defaultReceiptTable)
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("dynamodb reconcile store: load AWS config: %w", err)
	}
	return &DynamoDBStore{client: dynamodb.NewFromConfig(cfg), table: table}, nil
}

// NewDynamoDBStoreWithClient creates a DynamoDBStore from a pre-configured client.
// Use this for testing or when the calling binary already owns the DynamoDB client.
func NewDynamoDBStoreWithClient(client *dynamodb.Client, table string) *DynamoDBStore {
	if table == "" {
		table = defaultReceiptTable
	}
	return &DynamoDBStore{client: client, table: table}
}

func (s *DynamoDBStore) RecordSubmission(ctx context.Context, pollID, identityHash, submissionID string) error {
	item, err := attributevalue.MarshalMap(map[string]string{
		"poll_id":       pollID,
		"identity_hash": identityHash,
		"ballot_id":     submissionID,
	})
	if err != nil {
		return fmt.Errorf("dynamodb reconcile store marshal: %w", err)
	}
	if _, err := s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.table),
		Item:      item,
		// Unconditional put — last-write-wins upsert semantics match RecordSubmission's
		// idempotency contract: re-running with the same ballot_id is a no-op.
	}); err != nil {
		return fmt.Errorf("dynamodb reconcile store upsert poll=%s: %w", pollID, err)
	}
	return nil
}

func (s *DynamoDBStore) GetSubmissionID(ctx context.Context, pollID, identityHash string) (string, error) {
	return s.getField(ctx, pollID, identityHash, "GetSubmissionID")
}

func (s *DynamoDBStore) RevealBallotEvidence(ctx context.Context, pollID, identityHash string) (string, error) {
	// Caller must verify dual co-authorization and commit a reveal-evidence event
	// record to canonical state before returning the ballot_id to the requesting party.
	return s.getField(ctx, pollID, identityHash, "RevealBallotEvidence")
}

func (s *DynamoDBStore) DeleteSubmission(ctx context.Context, pollID, identityHash string) error {
	key, err := attributevalue.MarshalMap(map[string]string{
		"poll_id":       pollID,
		"identity_hash": identityHash,
	})
	if err != nil {
		return fmt.Errorf("dynamodb reconcile store marshal key: %w", err)
	}
	if _, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.table),
		Key:       key,
	}); err != nil {
		return fmt.Errorf("dynamodb reconcile store delete poll=%s: %w", pollID, err)
	}
	return nil
}

func (s *DynamoDBStore) getField(ctx context.Context, pollID, identityHash, op string) (string, error) {
	key, err := attributevalue.MarshalMap(map[string]string{
		"poll_id":       pollID,
		"identity_hash": identityHash,
	})
	if err != nil {
		return "", fmt.Errorf("dynamodb reconcile store marshal key: %w", err)
	}
	resp, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:            aws.String(s.table),
		Key:                  key,
		ProjectionExpression: aws.String("ballot_id"),
	})
	if err != nil {
		return "", fmt.Errorf("dynamodb reconcile store %s poll=%s: %w", op, pollID, err)
	}
	if resp.Item == nil {
		return "", fmt.Errorf("dynamodb reconcile store %s poll=%s: %w", op, pollID, sql.ErrNoRows)
	}
	v, ok := resp.Item["ballot_id"]
	if !ok {
		return "", fmt.Errorf("dynamodb reconcile store %s poll=%s: ballot_id attribute missing", op, pollID)
	}
	var ballotID string
	if err := attributevalue.Unmarshal(v, &ballotID); err != nil {
		return "", fmt.Errorf("dynamodb reconcile store %s poll=%s: unmarshal: %w", op, pollID, err)
	}
	return ballotID, nil
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// Ensure DynamoDBStore satisfies Store at compile time.
var _ Store = (*DynamoDBStore)(nil)

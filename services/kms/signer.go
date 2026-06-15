package kms

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// Signer wraps AWS KMS for ECDSA signing using an ECC_NIST_P256 asymmetric key.
// Every Sign call is logged in CloudTrail — that audit trail is the forensic record.
type Signer struct {
	client    *awskms.Client
	keyID     string
	pubKeyDER []byte // cached DER-encoded public key
	mu        sync.RWMutex
}

// NewSigner creates a Signer for the given KMS key ID or ARN.
func NewSigner(ctx context.Context, keyID string) (*Signer, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("kms: failed to load AWS config: %w", err)
	}

	s := &Signer{
		client: awskms.NewFromConfig(cfg),
		keyID:  keyID,
	}

	// Cache the public key on startup
	if err := s.loadPublicKey(ctx); err != nil {
		return nil, err
	}

	return s, nil
}

// Sign hashes the payload with SHA-256 and calls KMS to sign the digest.
// Returns the raw ECDSA signature bytes (DER-encoded).
// Every call is recorded in CloudTrail.
func (s *Signer) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	digest := sha256.Sum256(payload)

	out, err := s.client.Sign(ctx, &awskms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          digest[:],
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("kms: Sign failed: %w", err)
	}

	return out.Signature, nil
}

// PublicKeyDER returns the cached DER-encoded public key.
// Use this to verify signatures without a KMS call.
func (s *Signer) PublicKeyDER() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pubKeyDER
}

// PublicKeyBase64 returns the public key as a base64 string for embedding in genesis.
func (s *Signer) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(s.PublicKeyDER())
}

// VerifyDER verifies an ECDSA signature against a payload using the cached public key.
// Parses the DER-encoded SubjectPublicKeyInfo and DER-encoded ECDSA signature,
// then verifies against SHA-256(payload).
func (s *Signer) VerifyDER(payload, sigDER []byte) (bool, error) {
	s.mu.RLock()
	pubDER := s.pubKeyDER
	s.mu.RUnlock()

	if pubDER == nil {
		return false, fmt.Errorf("kms: public key not loaded")
	}

	// Parse SubjectPublicKeyInfo DER → *ecdsa.PublicKey
	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return false, fmt.Errorf("kms: failed to parse public key DER: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("kms: public key is not ECDSA")
	}

	// Parse DER signature (SEQUENCE { INTEGER r, INTEGER s })
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(sigDER, &sig); err != nil {
		return false, fmt.Errorf("kms: failed to parse DER signature: %w", err)
	}

	digest := sha256.Sum256(payload)
	return ecdsa.Verify(ecPub, digest[:], sig.R, sig.S), nil
}

func (s *Signer) loadPublicKey(ctx context.Context) error {
	out, err := s.client.GetPublicKey(ctx, &awskms.GetPublicKeyInput{
		KeyId: aws.String(s.keyID),
	})
	if err != nil {
		return fmt.Errorf("kms: GetPublicKey failed: %w", err)
	}

	s.mu.Lock()
	s.pubKeyDER = out.PublicKey
	s.mu.Unlock()
	return nil
}

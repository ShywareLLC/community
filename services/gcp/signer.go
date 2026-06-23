// Package gcp provides a signer.Signer implementation backed by Google Cloud KMS.
//
// Key resource name format:
//
//	projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}/cryptoKeyVersions/{version}
//
// The key must use algorithm EC_SIGN_P256_SHA256.
//
// Auth: uses Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS,
// Workload Identity, or gcloud application-default credentials).
//
// Required module dep:
//
//	go get cloud.google.com/go/kms@latest
//	go get google.golang.org/api@latest
package gcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/option"
)

// Signer wraps Google Cloud KMS for ECDSA signing (EC_SIGN_P256_SHA256).
// Every Sign call is recorded in GCP Cloud Audit Logs — the audit trail
// is the immutable signing record, equivalent to CloudTrail for AWS KMS.
type Signer struct {
	client  *kms.KeyManagementClient
	keyName string // full resource name including version
	pubDER  []byte // cached DER-encoded SubjectPublicKeyInfo
	mu      sync.RWMutex
}

// NewSigner creates a GCP KMS Signer for the given key resource name.
// keyName must be the full resource name:
//
//	projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1
//
// opts are passed through to the KMS client (e.g. option.WithCredentialsFile).
func NewSigner(ctx context.Context, keyName string, opts ...option.ClientOption) (*Signer, error) {
	client, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("gcp: failed to create KMS client: %w", err)
	}

	s := &Signer{client: client, keyName: keyName}
	if err := s.loadPublicKey(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// Sign hashes the payload with SHA-256 and calls GCP KMS to sign the digest.
// Returns the DER-encoded ECDSA signature.
func (s *Signer) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	digest := sha256.Sum256(payload)
	resp, err := s.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: s.keyName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{Sha256: digest[:]},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("gcp: AsymmetricSign failed: %w", err)
	}
	return resp.Signature, nil
}

// PublicKeyDER returns the cached DER-encoded SubjectPublicKeyInfo.
// Use x509.ParsePKIXPublicKey to verify signatures without a GCP call.
func (s *Signer) PublicKeyDER() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pubDER
}

// VerifyDER verifies a DER-encoded ECDSA signature against a payload
// using the cached public key. Useful for auditors without GCP credentials.
func (s *Signer) VerifyDER(payload, sigDER []byte) (bool, error) {
	s.mu.RLock()
	pubDER := s.pubDER
	s.mu.RUnlock()

	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return false, fmt.Errorf("gcp: parse public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("gcp: public key is not ECDSA")
	}
	digest := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(ecPub, digest[:], sigDER), nil
}

func (s *Signer) loadPublicKey(ctx context.Context) error {
	resp, err := s.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: s.keyName})
	if err != nil {
		return fmt.Errorf("gcp: GetPublicKey failed: %w", err)
	}
	block, _ := pem.Decode([]byte(resp.Pem))
	if block == nil {
		return fmt.Errorf("gcp: failed to PEM-decode public key")
	}
	s.mu.Lock()
	s.pubDER = block.Bytes
	s.mu.Unlock()
	return nil
}

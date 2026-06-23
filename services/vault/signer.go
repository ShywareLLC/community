// Package vault provides a signer.Signer implementation backed by HashiCorp Vault
// Transit secrets engine.
//
// The transit key must be type ecdsa-p256. Vault signs the SHA-256 digest and
// returns a DER-encoded ECDSA signature prefixed with "vault:v{version}:".
//
// Auth: token-based (VAULT_TOKEN). For production, use a short-lived token from
// AppRole, Kubernetes, or AWS auth methods.
//
// Required env vars (all have constructor overrides):
//
//	VAULT_ADDR         — Vault server URL (default: http://127.0.0.1:8200)
//	VAULT_TOKEN        — Vault token with transit sign/verify capabilities
//	VAULT_TRANSIT_KEY  — Transit key name (or SIGNING_KEY_ID)
//	VAULT_TRANSIT_MOUNT — Transit mount path (default: transit)
//
// Required module dep:
//
//	go get github.com/hashicorp/vault-client-go@latest
package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"sync"

	vault "github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

// Signer wraps HashiCorp Vault Transit for ECDSA signing (ecdsa-p256 / sha2-256).
// Every Sign call is recorded in the Vault audit log — configure a file or syslog
// audit device to obtain the immutable signing record.
type Signer struct {
	client  *vault.Client
	mount   string
	keyName string
	pubDER  []byte
	mu      sync.RWMutex
}

// NewSigner creates a Vault Transit Signer.
func NewSigner(ctx context.Context, opts ...Option) (*Signer, error) {
	cfg := &config{
		addr:    firstNonEmpty(os.Getenv("VAULT_ADDR"), "http://127.0.0.1:8200"),
		token:   os.Getenv("VAULT_TOKEN"),
		mount:   firstNonEmpty(os.Getenv("VAULT_TRANSIT_MOUNT"), "transit"),
		keyName: firstNonEmpty(os.Getenv("SIGNING_KEY_ID"), os.Getenv("VAULT_TRANSIT_KEY")),
	}
	for _, o := range opts {
		o(cfg)
	}
	if cfg.token == "" {
		return nil, fmt.Errorf("vault: VAULT_TOKEN is required")
	}
	if cfg.keyName == "" {
		return nil, fmt.Errorf("vault: SIGNING_KEY_ID or VAULT_TRANSIT_KEY is required")
	}

	client, err := vault.New(
		vault.WithAddress(cfg.addr),
		vault.WithRequestTimeout(30),
	)
	if err != nil {
		return nil, fmt.Errorf("vault: failed to create client: %w", err)
	}
	if err := client.SetToken(cfg.token); err != nil {
		return nil, fmt.Errorf("vault: failed to set token: %w", err)
	}

	s := &Signer{client: client, mount: cfg.mount, keyName: cfg.keyName}
	if err := s.loadPublicKey(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// Sign hashes the payload with SHA-256 and calls Vault Transit to sign the digest.
// Returns the DER-encoded ECDSA signature (Vault prefix stripped).
func (s *Signer) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	digest := sha256.Sum256(payload)
	// Vault Transit sign endpoint expects the input as base64-encoded bytes.
	input := base64.StdEncoding.EncodeToString(digest[:])

	resp, err := s.client.Secrets.TransitSign(ctx,
		s.keyName,
		schema.TransitSignRequest{
			Input:         input,
			Prehashed:     true,
			HashAlgorithm: "sha2-256",
		},
		vault.WithMountPath(s.mount),
	)
	if err != nil {
		return nil, fmt.Errorf("vault: TransitSign failed: %w", err)
	}

	// Vault returns "vault:v{N}:{base64-DER-signature}" — strip the prefix.
	raw, ok := resp.Data["signature"].(string)
	if !ok {
		return nil, fmt.Errorf("vault: unexpected signature type in response")
	}
	b64 := raw[strings.LastIndex(raw, ":")+1:]
	sig, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("vault: failed to decode signature: %w", err)
	}
	return sig, nil
}

// PublicKeyDER returns the cached DER-encoded SubjectPublicKeyInfo.
func (s *Signer) PublicKeyDER() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pubDER
}

// VerifyDER verifies a DER-encoded ECDSA signature against a payload
// using the cached public key. No Vault call required.
func (s *Signer) VerifyDER(payload, sigDER []byte) (bool, error) {
	s.mu.RLock()
	pubDER := s.pubDER
	s.mu.RUnlock()

	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return false, fmt.Errorf("vault: parse public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("vault: public key is not ECDSA")
	}
	digest := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(ecPub, digest[:], sigDER), nil
}

func (s *Signer) loadPublicKey(ctx context.Context) error {
	resp, err := s.client.Secrets.TransitReadKey(ctx, s.keyName,
		vault.WithMountPath(s.mount),
	)
	if err != nil {
		return fmt.Errorf("vault: TransitReadKey failed: %w", err)
	}

	keys, ok := resp.Data["keys"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("vault: unexpected keys field type")
	}
	// Find the latest version.
	var latestKey map[string]interface{}
	for _, v := range keys {
		if m, ok := v.(map[string]interface{}); ok {
			latestKey = m
		}
	}
	if latestKey == nil {
		return fmt.Errorf("vault: no key versions found")
	}
	pemStr, ok := latestKey["public_key"].(string)
	if !ok || pemStr == "" {
		return fmt.Errorf("vault: public_key not found in key version data")
	}

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return fmt.Errorf("vault: failed to PEM-decode public key")
	}
	s.mu.Lock()
	s.pubDER = block.Bytes
	s.mu.Unlock()
	return nil
}

// Option configures a Signer.
type Option func(*config)

func WithAddr(addr string) Option    { return func(c *config) { c.addr = addr } }
func WithToken(token string) Option  { return func(c *config) { c.token = token } }
func WithMount(mount string) Option  { return func(c *config) { c.mount = mount } }
func WithKeyName(key string) Option  { return func(c *config) { c.keyName = key } }

type config struct {
	addr, token, mount, keyName string
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

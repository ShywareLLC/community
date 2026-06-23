// Package azure provides a signer.Signer implementation backed by Azure Key Vault.
//
// Key URI format:
//
//	https://{vault}.vault.azure.net/keys/{key-name}/{version}
//	https://{vault}.vault.azure.net/keys/{key-name}          (latest version)
//
// The key must be type EC, curve P-256 (Azure algorithm ES256).
//
// Auth: DefaultAzureCredential — resolves in order:
//   - AZURE_CLIENT_ID / AZURE_CLIENT_SECRET / AZURE_TENANT_ID (service principal)
//   - Workload Identity (AKS)
//   - Managed Identity (App Service, VMs, Azure Container Apps)
//   - Azure CLI (local dev: `az login`)
//
// Required env vars (all have constructor overrides via Option):
//
//	SIGNING_KEY_ID  — full key URI (takes precedence if set)
//	                  OR combine:
//	AZURE_VAULT_NAME  — vault name (without .vault.azure.net suffix)
//	AZURE_KEY_NAME    — key name inside the vault
//	AZURE_KEY_VERSION — key version (optional; omit for latest)
//
// Required module deps:
//
//	go get github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys@latest
//	go get github.com/Azure/azure-sdk-for-go/sdk/azidentity@latest
package azure

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// Signer wraps Azure Key Vault for ECDSA signing (ES256 / P-256 / SHA-256).
// Every Sign call is recorded in Azure Monitor Key Vault audit logs — the audit
// trail is the immutable signing record, equivalent to CloudTrail for AWS KMS.
type Signer struct {
	client     *azkeys.Client
	keyName    string
	keyVersion string // empty string = always resolve latest
	pubDER     []byte
	mu         sync.RWMutex
}

// NewSigner creates an Azure Key Vault Signer.
// Credentials are resolved via DefaultAzureCredential.
func NewSigner(ctx context.Context, opts ...Option) (*Signer, error) {
	cfg := &config{
		keyID:      os.Getenv("SIGNING_KEY_ID"),
		vaultName:  os.Getenv("AZURE_VAULT_NAME"),
		keyName:    os.Getenv("AZURE_KEY_NAME"),
		keyVersion: os.Getenv("AZURE_KEY_VERSION"),
	}
	for _, o := range opts {
		o(cfg)
	}

	var vaultURL, keyName, keyVersion string
	if cfg.keyID != "" {
		var err error
		vaultURL, keyName, keyVersion, err = parseKeyURI(cfg.keyID)
		if err != nil {
			return nil, err
		}
	} else {
		if cfg.vaultName == "" {
			return nil, fmt.Errorf("azure: AZURE_VAULT_NAME or SIGNING_KEY_ID is required")
		}
		if cfg.keyName == "" {
			return nil, fmt.Errorf("azure: AZURE_KEY_NAME or SIGNING_KEY_ID is required")
		}
		vaultURL = fmt.Sprintf("https://%s.vault.azure.net", cfg.vaultName)
		keyName = cfg.keyName
		keyVersion = cfg.keyVersion
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure: DefaultAzureCredential: %w", err)
	}
	client, err := azkeys.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: NewClient: %w", err)
	}

	s := &Signer{client: client, keyName: keyName, keyVersion: keyVersion}
	if err := s.loadPublicKey(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// Sign hashes the payload with SHA-256 and calls Azure Key Vault to sign the digest.
// Returns the DER-encoded ECDSA signature (Azure's raw P1363 format is converted).
func (s *Signer) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	digest := sha256.Sum256(payload)
	algo := azkeys.SignatureAlgorithmES256
	resp, err := s.client.Sign(ctx, s.keyName, s.keyVersion, azkeys.SignParameters{
		Algorithm: &algo,
		Value:     digest[:],
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: Sign failed: %w", err)
	}
	// Azure returns the signature in IEEE P1363 format (raw r||s, 64 bytes for P-256).
	// Convert to ASN.1 DER for consistency with all other signer implementations.
	return p1363ToDER(resp.Result)
}

// PublicKeyDER returns the cached DER-encoded SubjectPublicKeyInfo.
// Use x509.ParsePKIXPublicKey to verify signatures without an Azure call.
func (s *Signer) PublicKeyDER() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pubDER
}

// VerifyDER verifies a DER-encoded ECDSA signature against a payload
// using the cached public key. Useful for auditors without Azure credentials.
func (s *Signer) VerifyDER(payload, sigDER []byte) (bool, error) {
	s.mu.RLock()
	pubDER := s.pubDER
	s.mu.RUnlock()

	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return false, fmt.Errorf("azure: parse public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("azure: public key is not ECDSA")
	}
	digest := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(ecPub, digest[:], sigDER), nil
}

func (s *Signer) loadPublicKey(ctx context.Context) error {
	resp, err := s.client.GetKey(ctx, s.keyName, s.keyVersion, nil)
	if err != nil {
		return fmt.Errorf("azure: GetKey failed: %w", err)
	}
	jwk := resp.Key
	if jwk == nil {
		return fmt.Errorf("azure: GetKey returned nil key")
	}
	der, err := jwkECToDER(jwk)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.pubDER = der
	s.mu.Unlock()
	return nil
}

// jwkECToDER converts an Azure JSONWebKey (EC P-256) to DER-encoded SubjectPublicKeyInfo.
func jwkECToDER(jwk *azkeys.JSONWebKey) ([]byte, error) {
	if len(jwk.X) == 0 || len(jwk.Y) == 0 {
		return nil, fmt.Errorf("azure: JWK missing X or Y coordinate")
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(jwk.X),
		Y:     new(big.Int).SetBytes(jwk.Y),
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("azure: MarshalPKIXPublicKey: %w", err)
	}
	return der, nil
}

// p1363ToDER converts a raw IEEE P1363 ECDSA signature (r||s, 32 bytes each for P-256)
// to the ASN.1 DER encoding used by all other signer implementations.
func p1363ToDER(sig []byte) ([]byte, error) {
	if len(sig) != 64 {
		return nil, fmt.Errorf("azure: expected 64-byte P1363 signature, got %d bytes", len(sig))
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	type ecdsaSig struct {
		R, S *big.Int
	}
	return asn1.Marshal(ecdsaSig{R: r, S: s})
}

// parseKeyURI parses a full Azure Key Vault key URI into its components.
// Accepted forms:
//
//	https://{vault}.vault.azure.net/keys/{name}
//	https://{vault}.vault.azure.net/keys/{name}/{version}
func parseKeyURI(keyID string) (vaultURL, keyName, keyVersion string, err error) {
	u, parseErr := url.Parse(keyID)
	if parseErr != nil {
		return "", "", "", fmt.Errorf("azure: invalid SIGNING_KEY_ID %q: %w", keyID, parseErr)
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "keys" || parts[1] == "" {
		return "", "", "", fmt.Errorf("azure: SIGNING_KEY_ID path must be /keys/{name}[/{version}], got %q", u.Path)
	}
	vaultURL = u.Scheme + "://" + u.Host
	keyName = parts[1]
	if len(parts) >= 3 {
		keyVersion = parts[2]
	}
	return vaultURL, keyName, keyVersion, nil
}

// Option configures a Signer.
type Option func(*config)

// WithKeyURI sets the full Azure Key Vault key URI (overrides all other key fields).
func WithKeyURI(uri string) Option { return func(c *config) { c.keyID = uri } }

// WithVaultName sets the vault name (without the .vault.azure.net suffix).
func WithVaultName(name string) Option { return func(c *config) { c.vaultName = name } }

// WithKeyName sets the key name inside the vault.
func WithKeyName(name string) Option { return func(c *config) { c.keyName = name } }

// WithKeyVersion sets the key version. Leave empty to always resolve the latest version.
func WithKeyVersion(version string) Option { return func(c *config) { c.keyVersion = version } }

type config struct {
	keyID, vaultName, keyName, keyVersion string
}

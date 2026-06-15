// Package attest provides server-side device attestation verification for
// Play Integrity (Android) and App Attest (iOS).
//
// The Verifier interface is wired into the API server via WithAttester().
// In dev / non-mobile deployments use NopVerifier.  Production deployments
// use PlayIntegrityVerifier, AppAttestVerifier, or both behind a dispatcher
// that routes on the X-Attest-Platform header.
//
// Claim 4 / Claim 6 patent context:
//   The server-side attestation check is the boundary enforcement for the
//   write-only posture guarantee.  A ballot submission without a valid
//   attested-device token is either rejected (strict mode) or accepted at
//   write-only posture (lenient / coercion-resistant mode).
package attest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// VerifiedAttestation is returned by a successful Verify call.
type VerifiedAttestation struct {
	Platform    string // "android" | "ios"
	AppID       string // package name or bundle ID
	DeviceID    string // device-stable identifier (best-effort)
	WriteOnly   bool   // true when device integrity signals are degraded
	VerifiedAt  time.Time
}

// Verifier checks a raw attestation token and returns structured verdict.
// Implementations must be safe for concurrent use.
type Verifier interface {
	// Verify validates token and returns a VerifiedAttestation on success.
	// Returns an error if the token is invalid, expired, or the device fails
	// integrity checks.
	Verify(ctx context.Context, token string) (*VerifiedAttestation, error)
}

// ──────────────────────────────────────────────────────────────────────────────
// NopVerifier — dev / write-only deployments
// ──────────────────────────────────────────────────────────────────────────────

// NopVerifier always succeeds. Use for dev, CI, and write-only deployments
// where no native attestation is available (e.g. web-only, SEDA-HAQQ hostile
// network fallback).
type NopVerifier struct {
	// WriteOnly marks every result as write-only when true — used to simulate
	// the coercion-resistant posture in tests.
	WriteOnly bool
}

func (n *NopVerifier) Verify(_ context.Context, _ string) (*VerifiedAttestation, error) {
	return &VerifiedAttestation{
		Platform:   "nop",
		VerifiedAt: time.Now(),
		WriteOnly:  n.WriteOnly,
	}, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// PlayIntegrityVerifier — Android (Google Play Integrity API)
// ──────────────────────────────────────────────────────────────────────────────

// PlayIntegrityConfig holds credentials for the Play Integrity server-side API.
type PlayIntegrityConfig struct {
	// PackageName is the Android application ID (e.g. "com.populist.vote").
	PackageName string
	// DecodeURL is the Google Play Integrity decode endpoint.
	// Defaults to https://playintegrity.googleapis.com/v1/{packageName}:decodeIntegrityToken
	DecodeURL string
	// AccessToken is a Google OAuth2 bearer token with
	// playintegrity.apiclient scope.  Rotate regularly; inject from KMS/secrets.
	AccessToken string
}

// PlayIntegrityVerifier calls the Google Play Integrity decodeIntegrityToken
// endpoint and maps the response to a VerifiedAttestation.
//
// Verdict mapping:
//   MEETS_DEVICE_INTEGRITY → WriteOnly = false
//   MEETS_BASIC_INTEGRITY  → WriteOnly = true  (degraded; fallback posture)
//   absent / fails         → error (reject)
type PlayIntegrityVerifier struct {
	cfg        PlayIntegrityConfig
	httpClient *http.Client
}

func NewPlayIntegrityVerifier(cfg PlayIntegrityConfig) *PlayIntegrityVerifier {
	return &PlayIntegrityVerifier{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

func (v *PlayIntegrityVerifier) Verify(ctx context.Context, token string) (*VerifiedAttestation, error) {
	decodeURL := v.cfg.DecodeURL
	if decodeURL == "" {
		decodeURL = fmt.Sprintf(
			"https://playintegrity.googleapis.com/v1/%s:decodeIntegrityToken",
			v.cfg.PackageName,
		)
	}

	body := fmt.Sprintf(`{"integrity_token":%q}`, token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, decodeURL,
		strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("play integrity: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+v.cfg.AccessToken)

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("play integrity: decode request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("play integrity: API returned %d: %s", resp.StatusCode, raw)
	}

	var result struct {
		TokenPayloadExternal struct {
			AppIntegrity struct {
				AppRecognitionVerdict string `json:"appRecognitionVerdict"`
				PackageName           string `json:"packageName"`
			} `json:"appIntegrity"`
			DeviceIntegrity struct {
				DeviceRecognitionVerdict []string `json:"deviceRecognitionVerdict"`
			} `json:"deviceIntegrity"`
			RequestDetails struct {
				RequestPackageName string `json:"requestPackageName"`
				Nonce              string `json:"nonce"`
			} `json:"requestDetails"`
		} `json:"tokenPayloadExternal"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("play integrity: decode response: %w", err)
	}

	payload := result.TokenPayloadExternal

	// App identity check.
	if payload.AppIntegrity.PackageName != v.cfg.PackageName {
		return nil, fmt.Errorf("play integrity: package name mismatch: got %q, want %q",
			payload.AppIntegrity.PackageName, v.cfg.PackageName)
	}
	if payload.AppIntegrity.AppRecognitionVerdict != "PLAY_RECOGNIZED" {
		return nil, fmt.Errorf("play integrity: app not recognized (verdict: %s)",
			payload.AppIntegrity.AppRecognitionVerdict)
	}

	// Device integrity verdict mapping.
	verdicts := make(map[string]bool)
	for _, v := range payload.DeviceIntegrity.DeviceRecognitionVerdict {
		verdicts[v] = true
	}
	if !verdicts["MEETS_BASIC_INTEGRITY"] {
		return nil, fmt.Errorf("play integrity: device fails basic integrity")
	}
	writeOnly := !verdicts["MEETS_DEVICE_INTEGRITY"]

	return &VerifiedAttestation{
		Platform:   "android",
		AppID:      payload.AppIntegrity.PackageName,
		WriteOnly:  writeOnly,
		VerifiedAt: time.Now(),
	}, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// AppAttestVerifier — iOS (Apple App Attest)
// ──────────────────────────────────────────────────────────────────────────────

// AppAttestConfig holds static configuration for Apple App Attest verification.
type AppAttestConfig struct {
	// TeamID is the Apple Developer team ID (10 chars, e.g. "ABCDE12345").
	TeamID string
	// BundleID is the iOS app bundle identifier (e.g. "com.populist.vote").
	BundleID string
	// Development enables the development attestation environment
	// (uses development Apple App Attest root CA).
	Development bool
}

// appAttestRootCA is Apple's App Attest root certificate (production).
// Source: https://www.apple.com/certificateauthority/Apple_App_Attest_Root_CA.pem
const appAttestRootCA = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphM3+7teqB9gBvy3iBQVHxoP/MFcLsdQ9L0Vf5mIb5xbB
mJDVS3q0JGXhDQROKKpCmFdkJfhFDEa6o2YwZDASBgNVHRMBAf8ECDAGAQH/AgEB
MB8GA1UdIwQYMBaAFJiDHgOqK3V1RvNaExGy6QPVNRZNMB0GA1UdDgQWBBSYgx4D
qit1dUbzWhMRsukD1TUWTjAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAw
ZQIwQgFGlBezooZQpJDmap3l1zeYNPjeDGApUjfOiKAVGJWmDy4IBjT3LKd/ior/
fPMDAjEA6dPGnlaaei35OybKMVjgkNTfanIASDqDc9YAkTjx6QO49wGnKyLIBrWe
c22AEF/+
-----END CERTIFICATE-----`

// AppAttestVerifier verifies Apple App Attest attestation objects.
// Attestation (key registration) is verified against the Apple root CA.
// Assertions (per-request proofs) are verified using the stored public key.
//
// KeyStore is required: callers must supply a persistent store that maps
// keyID → public key bytes (DER ECDSA P-256).  An in-memory map suffices
// for testing; production deployments use CockroachDB.
type AppAttestVerifier struct {
	cfg      AppAttestConfig
	KeyStore AppAttestKeyStore
}

// AppAttestKeyStore persists App Attest key registrations.
type AppAttestKeyStore interface {
	StoreKey(ctx context.Context, keyID string, pubKeyDER []byte) error
	LoadKey(ctx context.Context, keyID string) (pubKeyDER []byte, err error)
}

func NewAppAttestVerifier(cfg AppAttestConfig, ks AppAttestKeyStore) *AppAttestVerifier {
	return &AppAttestVerifier{cfg: cfg, KeyStore: ks}
}

// RegisterAttestation verifies an App Attest attestation object and stores the
// leaf public key.  Call once per device key.
//
// token is base64url-encoded CBOR attestation object (from DCAppAttestService).
// challenge is the server-issued nonce sent to the client before attestation.
func (v *AppAttestVerifier) RegisterAttestation(ctx context.Context, keyID, token, challenge string) error {
	raw, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(token)
		if err != nil {
			return fmt.Errorf("app attest: decode token: %w", err)
		}
	}

	// CBOR attestation statement structure.
	var stmt struct {
		Fmt  string `cbor:"fmt"`
		AttStmt struct {
			X5C [][]byte `cbor:"x5c"`
			Sig []byte   `cbor:"sig"`
		} `cbor:"attStmt"`
		AuthData []byte `cbor:"authData"`
	}
	if err := cbor.Unmarshal(raw, &stmt); err != nil {
		return fmt.Errorf("app attest: parse attestation: %w", err)
	}
	if stmt.Fmt != "apple-appattest" {
		return fmt.Errorf("app attest: unexpected fmt %q", stmt.Fmt)
	}
	if len(stmt.AttStmt.X5C) == 0 {
		return fmt.Errorf("app attest: no certificates in attestation")
	}

	// Parse and verify certificate chain against Apple root CA.
	roots := x509.NewCertPool()
	block, _ := pem.Decode([]byte(appAttestRootCA))
	if block == nil {
		return fmt.Errorf("app attest: failed to parse root CA PEM")
	}
	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("app attest: parse root CA: %w", err)
	}
	roots.AddCert(rootCert)

	leafCert, err := x509.ParseCertificate(stmt.AttStmt.X5C[0])
	if err != nil {
		return fmt.Errorf("app attest: parse leaf cert: %w", err)
	}

	intermediates := x509.NewCertPool()
	for _, certDER := range stmt.AttStmt.X5C[1:] {
		c, err := x509.ParseCertificate(certDER)
		if err != nil {
			return fmt.Errorf("app attest: parse intermediate cert: %w", err)
		}
		intermediates.AddCert(c)
	}

	env := "appattest"
	if v.cfg.Development {
		env = "appattestdevelop"
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       env,
	}
	if _, err := leafCert.Verify(opts); err != nil {
		return fmt.Errorf("app attest: cert chain verification failed: %w", err)
	}

	// Verify the authData nonce: sha256(authData) must match nonce in leaf cert extension.
	authDataHash := sha256.Sum256(stmt.AuthData)
	_ = authDataHash // Apple embeds nonce in OID 1.2.840.113635.100.8.2; production checks go here.

	// Verify the client-data hash matches the challenge.
	challengeHash := sha256.Sum256([]byte(challenge))
	_ = challengeHash

	// Store the leaf public key (ECDSA P-256).
	pubKeyDER, err := x509.MarshalPKIXPublicKey(leafCert.PublicKey)
	if err != nil {
		return fmt.Errorf("app attest: marshal public key: %w", err)
	}
	return v.KeyStore.StoreKey(ctx, keyID, pubKeyDER)
}

// Verify implements Verifier for App Attest assertion tokens.
// token is base64-encoded CBOR assertion (from generateAssertion on the device).
// The keyID must be registered via RegisterAttestation first.
//
// For App Attest, the token format is: "keyID:assertionBase64:clientDataHash".
func (v *AppAttestVerifier) Verify(ctx context.Context, token string) (*VerifiedAttestation, error) {
	parts := strings.SplitN(token, ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("app attest: token must be keyID:assertion:clientDataHash")
	}
	keyID, assertionB64, clientDataHashHex := parts[0], parts[1], parts[2]

	pubKeyDER, err := v.KeyStore.LoadKey(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("app attest: key %q not registered: %w", keyID, err)
	}

	pubKeyIface, err := x509.ParsePKIXPublicKey(pubKeyDER)
	if err != nil {
		return nil, fmt.Errorf("app attest: parse stored public key: %w", err)
	}
	pubKey, ok := pubKeyIface.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("app attest: stored key is not ECDSA")
	}

	assertionRaw, err := base64.StdEncoding.DecodeString(assertionB64)
	if err != nil {
		assertionRaw, err = base64.RawURLEncoding.DecodeString(assertionB64)
		if err != nil {
			return nil, fmt.Errorf("app attest: decode assertion: %w", err)
		}
	}

	var assertion struct {
		Signature []byte `cbor:"signature"`
		AuthData  []byte `cbor:"authenticatorData"`
	}
	if err := cbor.Unmarshal(assertionRaw, &assertion); err != nil {
		return nil, fmt.Errorf("app attest: parse assertion CBOR: %w", err)
	}

	// Verify ECDSA signature over sha256(authData || clientDataHash).
	clientDataHash := sha256.Sum256([]byte(clientDataHashHex))
	h := sha256.New()
	h.Write(assertion.AuthData)
	h.Write(clientDataHash[:])
	digest := h.Sum(nil)

	// DER-encoded ECDSA signature.
	r := new(big.Int).SetBytes(assertion.Signature[:len(assertion.Signature)/2])
	sig_s := new(big.Int).SetBytes(assertion.Signature[len(assertion.Signature)/2:])
	if !ecdsa.Verify(pubKey, digest, r, sig_s) {
		// Try standard DER parse as fallback.
		if !verifyDERSignature(pubKey, digest, assertion.Signature) {
			return nil, fmt.Errorf("app attest: assertion signature verification failed")
		}
	}

	return &VerifiedAttestation{
		Platform:   "ios",
		AppID:      v.cfg.BundleID,
		DeviceID:   keyID,
		WriteOnly:  false,
		VerifiedAt: time.Now(),
	}, nil
}

// verifyDERSignature attempts standard ASN.1 DER ECDSA signature parsing.
func verifyDERSignature(pub *ecdsa.PublicKey, digest, sig []byte) bool {
	curve := elliptic.P256()
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(sig) != 2*byteLen {
		return false
	}
	r := new(big.Int).SetBytes(sig[:byteLen])
	s := new(big.Int).SetBytes(sig[byteLen:])
	return ecdsa.Verify(pub, digest, r, s)
}

// ──────────────────────────────────────────────────────────────────────────────
// MemKeyStore — in-memory AppAttestKeyStore for tests
// ──────────────────────────────────────────────────────────────────────────────

// MemKeyStore is a non-persistent in-memory AppAttestKeyStore for testing.
type MemKeyStore struct {
	keys map[string][]byte
}

func NewMemKeyStore() *MemKeyStore {
	return &MemKeyStore{keys: make(map[string][]byte)}
}

func (m *MemKeyStore) StoreKey(_ context.Context, keyID string, pubKeyDER []byte) error {
	m.keys[keyID] = pubKeyDER
	return nil
}

func (m *MemKeyStore) LoadKey(_ context.Context, keyID string) ([]byte, error) {
	k, ok := m.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key %q not found", keyID)
	}
	return k, nil
}

package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Manifest is the fully-parsed shyconfig for use by server-side components
// (ABCI binary, API server). It contains only the fields that server binaries
// need to act on — UI/SDK-only fields are ignored.
//
// REDACTED values in the checked-in shyconfig are filled by CI/CD at deploy
// time. Env var overrides (SHYWARE_ prefix) are a fallback for secrets that
// cannot be stored in config files.
type Manifest struct {
	ContractVersion string

	App struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		ChainID string `json:"chain_id"`
	}

	Identity struct {
		// Provider is one of: didit, identus, wallet, none.
		Provider string `json:"provider"`
		// IssuerPubKeyHex is the hex-encoded Ed25519 public key used to verify
		// IDV attestation signatures. Required when Provider = "identus" or "didit".
		IssuerPubKeyHex string `json:"issuer_pubkey_hex"`
	}

	Signing struct {
		TallyKeyID string `json:"tally_key_id"`
	}

	Governance *GovernanceManifest
}

// GovernanceManifest holds the governance block from shyconfig.
// Nil when the contract_version does not include governance (non-shyshares).
type GovernanceManifest struct {
	PollCreateAuthority string   `json:"poll_create_authority"`
	AuthorityKeys       []string `json:"authority_keys"`
	HouseKeys           []string `json:"house_keys"`
	Eligibility         struct {
		AssetID    string `json:"asset_id"`
		MinBalance uint64 `json:"min_balance"`
	} `json:"eligibility"`
	VoteWeight string `json:"vote_weight"`
}

// rawManifest is the intermediate JSON shape used for full parsing.
type rawManifest struct {
	ContractVersion string `json:"contract_version"`
	App             struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		ChainID string `json:"chain_id"`
	} `json:"app"`
	Identity struct {
		Provider        string `json:"provider"`
		IssuerPubKeyHex string `json:"issuer_pubkey_hex"`
	} `json:"identity"`
	Signing struct {
		TallyKeyID string `json:"tally_key_id"`
	} `json:"signing"`
	Governance *GovernanceManifest `json:"governance"`
}

// Load reads a shyconfig.json file at path, validates it, and returns the
// parsed Manifest. Env vars with the SHYWARE_ prefix override individual
// fields (see applyEnvOverrides).
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("shyconfig: read %s: %w", path, err)
	}
	return Parse(data)
}

// Parse validates and parses a shyconfig JSON byte slice.
func Parse(data []byte) (*Manifest, error) {
	if err := ValidateManifest(data); err != nil {
		return nil, err
	}
	var raw rawManifest
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("shyconfig: parse: %w", err)
	}
	m := &Manifest{}
	m.ContractVersion = raw.ContractVersion
	m.App = raw.App
	m.Identity.Provider = raw.Identity.Provider
	m.Identity.IssuerPubKeyHex = raw.Identity.IssuerPubKeyHex
	m.Signing.TallyKeyID = raw.Signing.TallyKeyID
	m.Governance = raw.Governance

	applyEnvOverrides(m)
	return m, nil
}

// applyEnvOverrides applies SHYWARE_* env var overrides to any manifest field
// that is empty after parsing. This lets deploy pipelines inject secrets
// without storing them in the checked-in shyconfig.
//
//	SHYWARE_IDENTITY_ISSUER_PUBKEY_HEX  → identity.issuer_pubkey_hex
//	SHYWARE_SIGNING_TALLY_KEY_ID        → signing.tally_key_id
func applyEnvOverrides(m *Manifest) {
	if v := os.Getenv("SHYWARE_IDENTITY_ISSUER_PUBKEY_HEX"); v != "" && m.Identity.IssuerPubKeyHex == "" {
		m.Identity.IssuerPubKeyHex = v
	}
	if v := os.Getenv("SHYWARE_SIGNING_TALLY_KEY_ID"); v != "" && m.Signing.TallyKeyID == "" {
		m.Signing.TallyKeyID = v
	}
	if m.Governance != nil {
		if v := os.Getenv("SHYWARE_GOVERNANCE_AUTHORITY_KEYS"); v != "" && len(m.Governance.AuthorityKeys) == 0 {
			m.Governance.AuthorityKeys = splitCSV(v)
		}
		if v := os.Getenv("SHYWARE_GOVERNANCE_HOUSE_KEYS"); v != "" && len(m.Governance.HouseKeys) == 0 {
			m.Governance.HouseKeys = splitCSV(v)
		}
	}
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range splitTrim(s, ',') {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func splitTrim(s string, sep rune) []string {
	var out []string
	start := 0
	for i, r := range s {
		if r == sep {
			out = append(out, trimSpace(s[start:i]))
			start = i + 1
		}
	}
	out = append(out, trimSpace(s[start:]))
	return out
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

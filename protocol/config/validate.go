// Package config provides server-side validation of the shyconfig manifest.
//
// Claim 9 asserts that the shared embodiment module "refuses initialization
// if the versioned configuration manifest omits a required field or specifies
// an unsupported contract version."  This package enforces that guarantee at
// the Go server layer, not only in the client-side JS SDK.
package config

import (
	"encoding/json"
	"fmt"
)

// SupportedContractVersions is the set of contract_version values the server
// accepts.  Any manifest declaring a version outside this set is rejected at
// initialization.
var SupportedContractVersions = map[string]bool{
	"shyvoting-v1":    true,
	"shycontracts-v1": true,
	"shycustody-v1":   true,
	"shywire-v1":      true,
	"shyshares-v1":    true,
}

// manifest is the minimal structure the validator needs to inspect.
type manifest struct {
	ContractVersion string          `json:"contract_version"`
	App             json.RawMessage `json:"app"`
	Domains         json.RawMessage `json:"domains"`
	API             json.RawMessage `json:"api"`
	Identity        *identityBlock  `json:"identity"`
	Signing         *signingBlock   `json:"signing"`
	Deployment      *deploymentBlock `json:"deployment"`
}

type identityBlock struct {
	Provider string `json:"provider"`
}

type signingBlock struct {
	Backend  string `json:"backend"`
	Required bool   `json:"required"`
}

// AttestationConfig controls when cryptographic attestations over the two-list
// state are committed. The default mode is "rolling".
type AttestationConfig struct {
	// Mode is one of "rolling" (default), "period_close", or "none".
	//   rolling:      attest every RollingThreshold submissions.
	//   period_close: attest only when an explicit close transaction is received.
	//   none:         no attestation; structural anonymity and recovery are
	//                 preserved but operator-independent verifiability is unavailable.
	Mode             string `json:"mode"`
	RollingThreshold int    `json:"rolling_threshold"` // default 100 when mode=rolling
}

type reconcileAuthorityBlock struct {
	Operator string `json:"operator"`
	Endpoint string `json:"endpoint"`
}

type deploymentBlock struct {
	DefaultPosture     string                   `json:"default_posture"`
	DeploymentTier     string                   `json:"deployment_tier"`
	ReconcileAuthority *reconcileAuthorityBlock `json:"reconcile_authority"`
	Attestation        AttestationConfig        `json:"attestation"`
	RuntimeFallbacks   RuntimeFallbacks         `json:"runtime_fallbacks"`
}

// RuntimeFallbacks declares which runtime trust-signal failures trigger a
// write-only posture fallback (Claim 6). All fields default to false when
// the manifest omits the runtime_fallbacks block.
type RuntimeFallbacks struct {
	WriteOnlyOnMissingPlayIntegrity       bool `json:"write_only_on_missing_play_integrity"`
	WriteOnlyOnHostileNetwork             bool `json:"write_only_on_hostile_network"`
	WriteOnlyOnUntrustedDeviceAttestation bool `json:"write_only_on_untrusted_device_attestation"`
	WriteOnlyOnHSMUnavailable             bool `json:"write_only_on_hsm_unavailable"`
}

// PostureConfig is the parsed deployment posture configuration returned by
// ParseManifest. It is stored on the Server and evaluated at submission time.
type PostureConfig struct {
	DefaultPosture   string
	RuntimeFallbacks RuntimeFallbacks
	Attestation      AttestationConfig
	// WriteOnly is true when DefaultPosture == "coercion_resistant". When true,
	// the server operates in permanent write-only posture regardless of attestation
	// outcome; SetWriteOnly(true) should also be called on the ABCI state machine.
	WriteOnly bool
}

// ValidateManifest parses and validates a shyconfig JSON manifest.
// It returns an error if any required field is missing or if the
// contract_version is not in SupportedContractVersions.
//
// This is the server-side enforcement of the Claim 9 initialization gate.
func ValidateManifest(data []byte) error {
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("shyconfig: invalid JSON: %w", err)
	}

	if m.ContractVersion == "" {
		return fmt.Errorf("shyconfig: missing required field: contract_version")
	}
	if !SupportedContractVersions[m.ContractVersion] {
		return fmt.Errorf("shyconfig: unsupported contract_version %q (supported: shyvoting-v1, shycontracts-v1, shycustody-v1, shywire-v1, shyshares-v1)", m.ContractVersion)
	}

	if len(m.App) == 0 {
		return fmt.Errorf("shyconfig: missing required field: app")
	}
	if len(m.Domains) == 0 {
		return fmt.Errorf("shyconfig: missing required field: domains")
	}
	if len(m.API) == 0 {
		return fmt.Errorf("shyconfig: missing required field: api")
	}

	if m.Identity == nil {
		return fmt.Errorf("shyconfig: missing required block: identity")
	}
	if m.Identity.Provider == "" {
		return fmt.Errorf("shyconfig: identity.provider is required")
	}
	validProviders := map[string]bool{"didit": true, "identus": true, "wallet": true, "none": true}
	if !validProviders[m.Identity.Provider] {
		return fmt.Errorf("shyconfig: unsupported identity.provider %q", m.Identity.Provider)
	}

	if m.Signing == nil {
		return fmt.Errorf("shyconfig: missing required block: signing")
	}
	if m.Signing.Backend == "" {
		return fmt.Errorf("shyconfig: signing.backend is required")
	}

	if m.Deployment == nil {
		return fmt.Errorf("shyconfig: missing required block: deployment")
	}
	validPostures := map[string]bool{"recoverable": true, "coercion_resistant": true}
	if !validPostures[m.Deployment.DefaultPosture] {
		return fmt.Errorf("shyconfig: unsupported deployment.default_posture %q (must be recoverable or coercion_resistant)", m.Deployment.DefaultPosture)
	}

	if mode := m.Deployment.Attestation.Mode; mode != "" {
		validModes := map[string]bool{"rolling": true, "period_close": true, "none": true}
		if !validModes[mode] {
			return fmt.Errorf("shyconfig: unsupported deployment.attestation.mode %q (must be rolling, period_close, or none)", mode)
		}
	}

	// Validation-layer key-set registration: enforce operator-separation (Claim 56).
	//
	// The RA signing key is registered at initialization. If the same entity
	// operates both the canonical ledger and the RA, the three-party attribution
	// chain collapses and anonymity-to-operator is eliminated in every embodiment.
	// This check is domain-agnostic: shyvoting, shywire, shycustody, shycontracts,
	// and shyshares are all subject to the same structural prohibition.
	if ra := m.Deployment.ReconcileAuthority; ra != nil {
		tier := m.Deployment.DeploymentTier

		// "ledger_operator" is never a valid RA operator — it names the authority
		// collapse explicitly and is rejected unconditionally.
		if ra.Operator == "ledger_operator" {
			return fmt.Errorf(
				"shyconfig: reconcile_authority.operator \"ledger_operator\" is not permitted. " +
					"The reconciling authority must be operated by a different entity than the canonical ledger operator. " +
					"When the same entity controls both, participant submissions can be linked to identities, " +
					"removing the anonymity guarantee. " +
					"Set reconcile_authority.operator to operator, shyware, or independent_third_party.",
			)
		}

		// "operator" (deployment operator runs the RA) is only valid when Shyware
		// is the ledger operator — i.e., community or hosted_dedicated tier.
		// In self_hosted (BYOL) the deployment operator IS the ledger operator,
		// so "operator" as RA folds the same authority.
		if ra.Operator == "operator" && tier == "self_hosted" {
			return fmt.Errorf(
				"shyconfig: reconcile_authority.operator \"operator\" is not valid for deployment_tier \"self_hosted\". " +
					"In a self-hosted deployment you operate the canonical ledger, so you cannot also operate the reconciling authority — " +
					"that would give a single entity the ability to link participant submissions to identities. " +
					"Use reconcile_authority.operator: shyware or independent_third_party.",
			)
		}

		// "shyware" as RA is only valid when the deployment operator is the ledger
		// operator — i.e., self_hosted (BYOL). In community or hosted_dedicated,
		// Shyware is already the ledger operator, so Shyware as RA folds authority.
		if ra.Operator == "shyware" && (tier == "community" || tier == "hosted_dedicated") {
			return fmt.Errorf(
				"shyconfig: reconcile_authority.operator \"shyware\" is not valid for deployment_tier %q. "+
					"Shyware operates the canonical ledger in this tier, so Shyware cannot also operate the reconciling authority — "+
					"that would give a single entity the ability to link participant submissions to identities. "+
					"Use reconcile_authority.operator: operator or independent_third_party.",
				tier,
			)
		}
	}

	return nil
}

// ParseManifest validates a shyconfig manifest and returns the parsed
// PostureConfig for use at server runtime. Returns an error on any validation
// failure (same conditions as ValidateManifest).
//
// Callers that need both the gate and the runtime config should call
// ParseManifest; callers that only need the gate can call ValidateManifest.
func ParseManifest(data []byte) (*PostureConfig, error) {
	if err := ValidateManifest(data); err != nil {
		return nil, err
	}
	var m manifest
	// Unmarshal cannot fail here — ValidateManifest already confirmed valid JSON.
	_ = json.Unmarshal(data, &m)

	attest := m.Deployment.Attestation
	if attest.Mode == "" {
		attest.Mode = "rolling"
	}
	if attest.Mode == "rolling" && attest.RollingThreshold <= 0 {
		attest.RollingThreshold = 100
	}

	return &PostureConfig{
		DefaultPosture:   m.Deployment.DefaultPosture,
		RuntimeFallbacks: m.Deployment.RuntimeFallbacks,
		Attestation:      attest,
		WriteOnly:        m.Deployment.DefaultPosture == "coercion_resistant",
	}, nil
}

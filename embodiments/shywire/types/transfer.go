package types

// AssetRecord defines an asset that can flow through the shyware layer.
// The operator registers assets; the protocol enforces supply invariants.
// shyware does not issue assets — it provides the anonymous transfer layer.
type AssetRecord struct {
	AssetID     string `json:"asset_id"`     // operator-defined identifier (e.g. "usdc", "usd", "gov-token")
	Name        string `json:"name"`         // human-readable label
	Decimals    uint8  `json:"decimals"`     // precision (e.g. 6 for USDC-equivalent)
	TotalSupply int64  `json:"total_supply"` // sum of all minted minus burned; enforced by state
	CreatedAt   int64  `json:"created_at"`
}

// TransferRecord is List 1 — an anonymous transfer with no identity field.
//
// transfer_id = H(TransferNonce) is random and unlinkable to the nullifier.
// Amount is stored in plaintext in this scaffold; the production circuit will
// replace Amount with an AmountCommitment (Pedersen commitment over BN254) and
// enforce Σ inputs == Σ outputs in the ZK proof without revealing individual amounts.
//
// TODO(circuit): replace Amount int64 with AmountCommitment []byte once the
// Pedersen commitment + range proof circuit is built.
type TransferRecord struct {
	TransferID string `json:"transfer_id"` // H(TransferNonce) — no identity encoded
	AssetID    string `json:"asset_id"`
	Amount     int64  `json:"amount"` // plaintext scaffold; see TODO above
	Timestamp  int64  `json:"timestamp"`
	Height     int64  `json:"height"`
}

// PublicTransferRecord is the redacted transfer view exposed through public query
// surfaces. It preserves transfer existence and asset metadata without exposing
// the scaffold amount field.
type PublicTransferRecord struct {
	TransferID string `json:"transfer_id"`
	AssetID    string `json:"asset_id"`
	Timestamp  int64  `json:"timestamp"`
	Height     int64  `json:"height"`
}

// ParticipantRecord is List 2 — a participation record with no amount field.
//
// identity_hash = H(wallet_address, transfer_id) for the shyware deployment.
// The nullifier prevents double-spend: the same (account, transfer_id) pair
// cannot be used twice, identical to how the voting nullifier prevents double-voting.
type ParticipantRecord struct {
	TransferID   string `json:"transfer_id"`
	IdentityHash string `json:"identity_hash"` // nullifier = H(wallet_address, transfer_id)
	Height       int64  `json:"height"`
}

// AccountRecord holds the on-chain balance for an account.
// In the production circuit, Balance will be replaced with a BalanceCommitment
// (Pedersen commitment) so that balances are hidden while conservation is provable.
//
// TODO(circuit): replace Balance int64 with BalanceCommitment []byte.
type AccountRecord struct {
	AccountCommitment string `json:"account_commitment"` // H(wallet_address) — public identifier
	AssetID           string `json:"asset_id"`
	Balance           int64  `json:"balance"` // plaintext scaffold; see TODO above
	Disabled          bool   `json:"disabled,omitempty"` // set by AdverseAction "disable"/"rescind"; blocks all sends and receives
	Frozen            bool   `json:"frozen,omitempty"`   // set by AdverseAction "freeze"; blocks sends only (AML hold)
	UpdatedAt         int64  `json:"updated_at"`
	Height            int64  `json:"height"`
}

// AuthorityActionRecord is an append-only typed record of an authority-initiated
// adverse action against an account commitment. It is never deleted from canonical
// state — it constitutes the permanent, monotonically growing audit surface for
// disablement, rescission, freeze, restoration, and forced-redemption events.
//
// Two-party threshold: both EligibilityAuth and ReconciliationAuth must be valid
// ed25519 signatures over the canonical action message before this record is committed.
//
// ActionType values: "disable", "freeze", "rescind", "restore", "redeem_forced".
type AuthorityActionRecord struct {
	ActionID           string `json:"action_id"`                       // H(ActionNonce) — payload-free identifier
	AccountCommitment  string `json:"account_commitment"`              // which account is affected
	AssetID            string `json:"asset_id"`                        // empty = all assets for this commitment
	ActionType         string `json:"action_type"`                     // "disable"|"freeze"|"rescind"|"restore"|"redeem_forced"
	ReferencedActionID string `json:"referenced_action_id,omitempty"` // for "restore": the action_id being appealed
	EligibilityAuth    []byte `json:"eligibility_auth"`                // ed25519 sig from eligibility authority
	ReconciliationAuth []byte `json:"reconciliation_auth"`             // ed25519 sig from reconciling authority
	Reason             string `json:"reason"`                          // attestation reason; no PII
	Timestamp          int64  `json:"timestamp"`
	Height             int64  `json:"height"`
}

// SupplyRecord tracks total minted and burned for an asset.
// TotalSupply == TotalMinted - TotalBurned is enforced on every Mint and Burn tx.
type SupplyRecord struct {
	AssetID     string `json:"asset_id"`
	TotalMinted int64  `json:"total_minted"`
	TotalBurned int64  `json:"total_burned"`
	TotalSupply int64  `json:"total_supply"` // invariant: TotalMinted - TotalBurned
	UpdatedAt   int64  `json:"updated_at"`
}

// EnrollmentRecord marks a single-use enrollment authorization as consumed.
// Gated transfer deployments use this to prevent IDV/auth-only self-enrollment.
type EnrollmentRecord struct {
	Token             string `json:"token"`
	AccountCommitment string `json:"account_commitment"`
	Height            int64  `json:"height"`
}

// Errors

type ErrorInsufficientBalance struct {
	AccountCommitment string
	AssetID           string
	Have              int64
	Need              int64
}

func (e *ErrorInsufficientBalance) Error() string {
	return "insufficient balance: account " + e.AccountCommitment +
		" has " + itoa(e.Have) + " " + e.AssetID + ", needs " + itoa(e.Need)
}

type ErrorUnknownAsset struct {
	AssetID string
}

func (e *ErrorUnknownAsset) Error() string {
	return "unknown asset: " + e.AssetID
}

type ErrorDuplicateTransfer struct {
	IdentityHash string
}

func (e *ErrorDuplicateTransfer) Error() string {
	return "duplicate transfer: nullifier " + e.IdentityHash + " already used"
}

type ErrorAccountDisabled struct {
	AccountCommitment string
}

func (e *ErrorAccountDisabled) Error() string {
	return "account disabled: " + e.AccountCommitment + " has been disabled or rescinded by authority action"
}

type ErrorAccountFrozen struct {
	AccountCommitment string
}

func (e *ErrorAccountFrozen) Error() string {
	return "account frozen: " + e.AccountCommitment + " is frozen; sends are not permitted"
}

// itoa converts int64 to string without importing strconv into types.
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// Package zkp implements the ZK nullifier circuit for Populist.
//
// # Protocol
//
// The circuit proves knowledge of PersonSecret such that:
//
//	MiMC(PersonSecret) == Commitment          (Didit-attested binding)
//	MiMC(PersonSecret, PollID) == Nullifier   (per-poll dedup key)
//
// without revealing PersonSecret.
//
// ZK is a privacy layer ON TOP of Didit — not an alternative to it.
// Didit verifies the voter's biometric identity, then signs a commitment
// to the voter's self-generated person_secret. The circuit proves the
// voter knows the secret behind the Didit-attested commitment AND that
// their nullifier is correctly derived from it. This eliminates the
// operator trust dependency while preserving Sybil resistance.
//
//	Didit-only (no ZK):
//	  identity_hash = SHA-256(person_id ∥ poll_id)
//	  Trust: Didit correctly deduplicates and is honest
//
//	ZK mode (this package, layered over Didit):
//	  commitment  = MiMC(person_secret)           — Didit signs this at enrollment
//	  nullifier   = MiMC(person_secret, poll_id)  — derived per-poll
//	  identity_hash := nullifier                  — on-chain dedup key
//	  Trust: Groth16 proof + Didit commitment signature — no oracle trust
//
// # Enrollment flow (client-side, one-time per voter)
//  1. Voter generates a stable device-bound person_secret.
//  2. Client computes commitment = MiMC(person_secret).
//  3. Client submits commitment to Didit during biometric IDV.
//  4. Didit signs sha256(commitment || poll_id) with its Ed25519 key.
//  5. Client stores (person_secret, commitment, sig) for this poll.
//
// # Vote flow
//  1. Client computes nullifier = MiMC(person_secret, poll_id).
//  2. Client generates Groth16 proof of both circuit constraints.
//  3. BallotCastData includes: zk_nullifier, zk_nullifier_proof,
//     zk_commitment, didit_commitment_sig.
//  4. ABCI verifies Didit sig, then verifies ZK proof, then dedups on nullifier.
//
// # Trusted Setup
//
// Run `go run ./cmd/zk-setup` once to produce nullifier_pk.bin (proving key)
// and nullifier_vk.bin (verifying key). Distribute vk.bin to all validators.
// Keep pk.bin for clients. Do NOT use single-party setup in production —
// a Groth16 MPC ceremony (e.g. Hermez, snarkjs phase2) is required.
package zkp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	mimcbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
)

// NullifierCircuit proves knowledge of PersonSecret such that:
//
//	MiMC(PersonSecret) == Commitment           — links secret to Didit-attested identity
//	MiMC(PersonSecret, PollID) == Nullifier    — derives per-poll dedup key
//
// without revealing PersonSecret.
//
// TARGET DESIGN (preferred embodiment — pending circuit hardening):
//
//	Public inputs:  PollID, Nullifier, DiditPubKey
//	Private inputs: PersonSecret, Commitment, DiditCommitmentSig
//
//	The circuit should additionally prove:
//	  Ed25519.Verify(DiditPubKey, SHA-256(Commitment || PollID), DiditCommitmentSig) == true
//	so that Commitment and DiditCommitmentSig never appear in the transaction payload
//	or on-chain. Only the nullifier travels on-chain; the ABCI verifier needs only
//	(proof, nullifier, poll_id, didit_pub_key).
//
//	This requires gnark/std/algebra/emulated for Edwards25519 and gnark/std/hash/sha2.
//
// CURRENT IMPLEMENTATION (Commitment is public — interim):
//
//	Public inputs:  PollID, Nullifier, Commitment
//	Private inputs: PersonSecret
//
//	Commitment is currently a public input because the ABCI verifies the Didit sig
//	on-chain (outside the circuit), which requires Commitment in the transaction.
//	This means Didit can correlate commitment → nullifier → participation.
//	The target design above eliminates this by moving all Didit binding into the circuit.
type NullifierCircuit struct {
	PersonSecret frontend.Variable `gnark:",secret"`
	PollID       frontend.Variable `gnark:",public"`
	Nullifier    frontend.Variable `gnark:",public"`
	Commitment   frontend.Variable `gnark:",public"` // TODO: move to secret once Ed25519 added to circuit
}

// Define implements frontend.Circuit.
func (c *NullifierCircuit) Define(api frontend.API) error {
	// Constraint 1: MiMC(PersonSecret) == Commitment
	// Proves the voter knows the secret behind the Didit-attested commitment.
	hCommit, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hCommit.Write(c.PersonSecret)
	api.AssertIsEqual(hCommit.Sum(), c.Commitment)

	// Constraint 2: MiMC(PersonSecret, PollID) == Nullifier
	// Proves the nullifier is correctly derived from the same secret.
	hNull, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hNull.Write(c.PersonSecret, c.PollID)
	api.AssertIsEqual(hNull.Sum(), c.Nullifier)
	return nil
}

// Compile compiles the NullifierCircuit to a Groth16 R1CS over BN254.
// Called once during trusted setup — not at runtime.
func Compile() (constraint.ConstraintSystem, error) {
	var circuit NullifierCircuit
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, fmt.Errorf("compile NullifierCircuit: %w", err)
	}
	return cs, nil
}

// hashToField reduces an arbitrary string to a BN254 scalar field element
// via SHA-256 followed by big.Int mod-reduction.
//
// This is not a random oracle — it is a deterministic mapping used as
// input encoding, not as a commitment scheme. Security comes from the
// ZK proof, not from this function.
func hashToField(s string) *big.Int {
	h := sha256.Sum256([]byte(s))
	n := new(big.Int).SetBytes(h[:])
	return n.Mod(n, ecc.BN254.ScalarField())
}

// ComputeCommitment computes MiMC(personSecret) natively (no proof).
//
// Called client-side at enrollment to produce the commitment value submitted
// to Didit. Didit signs sha256(commitment || poll_id) with its Ed25519 key,
// binding the voter's device-generated person_secret to their verified identity.
// The commitment itself does not reveal person_secret (one-way hash).
func ComputeCommitment(personSecret string) (string, error) {
	h := mimcbn254.NewMiMC()

	var secretEl bn254fr.Element
	secretEl.SetBigInt(hashToField(personSecret))
	secretBytes := secretEl.Bytes()

	h.Write(secretBytes[:])
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ComputeNullifier computes MiMC(personSecret, pollID) natively (no proof).
//
// Called client-side to compute the nullifier value that must be included
// in the proof public inputs. personSecret is the stable device-bound secret
// whose commitment was attested by Didit at enrollment — never transmitted.
//
// The returned hex string is the on-chain identity_hash when ZK is enabled.
func ComputeNullifier(personSecret, pollID string) (string, error) {
	h := mimcbn254.NewMiMC()

	var secretEl, pollEl bn254fr.Element
	secretEl.SetBigInt(hashToField(personSecret))
	pollEl.SetBigInt(hashToField(pollID))

	secretBytes := secretEl.Bytes() // [32]byte, big-endian canonical field encoding
	pollBytes := pollEl.Bytes()

	h.Write(secretBytes[:])
	h.Write(pollBytes[:])

	return hex.EncodeToString(h.Sum(nil)), nil
}

// Verifier holds the Groth16 verifying key, loaded once at ABCI startup.
//
// Create with NewVerifier; the zero value is invalid.
// When zkVerifier is nil in State, ZK proof fields are rejected (fail-safe).
type Verifier struct {
	vk groth16.VerifyingKey
}

// Prover holds the compiled constraint system and proving key, loaded once.
//
// Create with NewProver; the zero value is invalid.
// NewProver compiles the circuit (~10ms) — call it once at startup, not per proof.
type Prover struct {
	cs constraint.ConstraintSystem
	pk groth16.ProvingKey
}

// NewProver compiles the NullifierCircuit and deserializes a Groth16 proving key
// from r. r is typically an open file produced by cmd/zk-setup.
//
// For the WASM browser prover, call once at WASM init and reuse the *Prover
// for every proof request.
func NewProver(r io.Reader) (*Prover, error) {
	cs, err := Compile()
	if err != nil {
		return nil, fmt.Errorf("compile circuit: %w", err)
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(r); err != nil {
		return nil, fmt.Errorf("read proving key: %w", err)
	}
	return &Prover{cs: cs, pk: pk}, nil
}

// Prove generates a Groth16 proof that:
//
//	F(personSecret) == commitment  AND  F(personSecret, pollID) == nullifier
//
// personSecret is the stable device-bound private value — never transmitted.
// pollID is the poll identifier string.
//
// Returns the raw serialized proof bytes for BallotCastData.ZKNullifierProof.
// The matching commitment and nullifier hex strings are also returned so the
// caller can include them in the ballot without recomputing.
func (p *Prover) Prove(personSecret, pollID string) (proofBytes []byte, commitmentHex, nullifierHex string, err error) {
	commitmentHex, err = ComputeCommitment(personSecret)
	if err != nil {
		return nil, "", "", fmt.Errorf("compute commitment: %w", err)
	}
	nullifierHex, err = ComputeNullifier(personSecret, pollID)
	if err != nil {
		return nil, "", "", fmt.Errorf("compute nullifier: %w", err)
	}

	commitmentBig, ok := new(big.Int).SetString(commitmentHex, 16)
	if !ok {
		return nil, "", "", fmt.Errorf("invalid commitment hex from ComputeCommitment")
	}
	nullifierBig, ok := new(big.Int).SetString(nullifierHex, 16)
	if !ok {
		return nil, "", "", fmt.Errorf("invalid nullifier hex from ComputeNullifier")
	}

	assignment := &NullifierCircuit{
		PersonSecret: hashToField(personSecret),
		PollID:       hashToField(pollID),
		Nullifier:    nullifierBig,
		Commitment:   commitmentBig,
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, "", "", fmt.Errorf("build witness: %w", err)
	}

	proof, err := groth16.Prove(p.cs, p.pk, witness)
	if err != nil {
		return nil, "", "", fmt.Errorf("groth16 prove: %w", err)
	}

	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return nil, "", "", fmt.Errorf("serialize proof: %w", err)
	}
	return buf.Bytes(), commitmentHex, nullifierHex, nil
}

// NewVerifier deserializes a Groth16 verifying key from an io.Reader.
// r is typically an open file produced by cmd/zk-setup.
func NewVerifier(r io.Reader) (*Verifier, error) {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(r); err != nil {
		return nil, fmt.Errorf("read verifying key: %w", err)
	}
	return &Verifier{vk: vk}, nil
}

// Verify verifies a Groth16 proof that:
//
//	MiMC(secret) == commitment  AND  MiMC(secret, pollID) == nullifier
//
//   - proofBytes: raw Groth16 proof (binary, as written by groth16.Prove)
//   - nullifierHex: hex-encoded nullifier (public, 32 bytes / 64 hex chars)
//   - commitmentHex: hex-encoded commitment MiMC(person_secret) (public, Didit-attested)
//   - pollID: the poll_id string (public, hashed to field element internally)
//
// Returns nil on success, non-nil on any failure (invalid proof, parse error, etc.).
func (v *Verifier) Verify(proofBytes []byte, nullifierHex, commitmentHex, pollID string) error {
	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return fmt.Errorf("deserialize proof: %w", err)
	}

	nullifierBig, ok := new(big.Int).SetString(nullifierHex, 16)
	if !ok {
		return fmt.Errorf("invalid nullifier hex: %q", nullifierHex)
	}

	commitmentBig, ok := new(big.Int).SetString(commitmentHex, 16)
	if !ok {
		return fmt.Errorf("invalid commitment hex: %q", commitmentHex)
	}

	assignment := &NullifierCircuit{
		PollID:     hashToField(pollID),
		Nullifier:  nullifierBig,
		Commitment: commitmentBig,
	}
	publicWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("build public witness: %w", err)
	}

	if err := groth16.Verify(proof, v.vk, publicWitness); err != nil {
		return fmt.Errorf("proof invalid: %w", err)
	}
	return nil
}

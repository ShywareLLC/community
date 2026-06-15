import test from "node:test"
import assert from "node:assert/strict"

import {
  createIdentityCommitment,
  createIdentityProofHash,
  createIdentityResolver,
  getIdentityProfile,
  normalizeIdentityInput,
} from "./protocol/identity/identityClient.js"

test("wallet commitments are deterministic", async () => {
  const manifest = {
    identity: {
      provider: "wallet",
      mode: "wallet_commitment",
    },
  }

  const first = await createIdentityCommitment(manifest, "0xAbC123")
  const second = await createIdentityCommitment(manifest, { walletAddress: "0xabc123" })

  assert.equal(first, second)
  assert.equal(first.length, 64)
})

test("identus commitments and proof hashes derive from attested identifiers", async () => {
  const manifest = {
    identity: {
      provider: "identus",
      mode: "stable_person_id",
      workflow_id: "issuer-flow",
      issuer_did: "did:prism:issuer",
      presentation_mode: "proof_hash",
    },
  }

  const commitment = await createIdentityCommitment(manifest, {
    subjectId: "did:prism:holder",
  }, {
    namespace: "account",
    scope: "vaults-biz",
  })

  const proof = await createIdentityProofHash(manifest, {
    subjectId: "did:prism:holder",
    presentationNonce: "nonce-001",
  }, {
    scope: "vaults-biz",
    audience: "bank.vaults.biz",
  })

  assert.equal(commitment.length, 64)
  assert.equal(proof.length, 64)
  assert.notEqual(commitment, proof)
})

test("identus identity profile advertises attested identity input", () => {
  const profile = getIdentityProfile({
    identity: {
      provider: "identus",
      mode: "stable_person_id",
      kyc_required: true,
      recommended_idv: "didit",
      byoid_policy: "allowed",
    },
  })

  assert.equal(profile.provider, "identus")
  assert.equal(profile.supportsAttestedIdentity, true)
  assert.match(profile.inputLabel, /Identus/i)
  assert.equal(profile.recommendedIdv, "didit")
  assert.equal(profile.canBypassWithByoid, true)
})

test("didit-managed identity can be wrapped into an identus provider input", () => {
  const manifest = {
    identity: {
      provider: "identus",
      mode: "stable_person_id",
      workflow_id: "issuer-flow",
      issuer_did: "did:prism:issuer",
      presentation_mode: "proof_hash",
      kyc_required: true,
      recommended_idv: "didit",
      byoid_policy: "allowed",
    },
  }

  const normalized = normalizeIdentityInput(manifest, {
    sourceProvider: "didit",
    personId: "didit-person-001",
    journeyId: "journey-001",
  })

  assert.equal(normalized.subjectId, "didit-person-001")
  assert.equal(normalized.credentialId, "didit-person-001")
})

test("byoid normalization is explicitly gated by policy", () => {
  const manifest = {
    identity: {
      provider: "didit",
      mode: "stable_person_id",
      kyc_required: true,
      recommended_idv: "didit",
      byoid_policy: "allowed",
    },
  }

  const resolver = createIdentityResolver(manifest)
  const normalized = resolver.normalizeByoid({
    personId: "custom-person-001",
    proofHash: "proof-001",
  })

  assert.equal(normalized.sourceProvider, "byoid")
  assert.equal(normalized.personId, "custom-person-001")
})

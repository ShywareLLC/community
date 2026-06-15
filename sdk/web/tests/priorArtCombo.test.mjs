import test from "node:test"
import assert from "node:assert/strict"
import fs from "node:fs/promises"
import path from "node:path"
import { fileURLToPath } from "node:url"

import {
  assertVotingManifest,
  initializeFromShyConfig,
  VOTING_MANIFEST_CONTRACT_VERSION,
} from "./clients/embodiments/votingClient.js"

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(__dirname, "..", "..")

const baseVotingManifest = {
  contract_version: VOTING_MANIFEST_CONTRACT_VERSION,
  app: { id: "combo-demo", name: "Combo Demo", chain_id: "shyware-1" },
  anon_layer: {
    black_box_required: true,
    required_flows: ["poll_read", "ballot_build", "ballot_submit", "receipt_verify"],
  },
  api: { base_url: "/api", submit_base_url: "/api" },
  identity: {
    provider: "didit",
    mode: "stable_person_id",
    workflow_id: "demo-workflow",
    byoid_policy: "disallowed",
  },
  signing: {
    required: true,
    backend: "local_ed25519",
    validator_key_id: "demo-validator",
    tally_key_id: "demo-tally",
  },
  deployment: {
    default_posture: "recoverable",
    runtime_fallbacks: {
      write_only_on_missing_play_integrity: true,
      write_only_on_hostile_network: true,
      write_only_on_untrusted_device_attestation: true,
    },
  },
}

test("a governance-style manifest does not substitute for the voting protocol contract", () => {
  assert.throws(
    () =>
      assertVotingManifest({
        ...baseVotingManifest,
        contract_version: "shyshares-v1",
        governance: {
          poll_create_authority: "any_holder",
          membership_sources: ["token_balance"],
          proposal_classes: ["parameter_change"],
          eligibility: { asset_id: "demo-token", min_balance: 1 },
          vote_weight: "one_per_holder",
        },
        execution: {
          default_mode: "internal_queue",
          adapters: ["shywire"],
          canonical_queue: true,
        },
      }),
    /contract_version=shyvoting-v1/,
  )
})

test("a manifest-driven ballot build does not become ZK/nullifier voting by configuration alone", async () => {
  const client = initializeFromShyConfig({
    ...baseVotingManifest,
    receipts: {
      match_store: "none",
      user_access: "never",
      double_vote_enforcement: "voter_registry_only",
    },
  }, {
    fetchImpl: async () => ({ ok: true, json: async () => ({}) }),
  })

  const envelope = await client.buildBallot({
    pollId: "proposal-42",
    choice: "yes",
    personId: "didit-journey-id",
  })

  const parsed = JSON.parse(envelope.txJson)
  assert.equal(parsed.type, 2)
  assert.ok(parsed.data.identity_hash, "manifest-driven voting computes a base identity_hash")
  assert.equal(parsed.data.zk_nullifier, undefined)
  assert.equal(parsed.data.zk_nullifier_proof, undefined)
  assert.equal(parsed.data.zk_commitment, undefined)
})

test("switching receipts off removes recoverable reconcile instead of preserving it", async () => {
  const client = initializeFromShyConfig({
    ...baseVotingManifest,
    receipts: {
      match_store: "none",
      user_access: "never",
      double_vote_enforcement: "voter_registry_only",
    },
    deployment: {
      ...baseVotingManifest.deployment,
      default_posture: "coercion_resistant",
    },
  }, {
    fetchImpl: async () => ({ ok: true, json: async () => ({}) }),
  })

  assert.equal(await client.getPrivateReceipt("proposal-42"), null)
  assert.equal(await client.savePrivateReceipt("proposal-42", {
    choice: "yes",
    ballotId: "b",
    ballotNonce: "n",
    identityHash: "i",
    submittedAt: 1,
  }), null)
})

test("restoring recovery recreates the separate protected linkage authority tier", () => {
  const client = initializeFromShyConfig({
    ...baseVotingManifest,
    receipts: {
      match_store: "cockroach_encrypted",
      user_access: "gated_recovery",
      double_vote_enforcement: "voter_registry_only",
    },
  }, {
    fetchImpl: async () => ({ ok: true, json: async () => ({}) }),
    runtimeSignals: {
      playIntegrity: { available: true, passed: true },
      deviceAttestation: { trusted: true },
      network: { hostile: false },
    },
  })

  const authority = client.getAuthorityMatrix().find((row) => row.authority === "reconciling_authority")
  assert.deepEqual(authority, {
    authority: "reconciling_authority",
    canonical_blockchain_read: "anonymous_public_state_only",
    canonical_blockchain_write: "none",
    private_reconcile_read: "read_only",
    private_reconcile_write: "none",
  })
})

test("the prior-art combo example documents a voting profile, not a config-only ZK/governance merge", async () => {
  const manifestPath = path.join(repoRoot, "shyconfig.prior-art-combo.example.json")
  const raw = await fs.readFile(manifestPath, "utf8")
  const manifest = JSON.parse(raw)

  assert.equal(manifest.contract_version, "shyvoting-v1")
  assert.equal(manifest.identity.provider, "didit")
  assert.equal(manifest.receipts.match_store, "none")
  assert.ok(manifest.governance, "the example carries governance context without becoming shyshares")
})

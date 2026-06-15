import test from "node:test"
import assert from "node:assert/strict"

import {
  assertSharesManifest,
  SHARES_MANIFEST_CONTRACT_VERSION,
  initializeFromShyConfig,
} from "./clients/embodiments/sharesClient.js"

const baseManifest = {
  contract_version: SHARES_MANIFEST_CONTRACT_VERSION,
  app: {
    id: "bigglom",
    name: "bigglom",
    product_type: "shyshares",
    chain_id: "shyware-1",
  },
  domains: {
    public: { splash: "bigglom.com" },
    private: { console: "quorum.bigglom.com" },
  },
  anon_layer: {
    sdk_id: "shyware-web-v1",
    black_box_required: true,
    required_flows: [
      "organization_read",
      "membership_snapshot_read",
      "proposal_create",
      "weighted_ballot_submit",
      "tally_read",
      "action_queue_read",
      "action_dispatch",
    ],
  },
  api: {
    base_url: "/api",
    submit_base_url: "/api",
    requires_auth: false,
    auth_scheme: "none",
  },
  identity: { provider: "wallet", mode: "wallet_commitment" },
  signing: {
    required: true,
    backend: "aws_kms",
    validator_key_id: "alias/demo-validator",
    tally_key_id: "alias/demo-tally",
    contract_key_id: "alias/demo-contract",
  },
  deployment: {
    default_posture: "recoverable",
    runtime_fallbacks: {
      write_only_on_missing_play_integrity: false,
      write_only_on_hostile_network: false,
      write_only_on_untrusted_device_attestation: false,
    },
  },
  governance: {
    membership_sources: ["token_balance", "delegation", "allowlist"],
    weighting_mode: "delegated_stake_snapshot",
    privacy_mode: "direction_and_weight_unlinkable",
    transfer_layer: "shywire",
    proposal_classes: ["payout", "parameter_change", "role_change", "delegate_change", "arbitrary_execution"],
  },
  execution: {
    default_mode: "internal_queue",
    adapters: ["shywire", "byodao"],
    canonical_queue: true,
  },
}

test("shares manifests must declare governance and execution settings", () => {
  assert.throws(() => assertSharesManifest({ ...baseManifest, governance: undefined }), /governance and execution/)
})

test("shares initialization exposes governance and execution config", () => {
  const client = initializeFromShyConfig(baseManifest, {
    fetchImpl: async () => ({ ok: true, json: async () => ({ ok: true }) }),
  })

  const state = client.initialize()
  assert.equal(state.governance.weighting_mode, "delegated_stake_snapshot")
  assert.deepEqual(state.execution.adapters, ["shywire", "byodao"])
})

test("shares proposal creation posts to the proposals endpoint", async () => {
  const calls = []
  const client = initializeFromShyConfig(baseManifest, {
    fetchImpl: async (url, options = {}) => {
      calls.push({ url, options })
      return { ok: true, json: async () => ({ ok: true, proposal_id: "prop-001" }) }
    },
  })

  await client.createProposal({ organization_id: "org-001", title: "Treasury vote" })

  assert.equal(calls.length, 1)
  assert.match(calls[0].url, /\/proposals$/)
  assert.equal(calls[0].options.method, "POST")
})

test("shares ballot submission posts weighted ballots", async () => {
  const calls = []
  const client = initializeFromShyConfig(baseManifest, {
    fetchImpl: async (url, options = {}) => {
      calls.push({ url, options })
      return { ok: true, json: async () => ({ ok: true, tally: { yes_weight: 60, no_weight: 40 } }) }
    },
  })

  await client.submitWeightedBallot({
    proposal_id: "prop-001",
    account_commitment: "acct-001",
    direction: "yes",
  })

  assert.equal(calls.length, 1)
  assert.match(calls[0].url, /\/ballots$/)
  assert.equal(calls[0].options.method, "POST")
  assert.match(calls[0].options.body, /"direction":"yes"/)
})

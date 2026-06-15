import test from "node:test"
import assert from "node:assert/strict"

import {
  BETS_MANIFEST_CONTRACT_VERSION,
  assertBetsManifest,
  initializeFromShyConfig,
} from "./clients/composites/betsClient.js"

const baseManifest = {
  contract_version: BETS_MANIFEST_CONTRACT_VERSION,
  app: {
    id: "shybets",
    name: "Shybets",
    product_type: "shybets",
    chain_id: "shyware-1",
  },
  domains: {
    public: { splash: "bets.example" },
    private: { console: "desk.bets.example" },
  },
  anon_layer: {
    sdk_id: "shyware-web-v1",
    black_box_required: true,
    required_flows: [
      "event_create",
      "order_place",
      "order_book_read",
      "settlement_read",
      "settlement_finalize",
      "reconcile_request",
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
  wire: {
    asset_id: "usd-bet",
    issuer_name: "Shybets Settlement",
    backing_asset: "USD",
    provider: "custom",
    provider_config: {
      mode: "sandbox",
      intent_path: "/wire-provider",
      settlement_asset: "USD",
      supported_rails: ["blockchain", "ach"],
      requires_operator_review: true,
    },
    supported_networks: ["base-sepolia"],
  },
}

test("bets manifests require wire settings", () => {
  assert.throws(() => assertBetsManifest({ ...baseManifest, wire: undefined }), /wire settings/)
})

test("bets settlement account registration auto-builds wallet proof from injected provider", async () => {
  const originalEthereum = globalThis.ethereum
  globalThis.ethereum = {
    async request({ method }) {
      if (method === "eth_requestAccounts") {
        return ["0xabc123"]
      }
      if (method === "personal_sign") {
        return `0x${"55".repeat(65)}`
      }
      throw new Error(`unexpected method ${method}`)
    },
  }

  try {
    const client = initializeFromShyConfig(baseManifest, {
      fetchImpl: async () => ({ ok: true, json: async () => ({ ok: true }) }),
    })

    const envelope = await client.buildRegisterSettlementAccount({
      identityInput: "0xabc123",
      accountCommitment: "acct-bets",
    })

    assert.equal(envelope.data.account_commitment, "acct-bets")
    assert.equal(typeof envelope.data.wallet_proof, "string")
    assert.equal(envelope.data.wallet_proof.length > 80, true)
  } finally {
    globalThis.ethereum = originalEthereum
  }
})

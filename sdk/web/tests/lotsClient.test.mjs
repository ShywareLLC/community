import test from "node:test"
import assert from "node:assert/strict"

import {
  LOTS_MANIFEST_CONTRACT_VERSION,
  assertLotsManifest,
  initializeFromShyConfig,
} from "./clients/composites/lotsClient.js"

const baseManifest = {
  contract_version: LOTS_MANIFEST_CONTRACT_VERSION,
  app: {
    id: "shylots",
    name: "Shylots",
    product_type: "shylots",
    chain_id: "shyware-1",
  },
  domains: {
    public: { splash: "lots.example" },
    private: { console: "desk.lots.example" },
  },
  anon_layer: {
    sdk_id: "shyware-web-v1",
    black_box_required: true,
    required_flows: [
      "policy_read",
      "lot_record",
      "silo_transfer",
      "redemption_request",
      "redemption_settlement",
      "demurrage_apply",
      "wire_issue",
      "wire_transfer",
      "wire_redeem",
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
  custody: {
    asset_id: "lot-unit",
    policy_source: "on_chain",
    accepted_sku_whitelist: ["warehouse_lot"],
    unit_of_measure: "lot",
    quantity_normalization: "whole_lot",
    demurrage_policy: "policy_burn",
    operator_mint_burn: true,
    redemption_mode: "physical_goods_only",
    redemption_routing: "holder_chooses_warehouse",
    evidence_requirements: ["camera_session_ref", "operator_receipt_ref"],
    transfer_layer: "shywire",
  },
  wire: {
    asset_id: "usd-lot",
    issuer_name: "Shylots Settlement",
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
  lots: {
    market_operator: "operator-west",
    sale_modes: ["sealed_bid"],
    open_mode: "operator_attested_close",
    bid_visibility: "sealed_until_close",
    reserve_funding_mode: "bid_bond_transfer",
    settlement_asset_id: "usd-lot",
    bidder_identity_mode: "anonymous_commitment",
    evidence_mode: "custody_refs",
    redemption_surface: "custody_request",
    dispute_window_hours: 48,
  },
}

test("lots manifests require composed custody, wire, and market settings", () => {
  assert.throws(() => assertLotsManifest({ ...baseManifest, lots: undefined }), /lots settings/)
  assert.throws(() => assertLotsManifest({ ...baseManifest, wire: undefined }), /wire settings/)
})

test("lots initialization exposes composed inventory and settlement profile", () => {
  const client = initializeFromShyConfig(baseManifest, {
    fetchImpl: async () => ({ ok: true, json: async () => ({ ok: true }) }),
  })

  const state = client.initialize()
  assert.equal(state.inventoryLayer.contractVersion, "shylots-v1")
  assert.equal(state.inventoryLayer.assetId, "lot-unit")
  assert.equal(state.settlementLayer.assetId, "usd-lot")
  assert.equal(state.lotsProfile.marketOperator, "operator-west")
  assert.deepEqual(state.lotsProfile.saleModes, ["sealed_bid"])
})

test("lots list filtering stays at the product surface", async () => {
  const client = initializeFromShyConfig(baseManifest, {
    fetchImpl: async (url) => {
      if (String(url).endsWith("/custody/lots")) {
        return {
          ok: true,
          json: async () => ([
            { id: "lot-1", asset_id: "lot-unit", operator_id: "operator-west", warehouse_id: "wh-1", status: "open" },
            { id: "lot-2", asset_id: "lot-unit", operator_id: "operator-east", warehouse_id: "wh-2", status: "closed" },
          ]),
        }
      }
      return { ok: true, json: async () => ({ ok: true }) }
    },
  })

  const openLots = await client.listMarketplaceLots({ operatorId: "operator-west", status: "open" })
  assert.equal(openLots.length, 1)
  assert.equal(openLots[0].id, "lot-1")
  assert.equal(openLots[0].settlement_asset_id, "usd-lot")
})

test("bid bond transfers default to the Shylots settlement asset", async () => {
  const calls = []
  const client = initializeFromShyConfig(baseManifest, {
    fetchImpl: async (url, options = {}) => {
      calls.push({ url, options })
      return { ok: true, json: async () => ({ ok: true }) }
    },
  })

  const envelope = await client.transferBidBond({
    senderCommitment: "acct-bidder",
    recipientCommitment: "acct-escrow",
    amount: 2500,
  })

  assert.equal(envelope.data.asset_id, "usd-lot")
  assert.equal(calls.length, 1)
  assert.match(calls[0].url, /\/transfers$/)
})

test("lot redemption requests default to the custody asset", async () => {
  const calls = []
  const client = initializeFromShyConfig(baseManifest, {
    fetchImpl: async (url, options = {}) => {
      calls.push({ url, options })
      return {
        ok: true,
        json: async () => ({ ok: true, redemption: { request_id: "redeem-1" } }),
      }
    },
  })

  const envelope = await client.requestLotRedemption({
    requestId: "redeem-1",
    accountCommitment: "acct-winner",
    warehouseId: "wh-1",
    skuClassId: "warehouse_lot",
    siloAmount: 1,
    requestedQuantity: 1,
    destinationRef: "dock-3",
  })

  assert.equal(envelope.requestId, "redeem-1")
  assert.equal(calls.length, 1)
  assert.match(calls[0].url, /\/custody\/redemptions$/)
  const body = JSON.parse(calls[0].options.body)
  const tx = JSON.parse(body.tx)
  assert.equal(tx.data.asset_id, "lot-unit")
})

test("lots bidder registration uses the stronger wire account proof path", async () => {
  const originalEthereum = globalThis.ethereum
  globalThis.ethereum = {
    async request({ method }) {
      if (method === "eth_requestAccounts") {
        return ["0xabc123"]
      }
      if (method === "personal_sign") {
        return `0x${"33".repeat(65)}`
      }
      throw new Error(`unexpected method ${method}`)
    },
  }

  try {
    const client = initializeFromShyConfig(baseManifest, {
      fetchImpl: async () => ({ ok: true, json: async () => ({ ok: true }) }),
    })

    const envelope = await client.buildRegisterBidderAccount({
      identityInput: "0xabc123",
      accountCommitment: "acct-bidder",
    })

    assert.equal(envelope.data.account_commitment, "acct-bidder")
    assert.equal(typeof envelope.data.wallet_proof, "string")
    assert.equal(envelope.data.wallet_proof.length > 80, true)
  } finally {
    globalThis.ethereum = originalEthereum
  }
})

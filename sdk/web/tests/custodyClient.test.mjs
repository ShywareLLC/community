import test from "node:test"
import assert from "node:assert/strict"

import {
  assertCustodyManifest,
  CUSTODY_MANIFEST_CONTRACT_VERSION,
  initializeFromShyConfig,
} from "./clients/embodiments/custodyClient.js"

const baseManifest = {
  contract_version: CUSTODY_MANIFEST_CONTRACT_VERSION,
  app: {
    id: "vaults-biz",
    name: "vaults.biz",
    product_type: "shycustody",
    chain_id: "shyware-1",
  },
  domains: {
    public: { splash: "vaults.biz" },
    private: { console: "bank.vaults.biz" },
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
      "cam_attest_store",
      "cam_attest_reveal",
      "stream_event",
      "stream_clip",
      "stream_read",
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
  store: {
    secret_categories: ["document"],
    payload_encryption: {
      mode: "participant_derived_key",
      kdf: "hkdf_sha256",
    },
    recovery_mode: "biometric_rederive",
  },
  stream: {
    media_classes: ["warehouse_observation"],
    clip_policy: "operator_declared",
    retention_mode: "policy_bound",
  },
  custody: {
    asset_id: "silo",
    policy_source: "on_chain",
    accepted_sku_whitelist: ["durum_wheat_grade_a"],
    unit_of_measure: "kg",
    quantity_normalization: "grade_weight_nav",
    demurrage_policy: "policy_burn",
    operator_mint_burn: true,
    redemption_mode: "physical_goods_only",
    redemption_routing: "holder_chooses_warehouse",
    evidence_requirements: ["camera_session_ref", "operator_receipt_ref"],
    transfer_layer: "shywire",
  },
}

test("custody manifests must declare custody settings", () => {
  assert.throws(() => assertCustodyManifest({ ...baseManifest, custody: undefined }), /custody settings/)
})

test("operator-only actions are rejected without operator authority", async () => {
  const client = initializeFromShyConfig(baseManifest, {
    fetchImpl: async () => ({ ok: true, json: async () => ({ ok: true }) }),
    operatorMode: false,
  })

  await assert.rejects(
    () => client.registerWarehouseOperator({
      operatorId: "operator-east",
      name: "East Consortium Warehouse",
      warehouseId: "wh-east-1",
    }),
    /operator authority/,
  )
})

test("redemption requests post through the custody endpoint", async () => {
  const calls = []
  const client = initializeFromShyConfig(baseManifest, {
    operatorMode: false,
    fetchImpl: async (url, options = {}) => {
      calls.push({ url, options })
      return {
        ok: true,
        json: async () => ({ ok: true }),
      }
    },
  })

  const response = await client.requestRedemption({
    requestId: "redemption-001",
    assetId: "silo",
    accountCommitment: "acct-001",
    warehouseId: "wh-east-1",
    skuClassId: "durum_wheat_grade_a",
    siloAmount: 100,
    requestedQuantity: 90,
    destinationRef: "pickup-window-001",
  })

  assert.equal(response.requestId, "redemption-001")
  assert.equal(calls.length, 1)
  assert.match(calls[0].url, /\/custody\/redemptions$/)
  assert.equal(calls[0].options.method, "POST")
})

test("custody account registration auto-builds wallet proof from injected provider", async () => {
  const originalEthereum = globalThis.ethereum
  globalThis.ethereum = {
    async request({ method }) {
      if (method === "eth_requestAccounts") {
        return ["0xabc123"]
      }
      if (method === "personal_sign") {
        return `0x${"22".repeat(65)}`
      }
      throw new Error(`unexpected method ${method}`)
    },
  }

  try {
    const client = initializeFromShyConfig(baseManifest, {
      fetchImpl: async () => ({ ok: true, json: async () => ({ ok: true }) }),
    })

    const envelope = await client.buildRegisterAccount({
      identityInput: "0xabc123",
      accountCommitment: "acct-001",
    })

    assert.equal(envelope.data.account_commitment, "acct-001")
    assert.equal(typeof envelope.data.wallet_proof, "string")
    assert.equal(envelope.data.wallet_proof.length > 80, true)
  } finally {
    globalThis.ethereum = originalEthereum
  }
})

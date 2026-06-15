import test from "node:test"
import assert from "node:assert/strict"

import {
  assertWireManifest,
  WIRE_MANIFEST_CONTRACT_VERSION,
  initializeFromShyConfig,
} from "./clients/embodiments/wireClient.js"

const baseManifest = {
  contract_version: WIRE_MANIFEST_CONTRACT_VERSION,
  app: {
    id: "oneway-wiki",
    name: "oneway.wiki",
    product_type: "shywire",
    chain_id: "shyware-1",
  },
  domains: {
    public: { splash: "oneway.wiki" },
    private: { console: "send.oneway.wiki" },
  },
  anon_layer: {
    sdk_id: "shyware-web-v1",
    black_box_required: true,
    required_flows: ["wire_issue", "wire_transfer", "wire_redeem"],
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
  wire: {
    asset_id: "usdce",
    issuer_name: "oneway issuer",
    backing_asset: "USDC",
    wrapper_mode: "stablecoin_wrapper",
    provider: "circle_usdc",
    provider_config: {
      mode: "sandbox",
      intent_path: "/api/wire/provider",
      settlement_asset: "USDC",
      supported_rails: ["blockchain", "ach", "wire"],
      requires_operator_review: true,
    },
    operator_mint_burn: true,
    reconcile_authority: "issuer_read_only",
    supported_networks: ["ethereum", "base"],
  },
}

test("wire manifests must declare wire settings", () => {
  assert.throws(() => assertWireManifest({ ...baseManifest, wire: undefined }), /wire settings/)
})

test("wire issue posts through the mint endpoint", async () => {
  const calls = []
  const client = initializeFromShyConfig(baseManifest, {
    operatorMode: true,
    fetchImpl: async (url, options = {}) => {
      calls.push({ url, options })
      return {
        ok: true,
        json: async () => ({ ok: true }),
      }
    },
  })

  await client.issueWire({
    assetId: "usdce",
    accountCommitment: "acct-001",
    amount: 1000,
  })

  assert.equal(calls.length, 1)
  assert.match(calls[0].url, /\/mint$/)
  assert.equal(calls[0].options.method, "POST")
})

test("wire issue requires operator authority", async () => {
  const client = initializeFromShyConfig(baseManifest, {
    fetchImpl: async () => ({ ok: true, json: async () => ({ ok: true }) }),
  })

  await assert.rejects(
    () => client.issueWire({
      assetId: "usdce",
      accountCommitment: "acct-001",
      amount: 1000,
    }),
    /operator authority/,
  )
})

test("wire transfer posts through the transfer endpoint", async () => {
  const calls = []
  const client = initializeFromShyConfig(baseManifest, {
    fetchImpl: async (url, options = {}) => {
      calls.push({ url, options })
      return {
        ok: true,
        json: async () => ({ ok: true }),
      }
    },
  })

  const result = await client.wireSubmission({
    assetId: "usdce",
    senderCommitment: "acct-001",
    recipientCommitment: "acct-002",
    amount: 250,
  })

  assert.ok(result.transferId)
  assert.equal(calls.length, 1)
  assert.match(calls[0].url, /\/transfers$/)
  assert.equal(calls[0].options.method, "POST")
})

test("wire account registration requires wallet proof", async () => {
  const client = initializeFromShyConfig(baseManifest, {
    fetchImpl: async () => ({ ok: true, json: async () => ({ ok: true }) }),
  })

  await assert.rejects(
    () => client.buildRegisterAccount({
      walletAddress: "0xabc123",
    }),
    /wallet proof|Ethereum provider/i,
  )
})

test("wire account registration passes through enrollment authorization", async () => {
  const client = initializeFromShyConfig(baseManifest, {
    fetchImpl: async () => ({ ok: true, json: async () => ({ ok: true }) }),
  })

  const envelope = await client.buildRegisterAccount({
    walletAddress: "0xabc123",
    accountCommitment: "acct-001",
    walletProofBase64: "proof-001",
    enrollmentToken: "enroll-001",
    enrollmentProofBase64: "enroll-proof-001",
  })

  assert.equal(envelope.data.account_commitment, "acct-001")
  assert.equal(envelope.data.wallet_proof, "proof-001")
  assert.equal(envelope.data.enrollment_token, "enroll-001")
  assert.equal(envelope.data.enrollment_proof, "enroll-proof-001")
})

test("wire account registration auto-builds wallet proof from injected provider", async () => {
  const originalEthereum = globalThis.ethereum
  globalThis.ethereum = {
    async request({ method, params }) {
      if (method === "eth_requestAccounts") {
        return ["0xabc123"]
      }
      if (method === "personal_sign") {
        assert.ok(Array.isArray(params))
        return `0x${"11".repeat(65)}`
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
    assert.equal(envelope.data.wallet_proof.length > 80, true)
  } finally {
    globalThis.ethereum = originalEthereum
  }
})

test("wire initialization exposes provider profile", () => {
  const client = initializeFromShyConfig(baseManifest, {
    operatorMode: true,
    fetchImpl: async () => ({ ok: true, json: async () => ({ ok: true }) }),
  })

  const state = client.initialize()
  assert.equal(state.providerProfile.mode, "sandbox")
  assert.equal(state.providerProfile.settlementAsset, "USDC")
  assert.deepEqual(state.providerProfile.supportedRails, ["blockchain", "ach", "wire"])
})

test("wire issue and redeem intents are built from provider config", async () => {
  const client = initializeFromShyConfig(baseManifest, {
    operatorMode: true,
    fetchImpl: async () => ({ ok: true, json: async () => ({ ok: true }) }),
  })

  const issueIntent = await client.buildIssueIntent({
    amount: 500,
    destinationNetwork: "base",
    destinationAddress: "0xabc123",
    externalReference: "issuer-batch-001",
  })
  const redeemIntent = await client.buildRedeemIntent({
    amount: 125,
    accountCommitment: "acct-001",
    payoutRail: "ach",
    payoutDestination: "bank-account-token",
    externalReference: "redeem-001",
  })

  assert.equal(issueIntent.provider, "circle_usdc")
  assert.equal(issueIntent.destination_network, "base")
  assert.equal(redeemIntent.payout_rail, "ach")
  assert.equal(redeemIntent.settlement_asset, "USDC")
})

test("wire create intent persists through provider intent endpoints", async () => {
  const calls = []
  const client = initializeFromShyConfig(baseManifest, {
    operatorMode: true,
    fetchImpl: async (url, options = {}) => {
      calls.push({ url, options })
      return {
        ok: true,
        json: async () => ({ ok: true, intent_id: "intent-001", status: "pending_operator_review" }),
      }
    },
  })

  await client.createIssueIntent(
    {
      amount: 2500,
      destinationNetwork: "ethereum",
      destinationAddress: "0xfeedface",
      externalReference: "batch-issuer-001",
    },
    { dispatch: true },
  )

  assert.equal(calls.length, 1)
  assert.match(calls[0].url, /\/api\/wire\/provider\/issue-intents$/)
  assert.equal(calls[0].options.method, "POST")
  assert.match(calls[0].options.body, /"dispatch":true/)
})

import test from "node:test"
import assert from "node:assert/strict"

import {
  CONTRACTS_MANIFEST_CONTRACT_VERSION,
  assertContractsManifest,
  initializeFromShyConfig,
} from "./clients/embodiments/contractsClient.js"

const baseManifest = {
  contract_version: CONTRACTS_MANIFEST_CONTRACT_VERSION,
  app: {
    id: "vau-money",
    name: "VAU Money",
    product_type: "shycontracts",
    chain_id: "shyware-1",
  },
  domains: {
    public: { splash: "vau.money" },
    private: { console: "desk.vau.money" },
  },
  anon_layer: {
    sdk_id: "shyware-web-v1",
    black_box_required: true,
    required_flows: [
      "contract_register",
      "contract_activate",
      "contract_execute",
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
  financing: {
    return_basis: "project_profit",
    remittance_source_mode: "matched_customer_revenue",
    funding_mode: "shared_financing",
    transfer_layer: "shywire",
  },
}

test("contracts manifests require financing settings", () => {
  assert.throws(
    () => assertContractsManifest({ ...baseManifest, financing: undefined }),
    /contract settings|financing/i,
  )
})

test("contracts account registration auto-builds wallet proof from injected provider", async () => {
  const originalEthereum = globalThis.ethereum
  globalThis.ethereum = {
    async request({ method }) {
      if (method === "eth_requestAccounts") {
        return ["0xabc123"]
      }
      if (method === "personal_sign") {
        return `0x${"44".repeat(65)}`
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
      accountCommitment: "acct-contract",
    })

    assert.equal(envelope.data.account_commitment, "acct-contract")
    assert.equal(typeof envelope.data.wallet_proof, "string")
    assert.equal(envelope.data.wallet_proof.length > 80, true)
  } finally {
    globalThis.ethereum = originalEthereum
  }
})

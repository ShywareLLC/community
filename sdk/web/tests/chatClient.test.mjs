import test from "node:test"
import assert from "node:assert/strict"

import {
  CHAT_MANIFEST_CONTRACT_VERSION,
  assertChatManifest,
  initializeFromShyConfig,
} from "./clients/embodiments/chatClient.js"

const baseManifest = {
  contract_version: CHAT_MANIFEST_CONTRACT_VERSION,
  app: {
    id: "shychat",
    name: "Scytale",
    product_type: "shychat",
    chain_id: "shyware-1",
  },
  domains: {
    public: { splash: "scytale.fyi" },
    private: { console: "confidential.scytale.fyi" },
  },
  api: {
    base_url: "/api",
    requires_auth: false,
    auth_scheme: "none",
  },
  identity: {
    provider: "none",
    surface_model: "mail",
    account_model: "multi_account",
    participant_binding: "scoped_commitment_optional",
  },
  messaging: {
    payload_model: "sealed_private_content",
    audit_model: "delivery_commitment_only",
    allowed_payload_formats: ["mail_text", "json_form"],
  },
  deployment: {
    attestation: {
      mode: "period_close",
    },
  },
}

test("chat manifests must declare a supported surface model", () => {
  assert.throws(
    () => assertChatManifest({ ...baseManifest, identity: { ...baseManifest.identity, surface_model: "fax" } }),
    /surface_model/,
  )
})

test("chat manifests must declare shychat as the product type", () => {
  assert.throws(
    () => assertChatManifest({ ...baseManifest, app: { ...baseManifest.app, product_type: "shyvoting" } }),
    /product_type/,
  )
})

test("chat initialization exposes payload and audit posture", () => {
  const client = initializeFromShyConfig(baseManifest, {
    fetchImpl: async () => ({ ok: true, json: async () => ({ ok: true }) }),
  })

  const state = client.initialize()
  assert.equal(state.surfaceModel, "mail")
  assert.equal(state.accountModel, "multi_account")
  assert.equal(state.payloadModel, "sealed_private_content")
  assert.equal(state.auditModel, "delivery_commitment_only")
  assert.deepEqual(state.allowedPayloadFormats, ["mail_text", "json_form"])
})

test("chat dispatch posts payload format and private fields through the SDK", async () => {
  const calls = []
  const client = initializeFromShyConfig(baseManifest, {
    fetchImpl: async (url, options = {}) => {
      calls.push({ url, options })
      return {
        ok: true,
        json: async () => ({ ok: true, dispatch: { dispatchId: "dispatch-001" } }),
      }
    },
  })

  await client.queueDispatch({
    mailboxId: "mbx-001",
    recipientAddress: "desk@confidential.scytale.fyi",
    subject: "Case packet",
    body: "Sealed private content",
    deliveryWindow: "next attested close",
    contentClass: "report",
    payloadFormat: "json_form",
    privateFields: {
      case_id: "case-001",
      reporter_email: "source@example.com",
    },
    auditMode: "delivery_commitment_only",
    attachmentRefs: ["ipfs://packet-001"],
  })

  assert.equal(calls.length, 1)
  assert.match(calls[0].url, /\/messages\/dispatches$/)
  assert.equal(calls[0].options.method, "POST")
  const body = JSON.parse(calls[0].options.body)
  assert.equal(body.payload_format, "json_form")
  assert.equal(body.audit_mode, "delivery_commitment_only")
  assert.deepEqual(body.private_fields, {
    case_id: "case-001",
    reporter_email: "source@example.com",
  })
})

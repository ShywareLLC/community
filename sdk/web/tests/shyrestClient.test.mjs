import test from "node:test"
import assert from "node:assert/strict"

import {
  SHYREST_MANIFEST_CONTRACT_VERSION,
  assertShyrestManifest,
  initializeFromShyConfig,
} from "./clients/composites/shyrestClient.js"

const baseManifest = {
  contract_version: SHYREST_MANIFEST_CONTRACT_VERSION,
  app: {
    id: "informant-stream",
    name: "informant.stream",
    product_type: "shyrest",
    chain_id: "review-1",
  },
  domains: {
    public: { splash: "informant.stream" },
    private: { console: "admin.informant.stream" },
  },
  api: {
    base_url: "/api",
    requires_auth: false,
    auth_scheme: "none",
  },
  identity: {
    provider: "didit",
    mode: "stable_person_id",
  },
  anon_layer: {
    sdk_id: "shyware-web-v1",
    black_box_required: true,
    required_flows: [
      "secret_store",
      "secret_retrieve",
      "secret_delete",
      "biometric_rederive",
      "mailbox_read",
      "mailbox_create",
      "dispatch_queue",
      "dispatch_close",
      "receipt_verify",
    ],
  },
  signing: {
    required: true,
    backend: "aws_kms",
    validator_key_id: "alias/demo-validator",
    tally_key_id: "alias/demo-tally",
  },
  store: {
    secret_categories: ["review_submission", "health_record", "arbitrary"],
    payload_encryption: {
      mode: "participant_derived_key",
      kdf: "hkdf_sha256",
    },
    recovery_mode: "biometric_rederivation",
    selective_disclosure: true,
    enumeration_protection: "structural",
  },
  messaging: {
    payload_model: "sealed_private_content",
    audit_model: "delivery_commitment_only",
    allowed_payload_formats: ["mail_text", "json_form", "review_packet"],
    mailbox_model: "multi_mailbox",
    delivery_model: "dispatch_queue",
    retention_policy: "mailbox_lifetime",
  },
}

test("shyrest manifests require both store and messaging blocks", () => {
  assert.throws(() => assertShyrestManifest({ ...baseManifest, store: undefined }), /store and messaging/i)
  assert.throws(() => assertShyrestManifest({ ...baseManifest, messaging: undefined }), /store and messaging/i)
})

test("shyrest initialization exposes composed store and chat surfaces", () => {
  const client = initializeFromShyConfig(baseManifest, {
    fetchImpl: async () => ({ ok: true, json: async () => ({ ok: true }) }),
  })

  const state = client.initialize()
  assert.equal(state.productType, "shyrest")
  assert.equal(state.store.contractVersion, "shystore-v1")
  assert.equal(state.messaging.contractVersion, "shychat-v1")
  assert.equal(typeof client.getStoreClient().storeSecret, "function")
  assert.equal(typeof client.getChatClient().createMailbox, "function")
})

import test from "node:test"
import assert from "node:assert/strict"

import {
  assertVotingManifest,
  createVotingClient,
  readBrowserRuntimeSignals,
  resolveEffectivePosture,
  VOTING_MANIFEST_CONTRACT_VERSION,
} from "./clients/embodiments/votingClient.js"

const baseManifest = {
  contract_version: VOTING_MANIFEST_CONTRACT_VERSION,
  deployment: {
    default_posture: "recoverable",
    runtime_fallbacks: {
      write_only_on_missing_play_integrity: true,
      write_only_on_hostile_network: true,
      write_only_on_untrusted_device_attestation: true,
      write_only_on_hsm_unavailable: false,
      write_only_on_missing_web_session_approval: false,
    },
  },
}

test("recoverable deployment stays recoverable when all trust signals pass", () => {
  const posture = resolveEffectivePosture(baseManifest, {
    playIntegrity: { available: true, passed: true },
    deviceAttestation: { trusted: true },
    network: { hostile: false },
  })

  assert.equal(posture.configuredPosture, "recoverable")
  assert.equal(posture.effectivePosture, "recoverable")
  assert.equal(posture.fallbackActive, false)
  assert.deepEqual(posture.fallbackReasons, [])
  assert.equal(posture.writeOnly, false)
})

test("missing Play Integrity forces write-only", () => {
  const posture = resolveEffectivePosture(baseManifest, {
    playIntegrity: { available: false, passed: false },
    deviceAttestation: { trusted: true },
    network: { hostile: false },
  })

  assert.equal(posture.effectivePosture, "write_only")
  assert.equal(posture.fallbackActive, true)
  assert.deepEqual(posture.fallbackReasons, ["missing_play_integrity"])
  assert.equal(posture.writeOnly, true)
})

test("hostile network forces write-only", () => {
  const posture = resolveEffectivePosture(baseManifest, {
    playIntegrity: { available: true, passed: true },
    deviceAttestation: { trusted: true },
    network: { hostile: true },
  })

  assert.equal(posture.effectivePosture, "write_only")
  assert.equal(posture.fallbackActive, true)
  assert.deepEqual(posture.fallbackReasons, ["hostile_network"])
  assert.equal(posture.writeOnly, true)
})

test("coercion-resistant deployments stay write-only even with trusted signals", () => {
  const posture = resolveEffectivePosture(
    {
      contract_version: VOTING_MANIFEST_CONTRACT_VERSION,
      deployment: {
        default_posture: "coercion_resistant",
        runtime_fallbacks: {
          write_only_on_missing_play_integrity: false,
          write_only_on_hostile_network: false,
          write_only_on_untrusted_device_attestation: false,
          write_only_on_hsm_unavailable: false,
          write_only_on_missing_web_session_approval: false,
        },
      },
    },
    {
      playIntegrity: { available: true, passed: true },
      deviceAttestation: { trusted: true },
      network: { hostile: false },
    },
  )

  assert.equal(posture.configuredPosture, "coercion_resistant")
  assert.equal(posture.effectivePosture, "write_only")
  assert.equal(posture.fallbackActive, false)
  assert.deepEqual(posture.fallbackReasons, [])
  assert.equal(posture.writeOnly, true)
})

test("voting manifests must declare the shared contract version", () => {
  assert.throws(
    () =>
      assertVotingManifest({
        anon_layer: {
          black_box_required: true,
          required_flows: ["poll_read", "ballot_build", "ballot_submit", "receipt_verify"],
        },
        identity: { provider: "didit", mode: "stable_person_id" },
        signing: {
          required: true,
          backend: "aws_kms",
          validator_key_id: "alias/demo-validator",
          tally_key_id: "alias/demo-tally",
        },
        receipts: {
          match_store: "firestore_plaintext",
          user_access: "gated_recovery",
          double_vote_enforcement: "voter_registry_only",
        },
        deployment: {
          default_posture: "recoverable",
          runtime_fallbacks: {
            write_only_on_missing_play_integrity: true,
            write_only_on_hostile_network: true,
            write_only_on_untrusted_device_attestation: true,
            write_only_on_hsm_unavailable: false,
            write_only_on_missing_web_session_approval: false,
          },
        },
      }),
    /contract_version/,
  )
})

test("browser runtime signals are read from shared app-scoped keys", () => {
  const originalWindow = globalThis.window
  const originalLocalStorage = globalThis.localStorage

  globalThis.window = {
    location: { search: "" },
    __SHYWARE_RUNTIME_SIGNALS__: {
      playIntegrity: { mode: "pass" },
      deviceAttestation: { mode: "trusted" },
      network: { mode: "public" },
      hsm: { mode: "available" },
      webSession: { approved: false },
    },
  }
  globalThis.sessionStorage = {
    getItem(key) {
      const values = {
        "shyware_runtime:seda-haqq:web_session_approval": JSON.stringify({
          approved: true,
          expiresAt: Date.now() + 60_000,
          allowedFunctions: ["receipt_readback"],
        }),
      }
      return values[key] ?? null
    },
  }
  globalThis.localStorage = {
    getItem(key) {
      const values = {
        "shyware_runtime:seda-haqq:play_integrity": "pass",
        "shyware_runtime:seda-haqq:device_attestation": "trusted",
        "shyware_runtime:seda-haqq:network": "hostile",
        "shyware_runtime:seda-haqq:hsm": "unavailable",
      }
      return values[key] ?? null
    },
  }

  const signals = readBrowserRuntimeSignals({
    app: { id: "seda-haqq" },
  })

  assert.equal(signals.playIntegrity.available, true)
  assert.equal(signals.playIntegrity.passed, true)
  assert.equal(signals.deviceAttestation.trusted, true)
  assert.equal(signals.network.hostile, true)
  assert.equal(signals.hsm.available, false)
  assert.equal(signals.webSession.approved, true)
  assert.deepEqual(signals.webSession.allowedFunctions, ["receipt_readback"])

  globalThis.window = originalWindow
  globalThis.sessionStorage = undefined
  globalThis.localStorage = originalLocalStorage
})

test("missing web-session approval can force write-only for browser recovery posture", () => {
  const posture = resolveEffectivePosture(
    {
      contract_version: VOTING_MANIFEST_CONTRACT_VERSION,
      deployment: {
        default_posture: "recoverable",
        runtime_fallbacks: {
          write_only_on_missing_play_integrity: false,
          write_only_on_hostile_network: false,
          write_only_on_untrusted_device_attestation: false,
          write_only_on_missing_web_session_approval: true,
        },
      },
    },
    {
      playIntegrity: { available: true, passed: true },
      deviceAttestation: { trusted: true },
      network: { hostile: false },
      webSession: { approved: false },
    },
  )

  assert.equal(posture.effectivePosture, "write_only")
  assert.deepEqual(posture.fallbackReasons, ["missing_web_session_approval"])
})

test("HSM unavailability can force write-only when declared by deployment", () => {
  const posture = resolveEffectivePosture(
    {
      contract_version: VOTING_MANIFEST_CONTRACT_VERSION,
      deployment: {
        default_posture: "recoverable",
        runtime_fallbacks: {
          write_only_on_missing_play_integrity: false,
          write_only_on_hostile_network: false,
          write_only_on_untrusted_device_attestation: false,
          write_only_on_hsm_unavailable: true,
          write_only_on_missing_web_session_approval: false,
        },
      },
    },
    {
      playIntegrity: { available: true, passed: true },
      deviceAttestation: { trusted: true },
      network: { hostile: false },
      hsm: { available: false },
    },
  )

  assert.equal(posture.effectivePosture, "write_only")
  assert.deepEqual(posture.fallbackReasons, ["hsm_unavailable"])
})

test("approved web session can preserve recoverable posture when it is the only missing signal", () => {
  const posture = resolveEffectivePosture(
    {
      contract_version: VOTING_MANIFEST_CONTRACT_VERSION,
      deployment: {
        default_posture: "recoverable",
        runtime_fallbacks: {
          write_only_on_missing_play_integrity: false,
          write_only_on_hostile_network: false,
          write_only_on_untrusted_device_attestation: false,
          write_only_on_missing_web_session_approval: true,
        },
      },
    },
    {
      playIntegrity: { available: true, passed: true },
      deviceAttestation: { trusted: true },
      network: { hostile: false },
      webSession: { approved: true, expiresAt: Date.now() + 60_000 },
    },
  )

  assert.equal(posture.effectivePosture, "recoverable")
  assert.deepEqual(posture.fallbackReasons, [])
})

// ── rescindBallot / replaceBallot ─────────────────────────────────────────────

test("rescindBallot posts to /ballots/update with empty new_choices (reconciled path)", async () => {
  const calls = []
  const client = createVotingClient({
    fetchImpl: async (url, options = {}) => {
      calls.push({ url, options })
      return { ok: true, json: async () => ({ ok: true }) }
    },
    manifest: baseManifest,
  })

  await client.rescindBallot({ pollId: "poll-1", personId: "voter-1" })

  assert.equal(calls.length, 1)
  assert.match(calls[0].url, /\/ballots\/update/)
  const body = JSON.parse(calls[0].options.body)
  assert.deepEqual(body.new_choices, [])
  assert.equal(body.poll_id, "poll-1")
  assert.ok(body.identity_hash, "must include identity_hash for reconciled path")
  assert.equal(body.old_ballot_id, undefined, "must not include old_ballot_id")
  assert.equal(body.tx, undefined, "must not wrap in tx field (reconciled path)")
})

test("rescindBallot includes a fresh new_ballot_nonce", async () => {
  const calls = []
  const client = createVotingClient({
    fetchImpl: async (url, options = {}) => {
      calls.push({ url, options })
      return { ok: true, json: async () => ({ ok: true }) }
    },
    manifest: baseManifest,
  })

  await client.rescindBallot({ pollId: "poll-1", personId: "voter-1" })

  const body = JSON.parse(calls[0].options.body)
  assert.ok(body.new_ballot_nonce, "must include new_ballot_nonce")
  assert.equal(typeof body.new_ballot_nonce, "string")
  assert.ok(body.new_ballot_nonce.length > 0)
})

test("replaceBallot posts to /ballots/update with non-empty new_choices (reconciled path)", async () => {
  const calls = []
  const client = createVotingClient({
    fetchImpl: async (url, options = {}) => {
      calls.push({ url, options })
      return { ok: true, json: async () => ({ ok: true }) }
    },
    manifest: baseManifest,
  })

  await client.replaceBallot({ pollId: "poll-1", newChoice: "yes", personId: "voter-1" })

  assert.equal(calls.length, 1)
  assert.match(calls[0].url, /\/ballots\/update/)
  const body = JSON.parse(calls[0].options.body)
  assert.deepEqual(body.new_choices, ["yes"])
  assert.equal(body.poll_id, "poll-1")
  assert.ok(body.identity_hash)
  assert.equal(body.old_ballot_id, undefined)
  assert.equal(body.tx, undefined)
})

test("replaceBallot includes a fresh new_ballot_nonce", async () => {
  const calls = []
  const client = createVotingClient({
    fetchImpl: async (url, options = {}) => {
      calls.push({ url, options })
      return { ok: true, json: async () => ({ ok: true }) }
    },
    manifest: baseManifest,
  })

  await client.replaceBallot({ pollId: "poll-1", newChoice: "yes", personId: "voter-1" })

  const body = JSON.parse(calls[0].options.body)
  assert.ok(body.new_ballot_nonce)
  assert.equal(typeof body.new_ballot_nonce, "string")
})

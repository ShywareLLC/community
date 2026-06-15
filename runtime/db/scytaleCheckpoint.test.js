const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

const {
  createCheckpointPayload,
  createSignedCheckpoint,
  verifySignedCheckpoint,
  createExportBundle,
  createBootstrapStatement,
  createSignedBootstrapStatement,
  verifyCutoverContinuity,
} = require("./scytaleCheckpoint");

test("checkpoint payload is stable for equivalent input ordering", () => {
  const base = {
    tenantId: "tenant-a",
    mailboxes: [
      { tenant_id: "tenant-a", mailbox_id: "mbx-2", address: "b@example.com" },
      { tenant_id: "tenant-a", mailbox_id: "mbx-1", address: "a@example.com" },
    ],
    dispatches: [
      { tenant_id: "tenant-a", message_id: "m-2", dispatch_id: "d-2", mailbox_id: "mbx-2", sealed_payload: { z: 1, a: 2 } },
      { tenant_id: "tenant-a", message_id: "m-1", dispatch_id: "d-1", mailbox_id: "mbx-1", sealed_payload: { a: 2, z: 1 } },
    ],
    receipts: [{ tenant_id: "tenant-a", mailbox_id: "mbx-1", recovery_ref: "rr-1" }],
    createdAt: "2026-03-21T00:00:00.000Z",
  };

  const forward = createCheckpointPayload(base);
  const reversed = createCheckpointPayload({
    ...base,
    mailboxes: [...base.mailboxes].reverse(),
    dispatches: [...base.dispatches].reverse(),
  });

  assert.equal(forward.digest, reversed.digest);
  assert.equal(forward.roots.mailboxes, reversed.roots.mailboxes);
  assert.equal(forward.roots.dispatches, reversed.roots.dispatches);
});

test("signed checkpoint verifies with derived public key", () => {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const checkpoint = createCheckpointPayload({
    tenantId: "tenant-a",
    createdAt: "2026-03-21T00:00:00.000Z",
  });
  const signed = createSignedCheckpoint(
    checkpoint,
    privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  );

  assert.ok(signed.signature);
  assert.ok(signed.signer.publicKeyPem);
  assert.equal(verifySignedCheckpoint(signed), true);
});

test("export bundle carries checkpoint and normalized rows", () => {
  const checkpoint = createCheckpointPayload({
    tenantId: "tenant-a",
    createdAt: "2026-03-21T00:00:00.000Z",
  });
  const bundle = createExportBundle({
    tenantId: "tenant-a",
    checkpoint,
    mailboxes: [{ tenant_id: "tenant-a", mailbox_id: "mbx-1", address: "ops@example.com" }],
  });

  assert.equal(bundle.schemaVersion, "scytale-export-v1");
  assert.equal(bundle.tenantId, "tenant-a");
  assert.equal(bundle.checkpoint.checkpointId, checkpoint.checkpointId);
  assert.equal(bundle.mailboxes[0].mailboxId, "mbx-1");
});

test("bootstrap statement binds destination deployment to a source bundle", () => {
  const checkpoint = createCheckpointPayload({
    tenantId: "tenant-a",
    mailboxes: [{ tenant_id: "tenant-a", mailbox_id: "mbx-1", address: "ops@example.com" }],
    createdAt: "2026-03-21T00:00:00.000Z",
  });
  const bundle = createExportBundle({
    tenantId: "tenant-a",
    checkpoint,
    mailboxes: [{ tenant_id: "tenant-a", mailbox_id: "mbx-1", address: "ops@example.com" }],
  });

  const statement = createBootstrapStatement({
    bundle,
    destinationDeployment: { tier: "hosted_dedicated", host: "tenant-a.shyware.fyi" },
    destinationGenesisRef: "genesis://tenant-a/0001",
    createdAt: "2026-03-21T01:00:00.000Z",
  });

  assert.equal(statement.schemaVersion, "scytale-bootstrap-v1");
  assert.equal(statement.sourceCheckpointId, checkpoint.checkpointId);
  assert.equal(statement.destinationDeployment.tier, "hosted_dedicated");
});

test("cutover continuity verification succeeds for a signed bootstrap statement", () => {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const checkpoint = createCheckpointPayload({
    tenantId: "tenant-a",
    mailboxes: [{ tenant_id: "tenant-a", mailbox_id: "mbx-1", address: "ops@example.com" }],
    createdAt: "2026-03-21T00:00:00.000Z",
  });
  const bundle = createExportBundle({
    tenantId: "tenant-a",
    checkpoint,
    mailboxes: [{ tenant_id: "tenant-a", mailbox_id: "mbx-1", address: "ops@example.com" }],
  });
  const bootstrap = createSignedBootstrapStatement(
    createBootstrapStatement({
      bundle,
      destinationDeployment: { tier: "self_hosted" },
      destinationGenesisRef: "genesis://tenant-a/self-hosted",
      createdAt: "2026-03-21T01:00:00.000Z",
    }),
    privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  );

  const verification = verifyCutoverContinuity({ bundle, bootstrapStatement: bootstrap });
  assert.equal(verification.ok, true);
  assert.equal(verification.signatureValid, true);
});

test("cutover continuity verification fails if bootstrap is altered", () => {
  const checkpoint = createCheckpointPayload({
    tenantId: "tenant-a",
    mailboxes: [{ tenant_id: "tenant-a", mailbox_id: "mbx-1", address: "ops@example.com" }],
    createdAt: "2026-03-21T00:00:00.000Z",
  });
  const bundle = createExportBundle({
    tenantId: "tenant-a",
    checkpoint,
    mailboxes: [{ tenant_id: "tenant-a", mailbox_id: "mbx-1", address: "ops@example.com" }],
  });
  const bootstrap = createBootstrapStatement({
    bundle,
    destinationDeployment: { tier: "community" },
    destinationGenesisRef: "genesis://tenant-a/community",
    createdAt: "2026-03-21T01:00:00.000Z",
  });
  bootstrap.destinationDeployment.tier = "self_hosted";

  const verification = verifyCutoverContinuity({ bundle, bootstrapStatement: bootstrap });
  assert.equal(verification.ok, false);
  assert.equal(verification.digestMatches, false);
});

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  assertVotingManifest,
  VOTING_MANIFEST_CONTRACT_VERSION
} from "./sdk/web/votingClient.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");

async function readJson(relPath) {
  const fullPath = path.join(repoRoot, relPath);
  const raw = await fs.readFile(fullPath, "utf8");
  return JSON.parse(raw);
}

function stableJson(value) {
  return JSON.stringify(value, null, 2);
}

function sharedVotingPolicy(manifest) {
  return {
    contract_version: manifest.contract_version,
    product_type: manifest.app?.product_type,
    anon_layer: {
      sdk_id: manifest.anon_layer?.sdk_id,
      black_box_required: manifest.anon_layer?.black_box_required,
      required_flows: manifest.anon_layer?.required_flows
    },
    identity: {
      provider: manifest.identity?.provider,
      mode: manifest.identity?.mode
    },
    signing: {
      required: manifest.signing?.required,
      backend: manifest.signing?.backend
    },
    deployment: manifest.deployment,
    receipts: manifest.receipts
  };
}

function predatoryComparablePolicy(manifest) {
  return {
    contract_version: manifest.contract_version,
    product_type: manifest.app?.product_type,
    anon_layer: {
      sdk_id: manifest.anon_layer?.sdk_id,
      black_box_required: manifest.anon_layer?.black_box_required,
      required_flows: manifest.anon_layer?.required_flows
    },
    identity: {
      provider: manifest.identity?.provider,
      mode: manifest.identity?.mode
    },
    signing: {
      required: manifest.signing?.required,
      backend: manifest.signing?.backend
    },
    deployment_runtime_fallbacks: manifest.deployment?.runtime_fallbacks,
    receipts_double_vote_enforcement:
      manifest.receipts?.double_vote_enforcement,
    receipts_high_risk_region_blocklist:
      manifest.receipts?.high_risk_region_blocklist ?? []
  };
}

function assertEqualPolicies(label, actual, expected) {
  if (stableJson(actual) !== stableJson(expected)) {
    throw new Error(
      `${label} drift detected.\nExpected:\n${stableJson(expected)}\nActual:\n${stableJson(actual)}`
    );
  }
}

const seda = await readJson("SEDA_HAQQ/shyconfig.json");
const sedaPredatory = await readJson(
  "SEDA_HAQQ/shyconfig.predatory_theocracy.json"
);
const populist = await readJson("POP-U-LIST/shyconfig.json");

for (const [label, manifest] of [
  ["SEDA_HAQQ/shyconfig.json", seda],
  ["SEDA_HAQQ/shyconfig.predatory_theocracy.json", sedaPredatory],
  ["POP-U-LIST/shyconfig.json", populist]
]) {
  assertVotingManifest(manifest);
  if (manifest.contract_version !== VOTING_MANIFEST_CONTRACT_VERSION) {
    throw new Error(
      `${label} has wrong contract_version: ${manifest.contract_version}`
    );
  }
}

assertEqualPolicies(
  "POP-U-LIST voting policy",
  sharedVotingPolicy(populist),
  sharedVotingPolicy(seda)
);

assertEqualPolicies(
  "SEDA_HAQQ predatory shared policy",
  predatoryComparablePolicy(sedaPredatory),
  predatoryComparablePolicy(seda)
);

if (sedaPredatory.deployment?.default_posture !== "coercion_resistant") {
  throw new Error(
    "SEDA_HAQQ/shyconfig.predatory_theocracy.json must declare default_posture=coercion_resistant"
  );
}

if (
  sedaPredatory.receipts?.match_store !== "none" ||
  sedaPredatory.receipts?.user_access !== "never"
) {
  throw new Error(
    "SEDA_HAQQ/shyconfig.predatory_theocracy.json must keep receipts disabled."
  );
}

console.log("Voting contract manifests are aligned.");

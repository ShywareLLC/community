// Polyfill window.crypto.subtle and window.crypto.getRandomValues for Node.js test environment
if (typeof globalThis.window === "undefined") {
  globalThis.window = {};
}
if (typeof window.crypto === "undefined") {
  const nodeCrypto = await import("crypto");
  window.crypto = {
    getRandomValues: (arr) => {
      const buf = nodeCrypto.randomBytes(arr.length);
      for (let i = 0; i < arr.length; i++) arr[i] = buf[i];
      return arr;
    },
    subtle: nodeCrypto.webcrypto.subtle
  };
}
// Polyfill localStorage for Node.js test environment
if (typeof globalThis.localStorage === "undefined") {
  let store = {};
  globalThis.localStorage = {
    getItem: (key) => (key in store ? store[key] : null),
    setItem: (key, value) => {
      store[key] = String(value);
    },
    removeItem: (key) => {
      delete store[key];
    },
    clear: () => {
      store = {};
    }
  };
}

// shybrowserClient.test.js
// Basic tests for shybrowserClient.js (structural invariant: no PII/session data is stored unsealed)

import test from "node:test";
import assert from "node:assert/strict";
import { createShybrowserClient } from "./clients/embodiments/shybrowserClient.js";

const manifest = {
  contract_version: "shybrowser-v1",
  sealer: { mode: "sealed_storage" }
};

test("should seal and store browser session data", async (t) => {
  localStorage.clear();
  const client = createShybrowserClient({
    manifest,
    deriveSealerKey: async () => "testkey"
  });
  const session = { user: "alice", tabs: ["https://example.com"] };
  const record = await client.storeSealedBrowserData(session, "session");
  assert.ok(record.sealedPayload);
  assert.equal(typeof record.sealedPayload.ciphertext, "object");
  // Should not store plaintext in localStorage
  const raw = localStorage.getItem("shybrowser_sessions");
  assert.ok(!raw.includes("alice"));
  assert.ok(!raw.includes("https://example.com"));
});

test("should retrieve and decrypt stored session data", async (t) => {
  localStorage.clear();
  const client = createShybrowserClient({
    manifest,
    deriveSealerKey: async () => "testkey"
  });
  const session = { user: "bob", bookmarks: ["https://shyware.fyi"] };
  await client.storeSealedBrowserData(session, "bookmarks");
  const decrypted = await client.getStoredBrowserDataDecrypted("bookmarks");
  assert.equal(decrypted.length, 1);
  assert.equal(decrypted[0].data.user, "bob");
  assert.equal(decrypted[0].data.bookmarks[0], "https://shyware.fyi");
});

test("should filter by category", async (t) => {
  localStorage.clear();
  const client = createShybrowserClient({
    manifest,
    deriveSealerKey: async () => "testkey"
  });
  await client.storeSealedBrowserData({ foo: 1 }, "foo");
  await client.storeSealedBrowserData({ bar: 2 }, "bar");
  const foo = client.getStoredBrowserData("foo");
  const bar = client.getStoredBrowserData("bar");
  assert.equal(foo.length, 1);
  assert.equal(bar.length, 1);
});

test("should submit List 2 identity attribute (mocked fetch, sealed)", async (t) => {
  // Mock fetch
  globalThis.fetch = async (url, opts) => {
    assert.equal(url, "/api/list2-identity");
    const body = JSON.parse(opts.body);
    assert.equal(body.category, "ip_address");
    // Should be a sealed payload, not plaintext
    assert.ok(body.sealedPayload);
    assert.ok(typeof body.sealedPayload.ciphertext === "object");
    // Should not contain plaintext value
    const ciphertextStr = JSON.stringify(body.sealedPayload.ciphertext);
    assert.ok(!ciphertextStr.includes("203.0.113.42"));
    return { ok: true, json: async () => ({ success: true }) };
  };
  const client = createShybrowserClient({
    manifest,
    deriveSealerKey: async () => "testkey"
  });
  const result = await client.submitList2IdentityAttribute("203.0.113.42");
  assert.equal(result.success, true);
});

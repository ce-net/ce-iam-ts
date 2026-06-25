// SDK smoke + golden-vector parity test (Node's built-in test runner, run against the COMPILED
// dist/ output). Exercises the full vault surface over a MemStore and then verifies the SAME
// `secrets_vectors.json` the Rust golden test uses (produced by the canonical JS vault), proving the
// SDK -> wasm -> ce-iam-core path agrees byte-for-byte with the JS reference.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { openVault, generateDeviceKey, verify, MemStore, ready } from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));

// In Node, hand the wasm bytes to ready() explicitly (the browser fetches them via import.meta.url).
async function initWasm() {
  const wasmPath = join(here, "..", "dist", "wasm", "ce_iam_core_wasm_bg.wasm");
  await ready(await readFile(wasmPath));
}

const FIXED_CLOCK = () => "2026-06-26T00:00:00.000Z";

test("vault lifecycle: init, put/get, list, fingerprint, delete", async () => {
  await initWasm();
  const store = new MemStore();
  const v = await openVault({ ns: "ts-ns", store, now: FIXED_CLOCK });

  assert.equal(await v.init("owner"), true);
  assert.equal(await v.init("owner"), false, "second init is a no-op");
  assert.equal(await v.isEnrolled(), true);

  const meta = await v.putString("api-key", "s3cr3t");
  assert.equal(meta.name, "api-key");
  assert.equal(meta.version, 1);
  assert.equal(await v.getString("api-key"), "s3cr3t");

  const meta2 = await v.putString("api-key", "rotated");
  assert.equal(meta2.version, 2, "re-put bumps the version");

  const list = await v.listSecrets();
  assert.equal(list.length, 1);
  assert.ok(await v.fingerprint("api-key"));

  await v.deleteSecret("api-key");
  assert.equal((await v.listSecrets()).length, 0);
});

test("two devices over one store: pair, approve, second device reads", async () => {
  await initWasm();
  const store = new MemStore(); // the shared durable store (the mesh KV in production)

  const owner = await openVault({ ns: "ns", store, now: FIXED_CLOCK });
  await owner.init("owner");
  await owner.putString("k", "v");

  // A fresh device requests pairing on the SAME store.
  const phoneKey = await generateDeviceKey();
  const phone = await openVault({ ns: "ns", store, device: phoneKey, now: FIXED_CLOCK });
  const code = await phone.requestPairing("phone");
  assert.equal(await phone.isEnrolled(), false);

  // Owner approves -> phone enrolled and can read the master-sealed secret.
  await owner.approve(code);
  assert.equal(await phone.isEnrolled(), true);
  assert.equal(await phone.getString("k"), "v");
});

test("grant: issue, verify, scope, revoke", async () => {
  await initWasm();
  const v = await openVault({ ns: "ns", store: new MemStore(), now: FIXED_CLOCK });
  await v.init("owner");

  const g = await v.grant("ce-cast", ["db-pw"]);
  await v.verifyGrant(g.token, "ce-cast", "read", "db-pw", 0); // resolves
  await assert.rejects(v.verifyGrant(g.token, "other", "read", "db-pw", 0));
  await assert.rejects(v.verifyGrant(g.token, "ce-cast", "read", "nope", 0));

  await v.revokeGrant(g.id);
  await assert.rejects(v.verifyGrant(g.token, "ce-cast", "read", "db-pw", 0));
});

test("challenge-response auth roundtrip", async () => {
  await initWasm();
  const v = await openVault({ ns: "ns", store: new MemStore(), now: FIXED_CLOCK });
  await v.init("owner");

  const proof = await v.signChallenge("ce-watch", "n0", "2026-06-26T00:00:00.000Z");
  const who = await v.verifyAuth("ce-watch", "n0", proof);
  assert.equal(who, v.deviceId());
  await assert.rejects(v.verifyAuth("ce-watch", "wrong", proof));
});

test("GOLDEN: SDK verifies the JS-issued challenge + grant + opens the JS-sealed secret", async () => {
  await initWasm();
  const vectors = JSON.parse(
    await readFile(
      join(here, "..", "..", "ce-iam-core-wasm", "tests", "fixtures", "secrets_vectors.json"),
      "utf8",
    ),
  );

  // Seed a store with the JS enrollment + grant + secret records, then drive the SDK over the SAME
  // owner device key. The SDK must verify/open them, proving end-to-end JS<->wasm parity.
  const store = new MemStore();
  await store.put(vectors.enrollment.key, vectors.enrollment.record);
  await store.put(`g.${vectors.grant.record.id}`, vectors.grant.record);
  const secretName = vectors.secretRecord.record.name;
  await store.put(`s.${secretName}`, vectors.secretRecord.record);

  const ownerKey = JSON.stringify(vectors.owner);
  const v = await openVault({ ns: vectors.ns, store, device: ownerKey, now: FIXED_CLOCK });

  assert.equal(v.deviceId(), vectors.deviceId, "device id matches the JS vault");
  assert.equal(await v.isEnrolled(), true);

  // The JS-signed challenge verifies.
  const who = await v.verifyAuth(vectors.challenge.aud, vectors.challenge.nonce, vectors.challenge.proof);
  assert.equal(who, vectors.deviceId);

  // The JS-issued grant token verifies.
  await v.verifyGrant(
    vectors.grant.token,
    vectors.grant.audience,
    vectors.grant.action,
    vectors.grant.name,
    0,
  );

  // The JS-sealed secret opens to the same plaintext (master-derived parity).
  assert.equal(await v.getString(secretName), vectors.secretSealed.expectOpenPlaintext);
});

test("capability verify: empty chain is default-denied (throws)", async () => {
  await initWasm();
  const id = "00".repeat(32);
  await assert.rejects(
    verify({ selfId: id, requester: id, action: "exec", chain: [] }),
    /no capability presented/,
  );
});

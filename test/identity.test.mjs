// Identities API: create / list / private-key reveal, and persistence across a reopen (the device key
// is persisted and recover() is idempotent, so identities survive between sessions). Runs against the
// COMPILED dist/ output over MemStores, no browser/mesh needed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { Identities, MemStore, ready } from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
async function initWasm() {
  await ready(await readFile(join(here, "..", "dist", "wasm", "ce_iam_core_wasm_bg.wasm")));
}

test("identities: create, list, key reveal, public view hides the key", async () => {
  await initWasm();
  const store = new MemStore();
  const deviceStore = new MemStore();
  const ids = await Identities.open({ ns: "test-ids", store, deviceStore });

  const a = await ids.create("Astral Falcon");
  assert.equal(a.name, "Astral Falcon");
  assert.equal(a.id, a.peerId, "the id IS the peer id");
  assert.ok(a.peerId.length > 10);
  assert.equal(a.node, null);
  assert.equal(/** @type {any} */ (a).key, undefined, "public view must not carry the private key");

  // the sealed private key reveals on demand and round-trips to a usable libp2p key
  const proto = await ids.privateKeyProtobuf(a.id);
  assert.ok(proto instanceof Uint8Array && proto.length > 0);
  const pk = await ids.libp2pPrivateKey(a.id);
  assert.ok(pk && typeof pk.sign === "function", "returns a usable libp2p PrivateKey");

  await ids.create("Iron Nomad");
  const all = await ids.list();
  assert.equal(all.length, 2);
  assert.deepEqual(all.map((i) => i.name).sort(), ["Astral Falcon", "Iron Nomad"]);
});

test("identities: survive a reopen (device key persisted, recover idempotent)", async () => {
  await initWasm();
  const store = new MemStore();
  const deviceStore = new MemStore();

  const ids1 = await Identities.open({ ns: "persist-ids", store, deviceStore });
  const a = await ids1.create("Lone Comet");
  const dev1 = await deviceStore.get("device");
  assert.equal(typeof dev1, "string", "device key was persisted on first open");

  // Reopen against the SAME stores — same device, vault already enrolled, secrets still decryptable.
  const ids2 = await Identities.open({ ns: "persist-ids", store, deviceStore });
  const all = await ids2.list();
  assert.equal(all.length, 1);
  assert.equal(all[0].id, a.id);
  assert.equal(all[0].name, "Lone Comet");
  // and the private key still reveals after reopen
  const proto = await ids2.privateKeyProtobuf(a.id);
  assert.ok(proto.length > 0);
  assert.equal(await deviceStore.get("device"), dev1, "device key unchanged across reopen");
});

# @ce-net/iam

The TypeScript SDK over [`ce-iam-core-wasm`](../ce-iam-core-wasm): the CE **secrets vault** +
**capability verify** for the browser and Node. All crypto and vault orchestration runs in the wasm
module — the SAME Rust code the `ce-iam` CLI runs — so the SDK, the CLI, and the `ce-secrets` JS
reference agree byte-for-byte (golden-vectored). This SDK only marshals JSON across the wasm boundary
and syncs the wasm's in-memory store to a pluggable durable store.

It is a **drop-in for ce-cast's vendored vault**: the surface (`openVault`/`recover`/`get`/`put`/
`grant`/`verify` + device pairing + grant verify + challenge-response auth) matches the verbs
`ce-cast/web/src/vault/{vault.mjs,delivery.ts}` call today, and `openVault({ store })` takes the SAME
`{ get, put, del, list }` mesh-KV store object ce-cast already builds.

## Install / build

```bash
npm install
npm run build      # tsc -> dist/, then vendors the wasm-pack output into dist/wasm
npm test           # node --test: full vault surface + golden-vector parity against the JS reference
```

The wasm artifacts are produced by `ce-iam-core-wasm` (`wasm-pack build --target web --out-dir
ce-iam-ts/src/wasm`) and vendored under `src/wasm` so consumers need no Rust toolchain.

## Use

```ts
import { openVault, verify, MemStore } from "@ce-net/iam";

// `store` is any { get, put, del, list } — in the browser, ce-cast's mesh-KV adapter; here, in-memory.
const vault = await openVault({ ns: "vault-c0be11e0ce", store: new MemStore() });

await vault.init("my laptop");                       // establish from the owner key
await vault.putString("ce-cast-publish", relayKey);  // seal a secret under the master
const key = await vault.getString("ce-cast-publish");// reveal it (for injection/use only)

// Issue + verify a scoped read-grant to another audience.
const g = await vault.grant("ce-cast", ["ce-cast-publish"]);
await vault.verifyGrant(g.token, "ce-cast", "read", "ce-cast-publish"); // resolves, or throws

// Enroll a second device (it requestPairing()s on the shared store; an enrolled device approves).
const code = await otherDevice.requestPairing("phone");
await vault.approve(code);

// Capability verify (ce_cap::authorize) — VERIFY only, minting never enters the browser.
const ok = await verify({ selfId, requester, action: "exec", chain }); // true, or throws the reason
```

### ce-cast migration

ce-cast's `delivery.ts` builds a mesh-KV store and a persisted device key, then calls its vendored
`V.isEnrolled` / `V.requestPairing` / `V.revealSecret`. To swap to this SDK:

```ts
import { openVault } from "@ce-net/iam";

const vault = await openVault({ ns, store: this.meshStore(ns), device: await this.device() });
const enrolled = await vault.isEnrolled();
const code = await vault.requestPairing(label);
const key = await vault.getString("ce-cast-publish");   // replaces V.revealSecret -> utf8
```

The crypto/vault core is now the wasm (one implementation), not vendored `crypto.mjs`/`vault.mjs`.

## API surface

- `ready(moduleOrPath?)` — initialise the wasm once (browser: bundler resolves the `.wasm`; Node: pass
  the bytes). Called automatically by `openVault`/`generateDeviceKey`/`verify`.
- `generateDeviceKey(): Promise<string>` — a fresh device-key bundle (persist it).
- `openVault({ ns, store, device?, now? }): Promise<Vault>`.
- `Vault`: `deviceKey()` · `deviceId()` · `namespace()` · `exists()` · `isEnrolled()` · `init(label?)`
  · `recover(label?)` · `requestPairing(label?)` · `listPairing()` · `approve(code)` · `listDevices()`
  · `revokeDevice(id)` · `put(name, bytes, kind?)` / `putString(name, value, kind?)` · `get(name)` /
  `getString(name)` · `listSecrets()` · `fingerprint(name)` · `deleteSecret(name)` · `grant(audience,
  names, expires?)` · `listGrants()` · `revokeGrant(id)` · `verifyGrant(token, audience, action, name,
  nowMs?)` · `signChallenge(aud, nonce, ts?)` · `verifyAuth(aud, nonce, proof)`.
- `verify({ selfId, requester, action, chain, acceptedRoots?, selfTags?, revoked?, now? }):
  Promise<boolean>` — `ce_cap::authorize`; returns `true` or throws the denial reason.
- `VaultStore` / `StoreEntry` / `MemStore` (also at `@ce-net/iam/store`).

### Passwordless node-auth (`@ce-net/iam/nodeauth`)

"Log in with your local CE node" — authorize an app via your own node instead of a password. Also
re-exported from the package root.

- `authorizeApp(options: AuthorizeAppOptions): Promise<AppGrant>` — ask your local node to mint an
  app grant over the mesh.
- `discoverNodes(transport: MeshTransport): Promise<NodeInfo[]>` — find candidate nodes that can
  authenticate you.
- `T_ANNOUNCE`, `tReq(...)`, `tResp(...)` — the mesh topic + request/response helpers.
- Types: `MeshTransport`, `MeshMessage`, `NodeInfo`, `AuthorizeAppOptions`, `AppGrant`.

## License

AGPL-3.0-only. A commercial license is also available — see [`LICENSING.md`](./LICENSING.md)
and [`COMMERCIAL-LICENSE.md`](./COMMERCIAL-LICENSE.md).

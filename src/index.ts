/**
 * # ce-iam-ts — the TypeScript SDK over `ce-iam-core-wasm`
 *
 * A thin, drop-in vault SDK for the browser (and Node): all crypto + vault orchestration runs in the
 * `ce-iam-core-wasm` wasm module — the SAME Rust code the `ce-iam` CLI runs — so the SDK, the CLI, and
 * the `ce-secrets` JS reference agree byte-for-byte (golden-vectored). This SDK only marshals JSON
 * across the wasm boundary and syncs the wasm's in-memory store to a pluggable durable {@link VaultStore}.
 *
 * ## Why a snapshot bridge
 *
 * The wasm vault operates over an in-memory store (so it stays synchronous + free of an async runtime
 * — see ce-iam-core-wasm's module docs). The durable store (the mesh KV) lives here in TS. So every
 * op: (1) loads the namespace's entries from the {@link VaultStore} into the wasm as a snapshot,
 * (2) runs the op in wasm, (3) diffs the resulting snapshot and persists the changed/new/removed keys
 * back to the store. The caller never sees this — they get plain async methods.
 *
 * ## Surface (matches ce-cast's vault usage)
 *
 * `openVault()` / `recover()` / `get()` / `put()` / `grant()` / `verify()` plus device pairing
 * (`requestPairing`/`approve`/`listDevices`), grant verify (`verifyGrant`), and challenge-response
 * auth (`signChallenge`/`verifyAuth`) — the same verbs `ce-cast/web/src/vault/{vault.mjs,delivery.ts}`
 * call today, so ce-cast can replace its vendored `crypto.mjs`/`vault.mjs` with this SDK.
 *
 * @packageDocumentation
 */

import initWasm, {
  WasmVault,
  verify as wasmVerify,
  init as wasmInit,
} from "./wasm/ce_iam_core_wasm.js";

import { type VaultStore, type StoreEntry, MemStore } from "./store.js";

export { type VaultStore, type StoreEntry, MemStore };

// Passwordless app authorization via your local CE node (the reusable consent primitive).
export {
  authorizeApp,
  discoverNodes,
  T_ANNOUNCE,
  tReq,
  tResp,
  type MeshTransport,
  type MeshMessage,
  type NodeInfo,
  type AuthorizeAppOptions,
  type AppGrant,
} from "./nodeauth.js";

// Named mesh identities (libp2p keypairs) managed in the vault — the reusable home for "create/list/
// select a player identity" so apps don't reinvent keypair gen + vault wiring + the node-vouch flow.
export { Identities, IdbStore, type Identity, type IdentitiesOptions } from "./identity.js";

// ---- wasm module init ---------------------------------------------------------------------------

let wasmReady: Promise<void> | null = null;

/**
 * Initialise the wasm module once. In the browser pass the URL/Response of the `.wasm` asset
 * (bundlers usually resolve `new URL("./wasm/ce_iam_core_wasm_bg.wasm", import.meta.url)`); in Node
 * the default fetch of the co-located file works. Safe to call repeatedly — it initialises once.
 */
export async function ready(
  moduleOrPath?: RequestInfo | URL | Response | BufferSource | WebAssembly.Module,
): Promise<void> {
  if (!wasmReady) {
    wasmReady = (async () => {
      await initWasm(moduleOrPath ? { module_or_path: moduleOrPath } : undefined);
      wasmInit(); // route Rust panics to console.error
    })();
  }
  return wasmReady;
}

// ---- types ---------------------------------------------------------------------------------------

/** A `DeviceKey` JSON bundle (the `generateDeviceKey()` form) — this device's vault identity. */
export type DeviceKeyJson = string;

/** Public metadata of a secret (never the bytes), as returned by {@link Vault.putSecret}/`listSecrets`. */
export interface SecretMeta {
  name: string;
  kind: string;
  version: number;
  fp: string;
  public: string | null;
  createdAt: string;
  rotatedAt: string | null;
}

/** An enrolled device, as returned by {@link Vault.listDevices}. */
export interface DeviceInfo {
  id: string;
  label: string;
  addedAt: string;
  self: boolean;
}

/** An issued grant, as returned by {@link Vault.grant}. */
export interface IssuedGrant {
  id: string;
  token: string;
  record: unknown;
}

/** Options for {@link openVault}. */
export interface OpenVaultOptions {
  /** The vault namespace (folds into the owner-master derivation; e.g. `vault-<castId>`). */
  ns: string;
  /** The durable store the vault reads/writes (the mesh KV in the browser). */
  store: VaultStore;
  /** This device's key bundle. If omitted, a fresh one is generated and returned via {@link Vault.deviceKey}. */
  device?: DeviceKeyJson;
  /** Clock for record timestamps; defaults to `() => new Date().toISOString()`. Inject for tests. */
  now?: () => string;
}

// ---- the vault -----------------------------------------------------------------------------------

/**
 * A secrets vault bound to one namespace, one device key, and one durable {@link VaultStore}.
 *
 * Construct via {@link openVault}. Every method loads the latest store state, runs the op in wasm,
 * and (for mutations) persists the diff back — so two devices pointed at the same durable store
 * converge, exactly as the CLI and the browser do over the mesh KV.
 */
export class Vault {
  private constructor(
    private readonly store: VaultStore,
    private readonly device: DeviceKeyJson,
    private readonly ns: string,
    private readonly now: () => string,
  ) {}

  /** @internal — use {@link openVault}. */
  static async _open(opts: OpenVaultOptions): Promise<Vault> {
    await ready();
    const device = opts.device ?? WasmVault.generateDeviceKey();
    const now = opts.now ?? (() => new Date().toISOString());
    return new Vault(opts.store, device, opts.ns, now);
  }

  /** This device's key bundle (persist it; it is this device's identity in the vault). */
  deviceKey(): DeviceKeyJson {
    return this.device;
  }

  /** This device's stable vault id. */
  deviceId(): string {
    return this.withVault((v) => v.deviceId);
  }

  /** This vault's namespace. */
  namespace(): string {
    return this.ns;
  }

  // ---- store <-> wasm snapshot bridge ------------------------------------------------------------

  /** Load the whole namespace into a fresh WasmVault seeded from the durable store. */
  private async loadVault(): Promise<{ v: WasmVault; before: Map<string, string> }> {
    const entries = await this.store.list("");
    const snap: Record<string, unknown> = {};
    const before = new Map<string, string>();
    for (const e of entries) {
      snap[e.key] = e.value;
      before.set(e.key, JSON.stringify(e.value));
    }
    const v = new WasmVault(this.device, this.ns, this.now());
    v.loadSnapshot(JSON.stringify(snap));
    return { v, before };
  }

  /** Persist the diff between the wasm vault's snapshot and what we loaded, then free the vault. */
  private async persist(v: WasmVault, before: Map<string, string>): Promise<void> {
    const after = JSON.parse(v.snapshot()) as Record<string, unknown>;
    const afterKeys = new Set(Object.keys(after));
    // Upserts: any key whose serialized value changed (or is new).
    for (const [key, value] of Object.entries(after)) {
      const ser = JSON.stringify(value);
      if (before.get(key) !== ser) await this.store.put(key, value);
    }
    // Deletions: keys we loaded that are gone from the snapshot.
    for (const key of before.keys()) {
      if (!afterKeys.has(key)) await this.store.del(key);
    }
    v.free();
  }

  /** Run a READ-ONLY op against a vault loaded from the store (no persist). */
  private async read<T>(fn: (v: WasmVault) => T): Promise<T> {
    const { v } = await this.loadVault();
    try {
      return fn(v);
    } finally {
      v.free();
    }
  }

  /** Run a MUTATING op, then persist the diff back to the store. */
  private async write<T>(fn: (v: WasmVault) => T): Promise<T> {
    const { v, before } = await this.loadVault();
    let out: T;
    try {
      out = fn(v);
    } catch (e) {
      v.free();
      throw e;
    }
    await this.persist(v, before);
    return out;
  }

  /** Synchronous helper for pure-local fields (deviceId) — loads, reads, frees. */
  private withVault<T>(fn: (v: WasmVault) => T): T {
    const v = new WasmVault(this.device, this.ns, this.now());
    try {
      return fn(v);
    } finally {
      v.free();
    }
  }

  // ---- lifecycle ---------------------------------------------------------------------------------

  /** True if the vault has been initialised (a `meta` record exists). */
  exists(): Promise<boolean> {
    return this.read((v) => v.exists());
  }

  /** True if THIS device is enrolled (can decrypt the master). */
  isEnrolled(): Promise<boolean> {
    return this.read((v) => v.isEnrolled());
  }

  /** Establish the vault from this (owner) device. Returns `false` if one already exists. */
  init(label = "this device (owner)"): Promise<boolean> {
    return this.write((v) => v.init(label));
  }

  /**
   * Re-establish the vault from the OWNER's key alone (re-derive the deterministic master, re-enroll
   * this device). Idempotent — safe after a store wipe so the owner is never locked out.
   */
  recover(label = "this device (owner)"): Promise<void> {
    return this.write((v) => v.recover(label));
  }

  // ---- devices / pairing -------------------------------------------------------------------------

  /** Publish a pairing request for this (unenrolled) device; returns the human-typable code. */
  requestPairing(label = "new device"): Promise<string> {
    return this.write((v) => v.requestPairing(label));
  }

  /** Pending pairing requests. */
  listPairing(): Promise<unknown[]> {
    return this.read((v) => JSON.parse(v.listPairing()) as unknown[]);
  }

  /** Approve a pairing request (wrap the master to the new device, enroll it). Returns its id. */
  approve(code: string): Promise<string> {
    return this.write((v) => v.approvePairing(code));
  }

  /** Enrolled devices. */
  listDevices(): Promise<DeviceInfo[]> {
    return this.read((v) => JSON.parse(v.listDevices()) as DeviceInfo[]);
  }

  /** Remove a device's enrollment (refuses to revoke the device you are using). */
  revokeDevice(id: string): Promise<void> {
    return this.write((v) => v.revokeDevice(id));
  }

  // ---- secrets -----------------------------------------------------------------------------------

  /** Store opaque secret bytes under `name`, sealed under the master. Returns the public metadata. */
  put(name: string, bytes: Uint8Array, kind = "opaque"): Promise<SecretMeta> {
    return this.write((v) => JSON.parse(v.putSecret(name, bytes, kind)) as SecretMeta);
  }

  /** Store a UTF-8 string secret (convenience over {@link put}). */
  putString(name: string, value: string, kind = "opaque"): Promise<SecretMeta> {
    return this.put(name, new TextEncoder().encode(value), kind);
  }

  /** Reveal the raw secret bytes — for INJECTION/USE only. Never display these. Throws if absent. */
  get(name: string): Promise<Uint8Array> {
    return this.read((v) => v.getSecret(name));
  }

  /** Reveal a secret as a UTF-8 string (convenience over {@link get}). */
  async getString(name: string): Promise<string> {
    return new TextDecoder().decode(await this.get(name));
  }

  /** Secret metadata (never bytes), sorted by name. */
  listSecrets(): Promise<SecretMeta[]> {
    return this.read((v) => JSON.parse(v.listSecrets()) as SecretMeta[]);
  }

  /** The displayable fingerprint of a named secret, or `null`. */
  fingerprint(name: string): Promise<string | null> {
    return this.read((v) => v.fingerprint(name) ?? null);
  }

  /** Delete a named secret. */
  deleteSecret(name: string): Promise<void> {
    return this.write((v) => v.deleteSecret(name));
  }

  // ---- grants ------------------------------------------------------------------------------------

  /**
   * Issue a signed read-grant to `audience` for the given secret `names`, optionally expiring at
   * `expires` (ISO-8601). Returns `{ id, token, record }`. Only an enrolled device may issue.
   */
  grant(audience: string, names: string[], expires?: string): Promise<IssuedGrant> {
    return this.write(
      (v) => JSON.parse(v.issueGrant(audience, JSON.stringify(names), expires ?? "")) as IssuedGrant,
    );
  }

  /** Issued grants. */
  listGrants(): Promise<unknown[]> {
    return this.read((v) => JSON.parse(v.listGrants()) as unknown[]);
  }

  /** Revoke (delete) an issued grant by id. */
  revokeGrant(id: string): Promise<void> {
    return this.write((v) => v.revokeGrant(id));
  }

  /**
   * Verify a presented grant `token` authorizes `action` on secret `name` for `audience`, against
   * THIS vault's enrolled devices + un-revoked grants. Resolves on success; rejects with the reason.
   * `nowMs` defaults to `Date.now()`.
   */
  verifyGrant(
    token: string,
    audience: string,
    action: string,
    name: string,
    nowMs: number = Date.now(),
  ): Promise<void> {
    return this.read((v) => v.verifyGrant(token, audience, action, name, nowMs));
  }

  // ---- challenge-response auth -------------------------------------------------------------------

  /**
   * This device signs a fresh challenge, proving it is an enrolled operator. Returns the auth proof
   * object the relying party verifies. `ts` defaults to now.
   */
  signChallenge(aud: string, nonce: string, ts: string = new Date().toISOString()): Promise<unknown> {
    return this.read((v) => JSON.parse(v.signChallenge(aud, nonce, ts)) as unknown);
  }

  /**
   * Verify an auth proof: valid signature, signer enrolled, aud/nonce match. Returns the proven
   * device id; rejects otherwise.
   */
  verifyAuth(aud: string, nonce: string, proof: unknown): Promise<string> {
    return this.read((v) => v.verifyAuth(aud, nonce, JSON.stringify(proof)));
  }
}

/**
 * Open a vault over a durable store. Generates a fresh device key if none is supplied (read it back
 * with {@link Vault.deviceKey} and persist it). Initialises the wasm module on first call.
 */
export async function openVault(opts: OpenVaultOptions): Promise<Vault> {
  return Vault._open(opts);
}

/** Generate a fresh device-key bundle (persist it; it is a device's vault identity). */
export async function generateDeviceKey(): Promise<DeviceKeyJson> {
  await ready();
  return WasmVault.generateDeviceKey();
}

// ---- capability VERIFY ---------------------------------------------------------------------------

/** Inputs to {@link verify} — a presented capability chain and the verifier's context. */
export interface VerifyInput {
  /** This node's 32-byte id as hex (the resource owner / verifier). */
  selfId: string;
  /** The requester's 32-byte id as hex. */
  requester: string;
  /** The action being authorized (an opaque ability string). */
  action: string;
  /** The presented chain — an array of `SignedCapability` records (root first). */
  chain: unknown[];
  /** Hex node ids trusted as roots besides `selfId` (default `[]`). */
  acceptedRoots?: string[];
  /** This node's tag strings, for tag-scoped resources (default `[]`). */
  selfTags?: string[];
  /** Known-revoked `[issuerHex, nonce]` pairs (default `[]`). */
  revoked?: [string, number][];
  /** Current unix SECONDS (default `Math.floor(Date.now()/1000)`). */
  now?: number;
}

/**
 * Verify a presented capability chain authorizes `requester` to perform `action` on `selfId`, using
 * `ce_cap::authorize` (VERIFY only — minting is never in the browser). Returns `true` if authorized;
 * THROWS with the denial reason otherwise (default-deny on an empty/invalid chain).
 */
export async function verify(input: VerifyInput): Promise<boolean> {
  await ready();
  return wasmVerify(
    input.selfId,
    JSON.stringify(input.acceptedRoots ?? []),
    JSON.stringify(input.selfTags ?? []),
    input.now ?? Math.floor(Date.now() / 1000),
    input.requester,
    input.action,
    JSON.stringify(input.chain),
    JSON.stringify(input.revoked ?? []),
  );
}

/* tslint:disable */
/* eslint-disable */

/**
 * A browser-side secrets vault: a vault bound to one device key + namespace, operating over an
 * in-memory snapshot of the namespace's store entries (see the module docs for the store split).
 */
export class WasmVault {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Approve a pairing request (wrap the master to the new device, enroll it). Returns its id.
     */
    approvePairing(code: string): string;
    /**
     * Delete a named secret.
     */
    deleteSecret(name: string): void;
    /**
     * True if the vault has been initialised (a `meta` record exists).
     */
    exists(): boolean;
    /**
     * The displayable fingerprint of a named secret, or `null`.
     */
    fingerprint(name: string): string | undefined;
    /**
     * Generate a fresh device key as the JS-compatible `DeviceKey` JSON string. Persist it in the
     * browser; it is this device's identity in the vault.
     */
    static generateDeviceKey(): string;
    /**
     * Reveal the raw secret bytes — for INJECTION/USE only. Never display these.
     */
    getSecret(name: string): Uint8Array;
    /**
     * Establish the vault from this (owner) device. Returns `false` if one already exists.
     */
    init(label: string): boolean;
    /**
     * True if THIS device is enrolled (can decrypt the master).
     */
    isEnrolled(): boolean;
    /**
     * Issue a signed read-grant to `audience` for the secret `names_json` (JSON array of names),
     * optionally expiring at `expires` (ISO-8601, or empty). Returns `{ id, token, record }` JSON.
     */
    issueGrant(audience: string, names_json: string, expires: string): string;
    /**
     * List enrolled devices as a JSON array of `{ id, label, addedAt, self }`.
     */
    listDevices(): string;
    /**
     * List issued grants as a JSON array.
     */
    listGrants(): string;
    /**
     * List pending pairing requests as a JSON array.
     */
    listPairing(): string;
    /**
     * List secret metadata (never bytes) as a JSON array, sorted by name.
     */
    listSecrets(): string;
    /**
     * Seed the in-memory store from a snapshot JSON object `{ "<key>": <value>, ... }` (replaces the
     * current contents). Call with the entries fetched off the mesh KV before running ops.
     */
    loadSnapshot(snapshot_json: string): void;
    /**
     * Build a vault for `device_json` (a `DeviceKey` JSON bundle, the `generateDeviceKey()` form) in
     * `ns`, stamping records with `now_iso` (an ISO-8601 UTC string, e.g. `new Date().toISOString()`
     * — injected so wasm never reaches `SystemTime`). Start empty; call `loadSnapshot` to seed it.
     */
    constructor(device_json: string, ns: string, now_iso: string);
    /**
     * Store opaque secret bytes under `name`, sealed under the master. Returns public metadata JSON.
     */
    putSecret(name: string, bytes: Uint8Array, kind: string): string;
    /**
     * Re-establish the vault from the OWNER's key alone (re-derive the master, re-enroll). Idempotent.
     */
    recover(label: string): void;
    /**
     * Publish a pairing request for this (unenrolled) device; returns the human-typable code.
     */
    requestPairing(label: string): string;
    /**
     * Remove a device's enrollment (refuses to revoke the device you are using).
     */
    revokeDevice(id: string): void;
    /**
     * Revoke (delete) an issued grant by id.
     */
    revokeGrant(id: string): void;
    /**
     * This device signs a fresh challenge, proving it is an enrolled operator. Returns the auth proof
     * JSON the relying party verifies.
     */
    signChallenge(aud: string, nonce: string, ts: string): string;
    /**
     * Export the current in-memory store as a snapshot JSON object `{ "<key>": <value>, ... }`.
     */
    snapshot(): string;
    /**
     * Verify an auth proof (JSON): valid signature, signer enrolled, aud/nonce match. Returns the
     * proven device id; throws otherwise.
     */
    verifyAuth(aud: string, nonce: string, proof_json: string): string;
    /**
     * Verify a presented grant `token` authorizes `action` on secret `name` for `audience`, against
     * THIS vault's enrolled devices + un-revoked grants. `now_ms` is the unix-ms clock. Throws on
     * denial with the reason.
     */
    verifyGrant(token: string, audience: string, action: string, name: string, now_ms: number): void;
    /**
     * This device's stable vault id.
     */
    readonly deviceId: string;
    /**
     * This device's PUBLIC projection (`{id, ecdhPub, ecdsaPub}`) as JSON — safe to share.
     */
    readonly devicePublic: string;
    /**
     * This vault's namespace.
     */
    readonly namespace: string;
}

/**
 * Called once from JS (`init()`): route Rust panics to `console.error` for debuggability.
 */
export function init(): void;

/**
 * Verify a presented capability chain authorizes `requester` to perform `action` on `self_id`.
 *
 * Pure `ce_cap::authorize` — VERIFY only. Inputs are the same JSON shapes the node uses on the wire:
 *   * `self_id_hex` / `requester_hex` — 32-byte node ids as hex.
 *   * `accepted_roots_json` — JSON array of hex node ids trusted as roots (besides self).
 *   * `self_tags_json` — JSON array of this node's tag strings (for tag-scoped resources).
 *   * `chain_json` — JSON array of `SignedCapability` (root first).
 *   * `revoked_json` — JSON array of `[issuerHex, nonce]` pairs known revoked (or `[]`).
 *   * `now` — current unix seconds.
 *
 * Returns `true` if authorized; throws a `JsValue` string with the denial reason otherwise.
 * Default-deny: an empty/invalid chain is denied.
 */
export function verify(self_id_hex: string, accepted_roots_json: string, self_tags_json: string, now: number, requester_hex: string, action: string, chain_json: string, revoked_json: string): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_wasmvault_free: (a: number, b: number) => void;
    readonly verify: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number) => [number, number, number];
    readonly wasmvault_approvePairing: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmvault_deleteSecret: (a: number, b: number, c: number) => [number, number];
    readonly wasmvault_deviceId: (a: number) => [number, number];
    readonly wasmvault_devicePublic: (a: number) => [number, number, number, number];
    readonly wasmvault_exists: (a: number) => [number, number, number];
    readonly wasmvault_fingerprint: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmvault_generateDeviceKey: () => [number, number, number, number];
    readonly wasmvault_getSecret: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmvault_init: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmvault_isEnrolled: (a: number) => [number, number, number];
    readonly wasmvault_issueGrant: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly wasmvault_listDevices: (a: number) => [number, number, number, number];
    readonly wasmvault_listGrants: (a: number) => [number, number, number, number];
    readonly wasmvault_listPairing: (a: number) => [number, number, number, number];
    readonly wasmvault_listSecrets: (a: number) => [number, number, number, number];
    readonly wasmvault_loadSnapshot: (a: number, b: number, c: number) => [number, number];
    readonly wasmvault_namespace: (a: number) => [number, number];
    readonly wasmvault_new: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly wasmvault_putSecret: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly wasmvault_recover: (a: number, b: number, c: number) => [number, number];
    readonly wasmvault_requestPairing: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmvault_revokeDevice: (a: number, b: number, c: number) => [number, number];
    readonly wasmvault_revokeGrant: (a: number, b: number, c: number) => [number, number];
    readonly wasmvault_signChallenge: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly wasmvault_snapshot: (a: number) => [number, number, number, number];
    readonly wasmvault_verifyAuth: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly wasmvault_verifyGrant: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number];
    readonly init: () => void;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;

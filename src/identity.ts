/**
 * identity.ts — named MESH IDENTITIES (libp2p keypairs) managed in the ce-iam vault.
 *
 * Every CE browser app needs the same thing: let a user pick or create a persistent player/peer
 * identity — a libp2p keypair + a display name — kept ENCRYPTED at rest, and optionally vouched for by
 * the user's own local CE node (a node-signed capability). This is the reusable home for that, so apps
 * (spacegame, cerena, …) don't each reinvent keypair generation, vault wiring, device-key persistence,
 * and the node-vouch flow. The app keeps only its own last-inch wiring: WHERE it injects the key, what
 * globals it sets, and its UI.
 *
 * An Identity = an Ed25519 libp2p keypair (its peerId IS its id) + a name, stored as ONE encrypted
 * vault secret `id.<peerId>`. The raw private key is sealed in the vault and only revealed on demand via
 * {@link Identities.libp2pPrivateKey} / {@link Identities.privateKeyProtobuf}.
 */

import { generateKeyPair, privateKeyToProtobuf, privateKeyFromProtobuf } from "@libp2p/crypto/keys";
import type { PrivateKey } from "@libp2p/interface";
import { peerIdFromPrivateKey } from "@libp2p/peer-id";
import { openVault } from "./index.js";
import type { Vault } from "./index.js";
import type { VaultStore, StoreEntry } from "./store.js";
import { authorizeApp } from "./nodeauth.js";
import type { MeshTransport, AuthorizeAppOptions } from "./nodeauth.js";

/** Vault secret name per identity: `id.<peerId>`. */
const PREFIX = "id.";
/** deviceStore slot holding this browser's persisted owner DeviceKey bundle. */
const DEVICE_KEY = "device";

/** A mesh identity — the PUBLIC view; never carries the raw private key. */
export interface Identity {
  /** The libp2p peer id — stable, self-certifying; this IS the identity id. */
  id: string;
  peerId: string;
  name: string;
  /** The CE node id that vouches for this identity, or null (set via {@link Identities.link}). */
  node: string | null;
  /** The node-signed capability (hex ce-cap chain) presented to mesh services, or null. */
  cap: string | null;
  createdAt: number;
  lastUsed: number;
}

/** Internal stored record — the public {@link Identity} plus the sealed private key (b64 protobuf). */
interface StoredIdentity extends Identity {
  key: string;
}

function publicView(s: StoredIdentity): Identity {
  const { key: _key, ...pub } = s;
  return pub;
}

const enc = (u8: Uint8Array): string => btoa(String.fromCharCode(...u8));
const dec = (s: string): Uint8Array => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

/** Options for {@link Identities.open}. */
export interface IdentitiesOptions {
  /** Vault namespace (folds into the owner-master derivation). Use the app id, e.g. `"spacegame"`. */
  ns: string;
  /** Durable store for the ENCRYPTED vault records. */
  store: VaultStore;
  /**
   * Separate durable store holding ONLY this browser's owner device key. It must NOT be the vault
   * `store`: the vault loads every key in its store into its snapshot, so the plaintext device key has
   * to live elsewhere.
   */
  deviceStore: VaultStore;
  /** Clock (ms). Defaults to `Date.now`. */
  now?: () => number;
}

/**
 * Manages a user's named mesh identities in an encrypted ce-iam vault. Construct with {@link open}
 * (generic — pass your own stores) or {@link openBrowser} (IndexedDB-backed convenience).
 */
export class Identities {
  private constructor(
    private readonly v: Vault,
    private readonly now: () => number,
  ) {}

  /**
   * Open the identity vault: load (or mint+persist) this browser's owner device key, then ensure the
   * vault is established and THIS device is enrolled via `recover()` — idempotent and safe after a
   * store wipe, so the owner is never locked out and identities survive across sessions.
   */
  static async open(opts: IdentitiesOptions): Promise<Identities> {
    const now = opts.now ?? (() => Date.now());
    const existing = await opts.deviceStore.get(DEVICE_KEY);
    const device = typeof existing === "string" ? existing : undefined;
    const v = await openVault({ ns: opts.ns, store: opts.store, device });
    // Only (re-)establish when this device can't already decrypt the master — so a normal reopen never
    // touches the deterministic master and existing secrets stay readable. A wiped store falls through
    // to recover(), which re-derives the master from the owner key and re-enrolls this device.
    if (!(await v.isEnrolled())) await v.recover("ce-iam browser identity (owner)");
    if (device === undefined) await opts.deviceStore.put(DEVICE_KEY, v.deviceKey());
    return new Identities(v, now);
  }

  /** Browser convenience: IndexedDB stores (`<ns>` for the vault, `<ns>-device` for the device key). */
  static openBrowser(ns: string): Promise<Identities> {
    return Identities.open({ ns, store: new IdbStore(ns), deviceStore: new IdbStore(`${ns}-device`) });
  }

  /** Create a new identity from a fresh Ed25519 libp2p keypair. */
  async create(name?: string): Promise<Identity> {
    const key = await generateKeyPair("Ed25519");
    const peerId = peerIdFromPrivateKey(key).toString();
    const t = this.now();
    const rec: StoredIdentity = {
      id: peerId,
      peerId,
      name: (name || "player").slice(0, 48),
      node: null,
      cap: null,
      createdAt: t,
      lastUsed: t,
      key: enc(privateKeyToProtobuf(key)),
    };
    await this.v.putString(PREFIX + peerId, JSON.stringify(rec));
    return publicView(rec);
  }

  private async load(id: string): Promise<StoredIdentity | null> {
    try {
      return JSON.parse(await this.v.getString(PREFIX + id)) as StoredIdentity;
    } catch {
      return null;
    }
  }

  /** All identities, most-recently-used first (public view; no private keys). */
  async list(): Promise<Identity[]> {
    const metas = await this.v.listSecrets();
    const out: Identity[] = [];
    for (const m of metas) {
      if (!m.name.startsWith(PREFIX)) continue;
      const rec = await this.load(m.name.slice(PREFIX.length));
      if (rec) out.push(publicView(rec));
    }
    return out.sort((a, b) => b.lastUsed - a.lastUsed);
  }

  /** One identity (public view), or null if absent. */
  async get(id: string): Promise<Identity | null> {
    const rec = await this.load(id);
    return rec ? publicView(rec) : null;
  }

  /** Mark `id` used now (call when entering with it) so {@link list} orders by recency. */
  async touch(id: string): Promise<Identity | null> {
    const rec = await this.load(id);
    if (!rec) return null;
    rec.lastUsed = this.now();
    await this.v.putString(PREFIX + id, JSON.stringify(rec));
    return publicView(rec);
  }

  /** Delete an identity. */
  async remove(id: string): Promise<void> {
    await this.v.deleteSecret(PREFIX + id);
  }

  /** The raw libp2p private-key protobuf bytes for `id` (for apps that must stash them somewhere). */
  async privateKeyProtobuf(id: string): Promise<Uint8Array> {
    const rec = await this.load(id);
    if (!rec) throw new Error(`no such identity ${id}`);
    return dec(rec.key);
  }

  /** The identity's libp2p {@link PrivateKey} object — hand straight to libp2p. */
  async libp2pPrivateKey(id: string): Promise<PrivateKey> {
    return privateKeyFromProtobuf(await this.privateKeyProtobuf(id));
  }

  /**
   * Link `id` to the user's local CE node via the passwordless node-vouch ({@link authorizeApp}), and
   * store the node-signed capability on the identity so future sessions are pre-authorized. Returns the
   * updated identity (public view).
   */
  async link(
    id: string,
    transport: MeshTransport,
    opts?: Partial<AuthorizeAppOptions>,
  ): Promise<Identity> {
    const rec = await this.load(id);
    if (!rec) throw new Error(`no such identity ${id}`);
    const grant = await authorizeApp(transport, {
      abilities: opts?.abilities ?? [],
      peerId: rec.peerId,
      name: opts?.name ?? rec.name,
      nodeId: opts?.nodeId,
      timeoutMs: opts?.timeoutMs,
      discoverMs: opts?.discoverMs,
    });
    rec.node = grant.node;
    rec.cap = grant.cap;
    rec.lastUsed = this.now();
    await this.v.putString(PREFIX + id, JSON.stringify(rec));
    return publicView(rec);
  }
}

/**
 * A browser {@link VaultStore} backed by IndexedDB — durable, same-origin, reusable by any CE app
 * (the vault records and the device key live in separate {@link IdbStore} databases).
 */
export class IdbStore implements VaultStore {
  constructor(
    private readonly dbName: string,
    private readonly storeName = "kv",
  ) {}

  private db(): Promise<IDBDatabase> {
    const sn = this.storeName;
    return new Promise((res, rej) => {
      const r = indexedDB.open(this.dbName, 1);
      r.onupgradeneeded = () => r.result.createObjectStore(sn);
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
  }
  async get(key: string): Promise<unknown> {
    const db = await this.db();
    const sn = this.storeName;
    return new Promise((res, rej) => {
      const t = db.transaction(sn, "readonly").objectStore(sn).get(key);
      t.onsuccess = () => res(t.result ?? null);
      t.onerror = () => rej(t.error);
    });
  }
  async put(key: string, value: unknown): Promise<void> {
    const db = await this.db();
    const sn = this.storeName;
    return new Promise((res, rej) => {
      const t = db.transaction(sn, "readwrite").objectStore(sn).put(value, key);
      t.onsuccess = () => res();
      t.onerror = () => rej(t.error);
    });
  }
  async del(key: string): Promise<void> {
    const db = await this.db();
    const sn = this.storeName;
    return new Promise((res, rej) => {
      const t = db.transaction(sn, "readwrite").objectStore(sn).delete(key);
      t.onsuccess = () => res();
      t.onerror = () => rej(t.error);
    });
  }
  async list(prefix: string): Promise<StoreEntry[]> {
    const db = await this.db();
    const sn = this.storeName;
    return new Promise((res, rej) => {
      const out: StoreEntry[] = [];
      const cur = db.transaction(sn, "readonly").objectStore(sn).openCursor();
      cur.onsuccess = () => {
        const c = cur.result;
        if (!c) return res(out);
        if (String(c.key).startsWith(prefix)) out.push({ key: String(c.key), value: c.value });
        c.continue();
      };
      cur.onerror = () => rej(cur.error);
    });
  }
}

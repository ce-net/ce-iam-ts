/**
 * The vault store interface — the SAME `{ get, put, del, list }` shape ce-cast's `delivery.ts`
 * already hands its vendored `vault.mjs` (its mesh-KV adapter over the local CE node). The ce-iam-ts
 * vault is generic over this, so ce-cast swaps its vendored vault for `openVault({ store })` with the
 * identical store object and no other change.
 *
 * Keys mirror the canonical layout exactly: `meta` · `d.<deviceId>` · `p.<code>` · `s.<name>` ·
 * `g.<grantId>`. Values are JSON records (objects); `null`/`undefined` from `get` means "absent".
 */

/** One stored key/value pair returned by {@link VaultStore.list}. */
export interface StoreEntry {
  key: string;
  value: unknown;
}

/**
 * The durable backend the vault reads/writes — in the browser this is the mesh KV (cast-control's
 * `ce-kv/<ns>/1` service) reached over the local node; in Node it can be any KV. Async throughout.
 */
export interface VaultStore {
  /** Fetch a record by key, or `null`/`undefined` if absent. */
  get(key: string): Promise<unknown>;
  /** Write a record. */
  put(key: string, value: unknown): Promise<void>;
  /** Delete a record. */
  del(key: string): Promise<void>;
  /** Every entry whose key starts with `prefix` (use `""` for all). */
  list(prefix: string): Promise<StoreEntry[]>;
}

/** An in-memory {@link VaultStore} — a fine default for tests and single-process use. */
export class MemStore implements VaultStore {
  private readonly m = new Map<string, unknown>();

  async get(key: string): Promise<unknown> {
    return this.m.has(key) ? this.m.get(key) : null;
  }
  async put(key: string, value: unknown): Promise<void> {
    this.m.set(key, value);
  }
  async del(key: string): Promise<void> {
    this.m.delete(key);
  }
  async list(prefix: string): Promise<StoreEntry[]> {
    const out: StoreEntry[] = [];
    for (const [key, value] of this.m) {
      if (key.startsWith(prefix)) out.push({ key, value });
    }
    return out;
  }
}

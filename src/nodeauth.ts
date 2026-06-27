/**
 * nodeauth — passwordless **app authorization** via your local CE node.
 *
 * The reusable, local-first equivalent of an OAuth consent screen: an app declares the abilities it
 * needs; your own CE node (the one you run) mints a signed, scoped capability granting exactly those,
 * over the mesh, with no password and no pasted secret. The app then presents that capability to
 * whatever mesh service it talks to (e.g. ce-cast's cast-control / cast-authd), which verifies it
 * OFFLINE rooted at your node id.
 *
 * This is the browser counterpart of `ce-iam`'s `nodeauth` responder (Rust). Keep the wire in
 * lock-step with it and with `spacegame-wasm/account.js`:
 *
 *   ANNOUNCE `ce-iam/nodes/announce`   : { nodeId, label, owner }
 *   REQUEST  `ce-iam/auth/req/<nodeId>`: { peerId, name, nonce, abilities }
 *   RESPONSE `ce-iam/auth/resp/<peerId>`: { nonce, cap, nodeId, name, abilities }
 *
 * Transport-agnostic: the caller supplies a {@link MeshTransport} (a thin adapter over its node
 * bridge — `window.__ceNode`, ce-serve's `/mesh-bridge`, or the same-origin `/ce` proxy). That keeps
 * this SDK free of any particular bridge shape so every app reuses the same flow.
 */

/** One inbound mesh message as delivered by the node's `/mesh/messages/stream`. */
export interface MeshMessage {
  topic: string;
  /** Hex-encoded payload bytes. */
  payload_hex: string;
}

/**
 * The minimal mesh surface `authorizeApp` needs, mapped 1:1 onto a node bridge's
 * `request`/`stream`. Implement it once per app over your transport (see ce-cast's `meshTransport`).
 */
export interface MeshTransport {
  /** Subscribe to a gossipsub topic (`POST /mesh/subscribe`). */
  subscribe(topic: string): Promise<void>;
  /** Publish `payloadHex` to a topic (`POST /mesh/publish` with `{topic, payload_hex}`). */
  publish(topic: string, payloadHex: string): Promise<void>;
  /** Subscribe to the inbound message stream; returns an unsubscribe fn. */
  onMessage(cb: (m: MeshMessage) => void): () => void;
}

/** The well-known node-announce topic. */
export const T_ANNOUNCE = "ce-iam/nodes/announce";
/** The per-node vouch-request topic. */
export const tReq = (nodeId: string): string => `ce-iam/auth/req/${nodeId}`;
/** The per-peer vouch-response topic. */
export const tResp = (peerId: string): string => `ce-iam/auth/resp/${peerId}`;

/** A discovered local node. */
export interface NodeInfo {
  nodeId: string;
  label: string;
  owner: string | null;
}

/** Options for {@link authorizeApp}. */
export interface AuthorizeAppOptions {
  /** App abilities to request, e.g. `["cast:publish", "cast:control"]`. */
  abilities: string[];
  /** A stable id for THIS app/device (binds `account:peer:<peerId>` into the cap). */
  peerId: string;
  /** Display name to bind (`account:name:<name>`). Default `"app"`. */
  name?: string;
  /** Target node id; default: the first node discovered via announce. */
  nodeId?: string;
  /** How long to wait for the node to respond (ms). Default 60_000. */
  timeoutMs?: number;
  /** How long to listen for node announcements when `nodeId` is not given (ms). Default 2_500. */
  discoverMs?: number;
}

/** The node-signed capability and what it grants. */
export interface AppGrant {
  /** Hex-encoded ce-cap chain. Present this to mesh services. */
  cap: string;
  /** The vouching node id (your local node) — the root services accept. */
  node: string;
  /** The peer/device id bound into the cap. */
  peerId: string;
  /** The abilities actually granted (may be a subset of those requested). */
  abilities: string[];
  /** The bound display name. */
  name: string;
}

const te = new TextEncoder();
const td = new TextDecoder();

function toHex(u8: Uint8Array): string {
  let s = "";
  for (const b of u8) s += b.toString(16).padStart(2, "0");
  return s;
}
function fromHex(h: string): Uint8Array {
  const o = new Uint8Array(h.length >> 1);
  for (let i = 0; i < o.length; i++) o[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return o;
}
function randHex(n: number): string {
  return toHex(globalThis.crypto.getRandomValues(new Uint8Array(n)));
}

/** Discover the CE nodes you are running, listening for `ms`. Returns one entry per node id. */
export async function discoverNodes(t: MeshTransport, ms = 2500): Promise<NodeInfo[]> {
  await t.subscribe(T_ANNOUNCE);
  const found = new Map<string, NodeInfo>();
  const off = t.onMessage((m) => {
    if (m.topic !== T_ANNOUNCE) return;
    try {
      const p = JSON.parse(td.decode(fromHex(m.payload_hex))) as {
        nodeId?: string;
        label?: string;
        owner?: string | null;
      };
      if (p.nodeId && !found.has(p.nodeId)) {
        found.set(p.nodeId, {
          nodeId: p.nodeId,
          label: p.label || p.nodeId.slice(0, 8),
          owner: p.owner ?? null,
        });
      }
    } catch {
      // ignore undecodable announce
    }
  });
  await new Promise((r) => setTimeout(r, ms));
  off();
  return [...found.values()];
}

/**
 * Ask your local node to authorize this app: discover it (or use `opts.nodeId`), request the abilities,
 * and resolve with the node-signed capability. Rejects if no node answers within `timeoutMs`.
 */
export async function authorizeApp(t: MeshTransport, opts: AuthorizeAppOptions): Promise<AppGrant> {
  const name = opts.name ?? "app";
  const timeoutMs = opts.timeoutMs ?? 60_000;
  let nodeId = opts.nodeId;
  if (!nodeId) {
    const nodes = await discoverNodes(t, opts.discoverMs ?? 2500);
    nodeId = nodes[0]?.nodeId;
    if (!nodeId) throw new Error("no local CE node found (is your node running `ce-iam nodeauth`?)");
  }
  const peerId = opts.peerId;
  const nonce = randHex(16);
  await t.subscribe(tResp(peerId));

  const grant = new Promise<AppGrant>((resolve, reject) => {
    const timer = setTimeout(() => {
      off();
      reject(new Error("node did not authorize in time"));
    }, timeoutMs);
    const off = t.onMessage((m) => {
      if (m.topic !== tResp(peerId)) return;
      try {
        const p = JSON.parse(td.decode(fromHex(m.payload_hex))) as {
          nonce?: string;
          cap?: string;
          nodeId?: string;
          name?: string;
          abilities?: string[];
        };
        if (p.nonce !== nonce || !p.cap || !p.nodeId) return;
        clearTimeout(timer);
        off();
        resolve({
          cap: p.cap,
          node: p.nodeId,
          peerId,
          abilities: p.abilities ?? [],
          name: p.name ?? name,
        });
      } catch {
        // ignore undecodable response
      }
    });
  });

  const reqBody = JSON.stringify({ peerId, name, nonce, abilities: opts.abilities });
  await t.publish(tReq(nodeId), toHex(te.encode(reqBody)));
  return grant;
}

// BLK3 snapshot parser, ported from edge-analyst src/blocklist.js load() (reference implementation).
//
// Container: sectioned little-endian uint32 —
//   [0] magic 0x424C4B33 ("BLK3")   [1] section count K
//   K x [type, offset(words), length(words)]   then the sections.
// Types: 1 V4_STARTS  2 V4_ENDS  3 V4_IDX16  4 V4_BM24  5 V6_STARTS  6 V6_ENDS  7 V6_BM24
//        8 ASN_BM  9 ASN_EXTRA.
// Meta travels separately: { version, country[], tls[], pathsExact[], pathsPrefix[], pathsRegex[] }.

export interface SnapshotMeta {
  version: string;
  country?: string[];
  tls?: string[];
  pathsExact?: string[];
  pathsPrefix?: string[];
  pathsRegex?: string[];
}

export interface Snapshot {
  version: string;
  s4: Uint32Array; e4: Uint32Array; idx4: Uint32Array; bm4: Uint32Array;
  s6: Uint32Array; e6: Uint32Array; n6: number; bm6: Uint32Array;
  asnBm: Uint32Array; asnExtra: Uint32Array;
  country: Set<string>; tls: Set<string>;
  pathsExact: Set<string>; pathsPrefix: Set<string>; pathsRegex: RegExp[];
}

const MAGIC = 0x424c4b33;

// The container is little-endian; Uint32Array views are native-endian. Every platform that
// matters is little-endian, but fail loudly rather than match garbage on the exception.
const LITTLE_ENDIAN = new Uint8Array(Uint32Array.of(1).buffer)[0] === 1;

function words(bin: ArrayBuffer | Uint8Array): Uint32Array {
  if (!LITTLE_ENDIAN) throw new Error('camada: big-endian platforms are not supported');
  if (bin instanceof Uint8Array) {
    if (bin.byteOffset % 4 === 0 && bin.byteLength % 4 === 0) return new Uint32Array(bin.buffer, bin.byteOffset, bin.byteLength >>> 2);
    const copy = new Uint8Array(bin);   // realign (e.g. a subarray of a pooled Buffer)
    return new Uint32Array(copy.buffer, 0, copy.byteLength >>> 2);
  }
  return new Uint32Array(bin);
}

/** Parses a BLK3 container + meta into a Snapshot. Throws on a malformed container —
 *  callers keep the previous snapshot, exactly like the edge collector does. */
export function parseSnapshot(bin: ArrayBuffer | Uint8Array, meta: SnapshotMeta): Snapshot {
  const u = words(bin);
  if (u.length < 2 || u[0] !== MAGIC) throw new Error('camada: not a BLK3 snapshot');
  const K = u[1], sec: Record<number, Uint32Array> = {};
  if (u.length < 2 + K * 3) throw new Error('camada: truncated BLK3 header');
  for (let i = 0; i < K; i++) {
    const t = u[2 + i * 3], off = u[3 + i * 3], len = u[4 + i * 3];
    if (off + len > u.length) throw new Error('camada: truncated BLK3 section');
    sec[t] = u.subarray(off, off + len);
  }
  const empty = new Uint32Array(0);
  const s6 = sec[5] || empty;
  return {
    version: meta.version,
    s4: sec[1] || empty, e4: sec[2] || empty, idx4: sec[3] || new Uint32Array(65537), bm4: sec[4] || new Uint32Array(524288),
    s6, e6: sec[6] || empty, n6: s6.length / 4, bm6: sec[7] || new Uint32Array(524288),
    asnBm: sec[8] || new Uint32Array(131072), asnExtra: sec[9] || empty,
    country: new Set(meta.country || []),
    tls: new Set(meta.tls || []),
    pathsExact: new Set(meta.pathsExact || []),
    pathsPrefix: new Set(meta.pathsPrefix || []),
    pathsRegex: (meta.pathsRegex || []).map((p) => new RegExp(p)),
  };
}

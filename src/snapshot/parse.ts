// BLK3 snapshot parser, ported from edge-analyst src/blocklist.js load() (reference implementation).
//
// Container: sectioned little-endian uint32 —
//   [0] magic 0x424c4b3<version>   [1] section count K
//   K x [type, offset(words), length(words)]   then the sections.
// Types: 1 V4_STARTS  2 V4_ENDS  3 V4_IDX16  4 V4_BM24  5 V6_STARTS  6 V6_ENDS  7 V6_BM24
//        8 ASN_BM  9 ASN_EXTRA.
// v4 (contracts §A3) adds two side lists as INTERLEAVED range pairs:
//        10 ALLOW_V4  11 ALLOW_V6  12 CHALLENGE_V4  13 CHALLENGE_V6
//   *_V4: [start, end, …] (2 words per range, sorted by start)
//   *_V6: [s0,s1,s2,s3, e0,e1,e2,e3, …] (8 words per range, big-endian word order, sorted by start)
// Meta travels separately: { version, country[], tls[], pathsExact[], pathsPrefix[], pathsRegex[],
//                            allow?: side, challenge?: side } with side = { asn[], country[], pathsExact[], pathsPrefix[] }.
// The version byte is advisory: sections 10-13 are read whenever they are present.

/** The non-IP half of a v4 side list (allow or challenge). */
export interface SnapshotSetMeta {
  asn?: number[];
  country?: string[];
  pathsExact?: string[];
  pathsPrefix?: string[];
}

export interface SnapshotMeta {
  version: string;
  country?: string[];
  tls?: string[];
  pathsExact?: string[];
  pathsPrefix?: string[];
  pathsRegex?: string[];
  allow?: SnapshotSetMeta;
  challenge?: SnapshotSetMeta;
}

/** A v4 side list. `empty` short-circuits the matcher on the (common) v3 snapshot. */
export interface RangeSet {
  r4: Uint32Array;   // interleaved [start, end]
  r6: Uint32Array;   // interleaved [4-word start, 4-word end]
  n6: number;        // range count in r6
  asn: Set<number>;
  country: Set<string>;
  pathsExact: Set<string>;
  pathsPrefix: Set<string>;
  empty: boolean;
}

export type SnapshotFormat = 3 | 4;

export interface Snapshot {
  version: string;
  format: SnapshotFormat;             // what the container's version byte claimed
  s4: Uint32Array; e4: Uint32Array; idx4: Uint32Array; bm4: Uint32Array;
  s6: Uint32Array; e6: Uint32Array; n6: number; bm6: Uint32Array;
  asnBm: Uint32Array; asnExtra: Uint32Array;
  country: Set<string>; tls: Set<string>;
  pathsExact: Set<string>; pathsPrefix: Set<string>; pathsRegex: RegExp[];
  allow: RangeSet; challenge: RangeSet;
}

// 'BLK' + an ASCII version digit -> container format.
const FORMATS: Record<number, SnapshotFormat | undefined> = { 0x424c4b33: 3, 0x424c4b34: 4 };

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

const EMPTY = new Uint32Array(0);

function rangeSet(r4: Uint32Array, r6: Uint32Array, m?: SnapshotSetMeta): RangeSet {
  const asn = new Set((m?.asn || []).map(Number));
  const country = new Set(m?.country || []);
  const pathsExact = new Set(m?.pathsExact || []);
  const pathsPrefix = new Set(m?.pathsPrefix || []);
  const empty = r4.length === 0 && r6.length === 0
    && asn.size === 0 && country.size === 0 && pathsExact.size === 0 && pathsPrefix.size === 0;
  return { r4, r6, n6: r6.length >>> 3, asn, country, pathsExact, pathsPrefix, empty };
}

/** Parses a BLK3 container + meta into a Snapshot. Throws on a malformed container —
 *  callers keep the previous snapshot, exactly like the edge collector does. */
export function parseSnapshot(bin: ArrayBuffer | Uint8Array, meta: SnapshotMeta): Snapshot {
  const u = words(bin);
  const format = u.length >= 2 ? FORMATS[u[0]] : undefined;
  if (!format) throw new Error('camada: not a BLK3 snapshot');
  const K = u[1], sec: Record<number, Uint32Array> = {};
  if (u.length < 2 + K * 3) throw new Error('camada: truncated BLK3 header');
  for (let i = 0; i < K; i++) {
    const t = u[2 + i * 3], off = u[3 + i * 3], len = u[4 + i * 3];
    if (off + len > u.length) throw new Error('camada: truncated BLK3 section');
    sec[t] = u.subarray(off, off + len);
  }
  const s6 = sec[5] || EMPTY;
  return {
    version: meta.version,
    format,
    s4: sec[1] || EMPTY, e4: sec[2] || EMPTY, idx4: sec[3] || new Uint32Array(65537), bm4: sec[4] || new Uint32Array(524288),
    s6, e6: sec[6] || EMPTY, n6: s6.length / 4, bm6: sec[7] || new Uint32Array(524288),
    asnBm: sec[8] || new Uint32Array(131072), asnExtra: sec[9] || EMPTY,
    country: new Set(meta.country || []),
    tls: new Set(meta.tls || []),
    pathsExact: new Set(meta.pathsExact || []),
    pathsPrefix: new Set(meta.pathsPrefix || []),
    pathsRegex: (meta.pathsRegex || []).map((p) => new RegExp(p)),
    allow: rangeSet(sec[10] || EMPTY, sec[11] || EMPTY, meta.allow),
    challenge: rangeSet(sec[12] || EMPTY, sec[13] || EMPTY, meta.challenge),
  };
}

// BLK snapshot parser (v3, v4, v5), ported from edge-analyst src/blocklist.js load() (reference implementation).
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
// v5 (contracts §D3) adds the tenant's ordered custom rules, which run BEFORE the three sides:
//        14 RULE_V4  15 RULE_V6   — repeated, word 0 = the rule's index into meta.rules, then range
//   pairs exactly as 10/11. One 14 + one 15 per `ip` condition, in condition order (an empty half
//   still ships its index word), so a rule with two ip conditions reads two pairs.
// Meta travels separately: { version, country[], tls[], pathsExact[], pathsPrefix[], pathsRegex[],
//                            allow?: side, challenge?: side, rules?: [] } with side = { asn[], country[], pathsExact[], pathsPrefix[] }.
// The version byte is advisory: sections 10-15 are read whenever they are present.

/** The non-IP half of a v4 side list (allow or challenge). */
export interface SnapshotSetMeta {
  asn?: number[];
  country?: string[];
  pathsExact?: string[];
  pathsPrefix?: string[];
}

/** One condition of a published rule. An `ip` condition carries no values: its addresses ride
 *  sections 14/15 for that rule index, and `set` marks the place in condition order. A `header`
 *  condition adds `name`, the header it reads (matched case-insensitively). */
export interface SnapshotCondMeta {
  f: string;                                     // ip | asn | country | tlsx | path | ua | header
  op: string;                                    // is | is_not | is_in | not_in | starts_with | contains | matches
  v?: string | number | Array<string | number>;
  set?: boolean;
  name?: string;                                 // header conditions only
}

/** A rule as the server published it (§D3): enabled and request-enforceable only, in evaluation
 *  order. `id` may repeat — the built-ins compile to one rule per entry kind. */
export interface SnapshotRuleMeta {
  id: string;
  action: string;
  conds?: SnapshotCondMeta[];
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
  rules?: SnapshotRuleMeta[];
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

export type SnapshotFormat = 3 | 4 | 5;

/** What a custom rule may do to a request (§A4). The four are the whole vocabulary — `skip` is
 *  the one that passes, and it absorbed the old `allow`: whether the analyst records the match
 *  is the rule's `record` flag, which never reaches the SDK because it changes nothing here. */
export type RuleAction = 'skip' | 'block' | 'challenge' | 'warn';

/** The request a compiled condition reads. `in6` runs the v6 range search over the caller's own
 *  parsed address, so the 128-bit scratch stays per Matcher instance. */
export interface RuleRequest {
  n4: number;                  // IPv4 as uint32, or -1 when this request has no IPv4 address
  has6: boolean;               // an IPv6 address was parsed into the caller's scratch
  asn?: number | null;
  country?: string | null;
  tlsx?: string | null;
  path: string;                // already query-stripped
  ua?: string | null;
  header?: ((name: string) => string | null) | null;   // called with an already lower-cased name; absent where the tap cannot read headers
  in6(pairs: Uint32Array, n: number): boolean;
}

/** A condition compiled to a predicate. A field this request cannot answer is false for EVERY op,
 *  negatives included — the rule then simply does not fire. */
export type RuleCond = (r: RuleRequest) => boolean;

export interface CompiledRule {
  id: string;
  action: RuleAction;
  conds: RuleCond[];
}

export interface Snapshot {
  version: string;
  format: SnapshotFormat;             // what the container's version byte claimed
  s4: Uint32Array; e4: Uint32Array; idx4: Uint32Array; bm4: Uint32Array;
  s6: Uint32Array; e6: Uint32Array; n6: number; bm6: Uint32Array;
  asnBm: Uint32Array; asnExtra: Uint32Array;
  country: Set<string>; tls: Set<string>;
  pathsExact: Set<string>; pathsPrefix: Set<string>; pathsRegex: RegExp[];
  allow: RangeSet; challenge: RangeSet;
  rules: CompiledRule[];        // v5 only; empty on v3/v4, and the matcher then skips them
}

// 'BLK' + an ASCII version digit -> container format.
const FORMATS: Record<number, SnapshotFormat | undefined> = { 0x424c4b33: 3, 0x424c4b34: 4, 0x424c4b35: 5 };

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

/** Binary search over interleaved [start, end] uint32 pairs sorted by start (sections 10/12 and
 *  the 14 half of a rule's ip condition). */
export function inRange4(r: Uint32Array, n: number): boolean {
  let lo = 0, hi = (r.length >>> 1) - 1;
  if (hi < 0) return false;
  while (lo < hi) { const m = (lo + hi + 1) >>> 1; if (r[m * 2] <= n) lo = m; else hi = m - 1; }
  return r[lo * 2] <= n && n <= r[lo * 2 + 1];
}

/* ---------- custom rules (v5) ---------- */

/** The string one condition reads, or null when this request cannot answer the field. `header`
 *  is not here: it needs the condition's own name, so compileCond builds its reader instead. */
function fieldValue(f: string, r: RuleRequest): string | null {
  if (f === 'asn') return r.asn === undefined || r.asn === null ? null : String(r.asn);
  if (f === 'country') return r.country || null;
  if (f === 'tlsx') return r.tlsx || null;
  if (f === 'path') return r.path;
  if (f === 'ua') return r.ua || null;
  return null;                                   // an entity-plane field (bot.verified, rule): never true here
}

/** One condition -> a predicate. `sets` yields this rule's (v4, v6) section pair per ip condition,
 *  in condition order, so an ip condition consumes the next one. */
function compileCond(c: SnapshotCondMeta, sets: Array<[Uint32Array, Uint32Array]>): RuleCond {
  const negate = c.op === 'is_not' || c.op === 'not_in';
  // A header condition reads the request through the caller's getter. The name is lower-cased
  // once, here, so the condition's own spelling never costs the hot path anything; a tap that
  // cannot read headers (no getter) and a header the request does not carry are both null, and
  // null is false for every op — the rule simply does not fire (fail open, §A4). The getter is
  // app code: one that throws, or answers `undefined` instead of null, is read as "no header"
  // rather than allowed to take the whole match() down.
  const hname = c.f === 'header' ? String(c.name || '').toLowerCase() : '';
  const read: (r: RuleRequest) => string | null = c.f === 'header'
    ? (r) => {
        if (!hname || !r.header) return null;
        try { const v = r.header(hname); return typeof v === 'string' ? v : null; } catch { return null; }
      }
    : (r) => fieldValue(c.f, r);
  if (c.f === 'ip') {
    const [p4 = EMPTY, p6 = EMPTY] = sets.shift() || [];
    const n6 = p6.length >>> 3;
    return (r) => {
      if (r.n4 < 0 && !r.has6) return false;     // no address: false for every op, negatives included
      const hit = (r.n4 >= 0 && inRange4(p4, r.n4)) || (r.has6 && r.in6(p6, n6));   // both searches answer false on an empty half
      return negate ? !hit : hit;
    };
  }
  const values = Array.isArray(c.v) ? c.v.map(String) : [String(c.v)];
  if (c.op === 'matches') {
    let re: RegExp | null = null;
    try { re = new RegExp(values[0]); } catch { re = null; }   // a pattern this runtime rejects never matches, and never throws
    return (r) => { const v = read(r); return v !== null && !!re && re.test(v); };
  }
  if (c.op === 'contains') return (r) => { const v = read(r); return v !== null && v.includes(values[0]); };
  if (c.op === 'starts_with') return (r) => { const v = read(r); return v !== null && v.startsWith(values[0]); };
  const set = new Set(values);                   // is | is_not | is_in | not_in
  return (r) => { const v = read(r); if (v === null) return false; return negate ? !set.has(v) : set.has(v); };
}

const ACTIONS = new Set<string>(['skip', 'block', 'challenge', 'warn']);

/** meta.rules + the repeated 14/15 sections -> predicates, in evaluation order. A rule this SDK
 *  cannot compile (unknown action, no conditions) is dropped rather than guessed at. */
function compileRules(meta: SnapshotMeta, v4s: Uint32Array[], v6s: Uint32Array[]): CompiledRule[] {
  const out: CompiledRule[] = [];
  (meta.rules || []).forEach((r, i) => {
    if (!ACTIONS.has(r.action)) return;          // an action this SDK does not know: ignore the rule rather than guess
    const v4 = v4s.filter((s) => s[0] === i), v6 = v6s.filter((s) => s[0] === i);
    const sets: Array<[Uint32Array, Uint32Array]> = [];
    for (let k = 0; k < Math.max(v4.length, v6.length); k++) {
      sets.push([v4[k] ? v4[k].subarray(1) : EMPTY, v6[k] ? v6[k].subarray(1) : EMPTY]);
    }
    try { out.push({ id: r.id, action: r.action as RuleAction, conds: (r.conds || []).map((c) => compileCond(c, sets)) }); }
    catch { /* a malformed rule is dropped, never enforced */ }
  });
  return out.filter((r) => r.conds.length > 0);  // a rule with no conditions would match everything
}

/** Parses a BLK3 container + meta into a Snapshot. Throws on a malformed container —
 *  callers keep the previous snapshot, exactly like the edge collector does. */
export function parseSnapshot(bin: ArrayBuffer | Uint8Array, meta: SnapshotMeta): Snapshot {
  const u = words(bin);
  const format = u.length >= 2 ? FORMATS[u[0]] : undefined;
  if (!format) throw new Error('camada: not a BLK3 snapshot');
  const K = u[1], sec: Record<number, Uint32Array> = {};
  const rule4: Uint32Array[] = [], rule6: Uint32Array[] = [];
  if (u.length < 2 + K * 3) throw new Error('camada: truncated BLK3 header');
  for (let i = 0; i < K; i++) {
    const t = u[2 + i * 3], off = u[3 + i * 3], len = u[4 + i * 3];
    if (off + len > u.length) throw new Error('camada: truncated BLK3 section');
    const s = u.subarray(off, off + len);
    if (t === 14) rule4.push(s);                 // repeated, one per ip condition: kept in container order
    else if (t === 15) rule6.push(s);
    else sec[t] = s;
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
    rules: compileRules(meta, rule4, rule6),
  };
}

# SDK Phase C Implementation Plan (SDK-02, SDK-04, SEC-07)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Teach the camada SDK family to read BLK3 v4 snapshots (allow + challenge sections), to enforce a `challenge` verdict with a first-party proof-of-work page, and to ship a new Workers-native package `@camada/hono`.

**Architecture:** `@camada/core` stays the single implementation of the wire: it grows a v4 container parser (sections 10–13 + meta `allow`/`challenge`), a three-way `match()` (allow → block → challenge) and a runtime-agnostic challenge kit (nonce/token/proof-of-work/HTML page). The three adapters (`@camada/node`, `@camada/next`, the new `@camada/hono`) only wire that kit into their host's request/response shape. Node uses `node:crypto` synchronously so `handle()` stays a sync boolean; Next and Hono use core's WebCrypto async twin.

**Tech Stack:** TypeScript 5.7, tsup (esm+cjs+dts), vitest 3, Node ≥18, Hono ≥4 (peer), no runtime dependencies outside the `@camada/*` file: siblings.

**Spec:** `/Users/gabe/Github/camada-all/camada/docs/superpowers/specs/2026-09-02-saas-requirements.md` (SDK-02, SDK-04, SEC-07, RULES-08, LISTS-10)
**Contracts:** `/Users/gabe/Github/camada-all/camada/docs/orchestration/contracts.md` §A3, §D2, §H (dogfood)
**Decisions:** `/Users/gabe/Github/camada-all/camada/docs/orchestration/decisions.md` D4, D31, D32, D33, D36

## Global Constraints

- Repos and branches: `camada-core`, `camada-node`, `camada-next` on `saas-phase-a`; `camada-node-example`, `camada-next-example` on `main`; `camada-hono` is a NEW repo (`git init`, branch `main`).
- Never `git push`. Never `wrangler deploy`. Never edit `docs/orchestration/contracts.md`. Never edit `~/Github/camada-all/camada/edge-analyst` or any other stream's repo.
- After EVERY task: agent `fable-simplifier` on the diff, then agent `fable-reviewer`; fix findings; commit with a conventional message. Then update `/Users/gabe/Github/camada-all/camada/docs/orchestration/status/sdk.md`.
- Commit message trailer (every commit): `Claude-Session: https://claude.ai/code/session_014GA5a631prhERB2zJ2by1n`
- Fail-open law (plan.md INT-2, unchanged): nothing in the SDK may throw into the customer's request path. Every new public entry point runs inside `guarded`/`guardedAsync`.
- Edge-runtime safety (unchanged): `@camada/core` and every module in `@camada/next`'s middleware import graph use Web APIs only — no `node:` imports. `camada-next/test/edge-safety.test.ts` proves it; it must stay green.
- Versions after this plan: `@camada/core` `0.1.0`, `@camada/node` `0.1.0`, `@camada/next` `0.1.0`, `@camada/hono` `0.1.0`. `@camada/browser` and `@camada/react` stay `0.0.1` (untouched).
- Wire constants that are contract, not choice: cookie `_cch`; TTL 1 h; PoW SHA-256 with **16** leading zero bits; node verify endpoint `POST /__camada/challenge`; next verify endpoint `POST /api/camada/challenge`; served event `{ st: 403, blk: "challenge" }`; passed event `{ st: 200, ch: 1 }`; header `x-camada-snapshot: 4`; non-HTML deny body `{"error":"challenge_required"}` with status 403.
- Assumptions recorded because edge-analyst's golden fixtures do not exist yet (see Task 1 note). They go into status/sdk.md under "Interface changes" and are re-verified when `~/Github/camada-all/camada/edge-analyst/fixtures/blk3/` lands.

---

## File Structure

**camada-core** (`~/Github/camada-all/camada-core`)
- Modify `src/snapshot/parse.ts` — BLK3 container parser; gains v4 magic tolerance, sections 10–13, meta `allow`/`challenge`, `format` field, `RangeSet`.
- Modify `src/snapshot/match.ts` — three-way matcher, order allow → block → challenge.
- Modify `src/snapshot/client.ts` — `snapshotVersion` option, `Verdict` gains `challenge`/`allowed`.
- Create `src/challenge/format.ts` — cookie name/TTL/PoW bits, message strings, token split, constant-time hex compare, PoW-prefix check, HTML escape, return-to sanitiser, `wantsHtml`.
- Create `src/challenge/verify.ts` — `createChallenge({ secret, hmac, sha })`, synchronous, runtime-injected primitives.
- Create `src/challenge/verify-async.ts` — `createChallengeAsync({ secret })` over WebCrypto (`globalThis.crypto.subtle`).
- Create `src/challenge/page.ts` — `challengePage()`, the self-contained 403 HTML with an inline synchronous SHA-256 solver.
- Modify `src/constants.ts` — `TAP_HONO`.
- Modify `src/index.ts` — new exports.
- Create `test/fixtures/v4/build.mjs` — writes the local v4 golden binary (replaced by edge-analyst's when it lands).
- Create `test/fixtures/snap-v4.bin`, `test/fixtures/snap-v4.meta.json`, `test/fixtures/cases-v4.json` (hand-written expectations).
- Create `test/challenge.test.ts`, extend `test/conformance.test.ts`, `test/parse.test.ts`, `test/client.test.ts`.

**camada-node** (`~/Github/camada-all/camada-node`)
- Modify `src/env.ts` — `secret` in `ResolvedEnv`.
- Create `src/challenge.ts` — node:crypto glue + the served/verify handlers.
- Modify `src/camada.ts` — options `challenge`, `challengePath`, `snapshotVersion`; challenge branch; `serveChallenge()` public method.
- Modify `src/index.ts` — `serveChallenge` on the default export.
- Create `test/challenge.test.ts`; modify `test/harness.ts` if needed.

**camada-next** (`~/Github/camada-all/camada-next`)
- Modify `src/engine.ts` — `secret`, `challengeEnabled`, `snapshotVersion`.
- Create `src/challenge.ts` — async glue, `challengeResponse()`, `verifyChallenge()`, `challengeGate()`, `isChallengeRoute()`.
- Modify `src/middleware.ts` — challenge branch (async return), bypass for the verify route.
- Modify `src/route.ts` — `POST …/challenge`.
- Modify `src/index.ts` — export `challengeGate`.
- Create `test/challenge.test.ts`.

**camada-hono** (`~/Github/camada-all/camada-hono`, new)
- Create `package.json`, `tsconfig.json`, `tsup.config.ts`, `.gitignore`, `LICENSE`, `README.md`.
- Create `src/index.ts`, `src/camada.ts`, `src/env.ts`, `src/version.ts`.
- Create `test/camada.test.ts`.

**Examples**
- Modify `~/Github/camada-all/camada-node-example/server.js` — `/challenge-me`.
- Create `~/Github/camada-all/camada-next-example/app/challenge-me/route.ts`.

---

### Task 1: core — BLK3 v4 container parsing

**Files:**
- Modify: `~/Github/camada-all/camada-core/src/snapshot/parse.ts`
- Create: `~/Github/camada-all/camada-core/test/fixtures/v4/build.mjs`
- Create: `~/Github/camada-all/camada-core/test/fixtures/snap-v4.bin` (generated), `snap-v4.meta.json` (generated)
- Test: `~/Github/camada-all/camada-core/test/parse.test.ts` (extend)

**Interfaces:**
- Consumes: nothing.
- Produces: `RangeSet`, `SnapshotSetMeta`, `Snapshot.allow`, `Snapshot.challenge`, `Snapshot.format`, `SnapshotMeta.allow`, `SnapshotMeta.challenge`. Task 2 matches over them; Task 3+ never touch them.

**Format note (contracts §A3, byte layout):** v4 adds section types `10` allow-v4 ranges, `11` allow-v6 ranges, `12` challenge-v4 ranges, `13` challenge-v6 ranges, and meta keys `allow` / `challenge`, each `{ asn: number[], country: string[], pathsExact: string[], pathsPrefix: string[] }`.
Two readings are pinned here because edge-analyst has not published `fixtures/blk3/` yet — both go in status/sdk.md as "Interface changes" and are re-checked on swap:
1. **Range encoding.** A v4 range section holds *interleaved pairs*: section 10/12 = `[start, end, start, end, …]` (2 words per range, sorted by `start`); section 11/13 = `[s0,s1,s2,s3, e0,e1,e2,e3, …]` (8 words per range, big-endian word order, sorted by start). This mirrors §A3's "sorted Uint32 start/end pairs" and "4×Uint32 start + 4×Uint32 end".
2. **Magic byte.** "BLK3 format byte 4" is read as the version byte of the magic: v3 = `0x424c4b33`, v4 = `0x424c4b34`. The parser accepts BOTH and also parses sections 10–13 whenever they are present, whatever the version byte says — so it works if edge-analyst keeps the v3 magic and merely adds sections.

- [ ] **Step 1: Write the failing test**

Append to `~/Github/camada-all/camada-core/test/parse.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseSnapshot } from '../src/index.js';

const fx = (f: string) => new URL(`./fixtures/${f}`, import.meta.url);
const bin = (f: string) => { const b = readFileSync(fx(f)); return new Uint8Array(b.buffer, b.byteOffset, b.byteLength); };
const json = (f: string) => JSON.parse(readFileSync(fx(f), 'utf8'));

describe('BLK3 v4 container', () => {
  it('reports format 4 and fills the allow/challenge sides', () => {
    const s = parseSnapshot(bin('snap-v4.bin'), json('snap-v4.meta.json'));
    expect(s.format).toBe(4);
    expect(s.allow.r4.length).toBeGreaterThan(0);
    expect(s.allow.n6).toBe(1);
    expect(s.allow.asn.has(3356)).toBe(true);
    expect(s.allow.country.has('CN')).toBe(true);
    expect(s.allow.pathsExact.has('/blocked-path')).toBe(true);
    expect(s.challenge.pathsPrefix.has('/checkout/')).toBe(true);
    expect(s.challenge.n6).toBe(1);
    expect(s.allow.empty).toBe(false);
    expect(s.challenge.empty).toBe(false);
  });

  it('reads a v3 container as format 3 with empty sides', () => {
    const s = parseSnapshot(bin('snap-basic.bin'), json('snap-basic.meta.json'));
    expect(s.format).toBe(3);
    expect(s.allow.empty).toBe(true);
    expect(s.challenge.empty).toBe(true);
    expect(s.allow.r4.length).toBe(0);
  });

  it('rejects a foreign magic', () => {
    const junk = new Uint32Array([0x11223344, 0]);
    expect(() => parseSnapshot(junk.buffer, { version: 'x' })).toThrow(/not a BLK3 snapshot/);
  });
});
```

- [ ] **Step 2: Write the fixture builder and generate the fixture**

Create `~/Github/camada-all/camada-core/test/fixtures/v4/build.mjs`. It is a *local stand-in* for `edge-analyst/scripts/gen-fixtures.mjs`; the range/section maths is copied from `edge-analyst/src/snapshot.js` (the format owner) so the bytes are the format owner's, not an invention.

```js
// Local BLK3 v4 golden builder — a stand-in until edge-analyst publishes fixtures/blk3/.
// v3 section maths copied verbatim from edge-analyst/src/snapshot.js (the format owner);
// sections 10-13 follow contracts.md §A3. Regenerate: node test/fixtures/v4/build.mjs
import { writeFileSync } from 'node:fs';

const MAGIC_V4 = 0x424c4b34;

const ip4 = (s) => { const p = s.split('.').map(Number); if (p.length !== 4 || p.some((b) => !Number.isInteger(b) || b < 0 || b > 255)) throw new Error('bad ipv4 ' + s); return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0; };
const ip6 = (s) => {
  const [head, tail = ''] = s.split('::');
  const h = head ? head.split(':') : [], t = tail ? tail.split(':') : [];
  const groups = s.includes('::') ? [...h, ...Array(8 - h.length - t.length).fill('0'), ...t] : h;
  if (groups.length !== 8) throw new Error('bad ipv6 ' + s);
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g, 16) || 0), 0n);
};
const MAX6 = (1n << 128n) - 1n;

function merge(ranges, cmp, succ) {
  ranges.sort((a, b) => cmp(a[0], b[0]) || cmp(a[1], b[1]));
  const out = [];
  for (const r of ranges) { const last = out[out.length - 1]; if (last && cmp(r[0], succ(last[1])) <= 0) { if (cmp(r[1], last[1]) > 0) last[1] = r[1]; } else out.push([r[0], r[1]]); }
  return out;
}

const ranges4 = (src) => {
  const r = [];
  for (const ip of src.ip4 || []) { const n = ip4(ip); r.push([n, n]); }
  for (const c of src.cidr4 || []) { const [ip, b] = c.split('/'); const bits = Number(b); const mask = bits === 32 ? 0xffffffff : ((0xffffffff << (32 - bits)) >>> 0); const start = (ip4(ip) & mask) >>> 0; r.push([start, (start | (~mask >>> 0)) >>> 0]); }
  return merge(r, (a, b) => a - b, (x) => x + 1);
};
const ranges6 = (src) => {
  const r = [];
  for (const ip of src.ip6 || []) { const n = ip6(ip); r.push([n, n]); }
  for (const c of src.cidr6 || []) { const [ip, b] = c.split('/'); const bits = Number(b); const mask = (MAX6 << BigInt(128 - bits)) & MAX6; const start = ip6(ip) & mask; r.push([start, start | (~mask & MAX6)]); }
  return merge(r, (a, b) => (a < b ? -1 : a > b ? 1 : 0), (x) => x + 1n);
};
const words6 = (x) => [Number((x >> 96n) & 0xffffffffn), Number((x >> 64n) & 0xffffffffn), Number((x >> 32n) & 0xffffffffn), Number(x & 0xffffffffn)];

// v4 side sections: interleaved [start,end] (32-bit) and [4x start, 4x end] (128-bit)
const pairs4 = (src) => { const m = ranges4(src); const a = new Uint32Array(m.length * 2); m.forEach(([s, e], i) => { a[i * 2] = s; a[i * 2 + 1] = e; }); return a; };
const pairs6 = (src) => { const m = ranges6(src); const a = new Uint32Array(m.length * 8); m.forEach(([s, e], i) => { a.set(words6(s), i * 8); a.set(words6(e), i * 8 + 4); }); return a; };

function build(src) {
  const m4 = ranges4(src), n4 = m4.length;
  const s4 = new Uint32Array(n4), e4 = new Uint32Array(n4);
  m4.forEach(([s, e], i) => { s4[i] = s; e4[i] = e; });
  const idx4 = new Uint32Array(65537);
  for (let b = 0, ri = 0; b <= 65536; b++) { const bs = b * 65536; while (ri < n4 && s4[ri] < bs) ri++; idx4[b] = ri; }
  const bm4 = new Uint32Array(524288);
  for (let i = 0; i < n4; i++) for (let b = s4[i] >>> 8, to = e4[i] >>> 8; b <= to; b++) bm4[b >>> 5] |= (1 << (b & 31));

  const m6 = ranges6(src), n6 = m6.length;
  const s6 = new Uint32Array(n6 * 4), e6 = new Uint32Array(n6 * 4);
  m6.forEach(([s, e], i) => { s6.set(words6(s), i * 4); e6.set(words6(e), i * 4); });
  const bm6 = new Uint32Array(524288);
  for (let i = 0; i < n6; i++) for (let b = Number(m6[i][0] >> 104n), to = Number(m6[i][1] >> 104n); b <= to; b++) bm6[b >>> 5] |= (1 << (b & 31));

  const asnBm = new Uint32Array(131072), asnExtra = [];
  for (const a of new Set((src.asn || []).map(Number))) { if (a < 4194304) asnBm[a >>> 5] |= (1 << (a & 31)); else asnExtra.push(a); }
  asnExtra.sort((a, b) => a - b);

  const sections = [
    [1, s4], [2, e4], [3, idx4], [4, bm4], [5, s6], [6, e6], [7, bm6], [8, asnBm], [9, Uint32Array.from(asnExtra)],
    [10, pairs4(src.allow || {})], [11, pairs6(src.allow || {})],
    [12, pairs4(src.challenge || {})], [13, pairs6(src.challenge || {})],
  ];
  let total = 2 + sections.length * 3; for (const [, arr] of sections) total += arr.length;
  const out = new Uint32Array(total); out[0] = MAGIC_V4; out[1] = sections.length;
  let off = 2 + sections.length * 3;
  sections.forEach(([type, arr], i) => { out[2 + i * 3] = type; out[3 + i * 3] = off; out[4 + i * 3] = arr.length; out.set(arr, off); off += arr.length; });

  const norm = (p) => (p.endsWith('/') ? p : p + '/');
  const side = (s) => ({ asn: [...new Set((s.asn || []).map(Number))], country: [...new Set(s.country || [])], pathsExact: [...new Set(s.pathsExact || [])], pathsPrefix: [...new Set((s.pathsPrefix || []).map(norm))] });
  const meta = {
    version: '2026-09-04T00:00:00.000Z',
    country: [...new Set(src.country || [])], tls: [...new Set(src.tls || [])],
    pathsExact: [...new Set(src.pathsExact || [])], pathsPrefix: [...new Set((src.pathsPrefix || []).map(norm))], pathsRegex: src.pathsRegex || [],
    allow: side(src.allow || {}), challenge: side(src.challenge || {}),
  };
  return { bin: out.buffer, meta };
}

const snap = build({
  ip4: ['203.0.113.66'],
  cidr4: ['10.0.0.0/8', '198.51.100.0/24'],
  ip6: ['2001:db8::1'],
  cidr6: ['2001:db8:dead::/48'],
  asn: [14061, 3356],
  country: ['RU', 'CN'],
  tls: ['9f0a77c2'],
  pathsExact: ['/blocked-path'],
  pathsPrefix: ['/locked/'],
  pathsRegex: [],
  allow: { ip4: ['10.1.2.3', '198.51.100.7'], ip6: ['2001:db8:dead::5'], asn: [3356], country: ['CN'], pathsExact: ['/blocked-path'], pathsPrefix: [] },
  challenge: { cidr4: ['192.0.2.0/24'], ip4: ['203.0.113.66'], cidr6: ['2001:db8:beef::/48'], asn: [64500], country: ['BR'], pathsExact: ['/login'], pathsPrefix: ['/checkout/'] },
});

const dir = new URL('../', import.meta.url).pathname;
writeFileSync(`${dir}snap-v4.bin`, Buffer.from(snap.bin));
writeFileSync(`${dir}snap-v4.meta.json`, JSON.stringify(snap.meta, null, 2));
console.log('wrote snap-v4.bin + snap-v4.meta.json');
```

Run: `cd ~/Github/camada-all/camada-core && node test/fixtures/v4/build.mjs`
Expected: `wrote snap-v4.bin + snap-v4.meta.json`

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd ~/Github/camada-all/camada-core && npx vitest run test/parse.test.ts`
Expected: FAIL — `s.format` is undefined, `s.allow` is undefined.

- [ ] **Step 4: Implement the parser**

Replace the header comment and the whole body of `~/Github/camada-all/camada-core/src/snapshot/parse.ts` with:

```ts
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

export interface Snapshot {
  version: string;
  format: number;                     // 3 or 4 — what the container's version byte claimed
  s4: Uint32Array; e4: Uint32Array; idx4: Uint32Array; bm4: Uint32Array;
  s6: Uint32Array; e6: Uint32Array; n6: number; bm6: Uint32Array;
  asnBm: Uint32Array; asnExtra: Uint32Array;
  country: Set<string>; tls: Set<string>;
  pathsExact: Set<string>; pathsPrefix: Set<string>; pathsRegex: RegExp[];
  allow: RangeSet; challenge: RangeSet;
}

const MAGIC_FAMILY = 0x424c4b00;   // 'BLK' + a version byte
const VERSION_BYTES: Record<number, number> = { 0x33: 3, 0x34: 4 };

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
  return {
    r4, r6, n6: r6.length >>> 3, asn, country, pathsExact, pathsPrefix,
    empty: r4.length === 0 && r6.length === 0 && asn.size === 0 && country.size === 0 && pathsExact.size === 0 && pathsPrefix.size === 0,
  };
}

/** Parses a BLK3 container + meta into a Snapshot. Throws on a malformed container —
 *  callers keep the previous snapshot, exactly like the edge collector does. */
export function parseSnapshot(bin: ArrayBuffer | Uint8Array, meta: SnapshotMeta): Snapshot {
  const u = words(bin);
  if (u.length < 2 || (u[0] & 0xffffff00) !== MAGIC_FAMILY) throw new Error('camada: not a BLK3 snapshot');
  const format = VERSION_BYTES[u[0] & 0xff];
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
```

Export the new types from `~/Github/camada-all/camada-core/src/index.ts` by replacing line 1 with:

```ts
export { parseSnapshot, type Snapshot, type SnapshotMeta, type SnapshotSetMeta, type RangeSet } from './snapshot/parse.js';
```

- [ ] **Step 5: Run the tests**

Run: `cd ~/Github/camada-all/camada-core && npm test && npm run check`
Expected: PASS (all existing tests plus the three new ones).

- [ ] **Step 6: Review and commit**

Run agent `fable-simplifier` on the diff, then agent `fable-reviewer`; apply findings.

```bash
cd ~/Github/camada-all/camada-core
git add -A src test
git commit -m "$(cat <<'MSG'
feat(core): BLK3 v4 container — allow/challenge sections 10-13 and side meta

Claude-Session: https://claude.ai/code/session_014GA5a631prhERB2zJ2by1n
MSG
)"
```

---

### Task 2: core — three-way match (allow → block → challenge) and `snapshotVersion`

**Files:**
- Modify: `~/Github/camada-all/camada-core/src/snapshot/match.ts`
- Modify: `~/Github/camada-all/camada-core/src/snapshot/client.ts`
- Modify: `~/Github/camada-all/camada-core/src/index.ts`
- Create: `~/Github/camada-all/camada-core/test/fixtures/cases-v4.json`
- Test: `~/Github/camada-all/camada-core/test/conformance.test.ts` (extend), `~/Github/camada-all/camada-core/test/client.test.ts` (extend)

**Interfaces:**
- Consumes: `Snapshot`, `RangeSet` from Task 1.
- Produces:
  - `type MatchReason = 'ip4' | 'ip6' | 'asn' | 'country' | 'tls' | 'path'` (and `type BlockReason = MatchReason`, kept for callers).
  - `interface MatchResult { block: boolean; challenge: boolean; allowed: boolean; reason?: MatchReason; version?: string }`
  - `interface Verdict { block: boolean; challenge: boolean; allowed: boolean; reason?: MatchReason | 'cold'; version?: string }`
  - `SnapshotClientOptions.snapshotVersion?: 3 | 4` (default `4`; `4` sends `x-camada-snapshot: 4`).
  Tasks 4–6 read `v.block`, `v.challenge` and `v.reason` only.

- [ ] **Step 1: Write the hand-derived expectation table**

Create `~/Github/camada-all/camada-core/test/fixtures/cases-v4.json`. Expectations are derived by hand from contracts §A3/§D2 (order allow → block → challenge), NOT from running the implementation — that is what makes this a conformance table.

```json
{
  "note": "Hand-derived from contracts.md §A3/§D2 against test/fixtures/v4/build.mjs. Replace with edge-analyst/fixtures/blk3/ when it lands.",
  "cases": [
    { "input": { "ip": "203.0.113.66" }, "expect": "block:ip4" },
    { "input": { "ip": "10.5.5.5" }, "expect": "block:ip4" },
    { "input": { "ip": "10.1.2.3" }, "expect": "allow:ip4" },
    { "input": { "ip": "198.51.100.7" }, "expect": "allow:ip4" },
    { "input": { "ip": "198.51.100.8" }, "expect": "block:ip4" },
    { "input": { "ip": "192.0.2.5" }, "expect": "challenge:ip4" },
    { "input": { "ip": "192.0.2.0" }, "expect": "challenge:ip4" },
    { "input": { "ip": "192.0.2.255" }, "expect": "challenge:ip4" },
    { "input": { "ip": "192.0.3.0" }, "expect": "none" },
    { "input": { "ip": "2001:db8::1" }, "expect": "block:ip6" },
    { "input": { "ip": "2001:db8:dead::5" }, "expect": "allow:ip6" },
    { "input": { "ip": "2001:db8:dead::6" }, "expect": "block:ip6" },
    { "input": { "ip": "2001:db8:beef::1" }, "expect": "challenge:ip6" },
    { "input": { "ip": "2001:db8:beef:ffff:ffff:ffff:ffff:ffff" }, "expect": "challenge:ip6" },
    { "input": { "ip": "2001:db8:beee::1" }, "expect": "none" },
    { "input": { "ip": "8.8.8.8", "asn": 14061 }, "expect": "block:asn" },
    { "input": { "ip": "8.8.8.8", "asn": 3356 }, "expect": "allow:asn" },
    { "input": { "ip": "8.8.8.8", "asn": 64500 }, "expect": "challenge:asn" },
    { "input": { "ip": "8.8.8.8", "asn": 65535 }, "expect": "none" },
    { "input": { "ip": "8.8.8.8", "country": "RU" }, "expect": "block:country" },
    { "input": { "ip": "8.8.8.8", "country": "CN" }, "expect": "allow:country" },
    { "input": { "ip": "8.8.8.8", "country": "BR" }, "expect": "challenge:country" },
    { "input": { "ip": "8.8.8.8", "country": "US" }, "expect": "none" },
    { "input": { "ip": "8.8.8.8", "tlsx": "9f0a77c2" }, "expect": "block:tls" },
    { "input": { "ip": "8.8.8.8", "tlsx": "deadbeef" }, "expect": "none" },
    { "input": { "ip": "8.8.8.8", "path": "/blocked-path" }, "expect": "allow:path" },
    { "input": { "ip": "8.8.8.8", "path": "/locked/x" }, "expect": "block:path" },
    { "input": { "ip": "8.8.8.8", "path": "/checkout/cart" }, "expect": "challenge:path" },
    { "input": { "ip": "8.8.8.8", "path": "/login" }, "expect": "challenge:path" },
    { "input": { "ip": "8.8.8.8", "path": "/login?next=/x" }, "expect": "challenge:path" },
    { "input": { "ip": "8.8.8.8", "path": "/" }, "expect": "none" },
    { "input": { "ip": "10.1.2.3", "path": "/locked/x" }, "expect": "allow:ip4" },
    { "input": { "ip": "10.1.2.3", "country": "RU" }, "expect": "allow:ip4" },
    { "input": { "ip": "192.0.2.5", "path": "/locked/x" }, "expect": "block:path" },
    { "input": { "ip": "8.8.8.8", "asn": 3356, "country": "RU" }, "expect": "allow:asn" }
  ]
}
```

Add to `~/Github/camada-all/camada-core/test/conformance.test.ts` (keep everything already there):

```ts
interface V4Case { input: MatchInput; expect: string }
const v4 = json('cases-v4.json') as { cases: V4Case[] };

describe('BLK3 v4 match order (allow -> block -> challenge)', () => {
  const m = new Matcher(parseSnapshot(bin('snap-v4.bin'), json('snap-v4.meta.json')));
  const label = (r: ReturnType<Matcher['match']>) =>
    r.allowed ? `allow:${r.reason}` : r.block ? `block:${r.reason}` : r.challenge ? `challenge:${r.reason}` : 'none';

  it.each(v4.cases.map((c) => [JSON.stringify(c.input), c] as const))('%s', (_l, c) => {
    expect(label(m.match(c.input))).toBe(c.expect);
  });

  it('never sets two outcome flags at once', () => {
    for (const c of v4.cases) {
      const r = m.match(c.input);
      expect(Number(r.allowed) + Number(r.block) + Number(r.challenge)).toBeLessThanOrEqual(1);
    }
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ~/Github/camada-all/camada-core && npx vitest run test/conformance.test.ts`
Expected: FAIL — `r.allowed` / `r.challenge` are undefined, so every case labels as `block:…` or `none`.

- [ ] **Step 3: Implement the matcher**

Replace `~/Github/camada-all/camada-core/src/snapshot/match.ts` with:

```ts
// Matcher: sub-microsecond checks over a parsed Snapshot, ported from edge-analyst
// src/blocklist.js blocked4/blocked6/blockedAsn/blockedPath/blockReason. The module-level
// scratch arrays of the original are instance fields here (safe under worker_threads and
// interleaved matchers); matching stays fully synchronous.
//
// Outcome order is contract (contracts §D2, fixtures pin it): allow -> block -> challenge.
// Within each side the axis order is ip4 -> ip6 -> asn -> country -> tls -> path.
// At the SDK position only ip and path are usually known; asn/country/tlsx entries then simply
// never match — that is the documented, honest enforcement scope (fail open, never guess).

import type { Snapshot, RangeSet } from './parse.js';
import { parseIp4, parseIp6Into } from './ipparse.js';

export interface MatchInput {
  ip?: string | null;
  asn?: number | null;
  country?: string | null;
  tlsx?: string | null;
  path?: string | null;
}

export type MatchReason = 'ip4' | 'ip6' | 'asn' | 'country' | 'tls' | 'path';
/** The name this was called before v4 gave allow and challenge the same axes. */
export type BlockReason = MatchReason;

export interface MatchResult {
  block: boolean;
  challenge: boolean;
  allowed: boolean;
  reason?: MatchReason;
  version?: string;
}

const cleanPath = (raw: string | null | undefined): string => {
  const p = raw || '/';
  const q = p.indexOf('?');
  return q === -1 ? p : p.slice(0, q);
};

/** Binary search over interleaved [start, end] uint32 pairs sorted by start. */
function inRange4(r: Uint32Array, n: number): boolean {
  let lo = 0, hi = (r.length >>> 1) - 1;
  if (hi < 0) return false;
  while (lo < hi) { const m = (lo + hi + 1) >>> 1; if (r[m * 2] <= n) lo = m; else hi = m - 1; }
  return r[lo * 2] <= n && n <= r[lo * 2 + 1];
}

/** Walks every '/'-terminated ancestor of `path`, the same way the block side does. */
function prefixHit(prefixes: Set<string>, path: string): boolean {
  let i = path.indexOf('/', 1);
  while (i !== -1) { if (prefixes.has(path.slice(0, i + 1))) return true; i = path.indexOf('/', i + 1); }
  return false;
}

export class Matcher {
  private readonly W = new Uint32Array(4);
  private readonly G = new Uint16Array(8);
  constructor(readonly snap: Snapshot) {}

  private blocked4(n: number): boolean {
    const S = this.snap, b = n >>> 8;
    if ((S.bm4[b >>> 5] & (1 << (b & 31))) === 0) return false;
    const hi = n >>> 16;
    let l = S.idx4[hi], r = S.idx4[hi + 1] - 1;
    if (l > 0) l--;
    if (r < l) return false;
    while (l < r) { const m = (l + r + 1) >>> 1; if (S.s4[m] <= n) l = m; else r = m - 1; }
    return S.s4[l] <= n && n <= S.e4[l];
  }

  /** Compares the 4 words at A[o..o+3] against the parsed address in W. */
  private cmpW(A: Uint32Array, o: number): number {
    for (let k = 0; k < 4; k++) { const a = A[o + k], w = this.W[k]; if (a !== w) return a < w ? -1 : 1; }
    return 0;
  }

  private blocked6(): boolean {
    const S = this.snap, b = this.W[0] >>> 8;
    if ((S.bm6[b >>> 5] & (1 << (b & 31))) === 0) return false;
    let l = 0, r = S.n6 - 1;
    if (r < 0) return false;
    while (l < r) { const m = (l + r + 1) >>> 1; if (this.cmpW(S.s6, m * 4) <= 0) l = m; else r = m - 1; }
    return this.cmpW(S.s6, l * 4) <= 0 && this.cmpW(S.e6, l * 4) >= 0;
  }

  /** Binary search over an interleaved [4-word start, 4-word end] side section. */
  private inRange6(r: Uint32Array, n: number): boolean {
    if (n < 1) return false;
    let lo = 0, hi = n - 1;
    while (lo < hi) { const m = (lo + hi + 1) >>> 1; if (this.cmpW(r, m * 8) <= 0) lo = m; else hi = m - 1; }
    const o = lo * 8;
    return this.cmpW(r, o) <= 0 && this.cmpW(r, o + 4) >= 0;
  }

  private blockedAsn(asn: number): boolean {
    const S = this.snap;
    if (asn < 4194304) return (S.asnBm[asn >>> 5] & (1 << (asn & 31))) !== 0;
    let l = 0, r = S.asnExtra.length - 1;
    while (l <= r) { const m = (l + r) >>> 1; const v = S.asnExtra[m]; if (v === asn) return true; if (v < asn) l = m + 1; else r = m - 1; }
    return false;
  }

  private blockedPath(path: string): boolean {
    const S = this.snap;
    if (S.pathsExact.has(path)) return true;
    if (S.pathsPrefix.size && prefixHit(S.pathsPrefix, path)) return true;
    for (const re of S.pathsRegex) if (re.test(path)) return true;
    return false;
  }

  /** The block side (v3 sections + top-level meta). */
  private blockSide(input: MatchInput, n4: number, has6: boolean): MatchReason | null {
    const S = this.snap;
    if (n4 >= 0 && this.blocked4(n4)) return 'ip4';
    if (has6 && this.blocked6()) return 'ip6';
    if (input.asn !== undefined && input.asn !== null && this.blockedAsn(input.asn)) return 'asn';
    if (input.country && S.country.size && S.country.has(input.country)) return 'country';
    if (input.tlsx && S.tls.has(input.tlsx)) return 'tls';
    if (S.pathsExact.size || S.pathsPrefix.size || S.pathsRegex.length) {
      if (this.blockedPath(cleanPath(input.path))) return 'path';
    }
    return null;
  }

  /** A v4 side list (allow or challenge). No tls axis: §A3's side meta has no tls key. */
  private side(set: RangeSet, input: MatchInput, n4: number, has6: boolean): MatchReason | null {
    if (n4 >= 0 && inRange4(set.r4, n4)) return 'ip4';
    if (has6 && this.inRange6(set.r6, set.n6)) return 'ip6';
    if (input.asn !== undefined && input.asn !== null && set.asn.has(input.asn)) return 'asn';
    if (input.country && set.country.has(input.country)) return 'country';
    if (set.pathsExact.size || set.pathsPrefix.size) {
      const p = cleanPath(input.path);
      if (set.pathsExact.has(p)) return 'path';
      if (set.pathsPrefix.size && prefixHit(set.pathsPrefix, p)) return 'path';
    }
    return null;
  }

  match(input: MatchInput): MatchResult {
    const S = this.snap;
    const ip = input.ip || '';
    let n4 = -1, has6 = false;
    if (ip) {
      if (ip.indexOf(':') === -1) n4 = parseIp4(ip);
      else has6 = parseIp6Into(ip, this.W, this.G);
    }
    const allowed = S.allow.empty ? null : this.side(S.allow, input, n4, has6);
    if (allowed) return { block: false, challenge: false, allowed: true, reason: allowed, version: S.version };
    const blocked = this.blockSide(input, n4, has6);
    if (blocked) return { block: true, challenge: false, allowed: false, reason: blocked, version: S.version };
    const chal = S.challenge.empty ? null : this.side(S.challenge, input, n4, has6);
    if (chal) return { block: false, challenge: true, allowed: false, reason: chal, version: S.version };
    return { block: false, challenge: false, allowed: false, version: S.version };
  }
}
```

**Beware:** `blocked6()` and `inRange6()` both read `this.W`, which `match()` fills once per call — keep the parse at the top of `match()` and never reorder it below a `side()` call.

- [ ] **Step 4: Update the SnapshotClient**

In `~/Github/camada-all/camada-core/src/snapshot/client.ts`:

Replace the `Verdict` interface and the import line with:

```ts
import { Matcher, type MatchInput, type MatchReason } from './match.js';

/** Like MatchResult, plus 'cold' for "never loaded yet" (fail open, mirrors the collector). */
export interface Verdict {
  block: boolean;
  challenge: boolean;
  allowed: boolean;
  reason?: MatchReason | 'cold';
  version?: string;
}
```

Add to `SnapshotClientOptions` (after `sdk`):

```ts
  snapshotVersion?: 3 | 4;        // 4 (default) asks for the v4 sections via x-camada-snapshot; 3 opts out
```

Change the `opts` field type and the constructor default:

```ts
  private readonly opts: Required<Omit<SnapshotClientOptions, 'fetchImpl' | 'sdk'>> & { fetchImpl: typeof fetch; sdk?: string };
  ...
    this.opts = {
      refreshMs: DEFAULT_REFRESH_MS, fetchTimeoutMs: 3_000, mode: 'timer', snapshotVersion: 4,
      fetchImpl: opts.fetchImpl ?? fetch,
      ...given,
    };
```

In `load()`, after the `x-camada-sdk` line:

```ts
    if (this.opts.snapshotVersion === 4) headers['x-camada-snapshot'] = '4';
```

And replace `verdict()`:

```ts
  /** Cold (never loaded) and no-snapshot both fail open, mirroring the edge collector. */
  verdict(input: MatchInput): Verdict {
    if (!this.loadedAt) return { block: false, challenge: false, allowed: false, reason: 'cold' };
    if (!this.matcher) return { block: false, challenge: false, allowed: false };
    return this.matcher.match(input);
  }
```

Update `~/Github/camada-all/camada-core/src/index.ts` line 2:

```ts
export { Matcher, type MatchInput, type MatchResult, type MatchReason, type BlockReason } from './snapshot/match.js';
```

- [ ] **Step 5: Add the client test**

Append to `~/Github/camada-all/camada-core/test/client.test.ts` (reuse the file's existing fetch-stub helper style; if it has none, use this self-contained form):

```ts
describe('snapshotVersion', () => {
  const respond = () => new Response(null, { status: 204 });

  it('asks for v4 by default', async () => {
    let seen: Headers | undefined;
    const c = new SnapshotClient({ url: 'http://x/snapshot', token: 't', fetchImpl: async (_u, i) => { seen = new Headers(i?.headers); return respond(); } });
    c.start();
    await new Promise((r) => setTimeout(r, 5));
    expect(seen?.get('x-camada-snapshot')).toBe('4');
    c.stop();
  });

  it('omits the header when pinned to 3', async () => {
    let seen: Headers | undefined;
    const c = new SnapshotClient({ url: 'http://x/snapshot', token: 't', snapshotVersion: 3, fetchImpl: async (_u, i) => { seen = new Headers(i?.headers); return respond(); } });
    c.start();
    await new Promise((r) => setTimeout(r, 5));
    expect(seen?.get('x-camada-snapshot')).toBeNull();
    c.stop();
  });

  it('fails open with all three flags false while cold', () => {
    const c = new SnapshotClient({ url: 'http://x/snapshot', token: 't', fetchImpl: async () => respond() });
    expect(c.verdict({ ip: '1.2.3.4' })).toEqual({ block: false, challenge: false, allowed: false, reason: 'cold' });
  });
});
```

- [ ] **Step 6: Run everything**

Run: `cd ~/Github/camada-all/camada-core && npm test && npm run check && npm run build`
Expected: PASS. If `test/client.test.ts` or `test/parse.test.ts` assert on the old `{ block: false }` object shape with `toEqual`, update those assertions to the new three-flag shape — that is an intended contract change.

- [ ] **Step 7: Review and commit**

Run agent `fable-simplifier` on the diff, then agent `fable-reviewer`; apply findings.

```bash
cd ~/Github/camada-all/camada-core
git add -A src test
git commit -m "$(cat <<'MSG'
feat(core): match() returns allow/block/challenge in that order; snapshotVersion asks for v4

Claude-Session: https://claude.ai/code/session_014GA5a631prhERB2zJ2by1n
MSG
)"
```

---

### Task 3: core — the challenge kit (nonce, token, proof of work, page) and `TAP_HONO`

**Files:**
- Create: `~/Github/camada-all/camada-core/src/challenge/format.ts`
- Create: `~/Github/camada-all/camada-core/src/challenge/verify.ts`
- Create: `~/Github/camada-all/camada-core/src/challenge/verify-async.ts`
- Create: `~/Github/camada-all/camada-core/src/challenge/page.ts`
- Modify: `~/Github/camada-all/camada-core/src/constants.ts`, `~/Github/camada-all/camada-core/src/index.ts`, `~/Github/camada-all/camada-core/package.json` (version `0.1.0`)
- Test: `~/Github/camada-all/camada-core/test/challenge.test.ts`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces (Tasks 4, 5, 6 consume exactly these):
  - `CHALLENGE_COOKIE = '_cch'`, `CHALLENGE_TTL_MS = 3_600_000`, `POW_BITS = 16`
  - `challengeCookie(value: string, secure: boolean): string`
  - `safeReturnTo(raw: string | null | undefined): string`
  - `wantsHtml(accept: string | null, secFetchDest: string | null): boolean`
  - `parseFormBody(body: string): Record<string, string>`
  - `createChallenge(opts: { secret: string; hmac: (secret: string, msg: string) => string; sha: (msg: string) => string }): ChallengeKit`
  - `createChallengeAsync(opts: { secret: string }): AsyncChallengeKit` (same methods, each returning a Promise)
  - `ChallengeKit`: `nonce(ip, now): string`, `nonceValid(ip, now, nonce): boolean`, `issue(ip, now): string`, `tokenValid(ip, now, cookieValue): boolean`, `solutionOk(nonce, solution): boolean`
  - `challengePage(o: { nonce: string; action: string; to: string; bits?: number }): string`
  - `TAP_HONO = 'sdk-hono'`, `Tap` widened to include it.

- [ ] **Step 1: Write the failing test**

Create `~/Github/camada-all/camada-core/test/challenge.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { createHash, createHmac } from 'node:crypto';
import {
  createChallenge, createChallengeAsync, challengePage, challengeCookie, safeReturnTo,
  wantsHtml, parseFormBody, CHALLENGE_COOKIE, CHALLENGE_TTL_MS, POW_BITS,
} from '../src/index.js';

const kit = createChallenge({
  secret: 'tok-acme.snap-acme',
  hmac: (s, m) => createHmac('sha256', s).update(m).digest('hex'),
  sha: (m) => createHash('sha256').update(m).digest('hex'),
});
const solve = (nonce: string): string => {
  for (let n = 0; ; n++) if (createHash('sha256').update(`${nonce}.${n}`).digest('hex').startsWith('0000')) return String(n);
};

describe('nonce', () => {
  const now = Date.UTC(2026, 8, 4, 12, 0, 0);

  it('is deterministic per (ip, UTC day) and 32 hex chars', () => {
    const a = kit.nonce('1.2.3.4', now);
    expect(a).toMatch(/^[0-9a-f]{32}$/);
    expect(kit.nonce('1.2.3.4', now + 60_000)).toBe(a);
    expect(kit.nonce('1.2.3.5', now)).not.toBe(a);
  });

  it('accepts today and yesterday, rejects two days back and forgeries', () => {
    const day = 86_400_000;
    expect(kit.nonceValid('1.2.3.4', now, kit.nonce('1.2.3.4', now))).toBe(true);
    expect(kit.nonceValid('1.2.3.4', now, kit.nonce('1.2.3.4', now - day))).toBe(true);
    expect(kit.nonceValid('1.2.3.4', now, kit.nonce('1.2.3.4', now - 2 * day))).toBe(false);
    expect(kit.nonceValid('1.2.3.4', now, kit.nonce('9.9.9.9', now))).toBe(false);
    expect(kit.nonceValid('1.2.3.4', now, 'f'.repeat(32))).toBe(false);
  });
});

describe('token', () => {
  const now = 1_800_000_000_000;

  it('round-trips within the hour and expires after it', () => {
    const t = kit.issue('1.2.3.4', now);
    expect(kit.tokenValid('1.2.3.4', now, t)).toBe(true);
    expect(kit.tokenValid('1.2.3.4', now + CHALLENGE_TTL_MS - 1, t)).toBe(true);
    expect(kit.tokenValid('1.2.3.4', now + CHALLENGE_TTL_MS + 1, t)).toBe(false);
  });

  it('is bound to the ip and unforgeable', () => {
    const t = kit.issue('1.2.3.4', now);
    expect(kit.tokenValid('9.9.9.9', now, t)).toBe(false);
    const [exp] = t.split('.');
    expect(kit.tokenValid('1.2.3.4', now, `${exp}.${'0'.repeat(64)}`)).toBe(false);
    expect(kit.tokenValid('1.2.3.4', now, 'garbage')).toBe(false);
    expect(kit.tokenValid('1.2.3.4', now, null)).toBe(false);
  });
});

describe('proof of work', () => {
  it('accepts a 16-bit solution and rejects anything else', () => {
    const nonce = kit.nonce('1.2.3.4', Date.now());
    const sol = solve(nonce);
    expect(kit.solutionOk(nonce, sol)).toBe(true);
    expect(kit.solutionOk(nonce, String(Number(sol) + 1))).toBe(false);
    expect(kit.solutionOk(nonce, '')).toBe(false);
    expect(kit.solutionOk(nonce, 'x'.repeat(64))).toBe(false);
    expect(POW_BITS).toBe(16);
  });
});

describe('async kit', () => {
  it('agrees with the sync kit byte for byte', async () => {
    const a = createChallengeAsync({ secret: 'tok-acme.snap-acme' });
    const now = 1_800_000_000_000;
    expect(await a.nonce('1.2.3.4', now)).toBe(kit.nonce('1.2.3.4', now));
    const t = await a.issue('1.2.3.4', now);
    expect(kit.tokenValid('1.2.3.4', now, t)).toBe(true);
    expect(await a.tokenValid('1.2.3.4', now, kit.issue('1.2.3.4', now))).toBe(true);
    const nonce = await a.nonce('1.2.3.4', now);
    expect(await a.solutionOk(nonce, solve(nonce))).toBe(true);
  });
});

describe('helpers', () => {
  it('builds the cookie', () => {
    expect(challengeCookie('abc', false)).toBe(`${CHALLENGE_COOKIE}=abc; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax`);
    expect(challengeCookie('abc', true)).toContain('; Secure');
  });

  it('sanitises the return target to a same-site path', () => {
    expect(safeReturnTo('/cart?x=1')).toBe('/cart?x=1');
    expect(safeReturnTo('//evil.test/x')).toBe('/');
    expect(safeReturnTo('https://evil.test')).toBe('/');
    expect(safeReturnTo('/a\nb')).toBe('/');
    expect(safeReturnTo(null)).toBe('/');
    expect(safeReturnTo('/' + 'a'.repeat(4000))).toBe('/');
  });

  it('tells HTML navigations from everything else', () => {
    expect(wantsHtml('text/html,application/xhtml+xml', 'document')).toBe(true);
    expect(wantsHtml('text/html', null)).toBe(true);
    expect(wantsHtml('application/json', null)).toBe(false);
    expect(wantsHtml('text/html', 'empty')).toBe(false);
    expect(wantsHtml(null, null)).toBe(false);
  });

  it('parses a urlencoded body', () => {
    expect(parseFormBody('nonce=ab&solution=42&to=%2Fcart%3Fx%3D1')).toEqual({ nonce: 'ab', solution: '42', to: '/cart?x=1' });
    expect(parseFormBody('')).toEqual({});
  });
});

describe('page', () => {
  const html = challengePage({ nonce: 'abc123', action: '/__camada/challenge', to: '/cart?a="b' });

  it('is self-contained and no-JS-safe', () => {
    expect(html).toContain('<!doctype html>');
    expect(html).not.toMatch(/<script[^>]+src=/);
    expect(html).not.toMatch(/<link[^>]+href=/);
    expect(html).toContain('<noscript>');
  });

  it('escapes what it interpolates', () => {
    expect(html).toContain('value="/cart?a=&quot;b"');
    expect(html).toContain('value="abc123"');
    expect(html).toContain('action="/__camada/challenge"');
  });

  it('ships a solver that finds the same answer the server accepts', async () => {
    // Run the page's inline SHA-256 in this process and check it against node:crypto.
    const js = /<script>([\s\S]*)<\/script>/.exec(html)![1];
    const probe = `${js.replace('window.__camadaAutostart!==false', 'false')}\nreturn __camadaSha256Hex('abc.7');`;
    const fn = new Function('window', 'document', probe) as (w: unknown, d: unknown) => string;
    const got = fn({ __camadaAutostart: false }, { getElementById: () => null, addEventListener: () => {} });
    expect(got).toBe(createHash('sha256').update('abc.7').digest('hex'));
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ~/Github/camada-all/camada-core && npx vitest run test/challenge.test.ts`
Expected: FAIL — module `../src/index.js` has no export `createChallenge`.

- [ ] **Step 3: Write `src/challenge/format.ts`**

```ts
// Wire constants and pure helpers for the SDK-served challenge (contracts §D2, D32).
// Nothing here does crypto: the runtime supplies HMAC/SHA-256 (node:crypto in @camada/node,
// WebCrypto everywhere else) so the format has exactly one definition.

export const CHALLENGE_COOKIE = '_cch';
export const CHALLENGE_TTL_MS = 3_600_000;   // 1 h (contract)
export const POW_BITS = 16;                  // leading zero bits of SHA-256(`${nonce}.${solution}`)
export const NONCE_HEX = 32;                 // the nonce is the first 32 hex chars of the HMAC
const DAY_MS = 86_400_000;
const MAX_RETURN_TO = 2048;
const MAX_SOLUTION = 32;

export const utcDay = (now: number): number => Math.floor(now / DAY_MS);

// Domain-separated messages: a nonce HMAC can never be replayed as a cookie HMAC.
export const nonceMessage = (ip: string | null, day: number): string => `camada-challenge-nonce|${ip ?? ''}|${day}`;
export const tokenMessage = (ip: string | null, exp: number): string => `camada-challenge-token|${ip ?? ''}|${exp}`;

export function splitToken(value: string | null | undefined): { exp: number; mac: string } | null {
  if (!value) return null;
  const dot = value.indexOf('.');
  if (dot <= 0) return null;
  const exp = Number(value.slice(0, dot));
  const mac = value.slice(dot + 1);
  if (!Number.isFinite(exp) || !mac) return null;
  return { exp, mac };
}

/** Constant-time for equal-length hex strings; length itself is not a secret here. */
export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

/** True when the hex digest starts with `bits` zero bits. */
export function powOk(hex: string, bits: number = POW_BITS): boolean {
  const nibbles = bits >> 2;
  for (let i = 0; i < nibbles; i++) if (hex.charCodeAt(i) !== 48) return false;
  const rest = bits & 3;
  if (rest === 0) return true;
  const v = parseInt(hex[nibbles] ?? 'f', 16);
  return Number.isFinite(v) && (v >> (4 - rest)) === 0;
}

export const solutionShapeOk = (solution: string | null | undefined): solution is string =>
  !!solution && solution.length <= MAX_SOLUTION;

export function challengeCookie(value: string, secure: boolean): string {
  return `${CHALLENGE_COOKIE}=${value}; Path=/; Max-Age=${CHALLENGE_TTL_MS / 1000}; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`;
}

/** Only a same-site absolute path survives: never an absolute URL, a protocol-relative
 *  '//host' redirect, a control character, or something absurdly long. */
export function safeReturnTo(raw: string | null | undefined): string {
  if (!raw || raw.length > MAX_RETURN_TO) return '/';
  if (raw[0] !== '/' || raw[1] === '/' || raw[1] === '\\') return '/';
  for (let i = 0; i < raw.length; i++) { const c = raw.charCodeAt(i); if (c < 0x20 || c === 0x7f) return '/'; }
  return raw;
}

/** A challenge page is only worth serving to a top-level HTML navigation (contract §D2:
 *  "Accept without text/html, or sec-fetch-dest not document" gets 403 JSON instead). */
export function wantsHtml(accept: string | null, secFetchDest: string | null): boolean {
  if (!accept || accept.indexOf('text/html') === -1) return false;
  return !secFetchDest || secFetchDest === 'document';
}

export function escapeAttr(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] as string));
}

/** application/x-www-form-urlencoded, last value wins. Never throws on junk. */
export function parseFormBody(body: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const pair of body.split('&')) {
    if (!pair) continue;
    const eq = pair.indexOf('=');
    const k = eq === -1 ? pair : pair.slice(0, eq);
    const v = eq === -1 ? '' : pair.slice(eq + 1);
    try { out[decodeURIComponent(k.replace(/\+/g, ' '))] = decodeURIComponent(v.replace(/\+/g, ' ')); } catch { /* skip a malformed pair */ }
  }
  return out;
}
```

- [ ] **Step 4: Write `src/challenge/verify.ts`**

```ts
// The synchronous challenge kit. @camada/node builds it over node:crypto so its handle() can
// stay a synchronous boolean; the async twin (verify-async.ts) is the same logic over WebCrypto.
import {
  CHALLENGE_TTL_MS, NONCE_HEX, nonceMessage, tokenMessage, safeEqual, splitToken, powOk,
  solutionShapeOk, utcDay,
} from './format.js';

export interface ChallengeCryptoSync {
  secret: string;
  hmac: (secret: string, msg: string) => string;   // hex
  sha: (msg: string) => string;                    // hex SHA-256
}

export interface ChallengeKit {
  /** Stateless per-(ip, UTC day) nonce; the verify endpoint recomputes it, nothing is stored. */
  nonce(ip: string | null, now: number): string;
  nonceValid(ip: string | null, now: number, nonce: string | null | undefined): boolean;
  issue(ip: string | null, now: number): string;
  tokenValid(ip: string | null, now: number, cookieValue: string | null | undefined): boolean;
  solutionOk(nonce: string, solution: string | null | undefined): boolean;
}

export function createChallenge({ secret, hmac, sha }: ChallengeCryptoSync): ChallengeKit {
  const at = (ip: string | null, day: number) => hmac(secret, nonceMessage(ip, day)).slice(0, NONCE_HEX);
  return {
    nonce: (ip, now) => at(ip, utcDay(now)),
    // Yesterday still passes: a solve started before midnight UTC must not be thrown away.
    nonceValid(ip, now, nonce) {
      if (!nonce || nonce.length !== NONCE_HEX) return false;
      const day = utcDay(now);
      return safeEqual(nonce, at(ip, day)) || safeEqual(nonce, at(ip, day - 1));
    },
    issue(ip, now) {
      const exp = now + CHALLENGE_TTL_MS;
      return `${exp}.${hmac(secret, tokenMessage(ip, exp))}`;
    },
    tokenValid(ip, now, cookieValue) {
      const t = splitToken(cookieValue);
      if (!t || t.exp <= now || t.exp > now + CHALLENGE_TTL_MS) return false;
      return safeEqual(t.mac, hmac(secret, tokenMessage(ip, t.exp)));
    },
    solutionOk: (nonce, solution) => (solutionShapeOk(solution) ? powOk(sha(`${nonce}.${solution}`)) : false),
  };
}
```

- [ ] **Step 5: Write `src/challenge/verify-async.ts`**

```ts
// The WebCrypto twin of verify.ts, for runtimes with no synchronous HMAC (@camada/next,
// @camada/hono). Same messages, same token format — the two kits are interchangeable on the wire.
import {
  CHALLENGE_TTL_MS, NONCE_HEX, nonceMessage, tokenMessage, safeEqual, splitToken, powOk,
  solutionShapeOk, utcDay,
} from './format.js';

const enc = new TextEncoder();

const toHex = (buf: ArrayBuffer): string => {
  const b = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
};

function subtle(): SubtleCrypto {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c?.subtle) throw new Error('camada: WebCrypto subtle is unavailable — the challenge needs it');
  return c.subtle;
}

export async function hmacHex(secret: string, msg: string): Promise<string> {
  const key = await subtle().importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return toHex(await subtle().sign('HMAC', key, enc.encode(msg)));
}

export async function sha256Hex(msg: string): Promise<string> {
  return toHex(await subtle().digest('SHA-256', enc.encode(msg)));
}

export interface AsyncChallengeKit {
  nonce(ip: string | null, now: number): Promise<string>;
  nonceValid(ip: string | null, now: number, nonce: string | null | undefined): Promise<boolean>;
  issue(ip: string | null, now: number): Promise<string>;
  tokenValid(ip: string | null, now: number, cookieValue: string | null | undefined): Promise<boolean>;
  solutionOk(nonce: string, solution: string | null | undefined): Promise<boolean>;
}

export function createChallengeAsync({ secret }: { secret: string }): AsyncChallengeKit {
  const at = async (ip: string | null, day: number) => (await hmacHex(secret, nonceMessage(ip, day))).slice(0, NONCE_HEX);
  return {
    nonce: (ip, now) => at(ip, utcDay(now)),
    async nonceValid(ip, now, nonce) {
      if (!nonce || nonce.length !== NONCE_HEX) return false;
      const day = utcDay(now);
      return safeEqual(nonce, await at(ip, day)) || safeEqual(nonce, await at(ip, day - 1));
    },
    async issue(ip, now) {
      const exp = now + CHALLENGE_TTL_MS;
      return `${exp}.${await hmacHex(secret, tokenMessage(ip, exp))}`;
    },
    async tokenValid(ip, now, cookieValue) {
      const t = splitToken(cookieValue);
      if (!t || t.exp <= now || t.exp > now + CHALLENGE_TTL_MS) return false;
      return safeEqual(t.mac, await hmacHex(secret, tokenMessage(ip, t.exp)));
    },
    async solutionOk(nonce, solution) {
      return solutionShapeOk(solution) ? powOk(await sha256Hex(`${nonce}.${solution}`)) : false;
    },
  };
}
```

- [ ] **Step 6: Write `src/challenge/page.ts`**

The page carries its own SHA-256 because `crypto.subtle` is unavailable on plain-HTTP origins (non-secure contexts) and 65 536 `await subtle.digest()` calls would be slow anyway. The solver checks the top 16 bits of the first digest word, which is exactly `powOk(hex, 16)` on the server.

```ts
// The 403 challenge page: one self-contained HTML document, no external assets, no-store.
// The inline solver hunts a counter whose SHA-256(`${nonce}.${counter}`) starts with 16 zero
// bits (~65k hashes, tens of milliseconds), fills the hidden form and submits it. The form POST
// means the browser follows the verify endpoint's 302 natively, so the cookie is set and the
// original URL is re-fetched without any fetch/CORS/cookie subtleties.
import { POW_BITS, escapeAttr } from './format.js';

export interface ChallengePageOptions {
  nonce: string;
  action: string;   // the verify endpoint path
  to: string;       // where to send the browser afterwards (already run through safeReturnTo)
  bits?: number;
}

const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// One SHA-256 over an ASCII string. Returns the 8 state words; callers take either the hex
// digest or just H[0] (the fast path: 16 leading zero bits === H[0] >>> 16 === 0).
const SOLVER = `
var K=[${K.map((k) => '0x' + k.toString(16)).join(',')}];
function rr(x,n){return (x>>>n)|(x<<(32-n))}
function __camadaSha256Words(msg){
  var l=msg.length,wl=(((l+9+63)>>6)<<4),M=new Uint32Array(wl),i;
  for(i=0;i<l;i++)M[i>>2]|=(msg.charCodeAt(i)&255)<<(24-(i%4)*8);
  M[l>>2]|=0x80<<(24-(l%4)*8);
  M[wl-1]=l*8;
  var H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  var W=new Uint32Array(64),bi,t;
  for(bi=0;bi<wl;bi+=16){
    for(t=0;t<16;t++)W[t]=M[bi+t];
    for(t=16;t<64;t++){var x=W[t-15],y=W[t-2];
      W[t]=(W[t-16]+((rr(x,7)^rr(x,18)^(x>>>3))>>>0)+W[t-7]+((rr(y,17)^rr(y,19)^(y>>>10))>>>0))>>>0}
    var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
    for(t=0;t<64;t++){
      var t1=(h+(rr(e,6)^rr(e,11)^rr(e,25))+((e&f)^(~e&g))+K[t]+W[t])>>>0;
      var t2=((rr(a,2)^rr(a,13)^rr(a,22))+((a&b)^(a&c)^(b&c)))>>>0;
      h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0}
    H[0]=(H[0]+a)>>>0;H[1]=(H[1]+b)>>>0;H[2]=(H[2]+c)>>>0;H[3]=(H[3]+d)>>>0;
    H[4]=(H[4]+e)>>>0;H[5]=(H[5]+f)>>>0;H[6]=(H[6]+g)>>>0;H[7]=(H[7]+h)>>>0}
  return H}
function __camadaSha256Hex(msg){
  var H=__camadaSha256Words(msg),s='',i;
  for(i=0;i<8;i++)s+=('00000000'+H[i].toString(16)).slice(-8);
  return s}
`;

export function challengePage(o: ChallengePageOptions): string {
  const bits = o.bits ?? POW_BITS;
  const nonce = escapeAttr(o.nonce);
  const action = escapeAttr(o.action);
  const to = escapeAttr(o.to);
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Checking your browser</title>
<style>
:root{color-scheme:light}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#fafafa;color:#1a1a1a;font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:28rem;padding:2rem;text-align:center}
h1{font-size:1.25rem;margin:0 0 .5rem}
p{margin:.25rem 0;color:#555}
.bar{margin:1.5rem auto 0;width:12rem;height:4px;border-radius:2px;background:#e5e5e5;overflow:hidden}
.bar i{display:block;height:100%;width:30%;background:#1a1a1a;animation:s 1.1s ease-in-out infinite}
@keyframes s{0%{transform:translateX(-120%)}100%{transform:translateX(400%)}}
</style></head>
<body>
<main>
<h1>Checking your browser</h1>
<p id="camada-msg">This takes a moment. It runs entirely in your browser.</p>
<noscript><p>JavaScript is required to continue.</p></noscript>
<div class="bar"><i></i></div>
</main>
<form id="camada-f" method="POST" action="${action}">
<input type="hidden" name="nonce" value="${nonce}">
<input type="hidden" name="solution" id="camada-s">
<input type="hidden" name="to" value="${to}">
</form>
<script>${SOLVER}
(function(){
  if(typeof window==='undefined'||window.__camadaAutostart===false)return;
  var nonce=${JSON.stringify(o.nonce)},shift=32-${bits};
  function go(){
    for(var n=0;n<5000000;n++){
      if((__camadaSha256Words(nonce+'.'+n)[0]>>>shift)===0){
        document.getElementById('camada-s').value=String(n);
        document.getElementById('camada-f').submit();
        return}}
    document.getElementById('camada-msg').textContent='Could not complete the check. Please reload.'}
  setTimeout(go,30);
})();
</script>
</body></html>`;
}
```

- [ ] **Step 7: Wire the exports and the tap**

In `~/Github/camada-all/camada-core/src/constants.ts` replace lines 4–6 with:

```ts
export const TAP_NODE = 'sdk-node';
export const TAP_NEXT = 'sdk-next';
export const TAP_HONO = 'sdk-hono';
export type Tap = typeof TAP_NODE | typeof TAP_NEXT | typeof TAP_HONO;
```

Append to `~/Github/camada-all/camada-core/src/index.ts`:

```ts
export {
  CHALLENGE_COOKIE, CHALLENGE_TTL_MS, POW_BITS, NONCE_HEX,
  challengeCookie, safeReturnTo, wantsHtml, escapeAttr, parseFormBody, powOk, safeEqual, splitToken,
} from './challenge/format.js';
export { createChallenge, type ChallengeKit, type ChallengeCryptoSync } from './challenge/verify.js';
export { createChallengeAsync, hmacHex, sha256Hex, type AsyncChallengeKit } from './challenge/verify-async.js';
export { challengePage, type ChallengePageOptions } from './challenge/page.js';
```

and update the constants export line:

```ts
export { TAP_NODE, TAP_NEXT, TAP_HONO, type Tap, DEFAULT_REFRESH_MS, KILL_SWITCH_ENV } from './constants.js';
```

Set `"version": "0.1.0"` in `~/Github/camada-all/camada-core/package.json`.

- [ ] **Step 8: Run everything**

Run: `cd ~/Github/camada-all/camada-core && npm test && npm run check && npm run build`
Expected: PASS.

- [ ] **Step 9: Review and commit**

Run agent `fable-simplifier` on the diff, then agent `fable-reviewer`; apply findings.

```bash
cd ~/Github/camada-all/camada-core
git add -A src test package.json
git commit -m "$(cat <<'MSG'
feat(core): challenge kit — stateless nonce, _cch token, 16-bit PoW, self-contained page

Claude-Session: https://claude.ai/code/session_014GA5a631prhERB2zJ2by1n
MSG
)"
```

---

### Task 4: @camada/node — serve and verify the challenge

**Files:**
- Modify: `~/Github/camada-all/camada-node/src/env.ts`
- Create: `~/Github/camada-all/camada-node/src/challenge.ts`
- Modify: `~/Github/camada-all/camada-node/src/camada.ts`, `~/Github/camada-all/camada-node/src/index.ts`
- Modify: `~/Github/camada-all/camada-node/package.json` (version `0.1.0`)
- Test: `~/Github/camada-all/camada-node/test/challenge.test.ts`

**Interfaces:**
- Consumes: from `@camada/core` — `createChallenge`, `challengePage`, `challengeCookie`, `safeReturnTo`, `wantsHtml`, `parseFormBody`, `CHALLENGE_COOKIE`; `SnapshotClient.verdict()` now returning `{ block, challenge, allowed, reason, version }`.
- Produces: `CamadaOptions.challenge?: boolean` (default `true`), `CamadaOptions.challengePath?: string` (default `/__camada/challenge`), `CamadaOptions.snapshotVersion?: 3 | 4`, `Camada.serveChallenge(req, res): boolean`, `camada.serveChallenge` on the default export (Task 7 uses it).

- [ ] **Step 1: Write the failing test**

Create `~/Github/camada-all/camada-node/test/challenge.test.ts`. Inspect `test/harness.ts` first and reuse its snapshot-serving stub; the shape below assumes a `makeCamada`-style helper — adapt names to what the harness actually exports, keeping the assertions identical.

```ts
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createHash } from 'node:crypto';
import { Camada } from '../src/camada.js';
import { CHALLENGE_COOKIE } from '@camada/core';
import { TEST_ENV, snapshotResponse, callHandle } from './harness.js';   // see the harness note below

// A snapshot whose challenge side holds 203.0.113.66 and /checkout/.
const CHALLENGED_IP = '203.0.113.66';

const solve = (nonce: string): string => {
  for (let n = 0; ; n++) if (createHash('sha256').update(`${nonce}.${n}`).digest('hex').startsWith('0000')) return String(n);
};

// TEST_ENV / snapshotResponse come from test/harness.ts (see the harness note below).
let cam: Camada;
beforeEach(async () => {
  cam = new Camada({ env: TEST_ENV, fetchImpl: snapshotResponse() });
  await callHandle(cam, { url: '/', headers: { 'x-forwarded-for': '8.8.8.8' } });   // first call is cold: it loads the snapshot
});
afterEach(() => cam?.stop());

describe('@camada/node challenge', () => {
  it('serves a 403 HTML page for an HTML navigation and ships blk: challenge', async () => {
    const { res, events } = await callHandle(cam, {
      url: '/cart', headers: { accept: 'text/html', 'sec-fetch-dest': 'document', 'x-forwarded-for': CHALLENGED_IP },
    });
    expect(res.statusCode).toBe(403);
    expect(res.headers['content-type']).toContain('text/html');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.body).toContain('Checking your browser');
    expect(events.at(-1)).toMatchObject({ st: 403, blk: 'challenge' });
  });

  it('answers 403 JSON for a non-HTML request', async () => {
    const { res } = await callHandle(cam, { url: '/api/x', headers: { accept: 'application/json', 'x-forwarded-for': CHALLENGED_IP } });
    expect(res.statusCode).toBe(403);
    expect(res.headers['content-type']).toContain('application/json');
    expect(JSON.parse(res.body)).toEqual({ error: 'challenge_required' });
  });

  it('accepts a correct solution, sets _cch, redirects back, and ships ch: 1', async () => {
    const page = await callHandle(cam, { url: '/cart', headers: { accept: 'text/html', 'x-forwarded-for': CHALLENGED_IP } });
    const nonce = /name="nonce" value="([0-9a-f]{32})"/.exec(page.res.body)![1];
    const body = `nonce=${nonce}&solution=${solve(nonce)}&to=%2Fcart`;
    const { res, events } = await callHandle(cam, {
      method: 'POST', url: '/__camada/challenge', headers: { 'x-forwarded-for': CHALLENGED_IP, 'content-type': 'application/x-www-form-urlencoded' }, body,
    });
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe('/cart');
    expect(String(res.headers['set-cookie'])).toContain(`${CHALLENGE_COOKIE}=`);
    expect(events.at(-1)).toMatchObject({ st: 200, ch: 1 });
  });

  it('lets a request with a valid _cch cookie through', async () => {
    const page = await callHandle(cam, { url: '/cart', headers: { accept: 'text/html', 'x-forwarded-for': CHALLENGED_IP } });
    const nonce = /name="nonce" value="([0-9a-f]{32})"/.exec(page.res.body)![1];
    const pass = await callHandle(cam, {
      method: 'POST', url: '/__camada/challenge', headers: { 'x-forwarded-for': CHALLENGED_IP, 'content-type': 'application/x-www-form-urlencoded' },
      body: `nonce=${nonce}&solution=${solve(nonce)}&to=%2Fcart`,
    });
    const cookie = String(pass.res.headers['set-cookie']).split(';')[0];
    const after = await callHandle(cam, { url: '/cart', headers: { accept: 'text/html', cookie, 'x-forwarded-for': CHALLENGED_IP } });
    expect(after.handled).toBe(false);   // the app renders it
  });

  it('rejects a wrong solution with a fresh page', async () => {
    const page = await callHandle(cam, { url: '/cart', headers: { accept: 'text/html', 'x-forwarded-for': CHALLENGED_IP } });
    const nonce = /name="nonce" value="([0-9a-f]{32})"/.exec(page.res.body)![1];
    const { res } = await callHandle(cam, {
      method: 'POST', url: '/__camada/challenge', headers: { 'x-forwarded-for': CHALLENGED_IP, 'content-type': 'application/x-www-form-urlencoded' },
      body: `nonce=${nonce}&solution=1&to=%2Fcart`,
    });
    expect(res.statusCode).toBe(403);
    expect(res.body).toContain('Checking your browser');
    expect(res.headers['set-cookie']).toBeUndefined();
  });

  it('never redirects off-site', async () => {
    const page = await callHandle(cam, { url: '/cart', headers: { accept: 'text/html', 'x-forwarded-for': CHALLENGED_IP } });
    const nonce = /name="nonce" value="([0-9a-f]{32})"/.exec(page.res.body)![1];
    const { res } = await callHandle(cam, {
      method: 'POST', url: '/__camada/challenge', headers: { 'x-forwarded-for': CHALLENGED_IP, 'content-type': 'application/x-www-form-urlencoded' },
      body: `nonce=${nonce}&solution=${solve(nonce)}&to=https%3A%2F%2Fevil.test`,
    });
    expect(res.headers.location).toBe('/');
  });

  it('does nothing when challenge: false', async () => {
    const off = new Camada({ env: TEST_ENV, fetchImpl: snapshotResponse(), challenge: false });
    try {
      await callHandle(off, { url: '/', headers: { 'x-forwarded-for': '8.8.8.8' } });   // warm the snapshot
      const { handled } = await callHandle(off, { url: '/cart', headers: { accept: 'text/html', 'x-forwarded-for': CHALLENGED_IP } });
      expect(handled).toBe(false);
    } finally { off.stop(); }
  });
});
```

**Harness note:** `test/harness.ts` already builds a `Camada` against a stub `fetchImpl` that serves a snapshot frame and collects `POST /e` bodies. Extend it with:
1. an exported `snapshotFrame(meta, bin)` builder if it does not have one (frame = `[u32 LE meta length][meta JSON][BLK3 bytes]`) — feed it `camada-core/test/fixtures/snap-v4.bin` + `snap-v4.meta.json` (copy both files into `camada-node/test/fixtures/`, they are golden data, not source);
2. `callHandle(cam, { method?, url, headers, body? })` that builds a fake `IncomingMessage`/`ServerResponse` pair (the file already fakes these for the blocked-path tests), calls `cam.handle`, waits a tick for the async verify path, and returns `{ handled, res: { statusCode, headers, body }, events }` where `events` is every event pushed to the queue so far.
Reuse the existing fakes; do not write a second set.

- [ ] **Step 2: Run to verify it fails**

Run: `cd ~/Github/camada-all/camada-node && npx vitest run test/challenge.test.ts`
Expected: FAIL — the engine has no challenge branch, so `/cart` is not handled.

- [ ] **Step 3: Add `secret` to the resolved env**

In `~/Github/camada-all/camada-node/src/env.ts`, add `secret: string;` to `ResolvedEnv` (with the comment `// HMAC key for the challenge nonce/cookie — never leaves the process`), and in the returned object:

```ts
    secret: env.CAMADA_KEY || `${ingestToken}.${snapToken}`,
```

- [ ] **Step 4: Write `src/challenge.ts`**

```ts
// The challenge for @camada/node. node:crypto gives us a synchronous HMAC, so the cookie check
// costs nothing on the hot path and Camada.handle() stays a synchronous boolean.
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createHash, createHmac } from 'node:crypto';
import { createChallenge, type ChallengeKit } from '@camada/core';

export const CHALLENGE_PATH = '/__camada/challenge';
export const BODY_MAX = 4 * 1024;   // the verify form is ~120 bytes; anything larger is not ours

export function nodeChallengeKit(secret: string): ChallengeKit {
  return createChallenge({
    secret,
    hmac: (s, m) => createHmac('sha256', s).update(m).digest('hex'),
    sha: (m) => createHash('sha256').update(m).digest('hex'),
  });
}

/** Reads at most BODY_MAX bytes; hands back '' when the client sends more (or errors). */
export function readBody(req: IncomingMessage, done: (body: string) => void): void {
  const chunks: Buffer[] = [];
  let size = 0, dead = false;
  req.on('data', (c: Buffer) => {
    if (dead) return;
    size += c.length;
    if (size > BODY_MAX) { dead = true; chunks.length = 0; return; }
    chunks.push(c);
  });
  req.on('end', () => done(dead ? '' : Buffer.concat(chunks).toString('utf8')));
  req.on('error', () => done(''));
}

export const isHttps = (req: IncomingMessage): boolean =>
  !!(req.socket as { encrypted?: boolean } | undefined)?.encrypted || req.headers['x-forwarded-proto'] === 'https';

export function writeChallengePage(res: ServerResponse, html: string): void {
  res.writeHead(403, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-camada-challenge': '1' });
  res.end(html);
}

export function writeChallengeJson(res: ServerResponse): void {
  res.writeHead(403, { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-camada-challenge': '1' });
  res.end('{"error":"challenge_required"}');
}
```

- [ ] **Step 5: Wire the engine**

In `~/Github/camada-all/camada-node/src/camada.ts`:

Extend the core import with `challengePage, challengeCookie, safeReturnTo, wantsHtml, parseFormBody, CHALLENGE_COOKIE, type ChallengeKit` and add:

```ts
import { CHALLENGE_PATH, nodeChallengeKit, readBody, isHttps, writeChallengePage, writeChallengeJson } from './challenge.js';
```

Add to `CamadaOptions`:

```ts
  challenge?: boolean;           // enforce `challenge` verdicts with the first-party page (default true)
  challengePath?: string;        // where the page posts its solution (default /__camada/challenge)
  snapshotVersion?: 3 | 4;       // 3 opts out of the v4 allow/challenge sections
```

Add fields and constructor wiring:

```ts
  private readonly challengeOn: boolean;
  private readonly challengePath: string;
  private readonly kit: ChallengeKit | null = null;
  ...
    this.challengeOn = opts.challenge !== false;
    this.challengePath = opts.challengePath ?? CHALLENGE_PATH;
    ...
    this.snap = new SnapshotClient({
      url: this.env.snapshotUrl, token: this.env.snapToken,
      mode: this.env.serverless ? 'lazy' : 'timer',
      refreshMs: opts.refreshMs, snapshotVersion: opts.snapshotVersion, fetchImpl: this.fetchImpl, sdk: SDK_ID,
    });
    this.kit = nodeChallengeKit(this.env.secret);
```

In `handleInner`, immediately after the `if (v.block) { … }` block, insert:

```ts
    if (this.challengeOn && this.kit) {
      // The verify endpoint answers first — a challenged client must be able to reach it.
      if (req.method === 'POST' && path === this.challengePath) { this.verifyChallenge(req, res, ip); return true; }
      if (v.challenge && !this.challengePassed(req, ip)) { this.serveChallengeInner(req, res, ip, path + query); return true; }
    }
```

Add the three methods (place them after `relayBeacon`):

```ts
  private challengePassed(req: IncomingMessage, ip: string | null): boolean {
    return !!this.kit?.tokenValid(ip, Date.now(), cookieValue((req.headers.cookie as string) || '', CHALLENGE_COOKIE));
  }

  /** 403 + the proof-of-work page (HTML navigations) or 403 JSON (everything else), plus the
   *  `blk: "challenge"` event — a served challenge is a block for accounting (contract §D2). */
  private serveChallengeInner(req: CamadaRequest, res: ServerResponse, ip: string | null, target: string): void {
    const html = wantsHtml(req.headers.accept as string | undefined ?? null, (req.headers['sec-fetch-dest'] as string | undefined) ?? null);
    if (html) {
      writeChallengePage(res, challengePage({
        nonce: this.kit!.nonce(ip, Date.now()),
        action: this.challengePath,
        to: safeReturnTo(target),
      }));
    } else {
      writeChallengeJson(res);
    }
    const qi = target.indexOf('?');
    const ev = this.buildEvent(req, qi === -1 ? target : target.slice(0, qi), qi === -1 ? '' : target.slice(qi), ip, { rid: randomUUID(), sid: null, newSession: false });
    ev.st = 403;
    ev.blk = 'challenge';
    this.queue!.push(ev);
  }

  /** POST from the challenge page: validate the nonce and the proof of work, set `_cch`, 302
   *  back to the (sanitised, same-site) original URL, and ship `{ st: 200, ch: 1 }`. */
  private verifyChallenge(req: CamadaRequest, res: ServerResponse, ip: string | null): void {
    readBody(req, (body) => guarded(() => {
      const form = parseFormBody(body);
      const to = safeReturnTo(form.to);
      const now = Date.now();
      if (!this.kit!.nonceValid(ip, now, form.nonce) || !this.kit!.solutionOk(form.nonce, form.solution)) {
        writeChallengePage(res, challengePage({ nonce: this.kit!.nonce(ip, now), action: this.challengePath, to }));
        return;
      }
      res.writeHead(302, {
        location: to,
        'set-cookie': challengeCookie(this.kit!.issue(ip, now), isHttps(req)),
        'cache-control': 'no-store',
      });
      res.end();
      const ev = this.buildEvent(req, this.challengePath, '', ip, { rid: randomUUID(), sid: null, newSession: false });
      ev.st = 200;
      ev.ch = 1;   // challenge passed (contract §A3 ingest field)
      this.queue!.push(ev);
    }, undefined));
  }

  /** Public: serve the challenge for this request on demand (used by the examples' /challenge-me
   *  and by apps that gate a route themselves). Returns false when the client already holds a
   *  valid `_cch` — the caller then renders its own page. */
  serveChallenge(req: IncomingMessage, res: ServerResponse): boolean {
    return guarded(() => {
      if (this.disabled || !this.kit || !this.queue) return false;
      const r = req as CamadaRequest;
      const ip = resolveClientIp(req.socket?.remoteAddress, req.headers['x-forwarded-for'] as string | undefined, this.trustedProxy());
      if (this.challengePassed(req, ip)) return false;
      this.serveChallengeInner(r, res, ip, req.url || '/');
      return true;
    }, false);
  }
```

In `~/Github/camada-all/camada-node/src/index.ts`, add to the default export object:

```ts
  serveChallenge: (req: IncomingMessage, res: ServerResponse) => getDefault().serveChallenge(req, res),
```

Set `"version": "0.1.0"` in `~/Github/camada-all/camada-node/package.json`.

- [ ] **Step 6: Run the tests**

Run: `cd ~/Github/camada-all/camada-core && npm run build && cd ~/Github/camada-all/camada-node && npm test && npm run check && npm run build`
Expected: PASS (existing 18 tests plus the new challenge suite).

- [ ] **Step 7: Review and commit**

Run agent `fable-simplifier` on the diff, then agent `fable-reviewer`; apply findings.

```bash
cd ~/Github/camada-all/camada-node
git add -A src test package.json
git commit -m "$(cat <<'MSG'
feat(node): first-party challenge — PoW page, POST /__camada/challenge, _cch cookie (SDK-04)

Claude-Session: https://claude.ai/code/session_014GA5a631prhERB2zJ2by1n
MSG
)"
```

---

### Task 5: @camada/next — challenge in the middleware and the route handler

**Files:**
- Modify: `~/Github/camada-all/camada-next/src/engine.ts`
- Create: `~/Github/camada-all/camada-next/src/challenge.ts`
- Modify: `~/Github/camada-all/camada-next/src/middleware.ts`, `~/Github/camada-all/camada-next/src/route.ts`, `~/Github/camada-all/camada-next/src/index.ts`
- Modify: `~/Github/camada-all/camada-next/package.json` (version `0.1.0`)
- Test: `~/Github/camada-all/camada-next/test/challenge.test.ts`

**Interfaces:**
- Consumes: `createChallengeAsync`, `challengePage`, `challengeCookie`, `safeReturnTo`, `wantsHtml`, `parseFormBody`, `CHALLENGE_COOKIE` from `@camada/core`.
- Produces: `challengeGate(req: Request): Promise<Response | null>` exported from `@camada/next` (Task 7 uses it); `camada()`'s return type widened to `Response | undefined | Promise<Response | undefined>`; `camadaRoute()`'s `POST` also answers `…/camada/challenge`.

- [ ] **Step 1: Write the failing test**

Create `~/Github/camada-all/camada-next/test/challenge.test.ts`, modelled on the existing `test/middleware.test.ts` (reuse its `configure({ env, fetchImpl })` setup and its snapshot-frame stub; copy `snap-v4.bin` / `snap-v4.meta.json` from `camada-core/test/fixtures/` into `camada-next/test/fixtures/`).

```ts
import { describe, it, expect, afterEach } from 'vitest';
import { createHash } from 'node:crypto';
import { CHALLENGE_COOKIE } from '@camada/core';
import { camada } from '../src/middleware';
import { camadaRoute } from '../src/route';
import { challengeGate } from '../src/challenge';
import { configure } from '../src/engine';
import { setupV4 } from './harness';   // adds a v4 snapshot to the existing harness

const CHALLENGED_IP = '203.0.113.66';
const solve = (nonce: string): string => {
  for (let n = 0; ; n++) if (createHash('sha256').update(`${nonce}.${n}`).digest('hex').startsWith('0000')) return String(n);
};
const nonceOf = (html: string) => /name="nonce" value="([0-9a-f]{32})"/.exec(html)![1];

afterEach(() => configure({}));

describe('@camada/next challenge', () => {
  it('serves the page from the middleware and ships blk: challenge', async () => {
    const { events, fetchImpl, env } = setupV4();
    configure({ env, fetchImpl });
    const mw = camada();
    const req = new Request('https://shop.test/cart', { headers: { 'x-forwarded-for': CHALLENGED_IP, accept: 'text/html', 'sec-fetch-dest': 'document' } });
    const res = await mw(req as never, { waitUntil: () => {} } as never)!;
    expect(res!.status).toBe(403);
    expect(res!.headers.get('content-type')).toContain('text/html');
    expect(await res!.text()).toContain('Checking your browser');
    expect(events.at(-1)).toMatchObject({ st: 403, blk: 'challenge' });
  });

  it('answers 403 JSON for a non-HTML request', async () => {
    const { fetchImpl, env } = setupV4();
    configure({ env, fetchImpl });
    const res = await camada()(new Request('https://shop.test/checkout/api', { headers: { 'x-forwarded-for': CHALLENGED_IP, accept: 'application/json' } }) as never, { waitUntil: () => {} } as never)!;
    expect(res!.status).toBe(403);
    expect(await res!.json()).toEqual({ error: 'challenge_required' });
  });

  it('never challenges its own verify route', async () => {
    const { fetchImpl, env } = setupV4();
    configure({ env, fetchImpl });
    const res = await camada()(new Request('https://shop.test/api/camada/challenge', { method: 'POST', headers: { 'x-forwarded-for': CHALLENGED_IP, accept: 'text/html' } }) as never, { waitUntil: () => {} } as never);
    expect(res === undefined || res.status !== 403).toBe(true);
  });

  it('verifies a solution, sets _cch and redirects', async () => {
    const { events, fetchImpl, env } = setupV4();
    configure({ env, fetchImpl });
    const page = await camada()(new Request('https://shop.test/cart', { headers: { 'x-forwarded-for': CHALLENGED_IP, accept: 'text/html' } }) as never, { waitUntil: () => {} } as never)!;
    const nonce = nonceOf(await page!.text());
    const { POST } = camadaRoute();
    const res = await POST(new Request('https://shop.test/api/camada/challenge', {
      method: 'POST',
      headers: { 'x-forwarded-for': CHALLENGED_IP, 'content-type': 'application/x-www-form-urlencoded' },
      body: `nonce=${nonce}&solution=${solve(nonce)}&to=%2Fcart`,
    }));
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/cart');
    expect(res.headers.get('set-cookie')).toContain(`${CHALLENGE_COOKIE}=`);
    expect(events.at(-1)).toMatchObject({ st: 200, ch: 1 });
  });

  it('lets a request holding a valid _cch through', async () => {
    const { fetchImpl, env } = setupV4();
    configure({ env, fetchImpl });
    const page = await camada()(new Request('https://shop.test/cart', { headers: { 'x-forwarded-for': CHALLENGED_IP, accept: 'text/html' } }) as never, { waitUntil: () => {} } as never)!;
    const nonce = nonceOf(await page!.text());
    const { POST } = camadaRoute();
    const ok = await POST(new Request('https://shop.test/api/camada/challenge', {
      method: 'POST',
      headers: { 'x-forwarded-for': CHALLENGED_IP, 'content-type': 'application/x-www-form-urlencoded' },
      body: `nonce=${nonce}&solution=${solve(nonce)}&to=%2Fcart`,
    }));
    const cookie = ok.headers.get('set-cookie')!.split(';')[0];
    const res = await camada()(new Request('https://shop.test/cart', { headers: { 'x-forwarded-for': CHALLENGED_IP, accept: 'text/html', cookie } }) as never, { waitUntil: () => {} } as never);
    expect(res?.status).not.toBe(403);
  });

  it('challengeGate returns the page, then null once passed', async () => {
    const { fetchImpl, env } = setupV4();
    configure({ env, fetchImpl });
    const gate = await challengeGate(new Request('https://shop.test/challenge-me', { headers: { accept: 'text/html', 'x-forwarded-for': '8.8.8.8' } }));
    expect(gate?.status).toBe(403);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ~/Github/camada-all/camada-next && npx vitest run test/challenge.test.ts`
Expected: FAIL — `../src/challenge` does not exist.

- [ ] **Step 3: Engine — secret, challenge flag, snapshot version**

In `~/Github/camada-all/camada-next/src/engine.ts`:
- add `secret: string;` to `ResolvedEnv` and `secret: env.CAMADA_KEY || \`${ingestToken}.${snapToken}\`,` to the returned object;
- add to `ConfigureOptions`: `challenge?: boolean;` and `snapshotVersion?: 3 | 4;`
- pass the snapshot version through: `new SnapshotClient({ url: env.snapshotUrl, token: env.snapToken, mode: 'lazy', sdk: SDK_ID, snapshotVersion: overrides.snapshotVersion ?? 4, ...injected })`
- export the flag: `export const challengeEnabled = (): boolean => overrides.challenge !== false && envSource().CAMADA_CHALLENGE !== '0';`

- [ ] **Step 4: Write `src/challenge.ts`**

```ts
// The challenge for @camada/next. Edge-runtime-safe: WebCrypto only, no node: imports — this
// module is in the middleware's import graph (test/edge-safety.test.ts proves it).
import {
  createChallengeAsync, challengePage, challengeCookie, safeReturnTo, wantsHtml, parseFormBody,
  CHALLENGE_COOKIE, type AsyncChallengeKit,
} from '@camada/core';
import { getEngine, isDisabled, trustedProxy, type Engine } from './engine';
import { resolveClientIp } from '@camada/core';
import { buildEvent, cookieValue, SESSION_COOKIE } from './event';

/** The verify endpoint sits under whatever the app mounted the catch-all route on, so match on
 *  the tail rather than an absolute path: `app/api/camada/[...camada]/route.ts` -> /api/camada/challenge. */
export const isChallengeRoute = (path: string): boolean => /\/camada\/challenge\/?$/.test(path);

/** Where the challenge page posts: the conventional mount of the catch-all route handler. */
const VERIFY_PATH = '/api/camada/challenge';

const kits = new WeakMap<Engine, AsyncChallengeKit>();
export function kitFor(engine: Engine): AsyncChallengeKit {
  let k = kits.get(engine);
  if (!k) { k = createChallengeAsync({ secret: engine.env.secret }); kits.set(engine, k); }
  return k;
}

export const clientIp = (engine: Engine, req: Request): string | null =>
  resolveClientIp(null, req.headers.get('x-forwarded-for'), trustedProxy(engine));

export async function challengePassed(engine: Engine, req: Request, ip: string | null): Promise<boolean> {
  return kitFor(engine).tokenValid(ip, Date.now(), cookieValue(req.headers.get('cookie') || '', CHALLENGE_COOKIE));
}

/** 403 + page (HTML navigation) or 403 JSON, plus the `blk: "challenge"` event. */
export async function serveChallenge(engine: Engine, req: Request, ip: string | null, target: string, waitUntil?: (p: Promise<unknown>) => void): Promise<Response> {
  const path = new URL(req.url).pathname;
  const ev = buildEvent(req, path, ip, crypto.randomUUID(), cookieValue(req.headers.get('cookie') || '', SESSION_COOKIE), false);
  ev.st = 403;
  ev.blk = 'challenge';
  engine.queue.push(ev);
  engine.queue.flush(waitUntil);

  if (!wantsHtml(req.headers.get('accept'), req.headers.get('sec-fetch-dest'))) {
    return new Response('{"error":"challenge_required"}', {
      status: 403,
      headers: { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-camada-challenge': '1' },
    });
  }
  const html = challengePage({
    nonce: await kitFor(engine).nonce(ip, Date.now()),
    action: VERIFY_PATH,
    to: safeReturnTo(target),
  });
  return new Response(html, { status: 403, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-camada-challenge': '1' } });
}

/** POST handler for `…/camada/challenge`. */
export async function verifyChallenge(engine: Engine, req: Request): Promise<Response> {
  const ip = clientIp(engine, req);
  const kit = kitFor(engine);
  const form = parseFormBody(await req.text());
  const to = safeReturnTo(form.to);
  const now = Date.now();
  if (!(await kit.nonceValid(ip, now, form.nonce)) || !(await kit.solutionOk(form.nonce, form.solution))) {
    const html = challengePage({ nonce: await kit.nonce(ip, now), action: new URL(req.url).pathname, to });
    return new Response(html, { status: 403, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
  }
  const ev = buildEvent(req, new URL(req.url).pathname, ip, crypto.randomUUID(), cookieValue(req.headers.get('cookie') || '', SESSION_COOKIE), false);
  ev.st = 200;
  ev.ch = 1;   // challenge passed (contract §A3 ingest field)
  engine.queue.push(ev);
  void engine.queue.flush();
  return new Response(null, {
    status: 302,
    headers: {
      location: to,
      'set-cookie': challengeCookie(await kit.issue(ip, now), new URL(req.url).protocol === 'https:'),
      'cache-control': 'no-store',
    },
  });
}

/** Public helper for a route that wants to gate itself (the examples' /challenge-me).
 *  Returns the challenge Response, or null when the caller already holds a valid `_cch`. */
export async function challengeGate(req: Request): Promise<Response | null> {
  if (isDisabled()) return null;
  const engine = getEngine();
  if (!engine) return null;
  const ip = clientIp(engine, req);
  if (await challengePassed(engine, req, ip)) return null;
  const url = new URL(req.url);
  return serveChallenge(engine, req, ip, url.pathname + url.search);
}
```

- [ ] **Step 5: Wire the middleware and the route**

In `~/Github/camada-all/camada-next/src/middleware.ts`:
- widen the signature: `export function camada(_options?: CamadaMiddlewareOptions): (req: NextRequest, event: NextFetchEvent) => Response | undefined | Promise<Response | undefined>` and the inner function's return type likewise;
- import `{ challengeEnabled }` from `./engine` and `{ isChallengeRoute, challengePassed, serveChallenge }` from `./challenge`;
- right after the `if (v.block) { … }` block, insert:

```ts
      if (v.challenge && challengeEnabled()) {
        if (isChallengeRoute(path)) return undefined;   // the route handler answers its own endpoint
        return challengePassed(engine, req, ip).then(
          (passed) => (passed ? undefined : serveChallenge(engine, req, ip, path + new URL(req.url).search, waitUntil)),
          () => undefined,                               // fail open, exactly like the catch below
        );
      }
```

In `~/Github/camada-all/camada-next/src/route.ts`, inside the returned `POST`, before the `lastSegment(req) !== 'fp'` guard:

```ts
      if (lastSegment(req) === 'challenge') {
        const engine = activeEngine();
        if (!engine || !challengeEnabled()) return notFound();
        engine.snap.ensureFresh();
        const deny = blocked(engine, req);
        if (deny) return deny;
        return verifyChallenge(engine, req);
      }
```

with `import { challengeEnabled } from './engine';` and `import { verifyChallenge } from './challenge';` added at the top.

In `~/Github/camada-all/camada-next/src/index.ts` add:

```ts
export { challengeGate } from './challenge';
```

Set `"version": "0.1.0"` in `~/Github/camada-all/camada-next/package.json`.

- [ ] **Step 6: Run the tests**

Run: `cd ~/Github/camada-all/camada-next && npm test && npm run check && npm run build`
Expected: PASS, **including `test/edge-safety.test.ts`** — if it fails, something in the challenge import graph pulled in a `node:` module; find it and remove it.

- [ ] **Step 7: Review and commit**

Run agent `fable-simplifier` on the diff, then agent `fable-reviewer`; apply findings.

```bash
cd ~/Github/camada-all/camada-next
git add -A src test package.json
git commit -m "$(cat <<'MSG'
feat(next): challenge in the middleware, POST /api/camada/challenge, challengeGate (SDK-04)

Claude-Session: https://claude.ai/code/session_014GA5a631prhERB2zJ2by1n
MSG
)"
```

---

### Task 6: `@camada/hono` — the new Workers package (SEC-07)

**Files (all new, in `~/Github/camada-all/camada-hono`):**
- Create: `package.json`, `tsconfig.json`, `tsup.config.ts`, `vitest.config.ts` (only if the sibling repos have one — otherwise vitest's defaults are enough), `.gitignore`, `LICENSE`, `README.md`
- Create: `src/index.ts`, `src/camada.ts`, `src/env.ts`, `src/version.ts`
- Test: `test/camada.test.ts`

**Interfaces:**
- Consumes: everything Tasks 1–3 produced from `@camada/core` (`SnapshotClient`, `EventQueue`, `buildWireEvent`, `resolveClientIp`, `parseKey`, `parseTrustedProxyEnv`, `guardedAsync`, `TAP_HONO`, the challenge kit).
- Produces: `camada(options?: CamadaHonoOptions): MiddlewareHandler` and `resetCamada()` (test hook).

**Copy the layout from `~/Github/camada-all/camada-node`:** same `scripts` block (`build`/`dev`/`test`/`check`), same tsup config shape, same `files`, `exports`, `engines`, `type: module`, MIT `LICENSE` (copy the file verbatim), same `.gitignore` (`node_modules`, `dist`, `*.log`). Copy `.claude/agents/fable-*.md` in as well.

- [ ] **Step 1: Initialise the repo and the manifest**

```bash
cd ~/Github/camada-all/camada-hono
git init -b main
cp ~/Github/camada-all/camada-node/LICENSE .
mkdir -p .claude/agents && cp ~/Github/camada-all/camada-backend/.claude/agents/fable-*.md .claude/agents/
printf 'node_modules\ndist\n*.log\n' > .gitignore
```

`package.json`:

```json
{
  "name": "@camada/hono",
  "version": "0.1.0",
  "description": "camada SDK for Hono on Cloudflare Workers: snapshot enforcement, challenge, waitUntil-flushed event shipping",
  "license": "MIT",
  "type": "module",
  "engines": { "node": ">=18" },
  "files": ["dist", "README.md", "LICENSE"],
  "scripts": {
    "build": "tsup",
    "dev": "tsup --watch",
    "test": "vitest run",
    "check": "tsc --noEmit"
  },
  "exports": {
    ".": {
      "types": "./dist/index.d.ts",
      "import": "./dist/index.js",
      "require": "./dist/index.cjs"
    }
  },
  "main": "./dist/index.cjs",
  "module": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "dependencies": {
    "@camada/core": "file:../camada-core"
  },
  "peerDependencies": { "hono": ">=4" },
  "devDependencies": {
    "@cloudflare/workers-types": "^4.20250109.0",
    "@types/node": "^22.10.0",
    "hono": "^4.6.0",
    "tsup": "^8.3.5",
    "typescript": "^5.7.2",
    "vitest": "^3.0.0"
  }
}
```

`tsup.config.ts`:

```ts
import { defineConfig } from 'tsup';
export default defineConfig({ entry: ['src/index.ts'], format: ['esm', 'cjs'], dts: true, sourcemap: true, clean: true, external: ['@camada/core', 'hono'] });
```

`tsconfig.json` — copy `~/Github/camada-all/camada-node/tsconfig.json` verbatim, then add `"resolveJsonModule": true` if it is not already set (`src/version.ts` needs it) and add `"types": ["@cloudflare/workers-types"]` if the node one pins `@types/node` only. Read the node file before copying; do not invent settings.

Then: `npm install`.

- [ ] **Step 2: Write the failing test**

Create `~/Github/camada-all/camada-hono/test/camada.test.ts`:

```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { Hono } from 'hono';
import { CHALLENGE_COOKIE } from '@camada/core';
import { camada, resetCamada } from '../src/index.js';

// Golden v4 snapshot copied from camada-core/test/fixtures (block 203.0.113.66 via the block
// side, challenge 192.0.2.0/24, allow 10.1.2.3).
const fx = (f: string) => new URL(`./fixtures/${f}`, import.meta.url);
const bin = readFileSync(fx('snap-v4.bin'));
const meta = readFileSync(fx('snap-v4.meta.json'), 'utf8');

function frame(): Uint8Array {
  const m = new TextEncoder().encode(meta);
  const out = new Uint8Array(4 + m.byteLength + bin.byteLength);
  new DataView(out.buffer).setUint32(0, m.byteLength, true);
  out.set(m, 4);
  out.set(new Uint8Array(bin.buffer, bin.byteOffset, bin.byteLength), 4 + m.byteLength);
  return out;
}

const ENV = { CAMADA_KEY: 'tok-acme.snap-acme', CAMADA_INGEST_URL: 'http://analyst.test', CAMADA_SNAPSHOT_URL: 'http://analyst.test/snapshot' };

let events: Record<string, unknown>[];
let sdkHeaders: string[];
let snapshotHeaders: string[];

const fetchImpl: typeof fetch = async (input, init) => {
  const url = String(input);
  if (url.endsWith('/snapshot')) {
    snapshotHeaders.push(new Headers(init?.headers).get('x-camada-snapshot') || '');
    return new Response(frame(), { status: 200, headers: { etag: '"v4"', 'x-camada-config': JSON.stringify({ tenant: 'acme', beacon: true, sample: 1, exclude: [], trusted_proxy: { mode: 'none' }, poll_seconds: 30 }) } });
  }
  sdkHeaders.push(new Headers(init?.headers).get('x-camada-sdk') || '');
  events.push(...JSON.parse(String(init?.body)));
  return new Response(null, { status: 204 });
};

const app = () => {
  const a = new Hono();
  a.use('*', camada({ env: ENV, fetchImpl }));
  a.get('/', (c) => c.text('home'));
  a.get('/cart', (c) => c.html('<p>cart</p>'));
  return a;
};

const call = (a: Hono, path: string, init: RequestInit = {}) => {
  const waits: Promise<unknown>[] = [];
  return a
    .request(path, init, {}, { waitUntil: (p: Promise<unknown>) => waits.push(p), passThroughOnException: () => {} } as never)
    .then(async (res) => { await Promise.all(waits); return res; });
};

beforeEach(() => { events = []; sdkHeaders = []; snapshotHeaders = []; resetCamada(); });

describe('@camada/hono', () => {
  it('passes an unlisted request through and ships the event with the response status', async () => {
    const a = app();
    await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8' } });   // cold: fails open, loads the snapshot
    const res = await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8' } });
    expect(res.status).toBe(200);
    expect(events.some((e) => e.tap === 'sdk-hono' && e.p === '/' && e.st === 200)).toBe(true);
    expect(sdkHeaders.every((h) => /^@camada\/hono\/\d+\.\d+\.\d+$/.test(h))).toBe(true);
  });

  it('asks for the v4 snapshot', async () => {
    await call(app(), '/', { headers: { 'cf-connecting-ip': '8.8.8.8' } });
    expect(snapshotHeaders[0]).toBe('4');
  });

  it('blocks a listed ip with 403 and blk', async () => {
    const a = app();
    await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8' } });
    const res = await call(a, '/', { headers: { 'cf-connecting-ip': '203.0.113.66' } });
    expect(res.status).toBe(403);
    expect(res.headers.get('x-block-reason')).toBe('ip4');
    expect(events.some((e) => e.st === 403 && e.blk === 'ip4')).toBe(true);
  });

  it('challenges a listed range and verifies the solution', async () => {
    const a = app();
    await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8' } });
    const page = await call(a, '/cart', { headers: { 'cf-connecting-ip': '192.0.2.5', accept: 'text/html', 'sec-fetch-dest': 'document' } });
    expect(page.status).toBe(403);
    const html = await page.text();
    const nonce = /name="nonce" value="([0-9a-f]{32})"/.exec(html)![1];
    let sol = 0;
    while (!createHash('sha256').update(`${nonce}.${sol}`).digest('hex').startsWith('0000')) sol++;
    const ok = await call(a, '/__camada/challenge', {
      method: 'POST',
      headers: { 'cf-connecting-ip': '192.0.2.5', 'content-type': 'application/x-www-form-urlencoded' },
      body: `nonce=${nonce}&solution=${sol}&to=%2Fcart`,
    });
    expect(ok.status).toBe(302);
    expect(ok.headers.get('set-cookie')).toContain(`${CHALLENGE_COOKIE}=`);
    expect(events.some((e) => e.st === 200 && e.ch === 1)).toBe(true);
    const cookie = ok.headers.get('set-cookie')!.split(';')[0];
    const after = await call(a, '/cart', { headers: { 'cf-connecting-ip': '192.0.2.5', accept: 'text/html', cookie } });
    expect(after.status).toBe(200);
  });

  it('answers 403 JSON for a non-HTML challenge', async () => {
    const a = app();
    await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8' } });
    const res = await call(a, '/cart', { headers: { 'cf-connecting-ip': '192.0.2.5', accept: 'application/json' } });
    expect(await res.json()).toEqual({ error: 'challenge_required' });
  });

  it('honours the allow side over the block side', async () => {
    const a = app();
    await call(a, '/', { headers: { 'cf-connecting-ip': '8.8.8.8' } });
    const res = await call(a, '/', { headers: { 'cf-connecting-ip': '10.1.2.3' } });   // inside blocked 10.0.0.0/8
    expect(res.status).toBe(200);
  });

  it('is inert without a key and never breaks the app', async () => {
    resetCamada();
    const a = new Hono();
    a.use('*', camada({ env: {}, fetchImpl }));
    a.get('/', (c) => c.text('home'));
    const res = await call(a, '/', { headers: { 'cf-connecting-ip': '203.0.113.66' } });
    expect(res.status).toBe(200);
    expect(events).toEqual([]);
  });

  it('respects CAMADA_DISABLED=1', async () => {
    resetCamada();
    const a = new Hono();
    a.use('*', camada({ env: { ...ENV, CAMADA_DISABLED: '1' }, fetchImpl }));
    a.get('/', (c) => c.text('home'));
    const res = await call(a, '/', { headers: { 'cf-connecting-ip': '203.0.113.66' } });
    expect(res.status).toBe(200);
  });
});
```

Copy the fixtures: `mkdir -p ~/Github/camada-all/camada-hono/test/fixtures && cp ~/Github/camada-all/camada-core/test/fixtures/snap-v4.bin ~/Github/camada-all/camada-core/test/fixtures/snap-v4.meta.json ~/Github/camada-all/camada-hono/test/fixtures/`

- [ ] **Step 3: Run to verify it fails**

Run: `cd ~/Github/camada-all/camada-hono && npx vitest run`
Expected: FAIL — `../src/index.js` does not exist.

- [ ] **Step 4: Write `src/version.ts` and `src/env.ts`**

`src/version.ts` (identical trick to @camada/node — tsup inlines the two literals):

```ts
// The SDK's wire identity (SDK-03): x-camada-sdk: <package>/<version>. Named JSON imports are
// inlined and tree-shaken by tsup at build, so dist carries two literals — no runtime fs read.
import { name, version } from '../package.json';
export const SDK_ID = `${name}/${version}`;
```

`src/env.ts`:

```ts
// Workers hand env vars per request on `c.env`, not on a process — so the engine is built from
// whatever the first request carries (merged with explicit options), then cached.
import { parseKey, parseTrustedProxyEnv, type TrustedProxyConfig } from '@camada/core';

export interface ResolvedEnv {
  ingestToken: string;
  snapToken: string;
  secret: string;                 // HMAC key for the challenge nonce/cookie
  ingestUrl: string;
  snapshotUrl: string;
  trustedProxy: TrustedProxyConfig | null;   // null = defer to server-delivered config
}

export interface CamadaHonoOptions {
  key?: string;
  ingestUrl?: string;
  snapshotUrl?: string;
  trustedProxy?: TrustedProxyConfig | string | null;
  challenge?: boolean;            // default true
  challengePath?: string;         // default /__camada/challenge
  snapshotVersion?: 3 | 4;        // default 4
  env?: Record<string, string | undefined>;   // overrides c.env (tests)
  fetchImpl?: typeof fetch;
}

const asProxy = (v: CamadaHonoOptions['trustedProxy']): TrustedProxyConfig | null =>
  typeof v === 'string' ? parseTrustedProxyEnv(v) : v ?? null;

/** Returns null (middleware stays inert, one log line) rather than throwing on bad config. */
export function resolveEnv(opts: CamadaHonoOptions, env: Record<string, string | undefined>): ResolvedEnv | null {
  const raw = opts.key || env.CAMADA_KEY;
  const key = parseKey(raw);
  const ingestToken = key?.ingestToken ?? env.CAMADA_TOKEN;
  const snapToken = key?.snapToken ?? env.CAMADA_SNAPSHOT_TOKEN;
  if (!ingestToken || !snapToken) return null;
  const ingestUrl = (opts.ingestUrl || env.CAMADA_INGEST_URL || 'https://in.camada.app').replace(/\/$/, '');   // PLACEHOLDER default — confirm the production ingest domain before any npm publish
  return {
    ingestToken, snapToken,
    secret: raw || `${ingestToken}.${snapToken}`,
    ingestUrl,
    snapshotUrl: opts.snapshotUrl || env.CAMADA_SNAPSHOT_URL || `${ingestUrl}/snapshot`,
    trustedProxy: asProxy(opts.trustedProxy) ?? parseTrustedProxyEnv(env.CAMADA_TRUSTED_PROXY),
  };
}
```

- [ ] **Step 5: Write `src/camada.ts`**

```ts
// @camada/hono — the Hono middleware for Cloudflare Workers (SEC-07, D33).
//   app.use('*', camada());                     // env: CAMADA_KEY (+ CAMADA_INGEST_URL in dev)
// Workers-native: `cf-connecting-ip` for the client, `request.cf` for asn/country/tls, and
// `c.executionCtx.waitUntil` so the snapshot poll and the event flush outlive the response.
// Every entry point is inside the fail-open envelope: a camada bug must never 5xx the app.
import type { Context, MiddlewareHandler, Next } from 'hono';
import {
  SnapshotClient, EventQueue, buildWireEvent, resolveClientIp, logRateLimited, guardedAsync,
  createChallengeAsync, challengePage, challengeCookie, safeReturnTo, wantsHtml, parseFormBody,
  CHALLENGE_COOKIE, TAP_HONO, type AsyncChallengeKit, type TrustedProxyConfig, type WireEvent,
} from '@camada/core';
import { resolveEnv, type CamadaHonoOptions, type ResolvedEnv } from './env.js';
import { SDK_ID } from './version.js';

const DEFAULT_CHALLENGE_PATH = '/__camada/challenge';
const SESSION_COOKIE = '_sfp';   // same cookie as every other tap: sid/ns stay comparable

interface Engine {
  env: ResolvedEnv;
  snap: SnapshotClient;
  queue: EventQueue;
  kit: AsyncChallengeKit;
}

let engine: Engine | null | undefined;   // undefined = not built; null = unconfigured

/** Test/reset hook: drops the cached engine (and its timers, though 'lazy' mode has none). */
export function resetCamada(): void {
  engine?.snap.stop();
  engine?.queue.stop();
  engine = undefined;
}

function ensure(opts: CamadaHonoOptions, ctxEnv: Record<string, string | undefined>): Engine | null {
  if (engine !== undefined) return engine;
  const env = resolveEnv(opts, ctxEnv);
  if (!env) {
    logRateLimited(new Error('CAMADA_KEY not set — camada is inactive'));
    return (engine = null);
  }
  const injected = opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {};   // never pass an explicit undefined key
  engine = {
    env,
    snap: new SnapshotClient({ url: env.snapshotUrl, token: env.snapToken, mode: 'lazy', sdk: SDK_ID, snapshotVersion: opts.snapshotVersion ?? 4, ...injected }),
    queue: new EventQueue({ url: env.ingestUrl, token: env.ingestToken, sdk: SDK_ID, ...injected }),
    kit: createChallengeAsync({ secret: env.secret }),
  };
  return engine;
}

const cookieValue = (cookie: string, name: string): string | null => {
  const src = '; ' + cookie;
  const i = src.indexOf('; ' + name + '=');
  if (i === -1) return null;
  const start = i + name.length + 3;
  const j = src.indexOf(';', start);
  return src.slice(start, j === -1 ? undefined : j);
};

interface CfProps { asn?: number; country?: string; tlsClientExtensionsSha1?: string }
const cfOf = (req: Request): CfProps => ((req as Request & { cf?: CfProps }).cf ?? {});

function trustedProxy(e: Engine): TrustedProxyConfig | null {
  return e.env.trustedProxy ?? e.snap.config?.trusted_proxy ?? null;
}

function buildEvent(req: Request, path: string, query: string, ip: string | null, sid: string | null, newSession: boolean): WireEvent {
  const headers: Array<[string, string]> = [];
  req.headers.forEach((v, k) => headers.push([k, v]));   // workerd sorts headers: no HEADER_ORDER capability
  const url = new URL(req.url);
  const cf = cfOf(req);
  const ev = buildWireEvent(
    { method: req.method, host: url.host, path, query, headers, ip, httpVersion: null },
    { tap: TAP_HONO, rid: crypto.randomUUID(), sid, newSession },
  );
  if (cf.asn) ev.asn = cf.asn;
  if (cf.country) ev.cc = cf.country;
  if (cf.tlsClientExtensionsSha1) ev.tlsx = cf.tlsClientExtensionsSha1;
  return ev;
}

export function camada(opts: CamadaHonoOptions = {}): MiddlewareHandler {
  const challengeOn = opts.challenge !== false;
  const challengePath = opts.challengePath ?? DEFAULT_CHALLENGE_PATH;

  return async function camadaHono(c: Context, next: Next): Promise<Response | void> {
    const env = { ...(c.env as Record<string, string | undefined> | undefined), ...opts.env };
    if (env.CAMADA_DISABLED === '1') return next();
    const eng = ensure(opts, env);
    if (!eng) return next();

    const waitUntil = (p: Promise<unknown>) => { try { c.executionCtx?.waitUntil(p); } catch { /* no ctx outside a fetch handler */ } };
    const answer = await guardedAsync(async (): Promise<Response | null> => {
      eng.snap.ensureFresh(waitUntil);

      const req = c.req.raw;
      const url = new URL(req.url);
      const path = url.pathname;
      const cf = cfOf(req);
      const ip = req.headers.get('cf-connecting-ip')
        || resolveClientIp(null, req.headers.get('x-forwarded-for'), trustedProxy(eng));
      const cookies = req.headers.get('cookie') || '';
      const sid = cookieValue(cookies, SESSION_COOKIE);

      const v = eng.snap.verdict({ ip, path, asn: cf.asn ?? null, country: cf.country ?? null, tlsx: cf.tlsClientExtensionsSha1 ?? null });

      if (v.block) {
        const ev = buildEvent(req, path, url.search, ip, sid, false);
        ev.st = 403;
        ev.blk = v.reason;
        eng.queue.push(ev);
        eng.queue.flush(waitUntil);
        return new Response('Forbidden', {
          status: 403,
          headers: { 'content-type': 'text/plain', 'x-block-reason': String(v.reason ?? ''), 'x-block-version': v.version ?? '' },
        });
      }

      if (challengeOn) {
        if (req.method === 'POST' && path === challengePath) return verify(eng, req, ip, sid, challengePath, waitUntil);
        if (v.challenge && !(await eng.kit.tokenValid(ip, Date.now(), cookieValue(cookies, CHALLENGE_COOKIE)))) {
          return serve(eng, req, ip, sid, challengePath, path + url.search, waitUntil);
        }
      }
      return null;
    }, null);

    if (answer) return answer;

    await next();

    // The response is settled: ship the row with its real status (Workers see it; @camada/next
    // in the middleware position does not).
    guardedAsync(async () => {
      const req = c.req.raw;
      const url = new URL(req.url);
      const cfg = eng.snap.config;
      const path = url.pathname;
      if ((cfg?.exclude || []).some((x) => path.startsWith(x))) return;
      if (Math.random() >= (cfg?.sample ?? 1)) return;
      const ip = req.headers.get('cf-connecting-ip') || resolveClientIp(null, req.headers.get('x-forwarded-for'), trustedProxy(eng));
      const ev = buildEvent(req, path, url.search, ip, cookieValue(req.headers.get('cookie') || '', SESSION_COOKIE), false);
      ev.st = c.res.status;
      eng.queue.push(ev);
      eng.queue.flush(waitUntil);
    }, undefined);
  };
}

/** 403 + the proof-of-work page (HTML navigation) or 403 JSON, plus the `blk: "challenge"` event. */
async function serve(eng: Engine, req: Request, ip: string | null, sid: string | null, action: string, target: string, waitUntil: (p: Promise<unknown>) => void): Promise<Response> {
  const url = new URL(req.url);
  const ev = buildEvent(req, url.pathname, url.search, ip, sid, false);
  ev.st = 403;
  ev.blk = 'challenge';
  eng.queue.push(ev);
  eng.queue.flush(waitUntil);

  if (!wantsHtml(req.headers.get('accept'), req.headers.get('sec-fetch-dest'))) {
    return new Response('{"error":"challenge_required"}', { status: 403, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-camada-challenge': '1' } });
  }
  const html = challengePage({ nonce: await eng.kit.nonce(ip, Date.now()), action, to: safeReturnTo(target) });
  return new Response(html, { status: 403, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-camada-challenge': '1' } });
}

/** POST from the page: validate, set `_cch`, 302 back, ship `{ st: 200, ch: 1 }`. */
async function verify(eng: Engine, req: Request, ip: string | null, sid: string | null, action: string, waitUntil: (p: Promise<unknown>) => void): Promise<Response> {
  const form = parseFormBody(await req.text());
  const to = safeReturnTo(form.to);
  const now = Date.now();
  if (!(await eng.kit.nonceValid(ip, now, form.nonce)) || !(await eng.kit.solutionOk(form.nonce, form.solution))) {
    const html = challengePage({ nonce: await eng.kit.nonce(ip, now), action, to });
    return new Response(html, { status: 403, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
  }
  const url = new URL(req.url);
  const ev = buildEvent(req, url.pathname, '', ip, sid, false);
  ev.st = 200;
  ev.ch = 1;   // challenge passed (contract §A3 ingest field)
  eng.queue.push(ev);
  eng.queue.flush(waitUntil);
  return new Response(null, {
    status: 302,
    headers: { location: to, 'set-cookie': challengeCookie(await eng.kit.issue(ip, now), url.protocol === 'https:'), 'cache-control': 'no-store' },
  });
}
```

`src/index.ts`:

```ts
// @camada/hono — the one-line install for a Hono app on Cloudflare Workers:
//   app.use('*', camada());   // env: CAMADA_KEY, CAMADA_INGEST_URL, CAMADA_SNAPSHOT_URL
export { camada, resetCamada } from './camada.js';
export { resolveEnv, type CamadaHonoOptions, type ResolvedEnv } from './env.js';
```

- [ ] **Step 6: Run the tests**

Run: `cd ~/Github/camada-all/camada-hono && npm test && npm run check && npm run build`
Expected: PASS. If `c.executionCtx` throws in the test harness (Hono raises when there is no execution context), the `try/catch` in `waitUntil` already swallows it — do not remove it.

- [ ] **Step 7: Write the README**

`~/Github/camada-all/camada-hono/README.md` — mirror `~/Github/camada-all/camada-node/README.md`'s structure (install, two-line quickstart, options table, what it observes, kill switch, fail-open promise) and include the camada-backend mounting example that contracts §H asks for:

````md
# @camada/hono

camada for [Hono](https://hono.dev) on Cloudflare Workers: snapshot enforcement (block, allow, challenge), a first-party proof-of-work challenge page, and event shipping flushed through `waitUntil`.

## Install

```
npm i @camada/hono
```

## Quickstart

```ts
import { Hono } from 'hono';
import { camada } from '@camada/hono';

const app = new Hono();
app.use('*', camada());        // reads CAMADA_KEY / CAMADA_INGEST_URL / CAMADA_SNAPSHOT_URL from the Worker env
app.get('/', (c) => c.text('hello'));
export default app;
```

## camada-backend (the dogfood mount, contracts §H / SEC-07)

Mount it in front of the API, and never in front of health or the Stripe webhook — those must answer even if the snapshot says otherwise:

```ts
import { camada } from '@camada/hono';

app.use('/api/*', async (c, next) => {
  if (c.req.path === '/api/health' || c.req.path === '/api/stripe/webhook') return next();
  return camada({
    key: c.env.CAMADA_KEY,               // inactive without it — the SDK fails open
    ingestUrl: c.env.INGEST_URL,
    snapshotUrl: `${c.env.INGEST_URL}/snapshot`,
  })(c, next);
});
```

## Options

| option | default | meaning |
|---|---|---|
| `key` | `env.CAMADA_KEY` | `<ingest_token>.<snap_token>`; without it the middleware is inert |
| `ingestUrl` | `env.CAMADA_INGEST_URL` | ingest base; `POST <ingestUrl>/e` |
| `snapshotUrl` | `<ingestUrl>/snapshot` | snapshot endpoint |
| `trustedProxy` | server config | `none` / `vercel` / `hops:N` / `cidrs:a,b`, or the parsed object |
| `challenge` | `true` | serve the proof-of-work page for `challenge` verdicts |
| `challengePath` | `/__camada/challenge` | where the page posts its solution |
| `snapshotVersion` | `4` | `3` opts out of the v4 allow/challenge sections |

`CAMADA_DISABLED=1` in the Worker env switches everything off, per request.

## What it sees

`cf-connecting-ip` for the client address, and `request.cf` for `asn`, `country` and `tlsClientExtensionsSha1` — so ASN and country rules enforce here, unlike in a bare Node app. workerd normalises header order, so header-order signals are not available at this tap.

## Fail open

Every path runs inside camada's guard: a bug, a dead ingest or a corrupt snapshot costs telemetry, never a 5xx.
````

- [ ] **Step 8: Commit**

Run agent `fable-simplifier` on the diff, then agent `fable-reviewer`; apply findings.

```bash
cd ~/Github/camada-all/camada-hono
git add -A
git commit -m "$(cat <<'MSG'
feat: @camada/hono 0.1.0 — Workers middleware with block, challenge and waitUntil flushes (SEC-07)

Claude-Session: https://claude.ai/code/session_014GA5a631prhERB2zJ2by1n
MSG
)"
```

---

### Task 7: examples — `/challenge-me` in both demos

**Files:**
- Modify: `~/Github/camada-all/camada-node-example/server.js`, `~/Github/camada-all/camada-node-example/README.md`
- Create: `~/Github/camada-all/camada-next-example/app/challenge-me/route.ts`
- Modify: `~/Github/camada-all/camada-next-example/README.md`

**Interfaces:**
- Consumes: `camada.serveChallenge(req, res)` (Task 4), `challengeGate(req)` (Task 5).
- Produces: nothing.

- [ ] **Step 1: Refresh the linked builds**

```bash
cd ~/Github/camada-all/camada-core && npm run build
cd ~/Github/camada-all/camada-node && npm run build
cd ~/Github/camada-all/camada-next && npm run build
cd ~/Github/camada-all/camada-node-example && npm install
cd ~/Github/camada-all/camada-next-example && npm install
```

- [ ] **Step 2: node example**

In `~/Github/camada-all/camada-node-example/server.js`, add before the 404 handler:

```js
// SDK-04 demo: force the challenge for this route, whatever the snapshot says. Once solved,
// the _cch cookie is valid for an hour and this page renders normally.
app.get('/challenge-me', (req, res) => {
  if (camada.serveChallenge(req, res)) return;
  res.send(page(req, 'Challenge passed', '<p>The <code>_cch</code> cookie is set for an hour. Clear it to see the check again.</p>'));
});
```

and add `/challenge-me` to the `<nav>` inside `page`:

```js
<nav><a href="/">home</a> · <a href="/pricing">pricing</a> · <a href="/login-form">login</a> · <a href="/challenge-me">challenge</a></nav>
```

- [ ] **Step 3: next example**

Create `~/Github/camada-all/camada-next-example/app/challenge-me/route.ts`:

```ts
// SDK-04 demo: force the challenge for this route, whatever the snapshot says. challengeGate
// returns null once the browser holds a valid _cch cookie.
import { challengeGate } from '@camada/next';

export async function GET(req: Request): Promise<Response> {
  const gate = await challengeGate(req);
  if (gate) return gate;
  return new Response(
    '<!doctype html><meta charset="utf-8"><title>Challenge passed</title><body style="font-family:system-ui;max-width:40rem;margin:3rem auto"><h1>Challenge passed</h1><p>The <code>_cch</code> cookie is set for an hour. Clear it to see the check again.</p><p><a href="/">home</a></p>',
    { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } },
  );
}
```

- [ ] **Step 4: Verify by hand**

```bash
cd ~/Github/camada-all/camada-node-example && node server.js &        # :3000
curl -s -D- -H 'accept: text/html' localhost:3000/challenge-me | head -20
```
Expected: `HTTP/1.1 403`, `x-camada-challenge: 1`, body containing `Checking your browser` and a 32-hex `name="nonce"`.

Then in Chrome (or with the tester's browser): open `http://localhost:3000/challenge-me`, watch it solve and land on "Challenge passed"; reload and confirm it renders straight away. Repeat for `http://localhost:3001/challenge-me` with `npm run dev` in `camada-next-example`.

- [ ] **Step 5: Document and commit**

Add a "Challenge (SDK-04)" section to both READMEs: what `/challenge-me` demonstrates, the `_cch` cookie, and that a real challenge comes from a snapshot v4 `challenge` entry.

```bash
cd ~/Github/camada-all/camada-node-example
git add -A && git commit -m "$(cat <<'MSG'
feat(example): /challenge-me demonstrates the SDK-04 proof-of-work challenge

Claude-Session: https://claude.ai/code/session_014GA5a631prhERB2zJ2by1n
MSG
)"
cd ~/Github/camada-all/camada-next-example
git add -A && git commit -m "$(cat <<'MSG'
feat(example): /challenge-me demonstrates the SDK-04 proof-of-work challenge

Claude-Session: https://claude.ai/code/session_014GA5a631prhERB2zJ2by1n
MSG
)"
```

---

### Task 8: bottom-up green, golden-fixture swap, end-to-end against a v4 snapshot

**Files:**
- Modify (only if the swap changes them): `~/Github/camada-all/camada-core/test/fixtures/*`, `~/Github/camada-all/camada-core/test/conformance.test.ts`
- Modify: `/Users/gabe/Github/camada-all/camada/docs/orchestration/status/sdk.md`

**Interfaces:** none — this task proves the whole stack.

- [ ] **Step 1: Bottom-up build**

```bash
for r in camada-core camada-browser camada-react camada-node camada-next camada-hono; do
  (cd ~/Github/$r && echo "== $r" && npm run build && npm test && npm run check) || break
done
```
Expected: every repo green. `camada-browser` and `camada-react` are untouched; if they break, the cause is a `@camada/core` export removal — restore the export.

- [ ] **Step 2: Prove the dist inlining survived (SDK-03 regression guard)**

```bash
grep -c '@camada/node' ~/Github/camada-all/camada-node/dist/index.js
grep -c '@camada/next' ~/Github/camada-all/camada-next/dist/index.js
grep -c '@camada/hono' ~/Github/camada-all/camada-hono/dist/index.js
```
Expected: each ≥ 1, and none of the dist bundles contains `require("../package.json")` or `readFileSync`.

- [ ] **Step 3: Swap in edge-analyst's golden fixtures if they exist**

```bash
ls ~/Github/camada-all/camada/edge-analyst/fixtures/blk3/ 2>/dev/null
```
- **If the directory does not exist:** keep the local fixtures, and leave the two format assumptions from Task 1 recorded in status/sdk.md under "Interface changes". Skip to Step 4.
- **If it does:** copy every file into `~/Github/camada-all/camada-core/test/fixtures/blk3/`, point `test/conformance.test.ts` at edge-analyst's expected-match table (its own JSON) alongside the hand table, and run `npm test`. A failure means the format reading in Task 1 was wrong: fix `parse.ts`/`match.ts` to edge-analyst's bytes (it owns the format), never the fixtures. Re-run Tasks 4–6 test suites afterwards and copy the new `snap-v4.*` into `camada-node/test/fixtures`, `camada-next/test/fixtures` and `camada-hono/test/fixtures`.

- [ ] **Step 4: End-to-end against a live v4 snapshot**

```bash
cd ~/Github/camada-all/camada/edge-analyst && npm run dev        # :8787, MOCK_AI=1 ADMIN_TOKEN=dev INTERNAL_TOKEN=dev-internal
# in another shell, seed and confirm the tenant serves v4:
curl -s -o /dev/null -D- -H 'authorization: Bearer snap-acme' -H 'x-camada-snapshot: 4' localhost:8787/snapshot
```
Expected: `200` (or `204` before a snapshot is published). If edge-analyst does not serve v4 yet, that is an ea dependency, not an SDK bug — record it in status/sdk.md under "Blocked", and prove the SDK path with the local v4 fixture instead (Task 6's tests already do).

With a challenge entry published for the test IP, run the node example and check both halves:
```bash
export CAMADA_KEY=tok-acme.snap-acme CAMADA_INGEST_URL=http://localhost:8787 CAMADA_SNAPSHOT_URL=http://localhost:8787/snapshot CAMADA_TRUSTED_PROXY=hops:1
(cd ~/Github/camada-all/camada-node-example && node server.js)
curl -si -H 'accept: text/html' -H 'X-Forwarded-For: <challenged ip>' localhost:3000/  | head -5   # 403 + the page
curl -si -H 'accept: application/json' -H 'X-Forwarded-For: <challenged ip>' localhost:3000/       # 403 {"error":"challenge_required"}
```
Then check the rows land: `GET http://localhost:8787/admin/events?tenant=acme&kind=events` should show `status: 403` with `blk: challenge` (and `ch: 1` after a solved challenge) once edge-analyst's EA-10/§A3 ingest accepts those fields.

- [ ] **Step 5: Update status/sdk.md**

Add a `## Phase C` block at the TOP of `/Users/gabe/Github/camada-all/camada/docs/orchestration/status/sdk.md`, keeping every existing line below it. It must carry:
- **Done:** SDK-02, SDK-04, SEC-07 with the commit hashes per repo and the new versions (`@camada/core` 0.1.0, `@camada/node` 0.1.0, `@camada/next` 0.1.0, `@camada/hono` 0.1.0) — web needs those exact numbers for the RULES-08 wording.
- **Interface changes (proposals for the orchestrator):**
  1. edge-analyst `src/capabilities.js` `TAP_CAPS` needs `'sdk-hono'`. Proposed value: `(IN_APP & ~CAP.BEACON) | CAP.GEO_ASN | CAP.TLS_FP` — Workers hand `request.cf` asn/country and `tlsClientExtensionsSha1`, workerd normalises header order, and @camada/hono does not serve the beacon. Until it lands, `sdk-hono` events fall back to the `proxy` mask, which over-credits the tap.
  2. The two v4 byte-layout readings from Task 1 (interleaved range pairs; magic version byte `0x34` accepted alongside `0x33`, sections 10–13 read whenever present).
  3. `ch: 1` and `blk: "challenge"` must be whitelisted by edge-analyst's ingest `fromCollector` (§A3) or the fields are dropped, exactly as `blk` was before EA-10.
- **Blocked:** whatever Step 4 could not prove against a live edge-analyst.
- **Runnable:** the bottom-up loop from Step 1 plus the `/challenge-me` URLs (`http://localhost:3000/challenge-me`, `http://localhost:3001/challenge-me`) and the curl lines from Step 4.
- Status **available** only when every package is green and nothing above is open on the SDK side.

- [ ] **Step 6: Commit the plan's completion state**

```bash
cd ~/Github/camada-all/camada-core
git add -A docs
git commit -m "$(cat <<'MSG'
docs(plan): SDK phase C plan and its execution notes

Claude-Session: https://claude.ai/code/session_014GA5a631prhERB2zJ2by1n
MSG
)"
```


---

## Execution notes (2026-09-04)

What the plan did not anticipate, recorded so the next reader is not misled by the task text above:

1. **The golden fixtures landed mid-execution.** `edge-analyst/fixtures/blk3/` appeared while Task 1 was in review, so the local stand-in builder (`test/fixtures/v4/build.mjs`, `snap-v4.*`, the hand-written `cases-v4.json`) was deleted rather than kept alongside them, and `test/fixtures/blk3/` became the single golden source. The old `snap-basic.*` / `snap-empty.*` / `cases.json` layout was retired with it: `v3-basic.bin` is byte-identical, and camada-node's and camada-next's harnesses were repointed at `blk3/v3-basic.*` through the `file:` symlink. `conformance.test.ts` now drives all 131 reference-generated cases (v3 + v4) and asserts the whole `{ block, challenge, allowed, reason }` object. **Both byte-layout readings recorded as assumptions in Task 1 were confirmed by the golden bytes.**

2. **Tasks 1-3 shipped as one commit.** The fixture swap ties the parser, the matcher and the conformance table together — committing the parser alone would have left the suite red — so `127a81a` covers SDK-02 and the challenge kit.

3. **Adapter tests use each repo's existing harness, not the shapes sketched in Tasks 4 and 5.** `camada-node/test/harness.ts` already spins a real `node:http` server, so the node challenge suite drives real HTTP with `fetch` instead of the fake `req`/`res` pair the plan sketched; `camada-next` drives `NextRequest` under `@vitest-environment edge-runtime`. Both harnesses gained a `v4` flag and a `snapshotVersions` recorder rather than a copied fixture directory.

4. **Widening the matcher's result broke `camada-next/test/middleware.test.ts` at the type level** (the middleware may now return a promise). Every `handler(...)` call site there is awaited.

5. **Findings applied beyond the plan** (from the review passes and the live run):
   - `safeReturnTo` rejects non-ASCII as well as control characters — the value goes into a `Location` header and Node throws `ERR_INVALID_CHAR` above 0xff.
   - The challenge kit refuses a **null client ip**, and all three adapters fail open rather than challenge a client they cannot identify; otherwise one solve would mint a `_cch` every unidentified client could present.
   - `challengePage` escapes `<` inside the inline `<script>`, clamps `bits` to 1..32; `parseFormBody` returns a null-prototype object.
   - `SnapshotClient.load()` re-parses when the **etag** moves under an unchanged `meta.version`: edge-analyst serves the v3 and v4 bodies of one publish with the same version string and different etags, so the version guard alone would have pinned a tenant to its v3 matcher forever after it gained a v4 snapshot.
   - `serveChallenge()` (node) marks the request so the response-finish hook stands down — the on-demand path was shipping two events for one request.

6. **`@camada/hono` reports the client protocol** from `request.cf.httpProtocol` (never a forwarded header), which ea's `TAP_CAPS['sdk-hono'] = 503` grants TRUE_PROTO on the strength of. That requirement arrived from the orchestrator after Task 6 was written.

7. **Task 8's live pass used a stub analyst**, not `edge-analyst npm run dev`: another stream's `workerd` held port 8797 and answered 401, which looks exactly like a broken SDK. The stub serves the same golden v4 bytes. Both examples were driven end to end through it — block, allow-beats-block, challenge served, challenge solved, cookie admitted, cookie refused for a different ip, and the shipped events checked.

8. **The Fable rate limit was exhausted during Task 8**, so the last review pass ran on an equivalent reviewer on another model instead of the repo-local `fable-reviewer`.

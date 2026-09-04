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
/** The name this had before v4 gave allow and challenge the same axes. */
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

/** Walks every '/'-terminated ancestor of `path`, the way the block side does. */
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

  /** Compares the 4 words at A[o..o+3] against the address parsed into W. */
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

  /** The block side: v3 sections plus the top-level meta. */
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
    if (set.empty) return null;   // the common v3 snapshot
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
    // Parse the address exactly once: blocked6()/inRange6() both read the W scratch, so the
    // parse must stay above every side() call.
    let n4 = -1, has6 = false;
    if (ip) {
      if (ip.indexOf(':') === -1) n4 = parseIp4(ip);
      else has6 = parseIp6Into(ip, this.W, this.G);
    }
    const allowed = this.side(S.allow, input, n4, has6);
    if (allowed) return { block: false, challenge: false, allowed: true, reason: allowed, version: S.version };
    const blocked = this.blockSide(input, n4, has6);
    if (blocked) return { block: true, challenge: false, allowed: false, reason: blocked, version: S.version };
    const chal = this.side(S.challenge, input, n4, has6);
    if (chal) return { block: false, challenge: true, allowed: false, reason: chal, version: S.version };
    return { block: false, challenge: false, allowed: false, version: S.version };
  }
}

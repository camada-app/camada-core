// Matcher: sub-microsecond block checks over a parsed Snapshot, ported from edge-analyst
// src/blocklist.js blocked4/blocked6/blockedAsn/blockedPath/blockReason. The module-level
// scratch arrays of the original are instance fields here (safe under worker_threads and
// interleaved matchers); matching stays fully synchronous.
//
// Evaluation order is part of the contract (fixtures pin it): ip4 -> ip6 -> asn -> country -> tls -> path.
// At the SDK position only ip and path are usually known; asn/country/tlsx entries then simply
// never match — that is the documented, honest enforcement scope (fail open, never guess).

import type { Snapshot } from './parse.js';
import { parseIp4, parseIp6Into } from './ipparse.js';

export interface MatchInput {
  ip?: string | null;
  asn?: number | null;
  country?: string | null;
  tlsx?: string | null;
  path?: string | null;
}

export type BlockReason = 'ip4' | 'ip6' | 'asn' | 'country' | 'tls' | 'path';

export interface MatchResult { block: boolean; reason?: BlockReason; version?: string }

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
    if (S.pathsPrefix.size) {
      let i = path.indexOf('/', 1);
      while (i !== -1) { if (S.pathsPrefix.has(path.slice(0, i + 1))) return true; i = path.indexOf('/', i + 1); }
    }
    for (const re of S.pathsRegex) if (re.test(path)) return true;
    return false;
  }

  match(input: MatchInput): MatchResult {
    const S = this.snap;
    const ip = input.ip || '';
    if (ip) {
      if (ip.indexOf(':') === -1) { const n = parseIp4(ip); if (n >= 0 && this.blocked4(n)) return { block: true, reason: 'ip4', version: S.version }; }
      else if (parseIp6Into(ip, this.W, this.G) && this.blocked6()) return { block: true, reason: 'ip6', version: S.version };
    }
    if (input.asn !== undefined && input.asn !== null && this.blockedAsn(input.asn)) return { block: true, reason: 'asn', version: S.version };
    if (input.country && S.country.size && S.country.has(input.country)) return { block: true, reason: 'country', version: S.version };
    if (input.tlsx && S.tls.has(input.tlsx)) return { block: true, reason: 'tls', version: S.version };
    if (S.pathsExact.size || S.pathsPrefix.size || S.pathsRegex.length) {
      const raw = input.path || '/';
      const q = raw.indexOf('?');
      if (this.blockedPath(q === -1 ? raw : raw.slice(0, q))) return { block: true, reason: 'path', version: S.version };
    }
    return { block: false };
  }
}

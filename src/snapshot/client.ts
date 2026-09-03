// SnapshotClient: the single-tenant port of the edge collector's snapshot lifecycle
// (edge-analyst src/blocklist.js entry/load/refresh) over the GET /snapshot contract:
//   200  BLK3 body + etag + x-camada-meta + x-camada-config
//   304  nothing changed; config headers repeated (config refreshes every poll for free)
//   204  authenticated, no snapshot published -> enforce nothing, fail open
// Semantics ported exactly: single-in-flight load; loadedAt stamped even on 204 (retry per
// poll cadence, not per request); any error keeps the previous snapshot; cold = fail open.

import { parseSnapshot, type SnapshotMeta } from './parse.js';
import { Matcher, type MatchInput, type BlockReason } from './match.js';
import type { CamadaRemoteConfig } from '../config.js';
import { DEFAULT_REFRESH_MS } from '../constants.js';

/** Like MatchResult, plus 'cold' for "never loaded yet" (fail open, mirrors the collector). */
export interface Verdict { block: boolean; reason?: BlockReason | 'cold'; version?: string }

export interface SnapshotClientOptions {
  url: string;                    // e.g. https://analyst.example.com/snapshot
  token: string;                  // the snapshot token (CAMADA_KEY's second half)
  refreshMs?: number;             // poll cadence. Leave unset and the server's poll_seconds steers it (its cost lever); set it and it is pinned
  fetchTimeoutMs?: number;
  mode?: 'timer' | 'lazy';        // timer: unref'd interval (long-lived Node); lazy: ensureFresh() per request (serverless/edge)
  fetchImpl?: typeof fetch;
  sdk?: string;                   // '<package>/<version>': sent as x-camada-sdk on every poll (SDK-03)
}

export class SnapshotClient {
  matcher: Matcher | null = null;
  config: CamadaRemoteConfig | null = null;
  private etag: string | null = null;
  private refreshMs: number;
  private readonly pinned: boolean;   // an explicit refreshMs option wins over the server's poll_seconds
  private loadedAt = 0;
  private loading: Promise<void> | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;
  private readonly opts: Required<Omit<SnapshotClientOptions, 'fetchImpl' | 'sdk'>> & { fetchImpl: typeof fetch; sdk?: string };

  constructor(opts: SnapshotClientOptions) {
    const given = Object.fromEntries(Object.entries(opts).filter(([, v]) => v !== undefined)) as SnapshotClientOptions;   // adapters forward optional options verbatim; undefined must not clobber a default
    this.opts = {
      refreshMs: DEFAULT_REFRESH_MS, fetchTimeoutMs: 3_000, mode: 'timer',
      fetchImpl: opts.fetchImpl ?? fetch,
      ...given,
    };
    this.pinned = given.refreshMs !== undefined;
    this.refreshMs = this.opts.refreshMs;
  }

  start(): void {
    if (this.timer || this.opts.mode !== 'timer') { this.ensureFresh(); return; }
    this.ensureFresh();
    this.schedule();
  }

  private schedule(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = setInterval(() => this.ensureFresh(), this.refreshMs);
    (this.timer as { unref?: () => void }).unref?.();   // never keep the process alive (no unref on edge runtimes)
  }

  stop(): void {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
  }

  /** Kicks a refresh when stale; never awaited on the request path, never throws.
   *  Staleness uses 0.9×refreshMs so a timer tick arriving at ~refreshMs-ε still refreshes —
   *  a full-interval comparison makes every other tick a no-op (effective cadence 2×). */
  ensureFresh(waitUntil?: (p: Promise<unknown>) => void): void {
    if (this.loading || Date.now() - this.loadedAt <= this.refreshMs * 0.9) return;
    this.loading = this.load().catch(() => {}).finally(() => { this.loading = null; });
    waitUntil?.(this.loading);
  }

  private async load(): Promise<void> {
    const headers: Record<string, string> = { authorization: `Bearer ${this.opts.token}` };
    if (this.etag) headers['if-none-match'] = this.etag;
    if (this.opts.sdk) headers['x-camada-sdk'] = this.opts.sdk;
    const res = await this.opts.fetchImpl(this.opts.url, { headers, signal: AbortSignal.timeout(this.opts.fetchTimeoutMs) });
    if (res.status !== 200 && res.status !== 204 && res.status !== 304) return;   // 401/5xx: keep what we have
    this.loadedAt = Date.now();
    this.readConfig(res);
    if (res.status === 304) return;
    if (res.status === 204) { this.matcher = null; this.etag = null; return; }   // no snapshot published: enforce nothing
    // 200 body frame: [u32 LE meta-length][meta JSON utf8][BLK3 container] — meta rides the
    // body (block lists grow without bound; headers must stay small)
    const frame = new Uint8Array(await res.arrayBuffer());
    if (frame.byteLength < 4) throw new Error('camada: truncated snapshot frame');
    const metaLen = new DataView(frame.buffer, frame.byteOffset).getUint32(0, true);
    if (4 + metaLen > frame.byteLength) throw new Error('camada: truncated snapshot frame');
    const meta = JSON.parse(new TextDecoder().decode(frame.subarray(4, 4 + metaLen))) as SnapshotMeta;
    if (this.matcher && meta.version === this.matcher.snap.version) return;
    this.matcher = new Matcher(parseSnapshot(frame.subarray(4 + metaLen), meta));   // throws on corrupt data -> caught above, previous kept
    this.etag = res.headers.get('etag');
  }

  private readConfig(res: { headers: { get(k: string): string | null } }): void {
    const raw = res.headers.get('x-camada-config');
    if (!raw) return;
    try { this.config = JSON.parse(raw) as CamadaRemoteConfig; } catch { return; /* keep previous config */ }
    // the server steers the poll cadence per tenant (its cost lever) unless the client pinned one
    const ms = Number(this.config.poll_seconds) * 1000;
    if (this.pinned || !Number.isFinite(ms) || ms < 5_000 || ms === this.refreshMs) return;
    this.refreshMs = ms;
    if (this.timer) this.schedule();
  }

  /** Cold (never loaded) and no-snapshot both fail open, mirroring the edge collector. */
  verdict(input: MatchInput): Verdict {
    if (!this.loadedAt) return { block: false, reason: 'cold' };
    if (!this.matcher) return { block: false };
    return this.matcher.match(input);
  }
}

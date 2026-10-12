// EventQueue: fire-and-forget batched shipping to POST /e. The collector ships one event per
// request with a 200 ms budget; an in-process SDK can do better — batch, flush on size or
// interval, and drain on process exit — but the same law holds: NOTHING here may ever throw
// into the customer's request path, and a dead ingest must cost nothing but dropped telemetry.
// Defaults (15 s / 500): every flush is one request and one R2 put at the analyst, so the bill scales
// with instance count x flush cadence — not with traffic. Beacons ride the same batch as sig:1 rows.

import { logRateLimited } from '../guarded.js';
import { parseRetryAfter } from '../snapshot/backoff.js';

const HOLD_MIN_MS = 1_000, HOLD_MAX_MS = 60_000;   // a 429 holds the queue for retry-after, clamped so a junk or huge value neither spins nor silences ingest for long

export interface EventQueueOptions {
  url: string;                    // ingest base, e.g. https://analyst.example.com
  token: string;                  // ingest token (x-tenant header)
  maxBatch?: number;              // flush when the queue reaches this many (server caps at 1000)
  maxQueue?: number;              // drop-oldest beyond this
  flushMs?: number;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  sdk?: string;                   // '<package>/<version>': sent as x-camada-sdk on every batch (SDK-03)
}

// Never store the bare global: workerd rejects `fetch` invoked with a receiver other than the
// global scope ("Illegal invocation"), and storing it on an options object means every call is
// `opts.fetchImpl(...)` — a method call. The closure resolves `fetch` against the global scope at
// call time, and callers who hand us a bare global are covered by `send()` below.
const defaultFetch: typeof fetch = (input, init) => fetch(input, init);

export class EventQueue {
  private q: unknown[] = [];
  private inflight: Promise<void> | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;
  private exitInstalled = false;
  private heldUntil = 0;           // a 429 holds the head batch until then (ms epoch)
  private holdTimer: ReturnType<typeof setTimeout> | null = null;
  dropped = 0;                    // debug counter, not an API promise
  private readonly opts: Required<Omit<EventQueueOptions, 'fetchImpl' | 'sdk'>> & { fetchImpl: typeof fetch; sdk?: string };

  constructor(opts: EventQueueOptions) {
    const given = Object.fromEntries(Object.entries(opts).filter(([, v]) => v !== undefined)) as EventQueueOptions;   // same rule as SnapshotClient: undefined never clobbers a default
    this.opts = { maxBatch: 500, maxQueue: 2000, flushMs: 15_000, timeoutMs: 2_000, fetchImpl: defaultFetch, ...given };
  }

  get size(): number { return this.q.length; }

  /** Synchronous, never throws. Starts the interval timer lazily on first push. */
  push(event: unknown): void {
    try {
      if (this.q.length >= this.opts.maxQueue) { this.q.shift(); this.dropped++; }
      this.q.push(event);
      if (!this.timer) {
        this.timer = setInterval(() => this.flush(), this.opts.flushMs);
        (this.timer as { unref?: () => void }).unref?.();
      }
      if (this.q.length >= this.opts.maxBatch) this.flush();
    } catch { /* never into the request path */ }
  }

  /** Drains the queue, ≤1000 events per POST (the server slices there); single-in-flight;
   *  the returned promise never rejects. Full drain matters for the exit flush. */
  flush(waitUntil?: (p: Promise<unknown>) => void): Promise<void> {
    return this.drain(false, waitUntil);
  }

  /** force = the process is exiting: ignore a 429 hold (nobody will be here when it ends) and, if the
   *  send still fails, count the rows as dropped instead of re-holding them. */
  private drain(force: boolean, waitUntil?: (p: Promise<unknown>) => void): Promise<void> {
    if (this.inflight) {
      // The running drain may already be past its last q.length check (its tail clears `inflight` a few
      // microtasks later): a row pushed now would sit until the next timer tick, or forever in a frozen
      // isolate. Drain again once it settles; edge runtimes hold the isolate open for the whole chain.
      const next = this.inflight.then(() => this.drain(force));
      try { waitUntil?.(next); } catch { /* a waitUntil outside its request throws: never into the block/challenge path (R7-4) */ }
      return next;
    }
    const left = this.heldUntil - Date.now();
    if (this.q.length === 0 || (!force && left > 0 && left <= HOLD_MAX_MS)) return Promise.resolve();   // held after a 429: the hold timer retries; a hold longer than the clamp means the wall clock stepped back
    this.inflight = (async () => {
      const headers: Record<string, string> = { 'x-tenant': this.opts.token, 'content-type': 'application/json' };
      if (this.opts.sdk) headers['x-camada-sdk'] = this.opts.sdk;
      const send = this.opts.fetchImpl;   // a local, so the call has no receiver even if a caller handed us a bare global
      while (this.q.length > 0) {
        const batch = this.q.splice(0, 1000);
        let res: Response;
        try {
          res = await send(`${this.opts.url}/e`, {
            method: 'POST',
            headers,
            body: JSON.stringify(batch),
            signal: AbortSignal.timeout(this.opts.timeoutMs),
          });
        } catch (err) {
          this.dropped += batch.length;
          // Dropping telemetry is by design, doing it silently is not: a mount that can never
          // reach ingest looks identical to a healthy one otherwise (finding 030).
          logRateLimited(err);
          continue;
        }
        void res?.body?.cancel().catch(() => {});   // free the connection; the answer's body is never needed
        const status = res?.status;   // a custom fetchImpl may resolve to a non-Response
        if (status !== undefined && status >= 200 && status < 300) continue;
        logRateLimited(new Error(`camada: /e answered ${status}`));   // 401/403/413/5xx: same signal as a thrown error (camada-all-a4m9)
        if (status === 429 && !force) {
          // The analyst's per-tenant ingest limit: nothing is lost yet. Put the batch back at the head,
          // hold until retry-after, and stop this drain. push() keeps working (drop-oldest at maxQueue).
          this.q.unshift(...batch);
          const over = this.q.length - this.opts.maxQueue;
          if (over > 0) { this.q.splice(0, over); this.dropped += over; }
          const ms = Math.min(Math.max(parseRetryAfter(res.headers.get('retry-after')) * 1000, HOLD_MIN_MS), HOLD_MAX_MS);
          this.heldUntil = Date.now() + ms;
          if (this.holdTimer) clearTimeout(this.holdTimer);
          this.holdTimer = setTimeout(() => { this.holdTimer = null; this.heldUntil = 0; void this.flush(); }, ms);   // the timer, not the wall clock, ends the hold
          (this.holdTimer as { unref?: () => void }).unref?.();
          return;
        }
        this.dropped += batch.length;
      }
    })().catch(logRateLimited).finally(() => { this.inflight = null; });
    const running = this.inflight;
    try { waitUntil?.(running); } catch { /* R7-4: see above */ }
    return running;
  }

  /** Stops the timers and removes the exit hooks. Rows held by a 429 would otherwise sit forever with
   *  no timer to retry them, so stop() force-drains them (sent, or counted in `dropped`); the returned
   *  promise settles when that drain does and never rejects. */
  stop(): Promise<void> {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
    const held = this.holdTimer !== null;
    if (this.holdTimer) { clearTimeout(this.holdTimer); this.holdTimer = null; }
    for (const [ev, fn] of this.exitHandlers.splice(0)) {
      ((globalThis as { process?: NodeJS.Process }).process)?.removeListener(ev, fn);
    }
    this.exitInstalled = false;
    if (!held) return Promise.resolve();
    this.heldUntil = 0;
    return this.drain(true);
  }

  private exitHandlers: Array<[string, (...a: unknown[]) => void]> = [];

  /** Node-only, opt-in (called by @camada/node): drain on beforeExit and on SIGTERM/SIGINT.
   *  The signal is re-raised with the default disposition ONLY when camada's handler was the
   *  sole listener — an app with its own graceful shutdown keeps full ownership of exit and
   *  never sees the signal delivered twice. stop() removes everything installed here. */
  installNodeExitFlush(): void {
    if (this.exitInstalled) return;
    const proc = (globalThis as { process?: NodeJS.Process }).process;
    if (!proc?.on) return;
    this.exitInstalled = true;
    const onBeforeExit = () => { void this.drain(true); };
    proc.on('beforeExit', onBeforeExit);
    this.exitHandlers.push(['beforeExit', onBeforeExit]);
    for (const sig of ['SIGTERM', 'SIGINT'] as const) {
      const handler = () => {
        proc.removeListener(sig, handler);
        if (proc.listenerCount(sig) > 0) { void this.drain(true); return; }   // the app owns shutdown; just drain quietly
        const done = () => {
          try {
            proc.kill(proc.pid, sig);   // re-raise: with this handler gone, the default action exits with the signal's status
          } catch {
            proc.exit(128 + (sig === 'SIGINT' ? 2 : 15));   // Deno without --allow-run refuses process.kill (NotCapable); exit with the same status
          }
        };
        Promise.race([this.drain(true), new Promise((r) => setTimeout(r, 500))]).then(done, done);
      };
      proc.on(sig, handler);
      this.exitHandlers.push([sig, handler]);
    }
  }
}

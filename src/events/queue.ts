// EventQueue: fire-and-forget batched shipping to POST /e. The collector ships one event per
// request with a 200 ms budget; an in-process SDK can do better — batch, flush on size or
// interval, and drain on process exit — but the same law holds: NOTHING here may ever throw
// into the customer's request path, and a dead ingest must cost nothing but dropped telemetry.
// Defaults (15 s / 500): every flush is one request and one R2 put at the analyst, so the bill scales
// with instance count x flush cadence — not with traffic. Beacons ride the same batch as sig:1 rows.

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

export class EventQueue {
  private q: unknown[] = [];
  private inflight: Promise<void> | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;
  private exitInstalled = false;
  dropped = 0;                    // debug counter, not an API promise
  private readonly opts: Required<Omit<EventQueueOptions, 'fetchImpl' | 'sdk'>> & { fetchImpl: typeof fetch; sdk?: string };

  constructor(opts: EventQueueOptions) {
    const given = Object.fromEntries(Object.entries(opts).filter(([, v]) => v !== undefined)) as EventQueueOptions;   // same rule as SnapshotClient: undefined never clobbers a default
    this.opts = { maxBatch: 500, maxQueue: 2000, flushMs: 15_000, timeoutMs: 2_000, fetchImpl: opts.fetchImpl ?? fetch, ...given };
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
    if (this.inflight) { waitUntil?.(this.inflight); return this.inflight; }   // edge runtimes must still hold the isolate open
    if (this.q.length === 0) return Promise.resolve();
    this.inflight = (async () => {
      const headers: Record<string, string> = { 'x-tenant': this.opts.token, 'content-type': 'application/json' };
      if (this.opts.sdk) headers['x-camada-sdk'] = this.opts.sdk;
      while (this.q.length > 0) {
        const batch = this.q.splice(0, 1000);
        try {
          await this.opts.fetchImpl(`${this.opts.url}/e`, {
            method: 'POST',
            headers,
            body: JSON.stringify(batch),
            signal: AbortSignal.timeout(this.opts.timeoutMs),
          });
        } catch { this.dropped += batch.length; }
      }
    })().finally(() => { this.inflight = null; });
    waitUntil?.(this.inflight);
    return this.inflight;
  }

  stop(): void {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
    for (const [ev, fn] of this.exitHandlers.splice(0)) {
      ((globalThis as { process?: NodeJS.Process }).process)?.removeListener(ev, fn);
    }
    this.exitInstalled = false;
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
    const onBeforeExit = () => { void this.flush(); };
    proc.on('beforeExit', onBeforeExit);
    this.exitHandlers.push(['beforeExit', onBeforeExit]);
    for (const sig of ['SIGTERM', 'SIGINT'] as const) {
      const handler = () => {
        proc.removeListener(sig, handler);
        if (proc.listenerCount(sig) > 0) { void this.flush(); return; }   // the app owns shutdown; just drain quietly
        const done = () => proc.kill(proc.pid, sig);
        Promise.race([this.flush(), new Promise((r) => setTimeout(r, 500))]).then(done, done);
      };
      proc.on(sig, handler);
      this.exitHandlers.push([sig, handler]);
    }
  }
}

import { describe, it, expect, vi, afterEach } from 'vitest';
import { EventQueue } from '../src/index.js';

const q = (fetchImpl: typeof fetch, opts = {}) =>
  new EventQueue({ url: 'https://a.test', token: 'tok', fetchImpl, ...opts });

describe('EventQueue', () => {
  it('flushes when the batch size is reached', async () => {
    const batches: unknown[][] = [];
    const queue = q(async (_u, init) => { batches.push(JSON.parse(init!.body as string)); return new Response(null, { status: 202 }); }, { maxBatch: 3 });
    queue.push({ n: 1 }); queue.push({ n: 2 });
    expect(batches).toHaveLength(0);
    queue.push({ n: 3 });
    await new Promise((r) => setTimeout(r, 10));
    expect(batches).toHaveLength(1);
    expect(batches[0]).toHaveLength(3);
    queue.stop();
  });

  it('defaults to a 15 s flush and 500-event batches (puts at the analyst scale with flushes, not traffic)', async () => {
    vi.useFakeTimers();
    const batches: unknown[][] = [];
    const queue = q(async (_u, init) => { batches.push(JSON.parse(init!.body as string)); return new Response(null, { status: 202 }); });
    queue.push({ n: 1 });
    await vi.advanceTimersByTimeAsync(14_000);
    expect(batches).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(1_500);
    expect(batches).toHaveLength(1);
    for (let i = 0; i < 499; i++) queue.push({ i });
    expect(batches).toHaveLength(1);
    queue.push({ last: true });
    await vi.advanceTimersByTimeAsync(10);
    expect(batches).toHaveLength(2);
    expect(batches[1]).toHaveLength(500);
    queue.stop();
    vi.useRealTimers();
  });

  it('flushes on the interval timer', async () => {
    vi.useFakeTimers();
    const batches: unknown[][] = [];
    const queue = q(async (_u, init) => { batches.push(JSON.parse(init!.body as string)); return new Response(null, { status: 202 }); }, { flushMs: 1000 });
    queue.push({ n: 1 });
    await vi.advanceTimersByTimeAsync(1100);
    expect(batches).toHaveLength(1);
    queue.stop();
    vi.useRealTimers();
  });

  it('sends the x-tenant token and posts to /e', async () => {
    let url = '', tenant: string | null = null;
    const queue = q(async (u, init) => { url = String(u); tenant = new Headers(init?.headers).get('x-tenant'); return new Response(null, { status: 202 }); });
    queue.push({});
    await queue.flush();
    expect(url).toBe('https://a.test/e');
    expect(tenant).toBe('tok');
    queue.stop();
  });

  it('sends x-camada-sdk when an sdk id is configured, and omits it otherwise', async () => {
    let hdr: string | null = 'unset';
    const capture = async (_u: unknown, init?: RequestInit) => { hdr = new Headers(init?.headers).get('x-camada-sdk'); return new Response(null, { status: 202 }); };
    const withId = q(capture as typeof fetch, { sdk: '@camada/node/0.0.1' });
    withId.push({}); await withId.flush(); withId.stop();
    expect(hdr).toBe('@camada/node/0.0.1');
    const without = q(capture as typeof fetch);
    without.push({}); await without.flush(); without.stop();
    expect(hdr).toBeNull();
  });

  it('hard-caps a flush at 1000 events (the server slices there anyway)', async () => {
    const sizes: number[] = [];
    const queue = q(async (_u, init) => { sizes.push(JSON.parse(init!.body as string).length); return new Response(null, { status: 202 }); }, { maxBatch: 5000, maxQueue: 5000 });
    for (let i = 0; i < 1500; i++) queue.push({ i });
    await queue.flush();
    await new Promise((r) => setTimeout(r, 10));   // the follow-up flush for the remainder
    expect(sizes[0]).toBe(1000);
    expect(sizes.reduce((a, b) => a + b, 0)).toBe(1500);
    queue.stop();
  });

  it('drops oldest beyond maxQueue and never throws', () => {
    const queue = q(async () => new Response(null, { status: 202 }), { maxQueue: 5, maxBatch: 100 });
    for (let i = 0; i < 12; i++) expect(() => queue.push({ i })).not.toThrow();
    expect(queue.size).toBe(5);
    expect(queue.dropped).toBe(7);
    queue.stop();
  });

  it('survives a dead ingest: push and flush never throw, queue stays bounded', async () => {
    const queue = q(async () => { throw new Error('ECONNREFUSED'); }, { maxQueue: 10, maxBatch: 100 });
    for (let i = 0; i < 30; i++) queue.push({ i });
    await expect(queue.flush()).resolves.toBeUndefined();
    expect(queue.size).toBeLessThanOrEqual(10);
    queue.stop();
  });

  it('runs one flush at a time', async () => {
    let inflight = 0, max = 0;
    const queue = q(async () => { inflight++; max = Math.max(max, inflight); await new Promise((r) => setTimeout(r, 10)); inflight--; return new Response(null, { status: 202 }); });
    queue.push({});
    const a = queue.flush(), b = queue.flush(), c = queue.flush();
    await Promise.all([a, b, c]);
    expect(max).toBe(1);
    queue.stop();
  });
});

describe('a flush that lands on the tail of a drain (camada-all-a4m9 int)', () => {
  // The drain loop has emptied the queue but `inflight` is cleared a few microtasks later. A row
  // pushed and flushed in that window used to get the finishing promise back and sat until the next
  // 15 s tick (or forever, in a frozen serverless isolate). Probe every microtask offset of the tail.
  it('ships a row pushed at any microtask after the in-flight send resolved, with no timer tick', async () => {
    for (let k = 0; k < 8; k++) {
      const batches: unknown[][] = [];
      let release!: () => void;
      const gate = new Promise<void>((r) => { release = r; });
      const queue = q(async (_u, init) => {
        batches.push(JSON.parse(init!.body as string));
        if (batches.length === 1) await gate;
        return new Response(null, { status: 202 });
      }, { flushMs: 3_600_000 });
      queue.push({ n: 'a' });
      const held: Promise<unknown>[] = [];
      void queue.flush();
      release();
      for (let i = 0; i < k; i++) await Promise.resolve();
      queue.push({ n: 'b' });
      void queue.flush((p) => held.push(p));
      await Promise.all(held);
      expect(batches.flat(), `offset ${k}`).toEqual([{ n: 'a' }, { n: 'b' }]);
      queue.stop();
    }
  });
});

describe('exit flush', () => {
  it('flushes on SIGTERM and still exits where the host refuses process.kill (Deno without --allow-run)', async () => {
    const { EventEmitter } = await import('node:events');
    const exits: number[] = [];
    const proc = Object.assign(new EventEmitter(), {
      pid: 4242,
      kill: () => { throw new Error('NotCapable: Requires run access'); },
      exit: (code: number) => { exits.push(code); },
    });
    const posted: string[] = [];
    vi.stubGlobal('process', proc);
    try {
      const queue = new EventQueue({ url: 'https://a.test', token: 't', fetchImpl: (async (u: string) => { posted.push(String(u)); return new Response(null, { status: 202 }); }) as typeof fetch });
      queue.installNodeExitFlush();
      queue.push({ p: '/' });
      proc.emit('SIGTERM');
      await vi.waitFor(() => expect(exits).toEqual([143]));
      expect(posted).toEqual(['https://a.test/e']);   // the batch went out before the exit
      queue.stop();
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe('EventQueue non-2xx answers (camada-all-a4m9)', () => {
  let base = 4_000_000_000_000;   // logRateLimited is a module-wide once-a-minute gate: every test starts a minute+ later
  const errSpy = () => vi.spyOn(console, 'error').mockImplementation(() => {});
  const start = () => { vi.useFakeTimers(); vi.setSystemTime((base += 3_600_000)); return errSpy(); };
  const lines = (spy: ReturnType<typeof errSpy>) => spy.mock.calls.map((c) => String(c[1]));
  afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); });   // a failing assertion must not leak fake timers or the console spy into the next test

  it('logs `/e answered 401`, counts the batch as dropped and cancels the body', async () => {
    const spy = start();
    let cancelled = false;
    const body = new ReadableStream({ cancel() { cancelled = true; } });
    const queue = q(async () => new Response(body, { status: 401 }));
    queue.push({ n: 1 }); queue.push({ n: 2 });
    await queue.flush();
    expect(lines(spy)).toEqual(['camada: /e answered 401']);
    expect(queue.dropped).toBe(2);
    expect(queue.size).toBe(0);
    expect(cancelled).toBe(true);
    queue.stop();
  });

  it('a 5xx is dropped and logged the same way', async () => {
    const spy = start();
    const queue = q(async () => new Response(null, { status: 503 }));
    queue.push({}); await queue.flush();
    expect(lines(spy)).toEqual(['camada: /e answered 503']);
    expect(queue.dropped).toBe(1);
    queue.stop();
  });

  it('a 2xx logs nothing and drops nothing', async () => {
    const spy = start();
    const queue = q(async () => new Response(null, { status: 202 }));
    queue.push({}); await queue.flush();
    expect(spy).not.toHaveBeenCalled();
    expect(queue.dropped).toBe(0);
    queue.stop();
  });

  it('a 429 holds the batch at the head, retries after retry-after, and loses nothing', async () => {
    const spy = start();
    const posts: unknown[][] = [];
    let limited = true;
    const queue = q(async (_u, init) => {
      posts.push(JSON.parse(init!.body as string));
      return limited ? new Response(null, { status: 429, headers: { 'retry-after': '7' } }) : new Response(null, { status: 202 });
    });
    queue.push({ n: 1 }); queue.push({ n: 2 });
    await queue.flush();
    expect(lines(spy)).toEqual(['camada: /e answered 429']);
    expect(posts).toHaveLength(1);
    expect(queue.dropped).toBe(0);
    expect(queue.size).toBe(2);
    queue.push({ n: 3 });                       // push() is never blocked by the hold
    expect(queue.size).toBe(3);
    await queue.flush();                         // still held: no POST
    await vi.advanceTimersByTimeAsync(6_000);
    expect(posts).toHaveLength(1);
    limited = false;
    await vi.advanceTimersByTimeAsync(1_500);    // retry-after elapsed: the hold timer drains
    expect(posts).toHaveLength(2);
    expect(posts[1]).toEqual([{ n: 1 }, { n: 2 }, { n: 3 }]);   // original order, batch at the head
    expect(queue.size).toBe(0);
    expect(queue.dropped).toBe(0);
    queue.stop();
  });

  it('while held, maxQueue still drops the oldest', async () => {
    const spy = start();
    const queue = q(async () => new Response(null, { status: 429, headers: { 'retry-after': '30' } }), { maxQueue: 3 });
    queue.push({ n: 1 }); queue.push({ n: 2 }); queue.push({ n: 3 });
    await queue.flush();
    expect(queue.size).toBe(3);
    queue.push({ n: 4 });
    expect(queue.size).toBe(3);
    expect(queue.dropped).toBe(1);
    queue.stop();
  });

  it('a 429 without a usable retry-after still holds (1 s floor) instead of spinning', async () => {
    const spy = start();
    let n = 0;
    const queue = q(async () => { n++; return new Response(null, { status: 429, headers: { 'retry-after': 'Wed, 21 Oct 2026 07:28:00 GMT' } }); });
    queue.push({}); await queue.flush();
    expect(n).toBe(1);
    await vi.advanceTimersByTimeAsync(900);
    expect(n).toBe(1);
    await vi.advanceTimersByTimeAsync(200);
    expect(n).toBe(2);
    queue.stop();
  });
  it('a fetchImpl that resolves to a non-Response never rejects flush() (R6-1)', async () => {
    start();
    const queue = q((async () => undefined) as unknown as typeof fetch);
    queue.push({});
    await expect(queue.flush()).resolves.toBeUndefined();
    expect(queue.size).toBe(0);
    queue.stop();
  });

  it('a backward clock step does not stall a 429 hold (R6-2)', async () => {
    start();
    let n = 0;
    const queue = q(async () => { n++; return n === 1 ? new Response(null, { status: 429, headers: { 'retry-after': '1' } }) : new Response(null, { status: 202 }); });
    queue.push({}); await queue.flush();
    expect(n).toBe(1);
    vi.setSystemTime(Date.now() - 3_600_000);
    await vi.advanceTimersByTimeAsync(1_100);
    expect(n).toBe(2);
    expect(queue.size).toBe(0);
    queue.stop();
  });

  it('an exit flush ignores a 429 hold and retries once (R6-3)', async () => {
    start();
    let n = 0;
    const queue = q(async () => { n++; return n === 1 ? new Response(null, { status: 429, headers: { 'retry-after': '30' } }) : new Response(null, { status: 202 }); });
    queue.installNodeExitFlush();
    queue.push({}); queue.push({});
    await queue.flush();
    expect(n).toBe(1);
    process.emit('beforeExit', 0);
    await vi.advanceTimersByTimeAsync(10);
    expect(n).toBe(2);
    expect(queue.size).toBe(0);
    queue.stop();
  });

  it('an exit flush that still fails counts the held rows as dropped (R6-3)', async () => {
    start();
    const queue = q(async () => new Response(null, { status: 429, headers: { 'retry-after': '30' } }));
    queue.installNodeExitFlush();
    queue.push({}); queue.push({});
    await queue.flush();
    expect(queue.dropped).toBe(0);
    process.emit('beforeExit', 0);
    await vi.advanceTimersByTimeAsync(10);
    expect(queue.dropped).toBe(2);
    expect(queue.size).toBe(0);
    queue.stop();
  });

  it('a 2xx body is cancelled too (R6-7)', async () => {
    start();
    let cancelled = false;
    const queue = q(async () => new Response(new ReadableStream({ cancel() { cancelled = true; } }), { status: 202 }));
    queue.push({}); await queue.flush();
    expect(cancelled).toBe(true);
    queue.stop();
  });
});

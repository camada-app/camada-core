// camada-all-is47. On workerd a JS stream never learns the client left (no pull, no cancel), so
// onBodyDone pipes an SSE body through the native IdentityTransformStream there. Node's
// TransformStream stands in for it: cancelling its readable errors the writable, as a client
// disconnect errors the native one. The real runtime is covered by the wrangler e2e in the bean.
import { describe, it, expect, vi, afterEach } from 'vitest';
import { onBodyDone } from '../src/index.js';

const enc = new TextEncoder();
const sse = { 'content-type': 'text/event-stream' };

/** An SSE source of `n` chunks, `ms` apart, that records whether it was cancelled. */
function source(n: number, ms: number) {
  let i = 0;
  const state = { cancelled: false };
  const stream = new ReadableStream<Uint8Array>({
    async pull(c) {
      await new Promise((r) => setTimeout(r, ms));
      if (i++ >= n) c.close(); else c.enqueue(enc.encode(`data: ${i}\n\n`));
    },
    cancel() { state.cancelled = true; },
  });
  return { stream, state };
}

afterEach(() => { vi.unstubAllGlobals(); });

describe('onBodyDone on workerd (IdentityTransformStream present)', () => {
  const its = () => vi.stubGlobal('IdentityTransformStream', class extends TransformStream<Uint8Array, Uint8Array> {});

  it('pipes an SSE body, holds waitUntil on the pipe, and is done once the body has been read', async () => {
    its();
    const { stream } = source(3, 30);
    const res = new Response(stream, { status: 200, headers: { ...sse, 'x-a': 'b' } });
    const done = vi.fn();
    const waits: Promise<unknown>[] = [];
    const t0 = Date.now();
    const out = onBodyDone(res, done, { waitUntil: (p) => { waits.push(p); } });
    expect(out).not.toBe(res);
    expect([...out.headers]).toEqual([...res.headers]);
    expect(waits).toHaveLength(1);
    expect(done).not.toHaveBeenCalled();
    expect(await out.text()).toBe('data: 1\n\ndata: 2\n\ndata: 3\n\n');
    await waits[0];
    expect(done).toHaveBeenCalledTimes(1);
    expect(Date.now() - t0).toBeGreaterThanOrEqual(100);   // 4 pulls x 30 ms: the body, not the first byte
  });

  it('on a client disconnect cancels the source, settles waitUntil and is done once', async () => {
    its();
    const { stream, state } = source(1000, 20);
    const done = vi.fn();
    const waits: Promise<unknown>[] = [];
    const out = onBodyDone(new Response(stream, { headers: sse }), done, { waitUntil: (p) => { waits.push(p); } });
    const reader = out.body!.getReader();
    await reader.read();
    await reader.cancel();
    await waits[0];
    expect(done).toHaveBeenCalledTimes(1);
    expect(state.cancelled).toBe(true);   // a proxied upstream closes instead of streaming to nobody
  });

  it('cancels the source at once when the request signal aborts, even with nobody reading', async () => {
    its();
    const { stream, state } = source(1000, 20);
    const done = vi.fn();
    const waits: Promise<unknown>[] = [];
    const ac = new AbortController();
    onBodyDone(new Response(stream, { headers: sse }), done, { waitUntil: (p) => { waits.push(p); }, signal: ac.signal });
    ac.abort();
    await waits[0];
    expect(done).toHaveBeenCalledTimes(1);
    expect(state.cancelled).toBe(true);
  });

  it('leaves every other response untouched and never reads the signal for it', async () => {
    its();
    const done = vi.fn();
    const res = new Response('x');
    const opts = { get signal(): AbortSignal { throw new Error('read'); } };
    expect(onBodyDone(res, done, opts)).toBe(res);
    expect(done).toHaveBeenCalledTimes(1);
  });

  it('throws on a locked body rather than send a copy that never ends', () => {
    its();
    const res = new Response(source(1, 1).stream, { headers: sse });
    res.body!.getReader();
    expect(() => onBodyDone(res, () => {})).toThrow();
  });
});

describe('onBodyDone elsewhere (no IdentityTransformStream)', () => {
  it('never reads the signal', async () => {
    const done = vi.fn();
    const opts = { get signal(): AbortSignal { throw new Error('read'); } };
    const out = onBodyDone(new Response(source(1, 1).stream, { headers: sse }), done, opts);
    expect(await out.text()).toBe('data: 1\n\n');
    expect(done).toHaveBeenCalledTimes(1);
  });
});

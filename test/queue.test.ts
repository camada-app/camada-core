import { describe, it, expect, vi } from 'vitest';
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

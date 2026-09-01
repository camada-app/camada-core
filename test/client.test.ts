import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { SnapshotClient } from '../src/index.js';

const bin = readFileSync(new URL('./fixtures/snap-basic.bin', import.meta.url));
// compact, as the server sends it — a header value cannot carry the pretty-printed file
const meta = JSON.stringify(JSON.parse(readFileSync(new URL('./fixtures/snap-basic.meta.json', import.meta.url), 'utf8')));
const CONFIG = JSON.stringify({ tenant: 'acme', beacon: true, sample: 1, exclude: [], trusted_proxy: { mode: 'none' }, poll_seconds: 30 });

// 200 body frame: [u32 LE meta-length][meta JSON][BLK3 bin]
const frame = (metaJson: string, body: Uint8Array) => {
  const m = new TextEncoder().encode(metaJson);
  const f = new Uint8Array(4 + m.length + body.length);
  new DataView(f.buffer).setUint32(0, m.length, true);
  f.set(m, 4); f.set(body, 4 + m.length);
  return f;
};

const ok200 = () => new Response(frame(meta, new Uint8Array(bin)), {
  status: 200,
  headers: { etag: `"${JSON.parse(meta).version}"`, 'x-camada-config': CONFIG },
});

const client = (fetchImpl: typeof fetch, mode: 'timer' | 'lazy' = 'lazy') =>
  new SnapshotClient({ url: 'https://a.test/snapshot', token: 'st', mode, refreshMs: 0, fetchImpl });

const settle = () => new Promise((r) => setTimeout(r, 10));

describe('SnapshotClient', () => {
  it('is cold (fail open) before the first load completes', () => {
    const c = client(() => new Promise(() => {}));   // never resolves
    expect(c.verdict({ ip: '203.0.113.66' })).toEqual({ block: false, reason: 'cold' });
  });

  it('loads on 200, matches, and exposes the config', async () => {
    const c = client(async () => ok200());
    c.ensureFresh();
    await settle();
    expect(c.verdict({ ip: '203.0.113.66' }).reason).toBe('ip4');
    expect(c.verdict({ ip: '8.8.8.8' }).block).toBe(false);
    expect(c.config?.tenant).toBe('acme');
  });

  it('sends If-None-Match and keeps the snapshot on 304 — config still refreshes', async () => {
    let inm: string | null = null, calls = 0;
    const c = client(async (_url, init) => {
      calls++;
      inm = new Headers(init?.headers).get('if-none-match');
      if (calls === 1) return ok200();
      return new Response(null, { status: 304, headers: { etag: inm!, 'x-camada-config': CONFIG.replace('"sample":1', '"sample":0.25') } });
    });
    c.ensureFresh(); await settle();
    c.ensureFresh(); await settle();
    expect(calls).toBe(2);
    expect(inm).toBe(`"${JSON.parse(meta).version}"`);
    expect(c.verdict({ ip: '203.0.113.66' }).block).toBe(true);   // snapshot kept
    expect(c.config?.sample).toBe(0.25);                          // config updated on the 304
  });

  it('keeps the previous snapshot across server errors and timeouts', async () => {
    let calls = 0;
    const c = client(async () => (++calls === 1 ? ok200() : new Response('boom', { status: 500 })));
    c.ensureFresh(); await settle();
    c.ensureFresh(); await settle();
    expect(calls).toBe(2);
    expect(c.verdict({ ip: '203.0.113.66' }).block).toBe(true);
  });

  it('keeps the previous snapshot when the body is corrupt', async () => {
    let calls = 0;
    const c = client(async () => {
      if (++calls === 1) return ok200();
      return new Response(frame(JSON.stringify({ version: 'v2' }), new Uint8Array([1, 2, 3, 4])), { status: 200, headers: { 'x-camada-config': CONFIG } });
    });
    c.ensureFresh(); await settle();
    c.ensureFresh(); await settle();
    expect(c.verdict({ ip: '203.0.113.66' }).block).toBe(true);
  });

  it('clears enforcement on 204 (tenant has no snapshot) but is no longer cold', async () => {
    let calls = 0;
    const c = client(async () => (++calls === 1 ? ok200() : new Response(null, { status: 204, headers: { 'x-camada-config': CONFIG } })));
    c.ensureFresh(); await settle();
    c.ensureFresh(); await settle();
    expect(c.verdict({ ip: '203.0.113.66' })).toEqual({ block: false });
  });

  it('runs a single load at a time', async () => {
    let calls = 0;
    const c = client(async () => { calls++; await settle(); return ok200(); });
    c.ensureFresh(); c.ensureFresh(); c.ensureFresh();
    await settle(); await settle();
    expect(calls).toBe(1);
  });

  it('never lets a network error escape ensureFresh', async () => {
    const c = client(async () => { throw new Error('ECONNREFUSED'); });
    expect(() => c.ensureFresh()).not.toThrow();
    await settle();
    expect(c.verdict({ ip: '203.0.113.66' }).reason).toBe('cold');
  });

  it('hands the load promise to waitUntil in lazy mode', async () => {
    const waits: Promise<unknown>[] = [];
    const c = client(async () => ok200());
    c.ensureFresh((p) => waits.push(p));
    expect(waits).toHaveLength(1);
    await Promise.all(waits);
    expect(c.verdict({ ip: '203.0.113.66' }).block).toBe(true);
  });

  it('timer mode starts and stops without keeping the process alive', async () => {
    vi.useFakeTimers();
    let calls = 0;
    const c = new SnapshotClient({ url: 'https://a.test/snapshot', token: 'st', mode: 'timer', refreshMs: 1000, fetchImpl: async () => { calls++; return ok200(); } });
    c.start();
    await vi.advanceTimersByTimeAsync(3500);
    c.stop();
    const at = calls;
    await vi.advanceTimersByTimeAsync(5000);
    expect(calls).toBe(at);
    expect(calls).toBeGreaterThanOrEqual(2);
    vi.useRealTimers();
  });
});

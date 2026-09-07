import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { SnapshotClient } from '../src/index.js';

const bin = readFileSync(new URL('./fixtures/blk3/v3-basic.bin', import.meta.url));
// compact, as the server sends it — a header value cannot carry the pretty-printed file
const meta = JSON.stringify(JSON.parse(readFileSync(new URL('./fixtures/blk3/v3-basic.meta.json', import.meta.url), 'utf8')));
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
    expect(c.verdict({ ip: '203.0.113.66' })).toEqual({ block: false, challenge: false, allowed: false, warn: false, action: null, reason: 'cold' });
  });

  it('loads on 200, matches, and exposes the config', async () => {
    const c = client(async () => ok200());
    c.ensureFresh();
    await settle();
    expect(c.verdict({ ip: '203.0.113.66' }).reason).toBe('ip4');
    expect(c.verdict({ ip: '8.8.8.8' }).block).toBe(false);
    expect(c.config?.tenant).toBe('acme');
  });

  it('sends x-camada-sdk on every poll when an sdk id is configured', async () => {
    const seen: Array<string | null> = [];
    const c = new SnapshotClient({
      url: 'https://a.test/snapshot', token: 'st', mode: 'lazy', refreshMs: 0, sdk: '@camada/next/0.0.1',
      fetchImpl: async (_u, init) => {
        seen.push(new Headers(init?.headers).get('x-camada-sdk'));
        return seen.length === 1 ? ok200() : new Response(null, { status: 304, headers: { 'x-camada-config': CONFIG } });
      },
    });
    c.ensureFresh(); await settle();
    c.ensureFresh(); await settle();   // the 304 path too
    expect(seen).toEqual(['@camada/next/0.0.1', '@camada/next/0.0.1']);
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
    expect(c.verdict({ ip: '203.0.113.66' })).toEqual({ block: false, challenge: false, allowed: false, warn: false, action: null });
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

  it('adopts the server-sent poll_seconds as its cadence (the server can slow every instance down)', async () => {
    vi.useFakeTimers();
    let calls = 0;
    const cfg60 = CONFIG.replace('"poll_seconds":30', '"poll_seconds":60');
    const ok60 = async () => { calls++; return new Response(frame(meta, new Uint8Array(bin)), { status: 200, headers: { etag: `"${JSON.parse(meta).version}"`, 'x-camada-config': cfg60 } }); };
    const c = new SnapshotClient({ url: 'https://a.test/snapshot', token: 'st', mode: 'timer', fetchImpl: ok60 });   // no refreshMs: the 30 s default, steerable
    c.start();
    await vi.advanceTimersByTimeAsync(10);
    expect(calls).toBe(1);
    await vi.advanceTimersByTimeAsync(31_000);   // the default 30 s tick is gone: the server said 60
    expect(calls).toBe(1);
    await vi.advanceTimersByTimeAsync(30_000);
    expect(calls).toBe(2);
    c.stop();
    // an explicit refreshMs is pinned: the server cannot move it
    calls = 0;
    const p = new SnapshotClient({ url: 'https://a.test/snapshot', token: 'st', mode: 'timer', refreshMs: 1000, fetchImpl: ok60 });
    p.start();
    await vi.advanceTimersByTimeAsync(3_050);
    expect(calls).toBe(4);
    p.stop();
    vi.useRealTimers();
  });

  it('treats an explicit undefined refreshMs as unset (adapters forward optional options verbatim)', async () => {
    vi.useFakeTimers();
    let calls = 0;
    // a bare 200 without x-camada-config: nothing but the constructor default can set the cadence
    const bare = () => new Response(frame(meta, new Uint8Array(bin)), { status: 200, headers: { etag: `"${JSON.parse(meta).version}"` } });
    const c = new SnapshotClient({ url: 'https://a.test/snapshot', token: 'st', mode: 'timer', refreshMs: undefined, fetchImpl: async () => { calls++; return bare(); } });
    c.start();
    await vi.advanceTimersByTimeAsync(5_000);   // a 0/undefined interval would have polled thousands of times by now
    expect(calls).toBe(1);
    await vi.advanceTimersByTimeAsync(26_000);
    expect(calls).toBe(2);
    c.stop();
    vi.useRealTimers();
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

describe('snapshotVersion', () => {
  const header = async (opts: { snapshotVersion?: 3 | 4 | 5 } = {}) => {
    let seen: string | null = 'unset';
    const c = new SnapshotClient({
      url: 'https://a.test/snapshot', token: 'st', mode: 'lazy', refreshMs: 0,
      fetchImpl: async (_u, i) => { seen = new Headers(i?.headers).get('x-camada-snapshot'); return ok200(); },
      ...opts,
    });
    c.ensureFresh();
    await vi.waitFor(() => expect(seen).not.toBe('unset'));
    return seen;
  };

  it('asks for v5 by default', async () => {
    expect(await header()).toBe('5');
  });

  it('asks for the version it was pinned to', async () => {
    expect(await header({ snapshotVersion: 4 })).toBe('4');
  });

  it('omits the header when pinned to 3', async () => {
    expect(await header({ snapshotVersion: 3 })).toBeNull();
  });
});

describe('v5 snapshot', () => {
  const bin5 = readFileSync(new URL('./fixtures/blk5/v5-rules.bin', import.meta.url));
  const meta5 = JSON.stringify(JSON.parse(readFileSync(new URL('./fixtures/blk5/v5-rules.meta.json', import.meta.url), 'utf8')));
  const ok5 = () => new Response(frame(meta5, new Uint8Array(bin5)), {
    status: 200, headers: { etag: `"${JSON.parse(meta5).version}-v5"`, 'x-camada-config': CONFIG },
  });

  it('carries the rule verdict through to the adapters', async () => {
    const c = client(async () => ok5());
    c.ensureFresh();
    await settle();
    expect(c.verdict({ ip: '8.8.8.8', ua: 'curl/8.4.0' })).toMatchObject({ block: true, action: 'block', rule: 'cr_00000000000f', reason: 'rule' });
    expect(c.verdict({ ip: '8.8.8.8', ua: 'Scrapy/2.11' })).toMatchObject({ block: false, allowed: false, warn: true, action: 'warn', rule: 'cr_00000000000e' });
    expect(c.verdict({ ip: '8.8.8.8', path: '/healthz' })).toMatchObject({ allowed: true, action: 'skip', rule: 'cr_00000000000a' });
    // the header getter travels the same path as every other MatchInput field
    expect(c.verdict({ ip: '8.8.8.8', header: (n) => (n === 'x-api-key' ? 'leaked-key-1' : null) }))
      .toMatchObject({ block: true, action: 'block', rule: 'cr_000000000019', reason: 'rule' });
    // nothing matched: the flags the adapters read are all present and false
    expect(c.verdict({ ip: '8.8.8.8', ua: 'Mozilla/5.0' })).toEqual({ block: false, challenge: false, allowed: false, warn: false, action: null, version: 'fixture-v5-rules' });
  });

  // The v4 body and the v5 body of one publish share meta.version; only the etag says which.
  it('re-parses when a tenant gains the v5 container', async () => {
    const v4 = readFileSync(new URL('./fixtures/blk3/v4-basic.bin', import.meta.url));
    const v4meta = JSON.stringify({ ...JSON.parse(readFileSync(new URL('./fixtures/blk3/v4-basic.meta.json', import.meta.url), 'utf8')), version: 'same' });
    const v5meta = JSON.stringify({ ...JSON.parse(meta5), version: 'same' });   // one publish, two bodies: same version, different etags
    const bodies = [
      new Response(frame(v4meta, new Uint8Array(v4)), { status: 200, headers: { etag: '"same-v4"', 'x-camada-config': CONFIG } }),
      new Response(frame(v5meta, new Uint8Array(bin5)), { status: 200, headers: { etag: '"same-v5"', 'x-camada-config': CONFIG } }),
    ];
    const c = client(async () => bodies.shift()!);
    c.ensureFresh();
    await vi.waitFor(() => expect(c.matcher?.snap.format).toBe(4));
    expect(c.verdict({ ip: '8.8.8.8', ua: 'curl/8.4.0' }).block).toBe(false);   // v4 cannot express the rule
    c.ensureFresh();
    await vi.waitFor(() => expect(c.matcher?.snap.format).toBe(5));
    expect(c.verdict({ ip: '8.8.8.8', ua: 'curl/8.4.0' }).rule).toBe('cr_00000000000f');
  });
});

describe('format switch', () => {
  // edge-analyst serves the v3 and v4 bodies of one publish under the same meta.version,
  // distinguished only by etag. A v4 asker on a tenant with no v4 snapshot yet gets the v3
  // body; when v4 lands, the client must re-parse instead of keeping the v3 matcher.
  it('re-parses when the etag changes under an unchanged version', async () => {
    const v3 = readFileSync(new URL('./fixtures/blk3/v3-basic.bin', import.meta.url));
    const v4 = readFileSync(new URL('./fixtures/blk3/v4-basic.bin', import.meta.url));
    const shared = JSON.stringify({ ...JSON.parse(readFileSync(new URL('./fixtures/blk3/v4-basic.meta.json', import.meta.url), 'utf8')), version: 'same' });
    const bodies = [
      new Response(frame(shared, new Uint8Array(v3)), { status: 200, headers: { etag: '"same"', 'x-camada-config': CONFIG } }),
      new Response(frame(shared, new Uint8Array(v4)), { status: 200, headers: { etag: '"same-v4"', 'x-camada-config': CONFIG } }),
    ];
    const c = client(async () => bodies.shift()!);
    c.ensureFresh();
    await vi.waitFor(() => expect(c.matcher?.snap.format).toBe(3));
    c.ensureFresh();
    await vi.waitFor(() => expect(c.matcher?.snap.format).toBe(4));
  });
});

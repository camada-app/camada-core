// Regression for finding 030. workerd rejects `fetch` invoked with a receiver other than the
// global scope ("Illegal invocation"), and @camada/core used to store the implementation on an
// options object — so every call was `this.opts.fetchImpl(...)`, a method call. Under Node the
// stubs are `this`-insensitive and every test passed; the SDK was inert on Workers, silently,
// because the queue swallowed the throw and the poll was caught by design.
//
// `strictFetch` reproduces the runtime's rule in Node: a plain call leaves `this` undefined in
// an ES module, a method call sets it to the owning object.
import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { SnapshotClient, EventQueue } from '../src/index.js';

const bin = readFileSync(new URL('./fixtures/blk3/v4-basic.bin', import.meta.url));
const meta = JSON.stringify(JSON.parse(readFileSync(new URL('./fixtures/blk3/v4-basic.meta.json', import.meta.url), 'utf8')));

const frame = () => {
  const m = new TextEncoder().encode(meta);
  const f = new Uint8Array(4 + m.length + bin.length);
  new DataView(f.buffer).setUint32(0, m.length, true);
  f.set(m, 4); f.set(new Uint8Array(bin), 4 + m.length);
  return f;
};

/** A fetch that refuses a wrong receiver, exactly as workerd does. */
function strictFetch(seen: string[]): typeof fetch {
  const impl = function (this: unknown, url: string | URL | Request): Promise<Response> {
    if (this !== undefined && this !== globalThis) {
      return Promise.reject(new TypeError('Illegal invocation: function called with incorrect `this` reference'));
    }
    const u = String(url);
    seen.push(u);
    if (u.endsWith('/snapshot')) return Promise.resolve(new Response(frame(), { status: 200, headers: { etag: '"v4"' } }));
    return Promise.resolve(new Response(null, { status: 202 }));
  };
  return impl as unknown as typeof fetch;
}

describe('a this-sensitive runtime (workerd)', () => {
  it('polls the snapshot when the caller hands over a bare global fetch', async () => {
    const seen: string[] = [];
    const c = new SnapshotClient({ url: 'https://a.test/snapshot', token: 'st', mode: 'lazy', refreshMs: 0, fetchImpl: strictFetch(seen) });
    c.ensureFresh();
    // The stub records the call synchronously; the body is parsed a tick later, so wait on the
    // matcher — the point is that the request both happened AND produced a usable snapshot.
    await vi.waitFor(() => expect(c.matcher).not.toBeNull());
    expect(seen).toEqual(['https://a.test/snapshot']);
    expect(c.verdict({ ip: '203.0.113.66' }).block).toBe(true);   // the snapshot really parsed
  });

  it('ships an event batch when the caller hands over a bare global fetch', async () => {
    const seen: string[] = [];
    const q = new EventQueue({ url: 'https://a.test', token: 'it', fetchImpl: strictFetch(seen) });
    q.push({ p: '/' });
    await q.flush();
    expect(seen).toEqual(['https://a.test/e']);
    expect(q.dropped).toBe(0);
    q.stop();
  });

  it('never stores the bare global as the default, so the default call has no receiver either', async () => {
    const seen: string[] = [];
    const original = globalThis.fetch;
    globalThis.fetch = strictFetch(seen);
    try {
      const q = new EventQueue({ url: 'https://a.test', token: 'it' });   // no fetchImpl: the default path
      q.push({ p: '/' });
      await q.flush();
      expect(seen).toEqual(['https://a.test/e']);
      expect(q.dropped).toBe(0);
      q.stop();
    } finally {
      globalThis.fetch = original;
    }
  });

  it('resolves the default fetch at call time, not at construction', async () => {
    const seen: string[] = [];
    const original = globalThis.fetch;
    const q = new EventQueue({ url: 'https://a.test', token: 'it' });   // constructed BEFORE fetch exists here
    globalThis.fetch = strictFetch(seen);
    try {
      q.push({ p: '/' });
      await q.flush();
      expect(seen).toEqual(['https://a.test/e']);
      q.stop();
    } finally {
      globalThis.fetch = original;
    }
  });
});

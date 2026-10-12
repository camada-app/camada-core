// readBodyCapped (camada-all-4u4i): camada answers /_cam/fp and the challenge verify path before
// the app, for any client, so their size caps must bound memory. A length-less (chunked) body is
// read through a reader and cut off once the running byte count passes the cap; the source
// stream is cancelled and at most cap + one chunk is ever pulled from it.
import { describe, it, expect, afterEach, vi } from 'vitest';
import { readBodyCapped } from '../src/index.js';
import { createFetchCamada, type FetchCamada } from '../src/fetch.js';
import { TAP_BUN } from '../src/constants.js';

const CHUNK = 1024;

/** A `limit`-chunk source that records how many bytes were pulled and whether it was cancelled. */
function source(limit = 1024, fill = 0x78) {   // 1 MB by default: big enough to tell a cap from a full read, small enough that an unfixed read does not OOM the runner
  const s = { pulled: 0, cancelled: false, stream: null as unknown as ReadableStream<Uint8Array> };
  let sent = 0;
  s.stream = new ReadableStream<Uint8Array>({
    pull(ctrl) {
      if (sent++ >= limit) { ctrl.close(); return; }
      s.pulled += CHUNK;
      ctrl.enqueue(new Uint8Array(CHUNK).fill(fill));
    },
    cancel() { s.cancelled = true; },
  }, { highWaterMark: 0 });   // pull only on demand, so `pulled` is exactly what the reader asked for
  return s;
}

const streamed = (body: ReadableStream<Uint8Array>, path = '/x', headers: Record<string, string> = {}) =>
  new Request(`http://app.test${path}`, { method: 'POST', body, headers, duplex: 'half' } as RequestInit);

describe('readBodyCapped', () => {
  it('returns the text of a body within the cap', async () => {
    expect(await readBodyCapped(new Request('http://app.test/', { method: 'POST', body: '{"rid":"abc"}' }), 32)).toBe('{"rid":"abc"}');
  });

  it('returns "" for a request without a body', async () => {
    expect(await readBodyCapped(new Request('http://app.test/'), 32)).toBe('');
  });

  it('accepts a streamed body of exactly the cap', async () => {
    const s = source(4);
    expect(await readBodyCapped(streamed(s.stream), 4 * CHUNK)).toBe('x'.repeat(4 * CHUNK));
    expect(s.cancelled).toBe(false);
  });

  it('cuts off a length-less body over the cap: null, source cancelled, at most cap + one chunk pulled', async () => {
    const s = source();
    const cap = 32 * 1024;
    expect(await readBodyCapped(streamed(s.stream), cap)).toBeNull();
    expect(s.cancelled).toBe(true);
    expect(s.pulled).toBeGreaterThan(cap);
    expect(s.pulled).toBeLessThanOrEqual(cap + CHUNK);
  });

  it('rejects on a declared Content-Length over the cap without reading the body', async () => {
    const s = source();
    expect(await readBodyCapped(streamed(s.stream, '/x', { 'content-length': String(64 * 1024) }), 32 * 1024)).toBeNull();
    expect(s.pulled).toBe(0);
    expect(s.cancelled).toBe(true);
  });

  it('counts bytes, not UTF-16 units', async () => {
    const req = () => new Request('http://app.test/', { method: 'POST', body: 'ééé' });   // 3 units, 6 bytes
    expect(await readBodyCapped(req(), 5)).toBeNull();
    expect(await readBodyCapped(req(), 6)).toBe('ééé');
  });

  it('a client that aborts mid-upload (the read rejects) gives null, quietly: no throw, no log', async () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    let n = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(ctrl) { if (n++ === 0) ctrl.enqueue(new Uint8Array(8)); else ctrl.error(new TypeError('terminated')); },
    }, { highWaterMark: 0 });
    try {
      expect(await readBodyCapped(streamed(stream), 1024)).toBeNull();
      expect(log).not.toHaveBeenCalled();
    } finally { log.mockRestore(); }
  });

  it('decodes a multi-byte character split across chunks', async () => {
    const bytes = new TextEncoder().encode('aé');   // 61 c3 a9
    const body = new ReadableStream<Uint8Array>({
      start(ctrl) { ctrl.enqueue(bytes.slice(0, 2)); ctrl.enqueue(bytes.slice(2)); ctrl.close(); },
    });
    expect(await readBodyCapped(streamed(body), 16)).toBe('aé');
  });
});

// The two endpoints core answers before the app, driven through createFetchCamada with a cold
// engine (no snapshot needed: the relay serves cold, and verify answers for any resolved ip).
describe('createFetchCamada caps streamed bodies (camada-all-4u4i)', () => {
  const created: FetchCamada[] = [];
  afterEach(() => { for (const c of created.splice(0)) c.reset(); });
  const fetchImpl = (async (url: string | URL | Request) =>
    String(url).endsWith('/snapshot') ? new Response(null, { status: 503 }) : new Response(null, { status: 202 })) as typeof fetch;
  const cam = () => {
    const c = createFetchCamada({ tap: TAP_BUN, sdk: '@camada/test/0.1.0', iife: '' }, {
      env: { CAMADA_KEY: 'tok-acme.snap-acme', CAMADA_INGEST_URL: 'http://analyst.test' }, fetchImpl,
    });
    created.push(c);
    return c;
  };

  it('/_cam/fp: 413 after at most 32 KB + one chunk, source cancelled', async () => {
    const s = source();
    const r = await cam().before(streamed(s.stream, '/_cam/fp', { 'content-type': 'application/json' }), { ip: '9.9.9.9' });
    expect(r?.response?.status).toBe(413);
    expect(s.cancelled).toBe(true);
    expect(s.pulled).toBeLessThanOrEqual(32 * 1024 + CHUNK);
  });

  it('challenge verify: 413 after at most 4 KB + one chunk, source cancelled', async () => {
    const s = source();
    const r = await cam().before(streamed(s.stream, '/__camada/challenge', { 'content-type': 'application/x-www-form-urlencoded' }), { ip: '9.9.9.9' });
    expect(r?.response?.status).toBe(413);
    expect(s.cancelled).toBe(true);
    expect(s.pulled).toBeLessThanOrEqual(4 * 1024 + CHUNK);
  });

  it('challenge verify counts bytes: 2100 two-byte characters (4200 bytes) are over the 4 KB cap', async () => {
    const r = await cam().before(new Request('http://app.test/__camada/challenge', { method: 'POST', body: `nonce=${'é'.repeat(2100)}` }), { ip: '9.9.9.9' });
    expect(r?.response?.status).toBe(413);
  });

  it('/_cam/fp: a client that aborts mid-upload gets 413, and nothing is logged', async () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const stream = new ReadableStream<Uint8Array>({ pull(ctrl) { ctrl.error(new TypeError('terminated')); } }, { highWaterMark: 0 });
    try {
      const r = await cam().before(streamed(stream, '/_cam/fp'), { ip: '9.9.9.9' });
      expect(r?.response?.status).toBe(413);
      expect(log).not.toHaveBeenCalled();
    } finally { log.mockRestore(); }
  });

  it('a streamed beacon under the cap is still relayed', async () => {
    const body = new ReadableStream<Uint8Array>({ start(ctrl) { ctrl.enqueue(new TextEncoder().encode('{"rid":"abc"}')); ctrl.close(); } });
    const r = await cam().before(streamed(body, '/_cam/fp'), { ip: '9.9.9.9' });
    expect(r?.response?.status).toBe(204);
  });
});

// @camada/core/fetch against the golden v4 and v5 snapshots, driven through a minimal adapter —
// the same suite @camada/hono runs, with the host-specific parts (request.cf, the Hono context)
// replaced by FetchRequestContext and the vars the adapter keeps. What is hono-only stays in
// hono (its cf-connecting-ip rule); what is adapter-only (the per-request slot) is tested there.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { CHALLENGE_COOKIE, TAP_BUN } from '../src/index.js';
import { createFetchCamada, withSetCookie, type FetchCamada, type FetchCamadaOptions, type FetchIdentity, type FetchRequestContext, type FetchVars } from '../src/fetch.js';

const FIX = fileURLToPath(new URL('./fixtures/blk3/', import.meta.url));
const FIX5 = fileURLToPath(new URL('./fixtures/blk5/', import.meta.url));
const container = (dir: string, name: string) => ({
  bin: readFileSync(dir + name + '.bin'),
  meta: JSON.stringify(JSON.parse(readFileSync(dir + name + '.meta.json', 'utf8'))),
});
const V4 = container(FIX, 'v4-basic');
const V5 = container(FIX5, 'v5-rules');
let served = V4;

const IIFE = '/* beacon */';
const SDK = '@camada/test/0.1.0';
const BLOCKED_IP = '203.0.113.66';     // block side
const CHALLENGED_IP = '192.0.2.20';    // challenge side only
const ALLOWED_IP = '10.0.0.7';         // allow-listed inside the blocked 10.0.0.0/8
const HTML = { accept: 'text/html', 'sec-fetch-dest': 'document' };
const RULE_BLOCKED_IP = '198.51.100.7';   // builtin:block, a manual-block entry
const SKIP_PATH = '/healthz';             // cr_00000000000a, skip — beats every side
const WARN_UA = 'Scrapy/2.11 (+https://scrapy.org)';   // cr_00000000000e, warn
const BLOCKED_UA = 'curl/8.4.0';                       // cr_00000000000f, block
const BLOCKED_HEADER = 'x-api-key';                    // cr_000000000019, `header is` → block
const BLOCKED_HEADER_VALUE = 'leaked-key-1';

type Config = { tenant: string; beacon: boolean; sample: number; exclude: string[]; trusted_proxy: Record<string, unknown>; poll_seconds: number };
const BASE_CONFIG: Config = { tenant: 'acme', beacon: true, sample: 1, exclude: [], trusted_proxy: { mode: 'none' }, poll_seconds: 30 };
let CONFIG = BASE_CONFIG;
const ENV = { CAMADA_KEY: 'tok-acme.snap-acme', CAMADA_INGEST_URL: 'http://analyst.test', CAMADA_SNAPSHOT_URL: 'http://analyst.test/snapshot' };

function frame(): ArrayBuffer {
  const m = new TextEncoder().encode(served.meta);
  const f = new Uint8Array(4 + m.length + served.bin.length);
  new DataView(f.buffer).setUint32(0, m.length, true);
  f.set(m, 4); f.set(new Uint8Array(served.bin), 4 + m.length);
  return f.buffer;
}

let events: Array<Record<string, unknown>>;
let sdkHeaders: string[];
let snapshotVersions: string[];
let tenantTokens: string[];

const fetchImpl: typeof fetch = (async (url: string | URL | Request, init?: RequestInit) => {
  const u = String(url);
  if (u.endsWith('/snapshot')) {
    snapshotVersions.push(new Headers(init?.headers).get('x-camada-snapshot') ?? '');
    return new Response(frame(), { status: 200, headers: { etag: `"${JSON.parse(served.meta).version}"`, 'x-camada-config': JSON.stringify(CONFIG) } });
  }
  sdkHeaders.push(new Headers(init?.headers).get('x-camada-sdk') ?? '');
  tenantTokens.push(new Headers(init?.headers).get('x-tenant') ?? '');
  events.push(...(JSON.parse(String(init?.body)) as Array<Record<string, unknown>>));
  return new Response(null, { status: 202 });
}) as typeof fetch;

/** The smallest possible adapter: before → app → after, cookie appended, vars kept in a local. */
interface App { cam: FetchCamada; fetch(req: Request, ctx: FetchRequestContext): Promise<Response>; lastVars?: FetchVars }
const created: FetchCamada[] = [];
function app(opts: FetchCamadaOptions = {}, ids: FetchIdentity = { tap: TAP_BUN, sdk: SDK, iife: IIFE }): App {
  const cam = createFetchCamada(ids, { env: ENV, fetchImpl, ...opts });
  created.push(cam);
  const html = (s: string) => new Response(s, { headers: { 'content-type': 'text/html' } });
  const handle = async (req: Request, vars: FetchVars | undefined): Promise<Response> => {
    const { pathname } = new URL(req.url);
    if (pathname === '/') return new Response('home');
    if (pathname === '/cart') return html('<p>cart</p>');
    if (pathname === '/checkout') return html('<p>checkout</p>');
    if (pathname === '/admin/users') return html('<p>admin</p>');
    if (pathname === '/healthz') return new Response('ok');
    if (pathname === '/page') return html(`<html><head>${cam.scriptTag(vars)}</head><body>page</body></html>`);
    if (pathname === '/redirect') return Response.redirect('http://app.test/', 302);   // immutable headers
    if (pathname === '/login' && req.method === 'POST') { await cam.track(vars, 'login_failed', { user: 'alice@example.com' }); return new Response('no', { status: 401 }); }
    if (pathname === '/signup' && req.method === 'POST') { void cam.track(vars, 'signup'); return new Response('ok'); }   // fire-and-forget: waitUntil must carry it
    return new Response('not found', { status: 404 });
  };
  const a: App = {
    cam,
    async fetch(req, ctx) {
      const r = await cam.before(req, ctx);
      if (!r) return handle(req, undefined);
      if (r.response) return r.response;
      a.lastVars = r.vars;
      const res = await handle(req, r.vars);
      cam.after(req, r.vars, res.status);
      return r.vars.sessionCookie ? withSetCookie(res, r.vars.sessionCookie) : res;
    },
  };
  return a;
}

const ip = (addr: string | null, extra: FetchRequestContext = {}): FetchRequestContext => ({ ip: addr, ...extra });

/** Drives one request, recording what the pipeline hands to waitUntil and settling it. */
async function call(a: App, path: string, init: RequestInit = {}, ctx: FetchRequestContext = ip('8.8.8.8')): Promise<Response> {
  const waits: Promise<unknown>[] = [];
  const res = await a.fetch(new Request(`http://app.test${path}`, init), { ...ctx, waitUntil: (p) => { waits.push(p); } });
  await Promise.all(waits);
  return res;
}

function postSolution(a: App, addr: string, body: string): Promise<Response> {
  return call(a, '/__camada/challenge', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body }, ip(addr));
}

/** The first request is cold (fail open) and loads the snapshot. */
async function primed(opts: FetchCamadaOptions = {}): Promise<App> {
  const a = app(opts);
  await call(a, '/');
  await call(a, '/');   // second request sees the loaded snapshot
  events.length = 0;
  return a;
}
async function primedV5(opts: FetchCamadaOptions = {}): Promise<App> { served = V5; return primed(opts); }

const nonceOf = (page: string) => /name="nonce" value="([0-9a-f]{32})"/.exec(page)![1];
const solve = (nonce: string): string => {
  for (let n = 0; ; n++) if (createHash('sha256').update(`${nonce}.${n}`).digest('hex').startsWith('0000')) return String(n);
};
const ridOf = (html: string): string => /\?r=([0-9a-f-]{36})"/.exec(html)![1];
const postBeacon = (a: App, body: string, addr = '9.9.9.9', path = '/_cam/fp'): Promise<Response> =>
  call(a, path, { method: 'POST', headers: { 'content-type': 'application/json' }, body }, ip(addr));

beforeEach(() => { events = []; sdkHeaders = []; snapshotVersions = []; tenantTokens = []; served = V4; CONFIG = BASE_CONFIG; });
afterEach(() => { for (const c of created.splice(0)) c.reset(); });

describe('capture', () => {
  it('lets an unlisted request through and ships the event with the real status', async () => {
    const a = await primed();
    const res = await call(a, '/');
    expect(res.status).toBe(200);
    expect(events.some((e) => e.tap === 'sdk-bun' && e.p === '/' && e.st === 200)).toBe(true);
  });

  it('ships a 404 as the app answered it, and st null where the host cannot see the status', async () => {
    const a = await primed();
    await call(a, '/nope');
    expect(events.at(-1)).toMatchObject({ p: '/nope', st: 404 });
    const req = new Request('http://app.test/blind');
    const r = await a.cam.before(req, ip('8.8.8.8'));
    a.cam.after(req, r!.vars!, null);
    await r!.vars!.eng.queue.flush();
    expect(events.at(-1)).toMatchObject({ p: '/blind', st: null });
  });

  it('reports the identity it was given on every batch and asks for the newest snapshot', async () => {
    const a = await primed();
    await call(a, '/');
    expect(snapshotVersions[0]).toBe('5');   // §D3: this tenant only has v4, and is answered with it
    expect(sdkHeaders.length).toBeGreaterThan(0);
    expect(sdkHeaders.every((h) => h === SDK)).toBe(true);
  });

  it('pins the container when the app asks for v4', async () => {
    const a = await primed({ snapshotVersion: 4 });
    await call(a, '/');
    expect(snapshotVersions[0]).toBe('4');
  });

  it('reports the client protocol the host vouches for, never a forwarded header', async () => {
    const a = await primed();
    await call(a, '/', { headers: { 'x-forwarded-proto': 'http' } }, ip('8.8.8.8', { httpVersion: '2' }));
    expect(events.at(-1)).toMatchObject({ proto: 'HTTP/2' });
    await call(a, '/', { headers: { 'x-forwarded-proto': 'http' } });
    expect(events.at(-1)!.proto).toBeNull();
  });

  it('carries the asn, country and tls fingerprint the host hands it', async () => {
    const a = await primed();
    await call(a, '/', {}, ip('8.8.8.8', { asn: 13335, country: 'US', tlsx: 'abc123', httpVersion: '3' }));
    expect(events.at(-1)).toMatchObject({ asn: 13335, cc: 'US', tlsx: 'abc123', proto: 'HTTP/3' });
  });

  it('honours the tenant exclude list and sample rate', async () => {
    CONFIG = { ...BASE_CONFIG, exclude: ['/healthz'] };
    const a = await primed();
    await call(a, '/healthz');
    expect(events).toEqual([]);
    CONFIG = { ...BASE_CONFIG, sample: 0 };
    const b = await primed();
    await call(b, '/');
    expect(events).toEqual([]);
  });
});

describe('enforcement', () => {
  it('blocks a listed ip with 403 and blk', async () => {
    const a = await primed();
    const res = await call(a, '/', {}, ip(BLOCKED_IP));
    expect(res.status).toBe(403);
    expect(res.headers.get('x-block-reason')).toBe('ip4');
    expect(res.headers.get('x-block-version')).toBeTruthy();
    expect(events.some((e) => e.st === 403 && e.blk === 'ip4')).toBe(true);
  });

  it('honours the v4 allow side over a wider block', async () => {
    const a = await primed();
    expect((await call(a, '/', {}, ip(ALLOWED_IP))).status).toBe(200);
  });

  it('enforces an asn rule when the host supplies the asn', async () => {
    const a = await primed();
    const res = await call(a, '/', { headers: HTML }, ip('8.8.8.8', { asn: 64512 }));   // the challenge side's asn
    expect(res.status).toBe(403);
    expect(res.headers.get('x-camada-challenge')).toBe('1');
  });
});

describe('ordered custom rules (v5)', () => {
  it('lets a skip rule beat the wider block below it', async () => {
    const a = await primedV5();
    expect((await call(a, SKIP_PATH, {}, ip(BLOCKED_IP))).status).toBe(200);
    expect((await call(a, '/', {}, ip(BLOCKED_IP))).status).toBe(403);
  });

  it('lets the built-in Allow-list rule beat the wider block below it', async () => {
    const a = await primedV5();
    expect((await call(a, '/', {}, ip(ALLOWED_IP))).status).toBe(200);
    expect(events.at(-1)!.wrn).toBeUndefined();
  });

  it('blocks by rule with x-block-rule and ships blk rule + rl', async () => {
    const a = await primedV5();
    const res = await call(a, '/', {}, ip(RULE_BLOCKED_IP));
    expect(res.status).toBe(403);
    expect(res.headers.get('x-block-reason')).toBe('rule');
    expect(res.headers.get('x-block-rule')).toBe('builtin:block');
    expect(res.headers.get('x-block-version')).toBeTruthy();
    expect(events.some((e) => e.st === 403 && e.blk === 'rule' && e.rl === 'builtin:block')).toBe(true);
  });

  it('blocks by a user-agent rule — ua passes through', async () => {
    const a = await primedV5();
    const res = await call(a, '/', { headers: { 'user-agent': BLOCKED_UA } });
    expect(res.status).toBe(403);
    expect(res.headers.get('x-block-rule')).toBe('cr_00000000000f');
  });

  it('blocks by a header rule however the client spelled the name', async () => {
    const a = await primedV5();
    const res = await call(a, '/', { headers: { [BLOCKED_HEADER]: BLOCKED_HEADER_VALUE } });
    expect(res.status).toBe(403);
    expect(res.headers.get('x-block-rule')).toBe('cr_000000000019');
    expect(events.some((e) => e.st === 403 && e.blk === 'rule' && e.rl === 'cr_000000000019')).toBe(true);
    const spelled = await call(a, '/', { headers: { 'X-API-Key': BLOCKED_HEADER_VALUE } });
    expect(spelled.headers.get('x-block-rule')).toBe('cr_000000000019');
  });

  it('passes when the header the rule reads is absent', async () => {
    const a = await primedV5();
    expect((await call(a, '/')).status).toBe(200);
    const ev = events.at(-1)!;
    expect(ev.blk).toBeUndefined();
    expect(ev.rl).toBeUndefined();
  });

  it('blocks by an asn + country rule from the host facts', async () => {
    const a = await primedV5();
    const res = await call(a, '/', {}, ip('8.8.8.8', { asn: 64500, country: 'FR' }));
    expect(res.status).toBe(403);
    expect(res.headers.get('x-block-rule')).toBe('cr_000000000010');
  });

  it('serves the challenge page for a challenge rule', async () => {
    const a = await primedV5();
    const res = await call(a, '/checkout', { headers: HTML }, ip('8.8.8.8', { country: 'DE' }));
    expect(res.status).toBe(403);
    expect(res.headers.get('x-camada-challenge')).toBe('1');
    expect(events.some((e) => e.st === 403 && e.blk === 'challenge')).toBe(true);
  });

  it('passes a warn rule and stamps wrn on the event', async () => {
    const a = await primedV5();
    const res = await call(a, '/', { headers: { 'user-agent': WARN_UA } });
    expect(res.status).toBe(200);
    const ev = events.at(-1)!;
    expect(ev.wrn).toBe('cr_00000000000e');
    expect(ev.blk).toBeUndefined();
  });

  it('leaves an unmatched request alone', async () => {
    const a = await primedV5();
    expect((await call(a, '/', { headers: { 'user-agent': 'Mozilla/5.0' } })).status).toBe(200);
    const ev = events.at(-1)!;
    expect(ev.wrn).toBeUndefined();
    expect(ev.rl).toBeUndefined();
  });
});

describe('challenge', () => {
  it('serves the page, verifies the solution, and lets the cookie holder through', async () => {
    const a = await primed();
    const page = await call(a, '/cart', { headers: HTML }, ip(CHALLENGED_IP));
    expect(page.status).toBe(403);
    expect(page.headers.get('cache-control')).toBe('no-store');
    const nonce = nonceOf(await page.text());
    expect(events.some((e) => e.st === 403 && e.blk === 'challenge')).toBe(true);

    const ok = await postSolution(a, CHALLENGED_IP, `nonce=${nonce}&solution=${solve(nonce)}&to=%2Fcart`);
    expect(ok.status).toBe(302);
    expect(ok.headers.get('location')).toBe('/cart');
    expect(ok.headers.get('set-cookie')).toContain(`${CHALLENGE_COOKIE}=`);
    expect(events.some((e) => e.st === 200 && e.ch === 1)).toBe(true);

    const cookie = ok.headers.get('set-cookie')!.split(';')[0];
    const after = await call(a, '/cart', { headers: { cookie, ...HTML } }, ip(CHALLENGED_IP));
    expect(after.status).toBe(200);
  });

  it('challenges on a path rule, not just an ip', async () => {
    const a = await primed();
    const res = await call(a, '/admin/users', { headers: HTML });
    expect(res.status).toBe(403);
    expect(res.headers.get('x-camada-challenge')).toBe('1');
  });

  it('answers 403 JSON for a non-HTML challenge', async () => {
    const a = await primed();
    const res = await call(a, '/checkout', { headers: { accept: 'application/json' } });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: 'challenge_required' });
  });

  it('refuses an oversized verify body instead of buffering it', async () => {
    const a = await primed();
    expect((await postSolution(a, CHALLENGED_IP, `nonce=x&solution=1&to=%2F&pad=${'a'.repeat(5000)}`)).status).toBe(413);
  });

  it('rejects a forged nonce and sets no cookie', async () => {
    const a = await primed();
    const forged = 'a'.repeat(32);
    const res = await postSolution(a, CHALLENGED_IP, `nonce=${forged}&solution=${solve(forged)}&to=%2Fcart`);
    expect(res.status).toBe(403);
    expect(res.headers.get('set-cookie')).toBeNull();
  });

  it('never redirects off-site', async () => {
    const a = await primed();
    const page = await call(a, '/cart', { headers: HTML }, ip(CHALLENGED_IP));
    const nonce = nonceOf(await page.text());
    const res = await postSolution(a, CHALLENGED_IP, `nonce=${nonce}&solution=${solve(nonce)}&to=${encodeURIComponent('https://evil.test')}`);
    expect(res.headers.get('location')).toBe('/');
  });

  it('still blocks a blocked ip at the verify endpoint', async () => {
    const a = await primed();
    const res = await postSolution(a, BLOCKED_IP, 'nonce=x&solution=1&to=%2F');
    expect(res.status).toBe(403);
    expect(res.headers.get('x-block-reason')).toBe('ip4');
  });

  it('posts to a custom challengePath', async () => {
    const a = await primed({ challengePath: '/verify-me' });
    const page = await call(a, '/cart', { headers: HTML }, ip(CHALLENGED_IP));
    expect(await page.text()).toContain('action="/verify-me"');
  });

  it('does nothing when challenge: false, or CAMADA_CHALLENGE=0', async () => {
    const a = await primed({ challenge: false });
    expect((await call(a, '/cart', { headers: HTML }, ip(CHALLENGED_IP))).status).toBe(200);
    const b = await primed({ env: { ...ENV, CAMADA_CHALLENGE: '0' } });
    expect((await call(b, '/cart', { headers: HTML }, ip(CHALLENGED_IP))).status).toBe(200);
  });
});

describe('resolving the client address', () => {
  it('uses the vouched peer and ignores X-Forwarded-For without a trusted proxy', async () => {
    const a = await primed();
    const res = await call(a, '/', { headers: { 'x-forwarded-for': BLOCKED_IP } }, { peer: '8.8.8.8' });
    expect(res.status).toBe(200);
    expect(events.at(-1)).toMatchObject({ ip: '8.8.8.8' });
    expect((await call(a, '/', {}, { peer: BLOCKED_IP })).status).toBe(403);
  });

  it('honours a trusted-proxy X-Forwarded-For behind the peer', async () => {
    const a = app({ env: { ...ENV, CAMADA_TRUSTED_PROXY: 'hops:1' } });
    await call(a, '/', {}, { peer: '10.1.1.1' });
    await call(a, '/', {}, { peer: '10.1.1.1' });
    const res = await call(a, '/', { headers: { 'x-forwarded-for': BLOCKED_IP } }, { peer: '10.1.1.1' });
    expect(res.status).toBe(403);
  });

  it('takes the server-delivered trusted_proxy when the app set none', async () => {
    CONFIG = { ...BASE_CONFIG, trusted_proxy: { mode: 'hops', hops: 1 } };
    const a = await primed();
    expect((await call(a, '/', { headers: { 'x-forwarded-for': BLOCKED_IP } }, { peer: '10.1.1.1' })).status).toBe(403);
  });

  it('lets a pre-resolved ip win over the peer and the header', async () => {
    const a = await primed();
    const res = await call(a, '/', { headers: { 'x-forwarded-for': '1.1.1.1' } }, { ip: BLOCKED_IP, peer: '8.8.8.8' });
    expect(res.status).toBe(403);
  });

  it('resolves to null with nothing vouched for — no ip rules, no challenge, still captured', async () => {
    const a = await primed();
    const res = await call(a, '/admin/users', { headers: { 'x-forwarded-for': BLOCKED_IP, ...HTML } }, {});
    expect(res.status).toBe(200);
    expect(events.at(-1)).toMatchObject({ p: '/admin/users', ip: null });
  });
});

describe('per-configuration engines', () => {
  it('never lends one tenant\'s snapshot or ingest token to another mount', async () => {
    const a = app();
    const b = app({ env: { ...ENV, CAMADA_KEY: 'tok-other.snap-other' } });
    await call(a, '/'); await call(b, '/'); await call(a, '/'); await call(b, '/');
    expect(tenantTokens).toContain('tok-acme');
    expect(tenantTokens).toContain('tok-other');
  });

  it('keys the engine on the host env when the options carry none', async () => {
    const a = app({ env: undefined });
    await call(a, '/', {}, { ip: '8.8.8.8', env: ENV });
    await call(a, '/', {}, { ip: '8.8.8.8', env: ENV });
    expect((await call(a, '/', {}, { ip: BLOCKED_IP, env: ENV })).status).toBe(403);
  });

  it('does not go permanently inert after one unconfigured request', async () => {
    const a = app({ env: undefined });
    await call(a, '/', {}, { ip: BLOCKED_IP, env: {} });   // no key: inert
    await call(a, '/', {}, { ip: '8.8.8.8', env: ENV });   // keyed now: must wake up
    await call(a, '/', {}, { ip: '8.8.8.8', env: ENV });
    expect((await call(a, '/', {}, { ip: BLOCKED_IP, env: ENV })).status).toBe(403);
  });
});

describe('session', () => {
  it('hands the adapter the shared _sfp cookie so sid and ns are real at this tap', async () => {
    const a = await primed();
    const res = await call(a, '/');
    expect(res.headers.get('set-cookie')).toContain('_sfp=');
    expect(res.headers.get('set-cookie')).toContain('HttpOnly');
    expect(res.headers.get('set-cookie')).not.toContain('Secure');
    expect(events.at(-1)).toMatchObject({ ns: 1, sid: a.lastVars!.sid });
  });

  it('marks the cookie Secure on https', async () => {
    const a = await primed();
    const r = await a.cam.before(new Request('https://app.test/'), ip('8.8.8.8'));
    expect(r!.vars!.sessionCookie).toContain('; Secure');
  });

  it('never overwrites an existing session', async () => {
    const a = await primed();
    const res = await call(a, '/', { headers: { cookie: '_sfp=known-sid' } });
    expect(res.headers.get('set-cookie')).toBeNull();
    expect(events.at(-1)).toMatchObject({ sid: 'known-sid', ns: 0 });
  });

  it('withSetCookie rebuilds a response whose headers are immutable', async () => {
    const a = await primed();
    const res = await call(a, '/redirect');
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('http://app.test/');
    expect(res.headers.get('set-cookie')).toContain('_sfp=');
    const plain = withSetCookie(new Response('body', { status: 201, headers: { 'x-a': '1' } }), '_sfp=x');
    expect(plain.status).toBe(201);
    expect(plain.headers.get('x-a')).toBe('1');
    expect(await plain.text()).toBe('body');
  });
});

describe('first-party beacon', () => {
  it('serves the injected IIFE at /_cam/b.js and ships nothing for it', async () => {
    const a = await primed();
    const res = await call(a, '/_cam/b.js?r=abc');
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('javascript');
    expect(res.headers.get('cache-control')).toBe('public, max-age=3600');
    expect(await res.text()).toBe(IIFE);
    expect(events).toEqual([]);
  });

  it('relays /_cam/fp as a sig:1 row with the server-resolved ip and tap', async () => {
    const a = await primed();
    const res = await postBeacon(a, JSON.stringify({ rid: 'abc', tz: 'UTC', ip: '1.1.1.1', tap: 'proxy' }));
    expect(res.status).toBe(204);
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ sig: 1, rid: 'abc', tz: 'UTC', ip: '9.9.9.9', tap: 'sdk-bun' });
    expect(events[0].st).toBeUndefined();
  });

  it('joins the beacon to the page event on rid', async () => {
    const a = await primed();
    const html = await (await call(a, '/page')).text();
    const rid = ridOf(html);
    expect(events.find((e) => e.p === '/page')).toMatchObject({ rid, tap: 'sdk-bun' });
    await postBeacon(a, JSON.stringify({ rid, tz: 'UTC' }), '8.8.8.8');
    expect(events.find((e) => e.sig === 1)).toMatchObject({ rid, ip: '8.8.8.8' });
  });

  it('drops a body that is not a beacon', async () => {
    const a = await primed();
    expect((await postBeacon(a, 'not-json')).status).toBe(204);
    expect((await postBeacon(a, '[1,2]')).status).toBe(204);
    expect(events).toEqual([]);
  });

  it('rejects an oversized beacon, declared or actual', async () => {
    const a = await primed();
    expect((await postBeacon(a, 'x'.repeat(80 * 1024))).status).toBe(413);
    const declared = await call(a, '/_cam/fp', { method: 'POST', headers: { 'content-type': 'application/json', 'content-length': String(64 * 1024) }, body: '{"rid":"abc"}' }, ip('9.9.9.9'));
    expect(declared.status).toBe(413);
    expect(events).toEqual([]);
  });

  it('still blocks a blocked client at both endpoints', async () => {
    const a = await primed();
    const script = await call(a, '/_cam/b.js', {}, ip(BLOCKED_IP));
    expect(script.status).toBe(403);
    expect(script.headers.get('x-block-reason')).toBe('ip4');
    expect((await postBeacon(a, JSON.stringify({ rid: 'abc' }), BLOCKED_IP)).status).toBe(403);
    expect(events).toHaveLength(2);
    expect(events.every((e) => e.blk === 'ip4' && e.sig === undefined)).toBe(true);
  });

  it('falls through to the app when the tenant disabled the beacon', async () => {
    CONFIG = { ...BASE_CONFIG, beacon: false };
    const a = await primed();
    expect((await call(a, '/_cam/b.js')).status).toBe(404);
    expect((await postBeacon(a, JSON.stringify({ rid: 'abc' }))).status).toBe(404);
    expect(events.some((e) => e.sig === 1)).toBe(false);
    const html = await (await call(a, '/page')).text();
    expect(html).not.toContain('<script');
  });

  it('honours scriptPath and fpPath', async () => {
    const a = await primed({ scriptPath: '/api/cam/b.js', fpPath: '/api/cam/fp' });
    const html = await (await call(a, '/page')).text();
    expect(html).toContain('<script src="/api/cam/b.js?r=');
    expect((await call(a, '/api/cam/b.js')).status).toBe(200);
    expect((await call(a, '/_cam/b.js')).status).toBe(404);
    events.length = 0;
    expect((await postBeacon(a, JSON.stringify({ rid: 'abc' }), '9.9.9.9', '/api/cam/fp')).status).toBe(204);
    expect(events[0]).toMatchObject({ sig: 1, rid: 'abc' });
  });

  it('emits no tag without vars', async () => {
    const a = app();
    expect(a.cam.scriptTag(undefined)).toBe('');
  });
});

describe('track', () => {
  it('ships an app-context event joined to the request, with the user hashed', async () => {
    const a = await primed();
    const res = await call(a, '/login', { method: 'POST', headers: { cookie: '_sfp=known-sid' } });
    expect(res.status).toBe(401);
    const row = events.find((e) => e.et === 'login_failed')!;
    expect(row).toMatchObject({ tap: 'sdk-bun', sid: 'known-sid', ip: '8.8.8.8' });
    expect(row.uid).toMatch(/^[0-9a-f]{32}$/);
    expect(typeof row.ts).toBe('number');
    expect(row.p).toBeUndefined();
    expect(row.st).toBeUndefined();
    expect(row.rid).toBe(events.find((e) => e.p === '/login')!.rid);
    expect(JSON.stringify(events)).not.toContain('alice');
  });

  it('uses the session it just minted on a first visit', async () => {
    const a = await primed();
    const res = await call(a, '/login', { method: 'POST' });
    const sid = /_sfp=([^;]+)/.exec(res.headers.get('set-cookie') ?? '')![1];
    expect(events.find((e) => e.et === 'login_failed')).toMatchObject({ sid });
    expect(events.find((e) => e.p === '/login')).toMatchObject({ sid, ns: 1 });
  });

  it('carries a fire-and-forget call through waitUntil, uid null without a user', async () => {
    const a = await primed();
    expect((await call(a, '/signup', { method: 'POST' })).status).toBe(200);
    expect(events.find((e) => e.et === 'signup')).toMatchObject({ uid: null, tap: 'sdk-bun' });
  });

  it('is a silent no-op without vars', async () => {
    const a = app();
    await expect(a.cam.track(undefined, 'login_failed', { user: 'x' })).resolves.toBeUndefined();
    expect(events).toEqual([]);
  });

  it('never throws while ingest is down', async () => {
    const dead: typeof fetch = (async () => { throw new Error('ECONNREFUSED'); }) as typeof fetch;
    const a = app({ fetchImpl: dead });
    expect((await call(a, '/login', { method: 'POST' })).status).toBe(401);
  });
});

describe('fail open', () => {
  it('is inert without a key and never touches the app', async () => {
    const a = app({ env: {} });
    expect((await call(a, '/', {}, ip(BLOCKED_IP))).status).toBe(200);
    expect(await a.cam.before(new Request('http://app.test/'), ip(BLOCKED_IP))).toBeNull();
    expect(events).toEqual([]);
  });

  it('respects CAMADA_DISABLED=1', async () => {
    const a = app({ env: { ...ENV, CAMADA_DISABLED: '1' } });
    expect((await call(a, '/', {}, ip(BLOCKED_IP))).status).toBe(200);
    expect(await a.cam.before(new Request('http://app.test/'), ip(BLOCKED_IP))).toBeNull();
  });

  it('lets traffic through while the snapshot server is down', async () => {
    const dead: typeof fetch = (async () => { throw new Error('ECONNREFUSED'); }) as typeof fetch;
    const a = app({ fetchImpl: dead });
    expect((await call(a, '/', {}, ip(BLOCKED_IP))).status).toBe(200);
  });

  it('serves no challenge to a client it cannot identify', async () => {
    const a = await primed();
    expect((await call(a, '/admin/users', { headers: HTML }, {})).status).toBe(200);
  });

  it('goes inert, not down, when reading the host env throws', async () => {
    const a = await primed();
    const ctx: FetchRequestContext = { ip: BLOCKED_IP, get env(): Record<string, string> { throw new Error('binding'); } };
    const res = await a.fetch(new Request('http://app.test/'), ctx);
    expect(res.status).toBe(200);   // a Workers binding that throws on read costs enforcement, never the response
    expect(events).toEqual([]);
  });

  it('still lets the app run and ships its event when the pipeline itself throws', async () => {
    const a = await primed();
    await call(a, '/');
    const eng = a.lastVars!.eng;
    const verdict = eng.snap.verdict;
    eng.snap.verdict = () => { throw new Error('boom'); };
    try {
      const res = await call(a, '/', {}, ip(BLOCKED_IP));
      expect(res.status).toBe(200);
      expect(res.headers.get('set-cookie')).toBeNull();   // no session decided: nothing minted
      expect(events.at(-1)).toMatchObject({ p: '/', st: 200, sid: null, ns: 0 });
    } finally { eng.snap.verdict = verdict; }
  });
});

describe('timer mode', () => {
  it('polls the snapshot on its own once started, and stops on reset', async () => {
    vi.useFakeTimers();
    try {
      const a = app({ mode: 'timer' });
      await call(a, '/');
      const polls = snapshotVersions.length;
      expect(polls).toBe(1);
      await vi.advanceTimersByTimeAsync(31_000);
      expect(snapshotVersions.length).toBe(polls + 1);
      a.cam.reset();
      await vi.advanceTimersByTimeAsync(60_000);
      expect(snapshotVersions.length).toBe(polls + 1);
    } finally { vi.useRealTimers(); }
  });

  it('is forced back to lazy by CAMADA_SERVERLESS=1', async () => {
    vi.useFakeTimers();
    try {
      const a = app({ mode: 'timer', env: { ...ENV, CAMADA_SERVERLESS: '1' } });
      await call(a, '/');
      await vi.advanceTimersByTimeAsync(31_000);
      expect(snapshotVersions.length).toBe(1);
    } finally { vi.useRealTimers(); }
  });
});

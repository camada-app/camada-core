import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { scrubQuery, scrubUrl, bodyShape, hashUserId, buildWireEvent } from '../src/index.js';

// Shared conformance fixture (contract C6): every server SDK runs the same cases.
interface RefCase { id: string; referer: string | null; ref: string | null; absent?: string[] }
const refFx = JSON.parse(readFileSync(new URL('./fixtures/redact/referer.json', import.meta.url), 'utf8')) as { cases: RefCase[] };

describe('Referer redaction conformance (fixtures/redact/referer.json)', () => {
  it.each(refFx.cases.map((c) => [c.id, c] as const))('%s', (_label, c) => {
    const ev = buildWireEvent({
      method: 'GET', host: 'shop.test', path: '/api/me', query: '',
      headers: [['User-Agent', 'ua'], ...(c.referer === null ? [] : [['Referer', c.referer] as [string, string]])],
      ip: '9.9.9.9',
    }, { tap: 'sdk-node', rid: 'r1' });
    expect(ev.ref).toBe(c.ref);
    const wire = JSON.stringify(ev);
    for (const s of c.absent ?? []) expect(wire).not.toContain(s);
  });
});

describe('scrubQuery', () => {
  it('redacts credential-named params and credential-looking values, preserving structure', () => {
    expect(scrubQuery('?a=1&token=xyz&b=2')).toBe('?a=1&token=~r&b=2');
    expect(scrubQuery('?password=hunter2')).toBe('?password=~r');
    expect(scrubQuery('?api_key=abc&apikey=def')).toBe('?api_key=~r&apikey=~r');
    expect(scrubQuery('?q=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig')).toBe('?q=~r');   // JWT-shaped value
    expect(scrubQuery('?id=' + 'a1'.repeat(20))).toBe('?id=~r');                       // long hex value
    expect(scrubQuery('?page=2&sort=name')).toBe('?page=2&sort=name');
    expect(scrubQuery('')).toBe('');
    expect(scrubQuery(null)).toBe('');
  });
});

describe('scrubQuery on the request query q (same rules as the Referer, C6 v2)', () => {
  const q = (query: string) => buildWireEvent({ method: 'GET', host: 'shop.test', path: '/cb', query, headers: [], ip: '9.9.9.9' }, { tap: 'sdk-node', rid: 'r1' }).q;
  it('scrubs bare credential parts, nested queries and encoded names in q', () => {
    expect(q('?eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig&page=2')).toBe('?~r&page=2');
    expect(q('?next=/reset?token=abc123')).toBe('?next=~r');
    expect(q('?redirect_uri=https%3A%2F%2Fb.test%2Fcb%3Fcode%3Dsecret99&state=xyz')).toBe('?redirect_uri=~r&state=xyz');
    expect(q('?%74oken=abc123')).toBe('?%74oken=~r');
    expect(q('?page=2&sort=name')).toBe('?page=2&sort=name');
  });

  it('bounds decoding: a deeply re-encoded value costs linear time and is scrubbed', () => {
    const deep = '?x=%' + '25'.repeat(8000) + '41';
    const t = performance.now();
    expect(scrubQuery(deep)).toBe('?x=~r');
    expect(performance.now() - t).toBeLessThan(200);
  });
});

describe('scrubUrl', () => {
  it('scrubs query and fragment, keeps the rest, passes null through', () => {
    expect(scrubUrl('https://a.test/x?token=t1&page=2#code=c1')).toBe('https://a.test/x?token=~r&page=2#code=~r');
    expect(scrubUrl('https://a.test/x')).toBe('https://a.test/x');
    expect(scrubUrl(null)).toBeNull();
    expect(scrubUrl(undefined)).toBeNull();
  });
});

describe('bodyShape', () => {
  it('keeps names and sizes, never values', () => {
    const shape = bodyShape({ user: 'alice@example.com', password: 'hunter2', n: 42 });
    expect(shape).toEqual({ user: 17, password: 7, n: 2 });
    expect(JSON.stringify(shape)).not.toContain('alice');
    expect(bodyShape('a string')).toBeNull();
    expect(bodyShape([1, 2])).toBeNull();
  });
});

describe('hashUserId', () => {
  it('is deterministic per tenant and never contains the identifier', async () => {
    const a = await hashUserId('alice@example.com', 'tok-1');
    expect(a).toBe(await hashUserId('alice@example.com', 'tok-1'));
    expect(a).not.toBe(await hashUserId('alice@example.com', 'tok-2'));
    expect(a).not.toBe(await hashUserId('bob@example.com', 'tok-1'));
    expect(a).toMatch(/^[0-9a-f]{32}$/);
    expect(a).not.toContain('alice');
  });
});

describe('the never-leaks property', () => {
  it('a schemeless Authorization header ships nothing at all', () => {
    const rawToken = 'eyJhbGciOiJIUzI1NiJ9.raw.credential-no-scheme';
    const ev = buildWireEvent({
      method: 'GET', host: 'x.test', path: '/', query: '',
      headers: [['Authorization', rawToken], ['authorization', 'Basic dXNlcjpwYXNz'], ['User-Agent', 'ua']],
      ip: '9.9.9.9',
    }, { tap: 'sdk-node', rid: 'r1' });
    expect(JSON.stringify(ev)).not.toContain(rawToken.slice(0, 16));   // no prefix either
    expect(ev.auth).toBeNull();   // first header wins and it has no scheme
  });

  it('a serialized event built from hostile inputs contains no credential material', () => {
    const secrets = ['eyJhbGciOiJIUzI1NiJ9.super.secretjwt', 'session=deadbeefcafe1234', 'hunter2-password', 'sk_live_abcdef123456'];
    const ev = buildWireEvent({
      method: 'POST', host: 'x.test', path: '/login',
      query: `?redirect=/home&token=${secrets[3]}&password=hunter2-password`,
      headers: [
        ['Authorization', `Bearer ${secrets[0]}`],
        ['Cookie', secrets[1]],
        ['User-Agent', 'Mozilla/5.0'],
        ['Content-Type', 'application/x-www-form-urlencoded'],
      ],
      ip: '9.9.9.9',
    }, { tap: 'sdk-node', rid: 'r1' });
    const wire = JSON.stringify(ev);
    for (const s of secrets) expect(wire).not.toContain(s);
    expect(ev.auth).toBe('Bearer');         // scheme survives
    expect(ev.ck).toBe(1);                  // cookie count survives, value does not
    expect(String(ev.q)).toContain('redirect=/home');   // benign params survive
  });
});

import { describe, it, expect } from 'vitest';
import { scrubQuery, bodyShape, hashUserId, buildWireEvent } from '../src/index.js';

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

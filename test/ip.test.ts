import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolveClientIp, parseTrustedProxyEnv, type TrustedProxyConfig } from '../src/index.js';

// Shared conformance fixture (contract C6): every server SDK runs the same cases.
interface IpCase { id: string; ticket: string; config: string; peer: string | null; xff: string | null; expect: string | null; note?: string }
const ipFx = JSON.parse(readFileSync(new URL('./fixtures/ip/resolve.json', import.meta.url), 'utf8')) as
  { configs: Record<string, TrustedProxyConfig | null>; cases: IpCase[] };

describe('resolveClientIp conformance (fixtures/ip/resolve.json)', () => {
  it.each(ipFx.cases.map((c) => [`${c.ticket} ${c.id}`, c] as const))('%s', (_label, c) => {
    expect(c.config in ipFx.configs).toBe(true);
    expect(resolveClientIp(c.peer, c.xff, ipFx.configs[c.config])).toBe(c.expect);
  });
});

const SOCK = '172.18.0.5';

describe('resolveClientIp', () => {
  it('ignores XFF entirely without trusted-proxy config (spoof rejection)', () => {
    expect(resolveClientIp(SOCK, '203.0.113.66, 1.2.3.4')).toBe(SOCK);
    expect(resolveClientIp(SOCK, '203.0.113.66', { mode: 'none' })).toBe(SOCK);
  });

  it('strips the Node v4-mapped prefix from the socket address', () => {
    expect(resolveClientIp('::ffff:203.0.113.9', null)).toBe('203.0.113.9');
  });

  it('takes the Nth-from-the-right entry in hops mode', () => {
    expect(resolveClientIp(SOCK, '9.9.9.9, 8.8.8.8, 173.245.48.1', { mode: 'hops', hops: 1 })).toBe('173.245.48.1');
    expect(resolveClientIp(SOCK, '9.9.9.9, 8.8.8.8, 173.245.48.1', { mode: 'hops', hops: 2 })).toBe('8.8.8.8');
    // fewer entries than hops: fail safe to the socket
    expect(resolveClientIp(SOCK, '9.9.9.9', { mode: 'hops', hops: 3 })).toBe(SOCK);
  });

  it('walks past trusted CIDRs from the right in cidrs mode', () => {
    const cfg = { mode: 'cidrs' as const, cidrs: ['173.245.48.0/20', '2400:cb00::/32'] };
    const EDGE = '173.245.48.5';   // the peer must itself be trusted for XFF to count (camada-all-yfc6)
    expect(resolveClientIp(EDGE, '203.0.113.66, 173.245.48.10, 173.245.48.99', cfg)).toBe('203.0.113.66');
    expect(resolveClientIp(EDGE, '203.0.113.66, 2400:cb00::1234', cfg)).toBe('203.0.113.66');
    // a forged left entry behind an untrusted hop never wins: the rightmost untrusted entry does
    expect(resolveClientIp(EDGE, '1.2.3.4, 9.9.9.9, 173.245.48.10', cfg)).toBe('9.9.9.9');
    // everything trusted: fail safe to the socket
    expect(resolveClientIp(EDGE, '173.245.48.10, 173.245.48.11', cfg)).toBe(EDGE);
  });

  it('ignores XFF in cidrs mode when the peer is not a trusted proxy (direct hit on the origin)', () => {
    const cfg = { mode: 'cidrs' as const, cidrs: ['173.245.48.0/20'] };
    expect(resolveClientIp(SOCK, '203.0.113.66', cfg)).toBe(SOCK);
    expect(resolveClientIp(SOCK, '8.8.8.8, 173.245.48.10', cfg)).toBe(SOCK);
  });

  it('takes the rightmost entry in vercel mode', () => {
    expect(resolveClientIp(SOCK, '203.0.113.66', { mode: 'vercel' })).toBe('203.0.113.66');
    expect(resolveClientIp(SOCK, 'spoofed, 203.0.113.66', { mode: 'vercel' })).toBe('203.0.113.66');
  });

  it('falls back to the socket when the candidate is not an IP', () => {
    expect(resolveClientIp(SOCK, 'not-an-ip', { mode: 'hops', hops: 1 })).toBe(SOCK);
    expect(resolveClientIp(SOCK, '', { mode: 'hops', hops: 1 })).toBe(SOCK);
    expect(resolveClientIp(null, '1.2.3.4')).toBeNull();
  });
});

describe('parseTrustedProxyEnv', () => {
  it('parses the four documented forms', () => {
    expect(parseTrustedProxyEnv('none')).toEqual({ mode: 'none' });
    expect(parseTrustedProxyEnv('vercel')).toEqual({ mode: 'vercel' });
    expect(parseTrustedProxyEnv('hops:2')).toEqual({ mode: 'hops', hops: 2 });
    expect(parseTrustedProxyEnv('cidrs:173.245.48.0/20, 2400:cb00::/32')).toEqual({ mode: 'cidrs', cidrs: ['173.245.48.0/20', '2400:cb00::/32'] });
  });

  it('returns null (defer to server config) on unset input', () => {
    expect(parseTrustedProxyEnv(undefined)).toBeNull();
    expect(parseTrustedProxyEnv(null)).toBeNull();
    expect(parseTrustedProxyEnv('')).toBeNull();
  });

  it('returns null on malformed input rather than granting trust', () => {
    expect(parseTrustedProxyEnv('hops:0')).toBeNull();
    expect(parseTrustedProxyEnv('hops:abc')).toBeNull();
    expect(parseTrustedProxyEnv('hops:1.5')).toBeNull();
    expect(parseTrustedProxyEnv('cidrs:')).toBeNull();
    expect(parseTrustedProxyEnv('cidrs: ,')).toBeNull();
    expect(parseTrustedProxyEnv('junk')).toBeNull();
  });
});

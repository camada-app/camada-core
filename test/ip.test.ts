import { describe, it, expect } from 'vitest';
import { resolveClientIp } from '../src/index.js';

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
    expect(resolveClientIp(SOCK, '203.0.113.66, 173.245.48.10, 173.245.48.99', cfg)).toBe('203.0.113.66');
    expect(resolveClientIp(SOCK, '203.0.113.66, 2400:cb00::1234', cfg)).toBe('203.0.113.66');
    // a forged left entry behind an untrusted hop never wins: the rightmost untrusted entry does
    expect(resolveClientIp(SOCK, '1.2.3.4, 9.9.9.9, 173.245.48.10', cfg)).toBe('9.9.9.9');
    // everything trusted: fail safe to the socket
    expect(resolveClientIp(SOCK, '173.245.48.10, 173.245.48.11', cfg)).toBe(SOCK);
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

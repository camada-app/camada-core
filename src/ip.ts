// Client-IP resolution under the tenant's trusted-proxy config (plan.md prerequisite 3).
// The default is the socket peer — raw X-Forwarded-For is attacker-writable and is NEVER
// trusted without explicit configuration; a spoofed XFF must not reach the analysis or the
// blocklist. Modes mirror the server-validated config (edge-analyst src/tenant-config.js).

import { parseIp4, parseIp6Into } from './snapshot/ipparse.js';

export type TrustedProxyConfig =
  | { mode: 'none' }
  | { mode: 'hops'; hops: number }
  | { mode: 'cidrs'; cidrs: string[] }
  | { mode: 'vercel' };   // Vercel overwrites XFF, so its rightmost entry is trustworthy

/** Parses the CAMADA_TRUSTED_PROXY env string: none | vercel | hops:N | cidrs:a,b.
 *  Unset or malformed input returns null — callers treat that as "defer to the
 *  server-delivered tenant config", never as an implicit trust grant. */
export function parseTrustedProxyEnv(v: string | null | undefined): TrustedProxyConfig | null {
  if (!v) return null;
  if (v === 'none') return { mode: 'none' };
  if (v === 'vercel') return { mode: 'vercel' };
  if (v.startsWith('hops:')) { const hops = Number(v.slice(5)); return Number.isInteger(hops) && hops >= 1 ? { mode: 'hops', hops } : null; }
  if (v.startsWith('cidrs:')) { const cidrs = v.slice(6).split(',').map((s) => s.trim()).filter(Boolean); return cidrs.length ? { mode: 'cidrs', cidrs } : null; }
  return null;
}

// Reusable scratch for parseIp6Into (whose params these mirror): parsing an address is
// synchronous and never interleaves, so one shared pair avoids per-check allocation.
const W = new Uint32Array(4), G = new Uint16Array(8);
const validIp = (s: string) => (s.indexOf(':') === -1 ? parseIp4(s) >= 0 : parseIp6Into(s, W, G));

interface Cidr4 { v: 4; base: number; bits: number }
interface Cidr6 { v: 6; base: Uint32Array; bits: number }

function parseCidr(c: string): Cidr4 | Cidr6 | null {
  const slash = c.indexOf('/');
  if (slash === -1) return null;
  const addr = c.slice(0, slash), bits = Number(c.slice(slash + 1));
  if (addr.indexOf(':') === -1) {
    const base = parseIp4(addr);
    return base >= 0 && bits >= 0 && bits <= 32 ? { v: 4, base, bits } : null;
  }
  const w = new Uint32Array(4);
  return parseIp6Into(addr, w, new Uint16Array(8)) && bits >= 0 && bits <= 128 ? { v: 6, base: w, bits } : null;
}

function inCidr(ip: string, cidr: Cidr4 | Cidr6): boolean {
  if (cidr.v === 4) {
    const n = parseIp4(ip);
    if (n < 0) return false;
    const mask = cidr.bits === 0 ? 0 : (~0 << (32 - cidr.bits)) >>> 0;
    return ((n & mask) >>> 0) === ((cidr.base & mask) >>> 0);
  }
  if (!parseIp6Into(ip, W, G)) return false;
  let remaining = cidr.bits;
  for (let k = 0; k < 4 && remaining > 0; k++) {
    const take = Math.min(32, remaining);
    const mask = take === 32 ? 0xffffffff : (~0 << (32 - take)) >>> 0;
    if (((W[k] & mask) >>> 0) !== ((cidr.base[k] & mask) >>> 0)) return false;
    remaining -= take;
  }
  return true;
}

/**
 * Resolves the client IP from the socket peer address and the X-Forwarded-For header per the
 * trusted-proxy config. Anything unresolvable falls back to the socket peer — fail safe.
 */
export function resolveClientIp(socketAddr: string | null | undefined, xff: string | null | undefined, cfg?: TrustedProxyConfig | null): string | null {
  const sock = socketAddr ? socketAddr.replace(/^::ffff:/, '') : null;   // Node dual-stack v4-mapped form
  if (!cfg || cfg.mode === 'none' || !xff) return sock;
  const entries = xff.split(',').map((s) => s.trim()).filter(Boolean);
  if (!entries.length) return sock;

  // An out-of-range index yields undefined, which falls back to the socket below.
  let candidate: string | undefined;
  switch (cfg.mode) {
    case 'hops':
      candidate = entries[entries.length - cfg.hops];
      break;
    case 'vercel':
      candidate = entries[entries.length - 1];
      break;
    case 'cidrs': {
      const trusted = cfg.cidrs.map(parseCidr).filter((c): c is Cidr4 | Cidr6 => c !== null);
      for (let i = entries.length - 1; i >= 0; i--) {
        if (!trusted.some((t) => inCidr(entries[i], t))) { candidate = entries[i]; break; }
      }
      break;
    }
  }
  return candidate && validIp(candidate) ? candidate : sock;
}

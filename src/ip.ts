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

const PORT_RE = /^:\d{1,5}$/;
/** One X-Forwarded-For entry with any port removed (camada-all-0vho): `[v6]:port` and `[v6]` → `v6`,
 *  `a.b.c.d:port` → `a.b.c.d`. A bare IPv6 literal is returned whole (its last group is never a port).
 *  Anything else malformed comes back unchanged, so validation still rejects it and the peer wins. */
function stripPort(e: string): string {
  if (e.charCodeAt(0) === 91 /* [ */) {
    const close = e.indexOf(']');
    if (close === -1) return e;
    const inner = e.slice(1, close), rest = e.slice(close + 1);
    return inner.indexOf(':') !== -1 && (rest === '' || PORT_RE.test(rest)) ? inner : e;
  }
  const colon = e.indexOf(':');
  if (colon === -1 || e.indexOf(':', colon + 1) !== -1) return e;   // no colon, or a bare IPv6 literal
  const host = e.slice(0, colon);
  return parseIp4(host) >= 0 && PORT_RE.test(e.slice(colon)) ? host : e;
}

/** 127.0.0.0/8 or ::1 (camada-all-yfc6, decision D1). The peer's `::ffff:127.x.x.x` form is already
 *  reduced to the dotted quad by resolveClientIp. */
function isLoopback(ip: string): boolean {
  if (ip.indexOf(':') === -1) { const n = parseIp4(ip); return n >= 0 && n >>> 24 === 127; }
  return parseIp6Into(ip, W, G) && W[0] === 0 && W[1] === 0 && W[2] === 0 && W[3] === 1;
}

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
 *
 * XFF entries are read without a port (`ip:port`, `[v6]:port`, as Azure writes them) in every mode.
 *
 * `cidrs` (also what the dashboard's Cloudflare option stores) walks the chain `[...xff, peer]` from
 * the right: if the socket peer is not a trusted proxy, the request did not come through one and the
 * peer IS the client — XFF is ignored, since anyone hitting the origin directly can write it.
 * A loopback peer (127.0.0.0/8, ::1, ::ffff:127.x.x.x) counts as a trusted hop: it is a local front
 * end or sidecar (App Engine's is always 127.0.0.1), and no remote client can be one. Loopback is
 * trusted only as the peer, never as an XFF entry.
 * With no peer at all (`socketAddr` null: adapters whose host exposes no socket, e.g. @camada/next)
 * the walk runs over XFF alone, as before: such adapters trust the host's network edge to have
 * written XFF, and the deployment must not let clients reach the app around that edge.
 * `hops` and `vercel` trust XFF by definition and do not look at the peer.
 */
export function resolveClientIp(socketAddr: string | null | undefined, xff: string | null | undefined, cfg?: TrustedProxyConfig | null): string | null {
  const sock = socketAddr ? socketAddr.replace(/^::ffff:/i, '') : null;   // Node dual-stack v4-mapped form
  if (!cfg || cfg.mode === 'none' || !xff) return sock;
  const entries = xff.split(',').map((s) => stripPort(s.trim())).filter(Boolean);
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
      const isTrusted = (ip: string) => trusted.some((t) => inCidr(ip, t));
      if (sock !== null && !isLoopback(sock) && !isTrusted(sock)) return sock;   // the peer is the first hop
      for (let i = entries.length - 1; i >= 0; i--) {
        if (!isTrusted(entries[i])) { candidate = entries[i]; break; }
      }
      break;
    }
  }
  return candidate && validIp(candidate) ? candidate : sock;
}

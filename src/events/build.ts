// Wire-event builder: reproduces the collector's record() (edge-analyst
// workers/collector/edge-collector.js) from a normalized request, so events are comparable
// across taps. HDRS bit order is pinned by the shared fixture (hdrs.json) — never reorder.

import { scrubQuery } from '../redact.js';
import type { Tap } from '../constants.js';

export const HDRS = Object.freeze([
  'accept', 'accept-language', 'accept-encoding', 'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest',
  'sec-fetch-user', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'upgrade-insecure-requests', 'dnt',
  'cache-control', 'pragma', 'referer', 'origin', 'cookie', 'authorization', 'x-requested-with', 'content-type',
  'via', 'x-forwarded-for', 'priority', 'sec-purpose', 'save-data', 'te', 'if-modified-since', 'if-none-match',
] as const);

export interface RequestInfo {
  method: string;
  host: string;
  path: string;
  query?: string | null;              // includes the leading '?', or empty
  /** Headers in WIRE ORDER as [name, value] pairs (Node: req.rawHeaders re-paired). */
  headers: Array<[string, string]>;
  ip: string | null;                  // already resolved via trusted-proxy config
  httpVersion?: string | null;        // Node req.httpVersion, e.g. '1.1'
}

export interface BuildOptions {
  tap: Tap;
  rid: string;
  sid?: string | null;
  newSession?: boolean;
  ja4?: string | null;                // x-vercel-ja4-digest on Vercel
}

/** The mutable wire event; the caller fills st/dur on response-finish before enqueueing. */
export interface WireEvent { [k: string]: unknown }

// A schemeless header (`Authorization: <raw token>`) has no safe prefix: the first "word" IS
// the credential. Only a real auth-scheme token followed by a space ever ships.
const SCHEME_RE = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,16}$/;
export function authScheme(value: string | null): string | null {
  if (!value) return null;
  const sp = value.indexOf(' ');
  if (sp <= 0) return null;
  const scheme = value.slice(0, sp);
  return SCHEME_RE.test(scheme) ? scheme : null;
}

export function buildWireEvent(r: RequestInfo, o: BuildOptions): WireEvent {
  let mask = 0, hn = 0, hb = 0, cookie = '', names: string[] = [];
  const first: Record<string, string> = {};
  for (const [name, value] of r.headers) {
    const k = name.toLowerCase();
    hn++; hb += name.length + value.length; names.push(k);
    if (!(k in first)) first[k] = value;
    const bit = HDRS.indexOf(k as (typeof HDRS)[number]);
    if (bit !== -1) mask |= 1 << bit;
    if (k === 'cookie') cookie = cookie ? cookie + '; ' + value : value;
  }
  const h = (k: string): string | null => first[k] ?? null;
  const query = r.query || '';
  const qn = query.length > 1 ? query.slice(1).split('&').filter(Boolean).length : 0;
  const auth = authScheme(h('authorization'));
  return {
    tap: o.tap, rid: o.rid, sid: o.sid ?? null, ns: o.newSession ? 1 : 0, ts: Date.now(),
    ip: r.ip,
    proto: r.httpVersion ? `HTTP/${r.httpVersion}` : null,
    m: r.method, h: r.host, p: r.path, q: scrubQuery(query).slice(0, 512), qn,
    ct: h('content-type'), cl: h('content-length'),
    ua: h('user-agent'), chua: h('sec-ch-ua'), chmob: h('sec-ch-ua-mobile'), chplat: h('sec-ch-ua-platform'),
    acc: h('accept'), lang: h('accept-language'), fs: h('sec-fetch-site'), fm: h('sec-fetch-mode'),
    fd: h('sec-fetch-dest'), fu: h('sec-fetch-user'), ref: h('referer'), org: h('origin'),
    xrw: h('x-requested-with'), auth,   // scheme only, never the credential (see authScheme)
    hm: mask >>> 0, hn, hb, ck: cookie ? cookie.split(';').length : 0,
    hord: names.join(',').slice(0, 2048),   // true wire header order — the signal only this position has
    ...(o.ja4 ? { ja4: o.ja4 } : {}),
    st: null, dur: null,                    // filled on response-finish ('dur': the collector wire already claims 'lat' for latitude)
  };
}

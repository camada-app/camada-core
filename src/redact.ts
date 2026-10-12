// Redaction, non-configurable-off (plan.md cross-cutting prerequisite 4). The SDK never ships:
// Authorization/Cookie values (scheme only — build.ts), body field values (shape only), query
// params that look like credentials, or raw user identifiers (HMAC-hashed here, inside the SDK,
// before anything reaches the queue). Customers can widen the ALLOWLIST, never narrow redaction.

const NAME_RE = /(pass(word)?|tok(en)?|secret|key|api[-_]?key|auth|sess(ion)?|sig(nature)?|code|jwt|bearer|credential)/i;
const JWT_RE = /^eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/;
const HEX_RE = /^[a-f0-9]{32,}$/i;
const B64_RE = /^[A-Za-z0-9+/_-]{40,}={0,2}$/;

/** Fields a customer may additionally report through app-context events. Additions only. */
export const REDACT_ALLOWLIST = Object.freeze(['plan', 'role', 'locale', 'ab_variant']);

const suspectValue = (v: string) => JWT_RE.test(v) || HEX_RE.test(v) || B64_RE.test(v);

const ESC_RE = /%[0-9a-f]{2}/i, ESC_RE_G = /%([0-9a-f]{2})/gi;
/** Percent-decoding that never throws: each `%HH` becomes that byte as one char (Latin-1), any other
 *  `%` stays. Up to 4 passes, so double (or triple) encoding cannot hide a name or a nested query; text
 *  that still holds a `%HH` after 4 passes returns null, which the caller scrubs. The cap keeps a
 *  crafted `%252525…` from costing O(n²). Only ever used to TEST a part; the output keeps the raw text. */
function decodeAll(s: string): string | null {
  for (let i = 0; i < 4 && ESC_RE.test(s); i++) s = s.replace(ESC_RE_G, (_m, h: string) => String.fromCharCode(parseInt(h, 16)));
  return ESC_RE.test(s) ? null : s;
}

/** Replaces credential-looking query parts with ~r, preserving structure and order (C6 v2). The
 *  string is split on `&`, never URL-parsed. Each part's name and value are percent-decoded
 *  (decodeAll) before testing. `name=value` → `name=~r` when the name looks like a credential, the
 *  value looks like one, or the value contains `?` or `=` (a nested query, e.g. `next=/reset?token=x`
 *  or an encoded `redirect_uri`, is dropped whole rather than scrubbed recursively). A bare part
 *  (no `=`) → `~r` when it looks like a credential value. Either half still encoded after 4 decode
 *  passes counts as a credential. Used for both the request's own `q` and the Referer (scrubUrl). */
export function scrubQuery(query: string | null | undefined): string {
  if (!query || query.length <= 1) return query || '';
  const lead = query.startsWith('?') ? '?' : '';
  const parts = (lead ? query.slice(1) : query).split('&');
  return lead + parts.map((p) => {
    const eq = p.indexOf('=');
    if (eq === -1) { const d = decodeAll(p); return d === null || suspectValue(d) ? '~r' : p; }
    const name = p.slice(0, eq), dn = decodeAll(name), dv = decodeAll(p.slice(eq + 1));
    return dn === null || dv === null || NAME_RE.test(dn) || suspectValue(dv) || /[?=]/.test(dv) ? `${name}=~r` : p;
  }).join('&');
}

/** A URL (a Referer) with its query and fragment run through scrubQuery (camada-all-ijsa); the
 *  scheme, host and path are kept as they are. The path is left alone on purpose: it gets the same
 *  treatment as the request's own path `p` (none). A same-origin Referer's path already shipped as `p`
 *  on that page's own event, and a cross-origin one carries only the origin under the browsers'
 *  default Referrer-Policy, so scrubbing it here would hide nothing that is not already sent. */
export function scrubUrl(url: string | null | undefined): string | null {
  if (url == null) return null;
  const hash = url.indexOf('#');
  const head = hash === -1 ? url : url.slice(0, hash);
  const frag = hash === -1 ? null : url.slice(hash + 1);
  const q = head.indexOf('?');
  const scrubbed = q === -1 ? head : head.slice(0, q) + scrubQuery(head.slice(q));
  return frag === null ? scrubbed : scrubbed + '#' + scrubQuery(frag);
}

/** Body shape only: field names and byte sizes, never values. One level deep. */
export function bodyShape(obj: unknown): Record<string, number> | null {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return null;
  const out: Record<string, number> = {};
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    if (typeof v === 'string') out[k] = v.length;
    else if (v === null || v === undefined) out[k] = 0;
    else out[k] = JSON.stringify(v)?.length ?? 0;   // undefined for functions/symbols -> 0
  }
  return out;
}

/** Stable per-tenant pseudonym for a user identifier: HMAC-SHA256 keyed by the ingest token,
 *  labeled so the hash can never double as anything else. The raw identifier never leaves.
 *  `subtle` defaults to the global WebCrypto (Node ≥20 and every edge runtime have one) and stays
 *  injectable for hosts that hand in their own, as @camada/node does. Core itself stays edge-safe. */
export async function hashUserId(id: string, ingestToken: string, subtle: SubtleCrypto | undefined = globalThis.crypto?.subtle): Promise<string> {
  if (!subtle) throw new Error('camada: no WebCrypto available — this SDK needs Node >=20 or an edge runtime with globalThis.crypto.subtle (or pass a SubtleCrypto)');
  const enc = new TextEncoder();
  const key = await subtle.importKey('raw', enc.encode(ingestToken), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await subtle.sign('HMAC', key, enc.encode('uid:' + id));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 32);
}

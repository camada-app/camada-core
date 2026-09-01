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

/** Replaces credential-looking query values with ~r, preserving structure and order. */
export function scrubQuery(query: string | null | undefined): string {
  if (!query || query.length <= 1) return query || '';
  const lead = query.startsWith('?') ? '?' : '';
  const parts = (lead ? query.slice(1) : query).split('&');
  return lead + parts.map((p) => {
    const eq = p.indexOf('=');
    if (eq === -1) return p;
    const name = p.slice(0, eq), value = p.slice(eq + 1);
    return NAME_RE.test(name) || suspectValue(value) ? `${name}=~r` : p;
  }).join('&');
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
 *  labeled so the hash can never double as anything else. The raw identifier never leaves. */
export async function hashUserId(id: string, ingestToken: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(ingestToken), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode('uid:' + id));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 32);
}

// Wire constants and pure helpers for the SDK-served challenge (contracts §D2, D32).
// Nothing here does crypto: the runtime supplies HMAC/SHA-256 (node:crypto in @camada/node,
// WebCrypto everywhere else) so the format has exactly one definition.

export const CHALLENGE_COOKIE = '_cch';
export const CHALLENGE_TTL_MS = 3_600_000;   // 1 h (contract)
export const POW_BITS = 16;                  // leading zero bits of SHA-256(`${nonce}.${solution}`)
export const NONCE_HEX = 32;                 // the nonce is the first 32 hex chars of the HMAC
const DAY_MS = 86_400_000;
const MAX_RETURN_TO = 2048;
const MAX_SOLUTION = 32;

export const utcDay = (now: number): number => Math.floor(now / DAY_MS);

// Domain-separated messages: a nonce HMAC can never be replayed as a cookie HMAC.
export const nonceMessage = (ip: string | null, day: number): string => `camada-challenge-nonce|${ip ?? ''}|${day}`;
export const tokenMessage = (ip: string | null, exp: number): string => `camada-challenge-token|${ip ?? ''}|${exp}`;

export function splitToken(value: string | null | undefined): { exp: number; mac: string } | null {
  if (!value) return null;
  const dot = value.indexOf('.');
  if (dot <= 0) return null;
  const exp = Number(value.slice(0, dot));
  const mac = value.slice(dot + 1);
  if (!Number.isFinite(exp) || !mac) return null;
  return { exp, mac };
}

/** Constant-time for equal-length hex strings; length itself is not a secret here. */
export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

/** True when the hex digest starts with `bits` zero bits. */
export function powOk(hex: string, bits: number = POW_BITS): boolean {
  const nibbles = bits >> 2, rest = bits & 3;
  if (hex.length < nibbles + (rest ? 1 : 0)) return false;
  for (let i = 0; i < nibbles; i++) if (hex.charCodeAt(i) !== 48) return false;
  if (rest === 0) return true;
  const v = parseInt(hex[nibbles], 16);
  return Number.isFinite(v) && (v >> (4 - rest)) === 0;
}

export const solutionShapeOk = (solution: string | null | undefined): solution is string =>
  !!solution && solution.length <= MAX_SOLUTION;

export function challengeCookie(value: string, secure: boolean): string {
  return `${CHALLENGE_COOKIE}=${value}; Path=/; Max-Age=${CHALLENGE_TTL_MS / 1000}; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`;
}

/** Only a printable-ASCII same-site absolute path survives: never an absolute URL, a
 *  protocol-relative '//host' redirect, a control character, or something absurdly long.
 *  Non-ASCII is rejected rather than escaped because this value goes straight into a `Location`
 *  header, and Node throws ERR_INVALID_CHAR on anything above 0xff — a percent-encoded path
 *  survives unchanged, a raw one is not worth guessing at. */
export function safeReturnTo(raw: string | null | undefined): string {
  if (!raw || raw.length > MAX_RETURN_TO) return '/';
  if (raw[0] !== '/' || raw[1] === '/' || raw[1] === '\\') return '/';
  for (let i = 0; i < raw.length; i++) { const c = raw.charCodeAt(i); if (c < 0x21 || c > 0x7e) return '/'; }
  return raw;
}

/** A challenge page is only worth serving to a top-level HTML navigation (contract §D2:
 *  "Accept without text/html, or sec-fetch-dest not document" gets 403 JSON instead). */
export function wantsHtml(accept: string | null, secFetchDest: string | null): boolean {
  if (!accept || accept.indexOf('text/html') === -1) return false;
  return !secFetchDest || secFetchDest === 'document';
}

const ENTITIES: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

export function escapeAttr(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ENTITIES[c]);
}

/** Safe to drop inside an inline <script>: `<` is escaped so no interpolated value can close
 *  the element early. Callers pass server-generated values today; this keeps that true anyway. */
export function escapeScript(s: string): string {
  return JSON.stringify(s).replace(/</g, '\\u003c');
}

/** application/x-www-form-urlencoded, last value wins. Never throws on junk. */
export function parseFormBody(body: string): Record<string, string> {
  const out: Record<string, string> = Object.create(null);   // no inherited keys to reason about
  for (const pair of body.split('&')) {
    if (!pair) continue;
    const eq = pair.indexOf('=');
    const k = eq === -1 ? pair : pair.slice(0, eq);
    const v = eq === -1 ? '' : pair.slice(eq + 1);
    try { out[decodeURIComponent(k.replace(/\+/g, ' '))] = decodeURIComponent(v.replace(/\+/g, ' ')); } catch { /* skip a malformed pair */ }
  }
  return out;
}

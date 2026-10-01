// Path canonicalisation, ported from edge-analyst src/blocklist.js (contracts §D3 "Path matching").
// A path rule must catch every spelling a router sends to the same handler (Hono decodes before
// routing; Express ignores case and a trailing slash), so both the request path and every
// published path value go through canonPath: query cut at ? or #; %XX decoded when printable ASCII
// other than / and % (so %2F is never a separator and decoding stays one pass); every other byte
// written as lower-case %xx of its UTF-8; ASCII lower-cased; each segment cut at its first ;
// (servlet path parameters); empty segments dropped (// and the trailing slash); . and ..
// resolved — `full`. `lit` skips the dot step, for a router that hands /locked/../x to the
// /locked handler unresolved. A deny (block, challenge, warn) fires when raw, lit or full matches;
// an exemption (allow side, skip) needs lit AND full, so /public/../admin never borrows /public/'s
// exemption. The golden fixtures pin every case.

/** [raw (query cut), lit, full] */
export type PathForms = readonly [string, string, string];

const HEX = '0123456789abcdef';
const hexv = (c: number): number => (c >= 48 && c <= 57 ? c - 48 : c >= 97 && c <= 102 ? c - 87 : c >= 65 && c <= 70 ? c - 55 : -1);
const UTF8 = new TextEncoder();
// Already canonical (the common case): skip the byte walk.
const CANON = /^(?:\/(?!\.\.?(?:\/|$))[a-z0-9\-._~!$&'()*+,=:@]+)+$/;

function stripQuery(raw: string | null | undefined): string {
  const p = raw || '/';
  let q = p.indexOf('?');
  const h = p.indexOf('#');
  if (h !== -1 && (q === -1 || h < q)) q = h;
  return q === -1 ? p : p.slice(0, q);
}

export function canonPath(raw: string | null | undefined, dots = true): string {
  const p = stripQuery(raw);
  if (p === '/' || CANON.test(p)) return p;
  const b = UTF8.encode(p);
  let s = '';
  for (let i = 0; i < b.length; i++) {
    let c = b[i];
    if (c === 37 && i + 2 < b.length && hexv(b[i + 1]) >= 0 && hexv(b[i + 2]) >= 0) {
      c = hexv(b[i + 1]) * 16 + hexv(b[i + 2]); i += 2;
      if (c === 47) { s += '%2f'; continue; }
    }
    if (c < 0x21 || c > 0x7e || c === 37) { s += '%' + HEX[c >> 4] + HEX[c & 15]; continue; }
    s += String.fromCharCode(c >= 65 && c <= 90 ? c + 32 : c);
  }
  const out: string[] = [];
  for (let seg of s.split('/')) {
    const k = seg.indexOf(';');
    if (k !== -1) seg = seg.slice(0, k);
    if (!seg || (dots && seg === '.')) continue;
    if (dots && seg === '..') { out.pop(); continue; }
    out.push(seg);
  }
  return '/' + out.join('/');
}

export function pathForms(raw: string | null | undefined): PathForms {
  const p = stripQuery(raw);
  if (p === '/' || CANON.test(p)) return [p, p, p];
  return [p, canonPath(p, false), canonPath(p, true)];
}

const dir = (p: string): string => (p.endsWith('/') ? p : p + '/');
/** A prefix entry, or a starts_with value ending in /, as its canonical directory key ('/' stays '/'). */
export const dirKey = (v: string): string => dir(canonPath(v));

/** Walks every '/' boundary of `path` as a directory: /a/b tries /, /a/, /a/b/. */
export function prefixHit(prefixes: Set<string>, path: string): boolean {
  const d = dir(path);
  for (let i = 0; i !== -1; i = d.indexOf('/', i + 1)) if (prefixes.has(d.slice(0, i + 1))) return true;
  return false;
}

/** Does `pred` hold for this request? deny = any spelling; an exemption = both canonical forms. */
export const pathHit = (pred: (p: string) => boolean, forms: PathForms, deny: boolean): boolean =>
  deny ? pred(forms[0]) || pred(forms[1]) || pred(forms[2]) : pred(forms[1]) && pred(forms[2]);

/** One v5 path condition -> a predicate over a single path form. A regex this runtime rejects never matches. */
export function pathPred(op: string, values: string[]): (p: string) => boolean {
  if (op === 'matches') {
    let re: RegExp | null = null;
    try { re = new RegExp(values[0], 'i'); } catch { re = null; }
    return (p) => !!re && re.test(p);
  }
  if (op === 'starts_with') {
    const v = values[0], key = v.endsWith('/') ? dirKey(v) : canonPath(v);
    return (p) => dir(p).startsWith(key);
  }
  const set = new Set(values.map((v) => canonPath(v)));
  return (p) => set.has(p);
}

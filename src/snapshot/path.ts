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

import { RE2JS } from 're2js';

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

/** The control characters a request may carry decoded: stripped from ua/header before a regex (parse.ts), %-encoded in the raw path form. */
export const CTL_G = /[\x00-\x1f\x7f]/g;
export const CTL_ANY = /[\x00-\x1f\x7f]/;   // non-global, safe for .test: the S5 one-scan check

export function pathForms(raw: string | null | undefined): PathForms {
  const p = stripQuery(raw);
  if (p === '/' || CANON.test(p)) return [p, p, p];
  return [p.replace(CTL_G, (c) => '%' + HEX[c.charCodeAt(0) >> 4] + HEX[c.charCodeAt(0) & 15]), canonPath(p, false), canonPath(p, true)];   // raw form: controls as lower-case %xx (contract regex-cap-sdk S3)
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

/** A `matches` rule tests at most this many UTF-16 code units of a path, user agent or header value (contract regex-cap-sdk S1).
 *  A longer value is never truncated: the regex does not run, and the value is a hit for a deny rule (block/challenge/warn)
 *  and a miss for a skip. */
export const MAX_MATCH_INPUT = 2048;

/** Does `pred` hold for this request? deny = any spelling; an exemption = both canonical forms. `deny` also tells a
 *  `matches` predicate what an over-cap form answers. */
export const pathHit = (pred: (p: string, deny: boolean) => boolean, forms: PathForms, deny: boolean): boolean =>
  // a spelling equal to one already tried is skipped: a test spends the request's regex budget, so skipping a repeat is also what keeps edge and core spending the same; keep the forms' order and skips identical in both
  deny ? pred(forms[0], true) || (forms[1] !== forms[0] && pred(forms[1], true)) || (forms[2] !== forms[0] && forms[2] !== forms[1] && pred(forms[2], true))
    : pred(forms[1], false) && (forms[2] === forms[1] || pred(forms[2], false));

const WS = '\\t-\\r \\x{a0}\\x{1680}\\x{2000}-\\x{200a}\\x{2028}\\x{2029}\\x{202f}\\x{205f}\\x{3000}\\x{feff}';   // JS \s
const SURR = /^[dD][89abAB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}/;
const HEX4 = /^[0-9a-fA-F]{4}/;
const HEX2 = /^[0-9a-fA-F]{2}/;

/** A JS (non-`u`) pattern -> RE2 syntax that keeps the JS meaning, via re2js' translateRegExp (contract regex-limit v1). The
 *  test vectors' `translate` rows pin the output; edge-analyst blocklist.js carries the same function. */
const BRACE = /\{(\d+)(,(\d*))?\}/y;
export function jsToRe2(p: string): string {
  let out = '', cls = false, ce = false, at = false, m: RegExpExecArray | null;
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === '\\' && i + 1 < p.length) {
      const n = p[++i];
      if (cls) { ce = 'sSdDwW'.includes(n); at = true; }   // ce: the last atom in this class is \s \d \w or the like
      if ('AzQEpPa'.includes(n) || (n === 'B' && cls)) out += n;   // JS reads the bare letter (RE2: an anchor, quote or class); [\B] is a literal B
      else if (n === 'u' && !cls && SURR.test(p.slice(i + 1, i + 11))) {        // \uD83D\uDE00: how a non-u regex writes an astral character
        out += '\\x{' + ((parseInt(p.substr(i + 1, 4), 16) - 0xd800) * 0x400 + parseInt(p.substr(i + 7, 4), 16) - 0xdc00 + 0x10000).toString(16) + '}';
        i += 10;
      }
      else if (n === 'u') out += HEX4.test(p.slice(i + 1, i + 5)) ? '\\u' : 'u';
      else if (n === 'x') out += HEX2.test(p.slice(i + 1, i + 3)) ? '\\x' : 'x';
      else if (n === 'c' && cls && /[0-9_]/.test(p[i + 1] ?? '')) out += '\\x' + (p.charCodeAt(++i) % 32).toString(16).padStart(2, '0');   // [\c_] is a control character in a class (Annex B)
      else if (n === 'c') out += /[A-Za-z]/.test(p[i + 1] || '') ? '\\c' : '\\\\c';
      else if (n === 'b' && cls) out += '\\x08';
      else if (n === 's') out += cls ? WS : '[' + WS + ']';
      else if (n === 'S' && !cls) out += '[^' + WS + ']';
      else out += c + n;
    } else if (cls) {
      if (c === ']') cls = false;
      else {
        if (c === '-' && at && p[i + 1] !== ']' && (ce || /^\\[sSdDwW]/.test(p.slice(i + 1, i + 3)))) throw new SyntaxError('a - next to \\s, \\d or \\w inside [ ]');   // JS reads it as a literal -, RE2 as a range: refuse, never emulate
        ce = false; at = true;
      }
      out += c;
    } else if (c === '[') {
      out += c;
      if (p[i + 1] === '^') out += p[++i];
      cls = true; ce = at = false;
    }
    else if (c === '{' && (BRACE.lastIndex = i, m = BRACE.exec(p))) { out += m[0].replace(/\b0+(?=\d)/g, ''); i += m[0].length - 1; }   // a{02} is a{2} in JS but RE2 reads the text: strip leading zeros as text (never Number()), skip the brace
    else out += c === '.' ? '[^\\n\\r\\x{2028}\\x{2029}]' : c;
  }
  return RE2JS.translateRegExp(out);
}

/** re2js' lazy DFA caches up to 8 MiB per pattern (200 wide rules held 1147 MiB); 64 KiB gives the same answers (a full cache is rebuilt or the NFA runs). */
export const RE2_DFA_MAX_MEM = 65536;
/** A customer `matches` pattern as a linear-time matcher; a stored pattern re2js refuses (a legacy lookaround) falls back to
 *  the native RegExp, null when neither compiles. */
export function compileMatches(p: string, ci: boolean): { test(s: string): boolean } | null {
  let re: RE2JS | undefined;
  try { re = RE2JS.compile(jsToRe2(p), ci ? RE2JS.CASE_INSENSITIVE : 0); } catch { /* fall through */ }
  if (re) {   // outside the try: a failure here must throw, not fall back to native
    const d = re.re2().dfa, clear = d.clearCache, match = d.match, step = d.step;
    if (typeof clear !== 'function' || typeof match !== 'function' || typeof step !== 'function' || typeof d.memBudget !== 'number' || typeof d.stateCount !== 'number') {
      WORK.set(re, { n: re.re2().numberOfInstructions() + REGEX_STATE_WORK, d: null, full: true });   // fail closed: re2js internals changed, so every test is charged the full worst case
      return re;
    }
    d.maxMem = d.stateBudget = d.memBudget = RE2_DFA_MAX_MEM;
    d.clearCache = function (this: typeof d) { dfaBuilt += this.stateBudget - this.memBudget; return clear.call(this); };   // the bytes of cache built before a clear (this.memBudget is what is left), for safeTest
    d.match = function (this: typeof d, ...a: Parameters<typeof d.match>) { const r = match.apply(this, a); if (r === null) dfaGiveUps++; return r; };   // null: the DFA gave up and the NFA runs the whole input
    // a transition computed to an already-cached state builds no bytes but costs CPU (anchor 0 is RE2Flags.UNANCHORED)
    d.step = function (this: typeof d, s: Parameters<typeof d.step>[0], cls: number, rune: number, anchor: number) { const t = anchor === 0 ? s.next : s.nextAnchored, miss = t == null || t[cls] == null, c0 = this.stateCount; const r = step.call(this, s, cls, rune, anchor); if (miss && this.stateCount === c0) dfaSteps += s.nfaStates.length + REGEX_STEP_WORK; return r; };
    WORK.set(re, { n: re.re2().numberOfInstructions() + REGEX_STATE_WORK, d, full: false });
    return re;
  }
  try { const nre = new RegExp(p, ci ? 'i' : ''); WORK.set(nre, { n: REGEX_STATE_WORK, d: null, full: false }); return nre; } catch { return null; }
}

/** Per-request regex work (camada-all-1oqz), mirrors edge-analyst blocklist.js: a test of a value of length L through n instructions
 *  runs while any of REQUEST_REGEX_WORK is left, so a walk spends at most that plus one test. */
export const REQUEST_REGEX_WORK = 8388608;
/** The fixed cost of one call, added to a program's instruction count for the give-up charge. */
export const REGEX_STATE_WORK = 64;
let regexLeft = Infinity;   // Infinity outside a request rule walk (entity plane, direct .test): unbudgeted
/** The fixed cost of one computed DFA transition to an already-cached state, added to the source state's NFA-state count. */
export const REGEX_STEP_WORK = 256;
let dfaBuilt = 0, dfaGiveUps = 0, dfaSteps = 0;
const WORK = new WeakMap<object, { n: number; d: { memBudget: number } | null; full: boolean }>();   // full: re2js internals missing, charge the worst case every test

/** Runs a request rule walk (synchronous: the budget is module state) under a fresh REQUEST_REGEX_WORK; nesting-safe. */
export function withRegexBudget<T>(f: () => T): T {
  const prev = regexLeft;
  regexLeft = REQUEST_REGEX_WORK;
  try { return f(); } finally { regexLeft = prev; }
}

/** re.test, except that a match-time engine failure (a RangeError) answers `onError`, like an over-cap value: deny for block/challenge/warn, miss for skip (contract regex-cap-sdk S4).
 *  Inside withRegexBudget a test runs while budget is left (regexLeft > 0), else it answers `onError` unrun. It is charged the full worst case (L+1)(n+64) when re2js's DFA
 *  gave up (the NFA then ran the whole input), else L+64 plus the DFA cache bytes built during the test (re2js's own per-state accounting, memBudget) plus, per DFA transition
 *  computed to an already-cached state (no bytes, real CPU), that state's NFA-state count + REGEX_STEP_WORK. The native fallback is charged L+64; if the re2js internals wrapped
 *  in compileMatches are missing, every test is charged the full worst case. */
export function safeTest(re: { test(s: string): boolean }, v: string, onError: boolean): boolean {
  if (regexLeft <= 0) return onError;
  const w = WORK.get(re), g0 = dfaGiveUps, b0 = dfaBuilt, s0 = dfaSteps, m0 = w?.d?.memBudget ?? 0;
  let hit: boolean;
  try { hit = re.test(v); } catch { hit = onError; }
  if (w) regexLeft -= w.full ? (v.length + 1) * w.n : !w.d ? v.length + REGEX_STATE_WORK : dfaGiveUps !== g0 ? (v.length + 1) * w.n : v.length + REGEX_STATE_WORK + dfaBuilt - b0 + m0 - w.d.memBudget + dfaSteps - s0;   // the cache bytes built: those before each clear (dfaBuilt) plus the budget this test used since
  return hit;
}

/** One v5 path condition -> a predicate over a single path form. A regex this runtime rejects never matches. */
export function pathPred(op: string, values: string[]): (p: string, deny: boolean) => boolean {
  if (op === 'matches') {
    const re = compileMatches(values[0], true);
    return (p, deny) => {
      if (!re) return false;
      if (p.length > MAX_MATCH_INPUT) return deny;
      return safeTest(re, p, deny);   // S4: a match-time failure answers like over-cap
    };
  }
  if (op === 'starts_with') {
    const v = values[0], key = v.endsWith('/') ? dirKey(v) : canonPath(v);
    return (p) => dir(p).startsWith(key);
  }
  const set = new Set(values.map((v) => canonPath(v)));
  return (p) => set.has(p);
}

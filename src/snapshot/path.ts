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

/** A predicate over one path form; `deny` also tells a `matches` predicate what an over-cap form answers. */
export type PathPred = (p: string, deny: boolean) => boolean;

/** Does `pred` hold for this request? deny = any spelling; an exemption = both canonical forms. `deny` also tells a
 *  `matches` predicate what an over-cap form answers. */
export const pathHit = (pred: PathPred, forms: PathForms, deny: boolean): boolean =>
  // a spelling equal to one already tried is skipped: a test spends the request's regex budget, so skipping a repeat is also what keeps edge and core spending the same; keep the forms' order and skips identical in both
  deny ? pred(forms[0], true) || (forms[1] !== forms[0] && pred(forms[1], true)) || (forms[2] !== forms[0] && forms[2] !== forms[1] && pred(forms[2], true))
    : pred(forms[1], false) && (forms[2] === forms[1] || pred(forms[2], false));

const WS = '\\t-\\r \\x{a0}\\x{1680}\\x{2000}-\\x{200a}\\x{2028}\\x{2029}\\x{202f}\\x{205f}\\x{3000}\\x{feff}';   // JS \s
const NOT_WS = '\\x00-\\x08\\x0e-\\x1f\\x21-\\x9f\\x{a1}-\\x{167f}\\x{1681}-\\x{1fff}\\x{200b}-\\x{2027}\\x{202a}-\\x{202e}\\x{2030}-\\x{205e}\\x{2060}-\\x{2fff}\\x{3001}-\\x{fefe}\\x{ff00}-\\x{10ffff}';   // JS \S: the complement of the set above, for inside [ ]
const SURR = /^[dD][89abAB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}/;
export const ASTRAL_QUANT = 'a quantifier right after a surrogate pair';
export const ASTRAL_CLASS = 'a surrogate pair inside [ ]';
const quantAt = (p: string, j: number) => '?*+'.includes(p[j]!) || (p[j] === '{' && ((BRACE.lastIndex = j), BRACE.test(p)));   // a ? * + or {n} {n,} {n,m} at p[j] (past the end p[j] is undefined, which matches neither)
const HEX4 = /^[0-9a-fA-F]{4}/;
const HEX2 = /^[0-9a-fA-F]{2}/;

/** A JS (non-`u`) pattern -> RE2 syntax that keeps the JS meaning, via re2js' translateRegExp (contract regex-limit v1). The
 *  test vectors' `translate` rows pin the output; edge-analyst blocklist.js carries the same function. */
const BRACE = /\{(\d+)(,(\d*))?\}/y;
export function jsToRe2(p: string): string {
  let out = '', cls = false, ce = false, at = false, rng = false, m: RegExpExecArray | null;
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === '\\' && i + 1 < p.length) {
      const n = p[++i];
      if (cls) { ce = 'sSdDwW'.includes(n); at = !rng; rng = false; }   // ce: the last atom in this class is \s \d \w or the like; rng: the - just read is a range operator, so the next atom (the range's high end) cannot start another range
      if ('AzQEpPa'.includes(n) || (n === 'B' && cls)) out += n;   // JS reads the bare letter (RE2: an anchor, quote or class); [\B] is a literal B
      else if (n === 'u' && !cls && SURR.test(p.slice(i + 1, i + 11))) {        // \uD83D\uDE00: how a non-u regex writes an astral character
        if (quantAt(p, i + 11)) throw new SyntaxError(ASTRAL_QUANT);   // JS repeats the low unit only, RE2 the whole character
        out += '\\x{' + ((parseInt(p.substr(i + 1, 4), 16) - 0xd800) * 0x400 + parseInt(p.substr(i + 7, 4), 16) - 0xdc00 + 0x10000).toString(16) + '}';
        i += 10;
      }
      // the digits or letter after \u \x \c belong to this atom, not the next one
      else if (n === 'u' && HEX4.test(p.slice(i + 1, i + 5))) { out += '\\u' + p.slice(i + 1, i + 5); i += 4; }
      else if (n === 'u') out += 'u';
      else if (n === 'x' && HEX2.test(p.slice(i + 1, i + 3))) { out += '\\x' + p.slice(i + 1, i + 3); i += 2; }
      else if (n === 'x') out += 'x';
      else if (n === 'c' && cls && /[0-9_]/.test(p[i + 1] ?? '')) out += '\\x' + (p.charCodeAt(++i) % 32).toString(16).padStart(2, '0');   // [\c_] is a control character in a class (Annex B)
      else if (n === 'c' && /[A-Za-z]/.test(p[i + 1] || '')) out += '\\c' + p[++i];
      else if (n === 'c') { out += '\\\\c'; if (cls) at = true; }   // a bare \c is a backslash then c: two atoms, so the c starts the next range
      else if (n === 'b' && cls) out += '\\x08';
      else if (n === 's') out += cls ? WS : '[' + WS + ']';
      else if (n === 'S') out += cls ? NOT_WS : '[^' + WS + ']';
      else if (n >= '0' && n <= '7') {   // a legacy octal escape (in or out of [ ]) is one atom: V8 reads up to 3 digits after 0-3, 2 after 4-7 (Annex B); RE2 would read a third after 4-7, so \400 is written \0400 (\040 then 0); in a class \1 is written \01, as RE2 reads a bare \1 as a backreference
        const d = p.slice(i, i + (n <= '3' ? 3 : 2)).match(/^[0-7]+/)![0];
        out += (cls && d.length < 3 || d.length === 2 && n >= '4' && /[0-7]/.test(p[i + 2] ?? '') ? '\\0' : '\\') + d; i += d.length - 1;
      }
      else out += c + n;
    } else if (cls) {
      if (p.codePointAt(i)! > 0xffff) throw new SyntaxError(ASTRAL_CLASS);   // JS reads the two units, RE2 one code point (camada-all-cfx4)
      if (c === ']') cls = false;
      else {
        if (c === '-' && at && p[i + 1] !== ']') {   // a range operator (not an atom); a - after a finished range, as in [a-b-\d], is a literal
          if (ce || /^\\[sSdDwW]/.test(p.slice(i + 1, i + 3))) throw new SyntaxError('a - next to \\s, \\d or \\w inside [ ]');   // JS reads it as a literal -, RE2 as a range: refuse, never emulate
          rng = true; at = false;
        } else { ce = false; at = !rng; rng = false; }
      }
      out += c === '[' ? '\\[' : c;   // camada-all-07c7: JS reads a [ inside a class as text, RE2 reads [:alpha:] as a POSIX class
    } else if (c === '[') {
      out += c;
      if (p[i + 1] === '^') out += p[++i];
      cls = true; ce = at = rng = false;
    }
    else if (c === '{' && (BRACE.lastIndex = i, m = BRACE.exec(p))) { out += m[0].replace(/\b0+(?=\d)/g, ''); i += m[0].length - 1; }   // a{02} is a{2} in JS but RE2 reads the text: strip leading zeros as text (never Number()), skip the brace
    else if (p.codePointAt(i)! > 0xffff && quantAt(p, i + 2)) throw new SyntaxError(ASTRAL_QUANT);   // a raw pair, same
    else out += c === '.' ? '[^\\n\\r\\x{2028}\\x{2029}]' : c;
  }
  return RE2JS.translateRegExp(out);
}

// camada-all-z8p7: re2js builds no prefilter from a case-folded literal, so a case-insensitive test of a value without the pattern's required literal ran the whole DFA
// (and gave up to the NFA on a long one) where the case-sensitive test answered after one scan. compileMatches gives a CI pattern re2js's own tree from a case-sensitive
// compile, its literals lower-cased; safeTest reads it on the folded value and counts every scan.
// camada-all-xata: a CS pattern's own tree ran uncharged inside re2js (up to 32 scans of the value per test). compileMatches takes it (unfolded; none for a prefix-complete
// pattern, which re2js answers by indexOf before any tree) and clears re2js's copy; safeTest pre-checks CS on the raw value and counts every scan.
interface Pf { type: number; str: string; subs: Pf[]; eval(input: unknown, pos: number): boolean; automaton16(): { searchUTF16(s: string, a: number, b: number): boolean } }
let pfIn = '', pfFold = '', pfLast = '', pfScans = 0;   // pfIn: what PF_IN reads (the fold for CI, the raw value for CS); pfFold/pfLast: the CI fold memo, written only by a fold (a walk tests the same few path forms against every rule)
const PF_IN = { hasString: (f: Pf) => (pfScans++, pfIn.includes(f.str)), hasAnyString: (f: Pf) => (pfScans++, f.automaton16().searchUTF16(pfIn, 0, pfIn.length)) };   // re2js's prefilter input; an OR of literals is one pass of re2js's own Aho-Corasick
function foldTree(f: Pf): Pf {   // re2js Prefilter types: 0 NONE, 1 EXACT, 2 AND, 3 OR; a literal with a non-ASCII char requires nothing, and so does an OR with such a choice
  if (f.type === 1) { if (/[^\x00-\x7f]/.test(f.str)) f.type = 0; else f.str = f.str.toLowerCase(); }
  else if (f.type > 1) { f.subs.forEach(foldTree); if (f.type === 3 ? f.subs.some((s) => s.type === 0) : f.subs.every((s) => s.type === 0)) f.type = 0; }
  return f;
}
const foldValue = (v: string): string => v.toLowerCase().replace(/\u017f/g, 's');   // re2js folds only U+212A (toLowerCase reads it as k) and U+017F (long s) onto ASCII letters

/** re2js' lazy DFA caches up to 8 MiB per pattern (200 wide rules held 1147 MiB); 64 KiB gives the same answers (a full cache is rebuilt or the NFA runs). */
export const RE2_DFA_MAX_MEM = 65536;
// camada-all-e20y: trimEdgeRepeats(src) drops/shrinks the top-level repeats at either edge of each top-level alternative (and of a whole-pattern (...)/(?:...) group's inside) of an RE2 source (see compileMatches). Anything it does not fully understand returns src unchanged.
// No RegExp in these scanner helpers: the cve matcher counts V8 regex reads.
// a {n} {n,} {n,m} repeat at s[i], else null
const braceAt = (s: string, i: number): { len: number; min: number; max: number } | null => {
  let j = i + 1;
  const digits = (): string => { const b = j; while (s[j]! >= '0' && s[j]! <= '9') j++; return s.slice(b, j); };
  const lo = digits(), hi = s[j] === ',' ? (j++, digits()) : undefined;
  return lo && s[j] === '}' ? { len: j + 1 - i, min: Number(lo), max: hi === undefined ? Number(lo) : hi === '' ? Infinity : Number(hi) } : null;
};
const classEnd = (s: string, i: number): number => {   // s[i] is '[': index just past the closing ']', -1 to bail (an unescaped '[' inside, or unterminated)
  let j = i + 1;
  if (s[j] === '^') j++;
  if (s[j] === ']') j++;
  for (; j < s.length; j++) {
    if (s[j] === '\\') j++;
    else if (s[j] === '[') return -1;
    else if (s[j] === ']') return j + 1;
  }
  return -1;
};
const atomEnd = (s: string, i: number): number => {   // index just past the atom at s[i], -1 to bail
  const c = s[i]!;
  if (c === '[') return classEnd(s, i);
  if (c === '(') {
    if (s[i + 1] === '?') { let j = i + 2; while (s[j]! === '-' || (s[j]! >= 'a' && s[j]! <= 'z') || (s[j]! >= 'A' && s[j]! <= 'Z')) j++; if (s[j] === ')') return -1; }   // a bare (?i) flag setter
    for (let j = i, depth = 0; j < s.length; j++) {
      if (s[j] === '\\') j++;
      else if (s[j] === '[') { if ((j = classEnd(s, j)) < 0) return -1; j--; }
      else if (s[j] === '(') depth++;
      else if (s[j] === ')' && !--depth) return j + 1;
    }
    return -1;
  }
  if (c === '\\') {
    const n = s[i + 1];
    if (n === undefined) return -1;
    if (n === 'x') {   // \x{hex+} or \x + 2 hex
      const hex = (j: number) => s[j] !== undefined && '0123456789abcdefABCDEF'.includes(s[j]!);
      if (s[i + 2] !== '{') return hex(i + 2) && hex(i + 3) ? i + 4 : -1;
      let j = i + 3;
      while (hex(j)) j++;
      return j > i + 3 && s[j] === '}' ? j + 1 : -1;
    }
    if (n >= '0' && n <= '7') { let j = i + 2; while (j < i + 4 && s[j]! >= '0' && s[j]! <= '7') j++; return j; }
    if ('dDwWsSbBAzfnrtv'.includes(n)) return i + 2;
    return (n >= '0' && n <= '9') || (n >= 'a' && n <= 'z') || (n >= 'A' && n <= 'Z') ? -1 : i + 1 + String.fromCodePoint(s.codePointAt(i + 1)!).length;
  }
  if ('|)*+?'.includes(c) || (c === '{' && braceAt(s, i))) return -1;
  return i + String.fromCodePoint(s.codePointAt(i)!).length;
};
export function trimEdgeRepeats(src: string): string {
  if (src.includes('\\Q')) return src;   // camada-all-fsnv: atomEnd misreads a quoted )
  const u: { a: string; q: string; min: number; max: number }[] = [];   // { a: atom text, q: its quantifier + lazy mark, min, max }
  for (let i = 0; i < src.length;) {
    // a|b tests true iff a or b does: trim each side (one may trim to '')
    if (src[i] === '|') return trimEdgeRepeats(src.slice(0, i)) + '|' + trimEdgeRepeats(src.slice(i + 1));
    const e = atomEnd(src, i);
    if (e < 0) return src;
    let q = '', min = 1, max = 1, m: ReturnType<typeof braceAt>;
    const c = src[e];
    if (c && '*?+'.includes(c)) { q = c; min = q === '+' ? 1 : 0; max = q === '?' ? 1 : Infinity; }
    else if (c === '{' && (m = braceAt(src, e))) { q = src.slice(e, e + m.len); ({ min, max } = m); }
    if (q && src[e + q.length] === '?') q += '?';
    u.push({ a: src.slice(i, e), q, min, max });
    i = e + q.length;
  }
  // a whole-pattern unquantified (?:...) or plain (...) group: its inside trimmed, else the group stays
  const g = u.length === 1 && !u[0]!.q ? u[0]!.a : '';
  const k = g.startsWith('(?:') ? 3 : g[0] === '(' && g[1] !== '?' ? 1 : 0;
  if (k) { const inner = g.slice(k, -1), t = trimEdgeRepeats(inner); return t !== inner ? t : src; }
  // for a test anywhere in the value, a match using k >= m copies of an edge repeat contains a match of its m nearest copies, and m = 0 copies drop the unit
  const shrink = (x: (typeof u)[number]) => { if (x.max !== x.min) { x.q = x.min === 1 ? '' : `{${x.min}}`; x.max = x.min; } };
  while (u.length && !u[0]!.min) u.shift();
  if (u.length) shrink(u[0]!);
  while (u.length && !u[u.length - 1]!.min) u.pop();
  if (u.length) shrink(u[u.length - 1]!);
  return u.map((x) => x.a + x.q).join('');
}
/** A customer `matches` pattern as a linear-time matcher; null when re2js refuses it (a stored lookaround, backreference or count over 1000): such a
 *  pattern never matches, as in camada-go, and no native RegExp ever runs (camada-all-rfyr). */
export function compileMatches(p: string, ci: boolean): { test(s: string): boolean } | null {
  const flags = ci ? RE2JS.CASE_INSENSITIVE : 0;
  let re: RE2JS | undefined, src = '';
  try { re = RE2JS.compile(src = jsToRe2(p), flags); } catch { /* fall through */ }
  if (re) {   // outside the try: a failure here must throw, not be read as a refusal
    // camada-all-e20y: a wide edge repeat with no required literal (`[^ ]{0,500}[#%]`) made the DFA give up on every test; trimEdgeRepeats is exact for .test, and a refusal stays a refusal
    const trimmed = trimEdgeRepeats(src);
    if (trimmed !== src) try { re = RE2JS.compile(trimmed, flags); src = trimmed; } catch { /* keep the original */ }
    let pf: Pf | null = null;
    const r2 = re.re2() as ReturnType<RE2JS['re2']> & { prefilter?: Pf | null; prefixComplete?: boolean }, own = Object.hasOwn(r2, 'prefilter');
    const t = ci ? (RE2JS.compile(src).re2() as { prefilter?: Pf | null }).prefilter : r2.prefixComplete === true ? null : r2.prefilter;
    pf = t && typeof t.eval === 'function' && (!ci || foldTree(t).type !== 0) ? t : null;   // CI folds a case-sensitive compile's tree; CS takes re2js's own, unfolded, none when prefix-complete (one indexOf in re2js, already in L + 64)
    r2.prefilter = null;   // re2js never scans uncharged again
    const d = r2.dfa, clear = d.clearCache, match = d.match, step = d.step, n = r2.numberOfInstructions() + REGEX_STATE_WORK;
    if (!own || typeof clear !== 'function' || typeof match !== 'function' || typeof step !== 'function' || typeof d.memBudget !== 'number' || typeof d.stateCount !== 'number') {
      WORK.set(re, { n, d: null, full: true, pf, ci });   // fail closed: re2js internals changed, so every test is charged the full worst case
      return re;
    }
    d.maxMem = d.stateBudget = d.memBudget = RE2_DFA_MAX_MEM;
    d.clearCache = function (this: typeof d) { dfaBuilt += this.stateBudget - this.memBudget; return clear.call(this); };   // the bytes of cache built before a clear (this.memBudget is what is left), for safeTest
    d.match = function (this: typeof d, ...a: Parameters<typeof d.match>) { const r = match.apply(this, a); if (r === null) dfaGiveUps++; return r; };   // null: the DFA gave up and the NFA runs the whole input
    // every transition computed (a table miss) scanned its source state, so it is charged the source's NFA-state count; one whose target was already cached (no new bytes) also closed over the target, so it is charged the target's count + REGEX_STEP_WORK (anchor 0 is RE2Flags.UNANCHORED)
    d.step = function (this: typeof d, s: Parameters<typeof d.step>[0], cls: number, rune: number, anchor: number) { const t = anchor === 0 ? s.next : s.nextAnchored, miss = t == null || t[cls] == null, c0 = this.stateCount, r = step.call(this, s, cls, rune, anchor); if (miss) dfaSteps += (s.nfaStates?.length ?? 0) + (this.stateCount === c0 ? (r?.nfaStates?.length ?? 0) + REGEX_STEP_WORK : 0); return r; };
    WORK.set(re, { n, d, pf, ci });
    return re;
  }
  return null;   // rfyr: a pattern re2js refuses never matches (as in camada-go); no native RegExp runs
}

/** Per-request regex work (camada-all-1oqz), mirrors edge-analyst blocklist.js: a test of a value of length L through n instructions
 *  runs while any of REQUEST_REGEX_WORK is left, so a walk spends at most that plus one test. */
export const REQUEST_REGEX_WORK = 8388608;
/** The fixed cost of one call, added to a program's instruction count for the give-up charge. */
export const REGEX_STATE_WORK = 64;
let regexLeft = Infinity;   // Infinity outside a request rule walk (entity plane, direct .test): unbudgeted
/** The request budget left (read by tests; Infinity outside withRegexBudget). */
export const regexWorkLeft = (): number => regexLeft;
/** The fixed cost of one DFA transition computed to an already-cached state (no new bytes), added to its target state's NFA-state count; every transition computed is charged its source state's NFA-state count. */
export const REGEX_STEP_WORK = 256;
let dfaBuilt = 0, dfaGiveUps = 0, dfaSteps = 0;
const WORK = new WeakMap<object, { n: number; d: { memBudget: number } | null; full?: true; pf: Pf | null; ci: boolean }>();   // full: re2js internals missing, charge the worst case every test

/** Runs a request rule walk (synchronous: the budget is module state) under a fresh REQUEST_REGEX_WORK; nesting-safe. */
export function withRegexBudget<T>(f: () => T): T {
  const prev = regexLeft;
  regexLeft = REQUEST_REGEX_WORK;
  try { return f(); } finally { regexLeft = prev; }
}

/** re.test, except that a match-time engine failure (a RangeError) answers `onError`, like an over-cap value: deny for block/challenge/warn, miss for skip (contract regex-cap-sdk S4).
 *  Inside withRegexBudget a test runs while budget is left (regexLeft > 0), else it answers `onError` unrun. It is charged the full worst case (L+1)(n+64) when re2js's DFA
 *  gave up (the NFA then ran the whole input), else L+64 plus the DFA cache bytes built during the test (re2js's own per-state accounting, memBudget) plus, per DFA transition
 *  computed (real CPU), its source state's NFA-state count, and for one whose target was already cached (no new bytes) also its target's count + REGEX_STEP_WORK. A test first checks the pattern's required literals (camada-all-z8p7, xata): a
 *  case-insensitive one on the case-folded value, a case-sensitive one on the raw value; it adds (CI: 1 fold + literal scans, CS: literal scans) x that value's length to the charge; a rejected value (the regex never ran) costs only that + 64. If the re2js internals wrapped
 *  in compileMatches are missing, every test is charged the full worst case. */
export function safeTest(re: { test(s: string): boolean }, v: string, onError: boolean): boolean {
  if (regexLeft <= 0) return onError;
  const w = WORK.get(re), g0 = dfaGiveUps, b0 = dfaBuilt, s0 = dfaSteps, m0 = w?.d?.memBudget ?? 0;
  let hit: boolean, ran = true;
  pfScans = 0;
  try {
    if (w?.pf) { if (w.ci) { if (v !== pfLast) pfFold = foldValue(pfLast = v); pfIn = pfFold; pfScans = 1; } else pfIn = v; ran = w.pf.eval(PF_IN, 0); hit = ran && re.test(v); }   // the fold is charged as one pass, memoised or not
    else hit = re.test(v);
  } catch { hit = onError; }
  if (w) regexLeft -= pfScans * pfIn.length + (!ran ? REGEX_STATE_WORK : w.full || dfaGiveUps !== g0 ? (v.length + 1) * w.n : v.length + REGEX_STATE_WORK + dfaBuilt - b0 + m0 - w.d!.memBudget + dfaSteps - s0);   // the cache bytes built: those before each clear (dfaBuilt) plus the budget this test used since
  pfIn = '';   // no raw ua or header value stays referenced after the test (the charge needed only its length)
  return hit;
}

/** One v5 path condition -> a predicate over a single path form. A regex this runtime rejects never matches. */
export function pathPred(op: string, values: string[]): PathPred {
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

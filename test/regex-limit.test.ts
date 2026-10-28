// Contract regex-limit v1 (camada-all-2pap): customer `matches` regexes run on a linear-time engine (re2js), so a
// pathological pattern costs bounded time. The vectors are a byte-identical copy shared with the other repos.
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { RE2JS } from 're2js';
import { parseSnapshot, Matcher } from '../src/index.js';
import { regexWorkLeft, ASTRAL_QUANT, ASTRAL_CLASS, compileMatches, jsToRe2, trimEdgeRepeats, MAX_MATCH_INPUT, pathPred, REGEX_STATE_WORK, REGEX_STEP_WORK, REQUEST_REGEX_WORK, RE2_DFA_MAX_MEM, safeTest, withRegexBudget } from '../src/snapshot/path.js';

const REGEX_LIMIT_VECTORS_SHA256 = '95a4a0ceda235f59f7a6224c2b9bb2f6f16445068f07cf7c45a111c6334cd144';
const at = (f: string) => new URL(`./fixtures/${f}`, import.meta.url);
const raw = readFileSync(at('regex-limit/regex-limit-vectors.json'));
const bytes = (f: string) => { const b = readFileSync(at(`blk5/${f}`)); return new Uint8Array(b.buffer, b.byteOffset, b.byteLength); };
const empty = bytes('v5-empty.bin');
const emptyMeta = JSON.parse(readFileSync(at('blk5/v5-empty.meta.json'), 'utf8'));

type Val = string | { prefix?: string; repeat: string; times: number; suffix?: string };
interface Rule { id: string; action: string; conds: Array<{ f: string; op: string; v: string }> }
const val = (v: Val): string => (typeof v === 'string' ? v : (v.prefix ?? '') + v.repeat.repeat(v.times) + (v.suffix ?? ''));
const V = JSON.parse(raw.toString('utf8')) as {
  constants: Record<string, string | number>;
  over_limit: Array<{ id: string; rule: Rule; input: Record<string, Val>; hit: { linear: boolean } }>;
  linear_time: Array<{ id: string; rule: Rule; input: Record<string, Val>; hit: boolean; max_ms: number }>;
  refused: Array<{ id: string; pattern: string; cases: Array<{ ua: Val; hit: { go: boolean } }> }>;
  astral_split: Array<{ id: string; pattern: string; cases: Array<{ ua: Val; hit: { go: boolean; v8: boolean } }> }>;
  accepted_match: Array<{ id: string; pattern: string; cases: Array<{ ua: Val; hit: { go: boolean; native: boolean } }> }>;
  refused_rule: { id: string; action: string; field: string };
  accepted: string[];
  translate: Array<[string, string]>;
  test_rewrite: Array<[string, string]>;
  translate_refused: string[];
};

const best = (f: () => unknown) => {   // best of 3 wall-clock ms
  let b = Infinity;
  for (let i = 0; i < 3; i++) { const t = performance.now(); f(); b = Math.min(b, performance.now() - t); }
  return b;
};

/** Public matcher over a v5 snapshot holding just this rule; hit = the result names the rule. */
const hits = (rule: Rule, input: Record<string, Val>): boolean => {
  const m = new Matcher(parseSnapshot(empty, { ...emptyMeta, rules: [rule] }));
  return m.match(Object.fromEntries(Object.entries(input).map(([k, v]) => [k, val(v)])) as never).rule === rule.id;
};

const LT1 = V.linear_time.find((r) => r.id === 'LT1')!.rule.conds[0].v;
const H1 = '/z' + 'a'.repeat(2046), H3 = '/Z/./' + 'a'.repeat(2043);   // each carries the z LT1 requires, 1 and 3 distinct path forms (z8p7: a CI test of a value without it is rejected by the pre-check)
const mk = (action: string, f: string, v: string, i: number): Rule => ({ id: `cr_${action}${f}${i}`, action, conds: [{ f, op: 'matches', v }] });
const many = (n: number, f: string, v: string) => Array.from({ length: n }, (_, i) => mk('block', f, v, i));
const res = (rules: Rule[], input: { path?: string; ua?: string }) => new Matcher(parseSnapshot(empty, { ...emptyMeta, rules })).match({ ip: '8.8.8.8', ...input } as never);
const run = (rules: Rule[], input: { path?: string; ua?: string }) => res(rules, input).rule;

describe('regex-limit vectors', () => {
  it('are the pinned bytes', () => {
    expect(createHash('sha256').update(raw).digest('hex')).toBe(REGEX_LIMIT_VECTORS_SHA256);
    expect(V.accepted_match.length).toBeGreaterThan(0);
  });

  it('constants match', () => {
    expect(MAX_MATCH_INPUT).toBe(V.constants.MAX_MATCH_INPUT);
    expect(JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).dependencies.re2js).toBe(V.constants.RE2JS_VERSION);
    expect(RE2_DFA_MAX_MEM).toBe(V.constants.RE2_DFA_MAX_MEM);
  });

  it.each(V.over_limit.map((r) => [r.id, r] as const))('over_limit %s answers the linear class', (_id, r) => {
    expect(hits(r.rule, r.input)).toBe(r.hit.linear);
  });

  it.each(V.linear_time.map((r) => [r.id, r] as const))('linear_time %s stays under max_ms', (_id, r) => {
    let got = !r.hit;
    const ms = best(() => { got = hits(r.rule, r.input); });   // best of 3 fresh compiles: still measures the cold DFA build
    expect(got).toBe(r.hit);
    expect(ms).toBeLessThan(r.max_ms);
  });

  const rr = V.refused_rule;
  it.each(V.refused.flatMap((r) => r.cases.map((c, i) => [`${r.id}#${i} ${r.pattern}`, r, c] as const)))('refused %s never matches', (_l, r, c) => {
    expect(() => RE2JS.compile(jsToRe2(r.pattern))).toThrow();
    expect(hits({ id: rr.id, action: rr.action, conds: [{ f: rr.field, op: 'matches', v: r.pattern }] }, { ip: '8.8.8.8', ua: c.ua })).toBe(c.hit.go);   // rfyr: as camada-go, a pattern re2js refuses never matches
    expect(c.hit.go).toBe(false);
  });

  it('astral_split is non-empty', () => expect(V.astral_split.length).toBeGreaterThan(0));
  it.each(V.astral_split.flatMap((r) => r.cases.map((c, i) => [`${r.id}#${i} ${r.pattern}`, r, c] as const)))('astral_split %s', (_l, r, c) => {
    expect(hits({ id: rr.id, action: rr.action, conds: [{ f: rr.field, op: 'matches', v: r.pattern }] }, { ip: '8.8.8.8', ua: c.ua })).toBe(c.hit.go);
    expect(new RegExp(r.pattern).test(val(c.ua))).toBe(c.hit.v8);
  });

  describe('a raw lone surrogate (camada-all-5fxz): a stored one never matches the half', () => {
    const H = String.fromCharCode(0xD83D), L = String.fromCharCode(0xDE00), E = 'x\u{1F600}y';
    it('compileMatches: each form misses x\u{1F600}y and xy', () => {
      for (const p of ['x' + H, L + 'y', 'x' + H + '\\uDE00y', 'x\\uD83D' + L + 'y', 'x' + H + '\\uDE00?y']) {
        const re = compileMatches(p, false);
        expect(re, JSON.stringify(p)).not.toBeNull();
        for (const t of [E, 'xy']) expect(re!.test(t), `${JSON.stringify(p)} ${t}`).toBe(false);
      }
    });
    it('a|x+half still hits a; x[half+a]y hits xay, misses x\u{1F600}y', () => {
      expect(compileMatches('a|x' + H, false)!.test('a')).toBe(true);
      const re = compileMatches('x[' + H + 'a]y', false)!;
      expect(re.test('xay')).toBe(true);
      expect(re.test(E)).toBe(false);
    });
  });

  it.each(V.accepted_match.flatMap((r) => r.cases.map((c, i) => [`${r.id}#${i} ${r.pattern} on ${JSON.stringify(c.ua)}`, r, c] as const)))('accepted_match %s', (_l, r, c) => {
    expect(V.accepted).toContain(r.pattern);
    expect(c.hit.go).toBe(c.hit.native);
    expect(hits({ id: rr.id, action: rr.action, conds: [{ f: rr.field, op: 'matches', v: r.pattern }] }, { ip: '8.8.8.8', ua: c.ua })).toBe(c.hit.go);
    expect(new RegExp(r.pattern).test(val(c.ua))).toBe(c.hit.native);   // V8 is the reference the native SDKs follow
  });

  it.each(V.accepted.map((p) => [p] as const))('accepted %s compiles on re2js', (p) => {
    expect(() => RE2JS.compile(jsToRe2(p))).not.toThrow();
    expect(compileMatches(p, false)).toBeInstanceOf(RE2JS);
  });

  it('a - next to a class escape is refused (never translated); a stored pattern never matches (rfyr)', () => {
    for (const p of V.translate_refused) {
      expect(() => jsToRe2(p), p).toThrow(SyntaxError);
      expect(() => RE2JS.compile(jsToRe2(p)), p).toThrow();
      expect(compileMatches(p, false), p).toBeNull();
      expect(compileMatches(p, true), p).toBeNull();
    }
    for (const p of ['[-\\sz]', '[\\s-]', '[a-z\\s]']) {
      expect(() => RE2JS.compile(jsToRe2(p)), p).not.toThrow();
      expect(compileMatches(p, false) instanceof RegExp, p).toBe(false);
    }
  });

  it('a - after a finished class range is a literal and compiles (camada-all-uged; the vectors\' accepted_match rows hold the rest)', () => {
    const cases: [string, string[], string[]][] = [['x[a-b-\\d]y', ['xay'], []], ['x[\\x41-\\x5a-\\w]y', ['x_y'], []], ['x[\\u0041-\\u005a-\\w]y', ['xAy', 'x-y', 'x_y'], ['x.y']], ['x[\\x01-\\cB-\\d]y', ['x\x01y', 'x-y', 'x5y'], ['xay']], ['x[\\x00-\\x41-\\d]y', ['xAy', 'x-y', 'x5y'], ['xay']]];
    for (const [p, yes, no] of cases) {
      const re = compileMatches(p, false), js = new RegExp(p);
      expect(re, p).not.toBeNull();   // null when jsToRe2 throws
      for (const s of yes) expect([re!.test(s), js.test(s)], s).toEqual([true, true]);
      for (const s of no) expect([re!.test(s), js.test(s)], s).toEqual([false, false]);
    }
  });

  it('a bare \\c in a class is two atoms (camada-all-uged r2)', () => {
    expect(() => jsToRe2('x[!-\\c-\\w]y')).toThrow(SyntaxError);
    expect(() => jsToRe2('[\\s-\\x41-z]')).toThrow(SyntaxError);   // camada-all-kfe1: \x41 is one atom, so the - after it still meets \s
  });

  it('a legacy octal escape, in or out of [ ], is one atom, as V8 reads it (camada-all-0ksq, camada-all-sm1u)', () => {
    expect(jsToRe2('x[\\400]y')).toBe('x[\\0400]y');
    expect(jsToRe2('x[\\12]y')).toBe('x[\\012]y');
    expect(jsToRe2('x[\\1]y')).toBe('x[\\01]y');
    expect(jsToRe2('x\\400y')).toBe('x\\0400y');
    expect(jsToRe2('x\\777y')).toBe('x\\0777y');
    expect(jsToRe2('x\\40y')).toBe('x\\40y');
    for (const p of ['x[\\0-\\12-\\d]y', 'x[\\400]y', 'x[\\777]y', 'x[\\377]y', 'x[\\08]y', 'x[\\40]y', 'x[\\1]y', 'x[\\7]y', 'x[\\1-\\3]y', 'x[\\12]y', 'x\\400y', 'x\\777y', 'x\\377y', 'x\\40y']) {
      const re = new RegExp(p), r2 = compileMatches(p, false)!, bad: string[] = [];
      expect(r2, p).not.toBeNull();
      for (let c = 0; c < 0x10000; c++) {
        if (c >= 0xd800 && c <= 0xdfff) continue;
        const s = 'x' + String.fromCharCode(c) + 'y';
        if (r2.test(s) !== re.test(s)) bad.push(c.toString(16));
        const s0 = 'x' + String.fromCharCode(c) + '0y';   // a trailing 0 is a literal, not a third octal digit
        if (r2.test(s0) !== re.test(s0)) bad.push(c.toString(16) + '0');
      }
      expect(bad, p).toEqual([]);
    }
  });
  it.each(V.translate)('translate %s', (from, to) => {
    expect(jsToRe2(from)).toBe(to);
  });
});

it('jsToRe2 reads \\S inside [ ] as JS does (camada-all-ao29)', () => {
  for (const s of ['x y', 'x\u00a0y']) expect(compileMatches('x[\\S]y', false)!.test(s), s).toBe(false);
  for (const p of ['x[\\S]y', 'x[^\\S]y', 'x[a\\S]y'])
    for (const ci of [false, true]) {
      const re = new RegExp(p, ci ? 'i' : ''), r2 = compileMatches(p, ci)!, bad: string[] = [];
      for (let c = 0; c < 0x10000; c++) {
        if (c >= 0xd800 && c <= 0xdfff) continue;
        const s = 'x' + String.fromCharCode(c) + 'y';
        if (r2.test(s) !== re.test(s)) bad.push(c.toString(16));
      }
      expect(bad, `${p} ${ci}`).toEqual([]);
    }
});

describe('kdq0: a [ inside a class is literal', () => {
  it('escapes the [ in a class, not the one that opens it', () => {
    for (const [from, to] of [['x[[:alpha:]]y', 'x[\\[:alpha:]]y'], ['x[^[:a:]]y', 'x[^\\[:a:]]y'], ['x[a[]y', 'x[a\\[]y'], ['x[\\[:a:]]y', 'x[\\[:a:]]y']]) expect(jsToRe2(from), from).toBe(to);
  });

  it('matches as JS does', () => {
    for (const p of ['x[[:alpha:]]y', 'x[[:x:]]y', 'x[^[:a:]]y', 'x[[:a]y|b:]', 'x[[:]y', 'x[a[:]y']) {
      for (const ci of [false, true]) {
        const re = compileMatches(p, ci);
        expect(re, p).not.toBeNull();
        for (const s of ['xa]y', 'xby', 'x[]y', 'x:]y', 'xA]y', 'xb]y', 'xay', 'x[y', 'b:]']) expect(re!.test(s), `${p} ${ci} ${s}`).toBe(new RegExp(p, ci ? 'i' : '').test(s));
      }
    }
  });
});

// camada-all-1oqz: a per-request regex work budget (mirrors edge-analyst blocklist.js).
describe('1oqz: per-request regex work budget', () => {
  const UA_HIT = 4;   // the ua is one form: rules 0-3 run, rule 4 finds the budget spent
  const LT2 = V.linear_time.find((r) => r.id === 'LT2')!.rule.conds[0].v;
  const P8 = '(?:a[^ ]{0,500}dQ|b[^ ]{0,500}kQ|c[^ ]{0,500}mQ|e[^ ]{0,500}pQ|f[^ ]{0,500}rQ|g[^ ]{0,500}tQ|h[^ ]{0,500}vQ|j[^ ]{0,500}xQ)';   // 8 branches of ~1000 instructions each, never gives up on a short path
  const UA_BENIGN = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0';

  it('REQUEST_REGEX_WORK is 8388608 and a call costs 64', () => {
    expect(REQUEST_REGEX_WORK).toBe(8388608);
    expect(REGEX_STATE_WORK).toBe(64);
    expect(REGEX_STEP_WORK).toBe(256);
  });

  it('a test runs while budget is left, so a walk spends at most the budget plus one test', () => {
    const res = Array.from({ length: 200 }, () => compileMatches(LT1, true)!);
    // LT1 on H1 gives up to the NFA, so each test is charged the full W = 2049 x (1191 + 64) = ~2.57 M: the fourth starts with ~0.7 M of 8.39 M left and runs, the rest find none left
    expect(withRegexBudget(() => res.map((re) => safeTest(re, H1, true)))).toEqual([false, false, false, false, ...Array(196).fill(true)]);
  }, 30_000);

  it('outside a request walk nothing is budgeted', () => {
    const res = Array.from({ length: 3 }, () => compileMatches(LT1, true)!);
    expect(res.map((re) => safeTest(re, H1, true))).toEqual([false, false, false]);
  }, 30_000);

  it('a nested walk restores the outer budget, also when it throws', () => {
    const [a, b, c, d, e, f, g, h, i] = Array.from({ length: 9 }, () => compileMatches(LT1, true)!);
    withRegexBudget(() => {
      for (const r of [a, b, c, d]) expect(safeTest(r, H1, true)).toBe(false);   // the outer walk spends its budget: four tests of ~2.57 M, the fourth starting with ~0.7 M left
      withRegexBudget(() => expect(safeTest(e, H1, true)).toBe(false));   // a nested walk starts fresh
      expect(safeTest(f, H1, true)).toBe(true);   // the outer budget is still spent
      expect(() => withRegexBudget(() => { throw new Error('x'); })).toThrow('x');
      expect(safeTest(g, H1, true)).toBe(true);   // and still spent after a throw
    });
    expect(safeTest(h, H1, true)).toBe(false);   // unbudgeted after
    expect(safeTest(i, H1, true)).toBe(false);
  }, 30_000);

  it('N stored LT1 rules: a bounded walk that answers like over-cap', () => {
    const rules = many(200, 'path', LT1), uas = many(200, 'ua', '[^/]{1000}x');   // a ua rule compiles case-sensitive, where LT1 on 'a's is cheap (re2js skips a value lacking the literal z); this one costs ~20 ms on UA below
    for (let i = 0; i < 2; i++) {   // twice, same answer: the budget is per request
      expect(run(rules, { path: H1 })).toBe(rules[4].id);   // rules 0-3 run (a miss each), rule 4 finds the budget spent
      expect(run(rules, { path: H3 })).toBe(rules[1].id);   // rule 0 runs its three forms (~2.5 M each, a miss), rule 1 runs the first and finds none left for the second
      expect(run(uas, { path: '/', ua: 'a'.repeat(1500) + '/' + 'a'.repeat(546) + 'x' })).toBe(uas[UA_HIT].id);
    }
  }, 30_000);

  it('over the budget a deny rule hits and a skip rule misses', () => {
    // four LT1 rules run (a miss each) and spend the budget; the skip would match '^/' and let the request through, but it does not run and misses; the last block does not run and hits
    const rules = [...many(4, 'path', LT1), mk('skip', 'path', '^/', 4), mk('block', 'path', '^/', 5)];
    expect(run(rules, { path: H1 })).toBe(rules[5].id);
  }, 30_000);

  it('no rule fires on harmless input after a cache clear (regression: a clear charged the full worst case)', () => {
    expect(run([mk('block', 'path', '[^/]{1000}x', 0)], { path: '/Static/./' + 'b'.repeat(2030) })).toBeUndefined();
    expect(run(many(3, 'path', '^/.{1000}z'), { path: '/' + 'b'.repeat(2040) })).toBeUndefined();
  }, 30_000);

  it('a pattern of more than 1983 instructions still runs on a long value (regression: a reservation refused it)', () => {
    expect(run([mk('block', 'ua', '[^/]{999}[^/]{999}[^/]{999}x', 0)], { path: '/', ua: 'Mozilla/5.0 ' + 'c'.repeat(1400) })).toBeUndefined();
  }, 30_000);

  it('cheap rules never reach the budget', () => {
    expect(run(many(200, 'path', 'sqlmap|nikto'), { path: H3 })).toBeUndefined();
  }, 30_000);

  // regression (review): a cold test that does not give up is charged the DFA bytes it built, not the program size per state; fresh Matcher each, three requests in a row, none may hit
  it.each([
    ['P8 on a short path', 'path', P8, { path: '/products/item-123/reviews' }],
    ['P8 on a three-form path', 'path', P8, { path: '/Shop/Products/./Item-123/Reviews' }],
    ['three [^/]{999} on a browser ua', 'ua', '[^/]{999}[^/]{999}[^/]{999}x', { path: '/', ua: UA_BENIGN }],
  ])('200 cold rules on benign input: %s gives no rule', (_n, f, p, input) => {
    const m = new Matcher(parseSnapshot(empty, { ...emptyMeta, rules: many(200, f, p) }));
    for (let i = 0; i < 3; i++) expect(m.match({ ip: '8.8.8.8', ...input } as never).rule).toBeUndefined();
  }, 60_000);

  it('the give-up counter and the re2js DFA wraps are wired', () => {
    const re = compileMatches(LT1, true) as RE2JS, d = re.re2().dfa;
    expect(Object.hasOwn(d, 'clearCache')).toBe(true);
    expect(Object.hasOwn(d, 'match')).toBe(true);
    expect(Object.hasOwn(d, 'step')).toBe(true);   // CI tripwire for an re2js upgrade: without the internals the budget fails closed (every test charged the worst case); the 46-branch test below catches a wrap that stops being called
    // LT1 on H1 gives up (counted): four tests are charged the full ~2.57 M each, so a fifth finds nothing left
    const three = Array.from({ length: 5 }, () => compileMatches(LT1, true)!);
    expect(withRegexBudget(() => three.map((r) => safeTest(r, H1, true)))).toEqual([false, false, false, false, true]);
    // the same patterns on a harmless short path build a few states and never give up: 200 of them all run
    const many200 = Array.from({ length: 200 }, () => compileMatches(LT1, true)!);
    expect(withRegexBudget(() => many200.map((r) => safeTest(r, '/a', true)))).toEqual(Array(200).fill(false));
  }, 30_000);

  it('200 LT1 rules x 3 path forms cost one bounded walk', () => {
    const rules = many(200, 'path', LT1);
    const m = new Matcher(parseSnapshot(empty, { ...emptyMeta, rules }));
    let rule: string | undefined;
    const ms = best(() => { rule = m.match({ ip: '8.8.8.8', path: H3 }).rule; });
    expect(rule).toBe(rules[1].id);
    expect(ms).toBeLessThan(500);   // bounded vs ~16 s unbounded; loose for slow CI runners
  }, 60_000);

  it('200 rules of a 46-branch `$` pattern on a 2 KiB user agent: DFA transitions to cached states are charged', () => {
    const L46 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRST';
    const P46 = '(?:' + [...L46].map((c) => c + '$').join('|') + ')';
    let seed = 7;
    const ua = Array.from({ length: 2047 }, () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return L46[seed % 46]; }).join('') + '-';
    const rules = many(200, 'ua', P46);
    const m = new Matcher(parseSnapshot(empty, { ...emptyMeta, rules }));
    const first = m.match({ ip: '8.8.8.8', path: '/', ua } as never).rule;   // the cold request
    expect(first).toBe(rules[30].id);   // the budget engaged (deterministic: seeded UA, charges are counts): rules 0-29 run and miss, rule 30 finds it spent and hits
    const ms = best(() => m.match({ ip: '8.8.8.8', path: '/', ua } as never));
    expect(ms).toBeLessThan(500);
  }, 60_000);

  it('the worst shape found stays under the stated bound', () => {
    const m = new Matcher(parseSnapshot(empty, { ...emptyMeta, rules: many(200, 'path', LT2) }));
    const ms = best(() => m.match({ ip: '8.8.8.8', path: '/A/./' + 'a'.repeat(95) }));
    expect(ms).toBeLessThan(500);   // bounded vs unbounded; loose for slow CI runners
  }, 60_000);
});

// camada-all-rfyr: a stored pattern re2js refuses never matches (as in camada-go); no native RegExp runs.
describe('rfyr: a pattern re2js refuses never matches', () => {
  const RF = V.refused.map((r) => r.pattern);
  const EXTRA = ['(?:a{99}|a{99}){12}z', '[\\s-z]', '[\\w-.]+@x', '(a)\\1', 'a{01001}'];
  const REFUSED = '(?:a{99}|a{99}){12}z';

  it.each([...RF, ...EXTRA].map((p) => [p] as const))('rfyr: %s compiles to null', (p) => {
    expect(compileMatches(p, true)).toBeNull();
    expect(compileMatches(p, false)).toBeNull();
  });

  it('rfyr: a refused skip rule does not exempt', () => {
    const blk: Rule = { id: 'cr_blk', action: 'block', conds: [{ f: 'ip', op: 'is_not', v: '1.1.1.1' }] };
    const r = res([mk('skip', 'ua', V.refused[0].pattern, 0), blk], { ua: 'Mozilla/5.0 Firefox/130.0' });
    expect(r.allowed).toBe(false);
    expect(r.rule).toBe('cr_blk');
  });

  it('rfyr: a{01001} never matches a{1001}', () => {
    expect(hits(mk('block', 'ua', 'a{01001}', 0), { ip: '8.8.8.8', ua: 'a'.repeat(1001) })).toBe(false);
  });

  it('rfyr: N stored refused rules spend no regex work', () => {
    const refused = Array.from({ length: 200 }, () => pathPred('matches', [REFUSED]));
    const lt1 = Array.from({ length: 5 }, () => compileMatches(LT1, true)!);
    const out = withRegexBudget(() => [...refused.map((p) => p(H1, true)), ...lt1.map((re) => safeTest(re, H1, true))]);
    expect(out).toEqual([...Array(200).fill(false), false, false, false, false, true]);   // 4 run, then over: the same as with no refused rules
  }, 30_000);

  it('rfyr: 200 refused + 200 LT1 path rules cost one bounded walk', () => {
    const rules = [...many(200, 'path', REFUSED), ...many(200, 'path', LT1)].map((r, i) => ({ ...r, id: `cr_${i}` }));
    const m = new Matcher(parseSnapshot(empty, { ...emptyMeta, rules }));
    let rule: string | undefined;
    const ms = best(() => { rule = m.match({ ip: '8.8.8.8', path: H3 }).rule; });
    expect(rule).toBe(rules[201].id);
    expect(ms).toBeLessThan(500);   // measured 114-117 ms; today minutes
  }, 60_000);
});

// camada-all-7ztr, camada-all-510r: a stored `matches` value that is not a string, or is '', never matches (no String() coercion, no empty regex).
describe('7ztr, 510r: a non-string or empty matches value never matches', () => {
  const VALS: unknown[] = [123, 0, true, null, { x: 1 }, ['^/a'], [123], ''];   // '': an empty regex would match everything (camada-all-510r)
  const STR = '123 null 0 true [object Object]';   // every String()-coerced form of VALS appears in the ua, header and path
  const OVER = 'a'.repeat(MAX_MATCH_INPUT + 1);
  const run7 = (rules: unknown[], over = '') => new Matcher(parseSnapshot(empty, { ...emptyMeta, rules } as never))
    .match({ ip: '8.8.8.8', path: over === 'path' ? `/a/123/null/0/true/${OVER}` : '/a/123/null/0/true', ua: over === 'ua' ? `${STR} ${OVER}` : STR, header: () => (over === 'header' ? `${STR} ${OVER}` : STR) } as never);
  const cond = (f: string, v: unknown) => ({ f, op: 'matches', v, ...(f === 'header' ? { name: 'x-h' } : {}) });
  const blk = { id: 'cr_blk', action: 'block', conds: [{ f: 'ip', op: 'is_not', v: '1.1.1.1' }] };

  for (const v of VALS) for (const f of ['ua', 'path', 'header']) for (const over of ['', f]) {
    it(`${JSON.stringify(v)} on ${f}${over ? ' over the cap' : ''}: block never matches, skip does not exempt`, () => {
      expect(run7([{ id: 'cr_b', action: 'block', conds: [cond(f, v)] }], over).block).toBe(false);
      const r = run7([{ id: 'cr_s', action: 'skip', conds: [cond(f, v)] }, blk], over);
      expect(r.allowed).toBe(false);
      expect(r.rule).toBe('cr_blk');
    });
  }
});

// camada-all-k938: a written surrogate pair right before a quantifier is refused (JS repeats the low unit, RE2 the whole character)
describe('k938: a quantifier right after a written surrogate pair', () => {
  const QUANTS = ['?', '*', '+', '{2}', '{0,2}', '{1,}', '??', '*?', '+?', '{2}?'];
  const PAIRS = ['\u{1F600}', '\\uD83D\\uDE00'];   // raw, then escaped
  // a pair inside [ ] is camada-all-cfx4
  const KEEP = ['x\u{1F600}y', 'x\\uD83D\\uDE00y', 'x\u{1F600}{y', 'x\u{1F600}{a}y', '(?:\u{1F600})?', '(\u{1F600})+', '\u{1F600}|a?'];
  it('jsToRe2 throws ASTRAL_QUANT and compileMatches is null, raw and escaped, ci or not', () => {
    for (const pair of PAIRS) for (const q of QUANTS) for (const ci of [false, true]) {
      const p = 'x' + pair + q + 'y';
      expect(() => jsToRe2(p), p).toThrow(ASTRAL_QUANT);
      expect(compileMatches(p, ci), p).toBeNull();
    }
  });
  it('the keep-working patterns still translate', () => {
    for (const p of KEEP) { expect(() => jsToRe2(p), p).not.toThrow(); expect(compileMatches(p, false), p).not.toBeNull(); }
  });
  it('x(?:\u{1F600})?y answers as V8', () => {
    const p = 'x(?:\u{1F600})?y', re = compileMatches(p, false)!;
    for (const s of ['xy', 'x\u{1F600}y', 'x\u{1F600}\u{1F600}y']) expect(re.test(s), s).toBe(new RegExp(p).test(s));
  });
});

// camada-all-cfx4: a raw surrogate pair inside [ ] is refused (JS reads the two units, RE2 one code point)
describe('cfx4: a raw astral character inside [ ]', () => {
  const E = '\u{1F600}';
  const REF = [`x[${E}]y`, `x[${E}]?y`, `x[a${E}]y`, `x[${E}a]y`, `x[a-${E}]y`, `x[^${E}]y`, `x[${E}-\u{1F602}]y`, `x[\\]${E}]y`, `x[[${E}]y`, `[${E}]`, `x[${E}-￿]y`, `x[${E}]+y`, `x[a-${E}-\\d]y`];
  const KEEP = ['x[a-z]y', 'x[\\x41-\\x5a]y', 'x[é]y', 'x[\\uD83D\\uDE00]y', 'x[^\\uD83D\\uDE00]y', 'x[\\uD83D]y', `x${E}y`, `x(?:${E})y`, `x(?:${E}|a)y`, `x(?:${E}|a)+y`, `x(?:${E})?y`, `x(?:[a-z]|${E})y`, `x\\[${E}]y`, `x[^]${E}y`, `x[]${E}y`];
  it('jsToRe2 throws ASTRAL_CLASS and compileMatches is null, ci or not', () => {
    for (const p of REF) for (const ci of [false, true]) {
      expect(() => jsToRe2(p), p).toThrow(ASTRAL_CLASS);
      expect(compileMatches(p, ci), p).toBeNull();
    }
  });
  it('the keep-working patterns still translate and compile', () => {
    for (const p of KEEP) { expect(() => jsToRe2(p), p).not.toThrow(); for (const ci of [false, true]) expect(compileMatches(p, ci), p).not.toBeNull(); }
  });
  it('the group-with-| rewrites answer as V8', () => {
    for (const p of [`x(?:${E}|a)y`, `x(?:${E})?y`]) {
      const re = compileMatches(p, false)!;
      for (const s of ['xy', `x${E}y`, `x${E}${E}y`, 'xay']) expect(re.test(s), p + ' ' + s).toBe(new RegExp(p).test(s));
    }
  });
});

// camada-all-z8p7: a case-insensitive test checks the pattern's required literals on the case-folded value before re2js runs, and charges every scan at the value's length.
const WIDE = '[^/]{256}\\.(?:php|aspx?|jsp)';
const charge = (p: string | { test(s: string): boolean }, v: string, ci = true): { hit: boolean; spent: number } => withRegexBudget(() => {   // a pattern, or a compiled one to reuse
  const re = typeof p === 'string' ? compileMatches(p, ci)! : p, hit = safeTest(re, v, true);
  return { hit, spent: REQUEST_REGEX_WORK - regexWorkLeft() };
});
const fresh = (p: string, v: string, ci = true) => RE2JS.compile(jsToRe2(p), ci ? RE2JS.CASE_INSENSITIVE : 0).test(v);

describe('z8p7: case-insensitive literal pre-check', () => {
  const P = WIDE;
  const BENIGN = '/download/' + 'aB3'.repeat(134) + '/report-2';   // 421 characters, no '.', so the pre-check rejects after the '.' literal

  it('a benign path lacking the literal answers false, charged (fold + scans) x L + 64', () => {
    const L = BENIGN.length;
    expect(L).toBe(421);
    expect(charge(P, BENIGN)).toEqual({ hit: false, spent: 2 * L + 64 });   // 906: the fold and the '.' scan; the regex never ran
  });

  it('round 3: 30 such rules and a later `\\.env$` block rule do not fire on a long benign download path', () => {
    const v = '/download/' + 'aB3'.repeat(133) + '/report.pdf';
    const rules = [...many(30, 'path', P), mk('block', 'path', '\\.env$', 30)];
    expect(run(rules, { path: v })).toBeUndefined();
  });

  it('fold soundness: the answer equals a fresh case-insensitive compile', () => {
    const cases: Array<[string, string[]]> = [
      ['PHP', ['/x.php', '/X.PhP', '/x.pdf']],
      ['ks', ['/Kſ', '/Ks', '/ks', '/k']],
      ['é', ['/É', '/é', '/e']],
      ['İ', ['/İ', '/i', '/I']],
      ['\\.(?:PHP|aspx?)$', ['/a.ASP', '/a.aspx', '/a.ASPX', '/a.p']],
      ['x[0]y', ['/x0y', '/X0Y', '/xy']],
    ];
    for (const [p, vs] of cases) for (const v of vs) expect(charge(p, v).hit, `${p} ${v}`).toBe(fresh(p, v));
  });

  it('seeded differential: random patterns x values, case-sensitive and not, equal a fresh re2js compile (its own prefilter on), and re2js keeps no tree of its own', () => {
    let seed = 42;
    const rnd = (n: number) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
    const A = ['a', 'A', 'k', 'K', 's', 'ſ', 'K', 'İ', 'ı', 'é', 'É', 'ß', '中', '😀', '\ud800', '\ufffd', 'p', 'h', '.', '/', '0', '1', 'x', 'x'.repeat(300)];
    const atom = () => { const a = A[rnd(A.length)]; return a === '.' ? '\\.' : a === '\ud800' ? '\\x{d800}' : a; };
    const piece = (): string => {
      const r = rnd(9);
      if (r === 0) return '(?:' + atom() + atom() + '|' + atom() + ')';
      if (r === 1) return '[' + atom() + atom() + ']';
      if (r === 2) return atom() + '+';
      if (r === 3) return atom() + '*';
      if (r === 4) return '.' + '*';
      if (r === 5) return atom() + '{2}';
      return atom();
    };
    for (let i = 0; i < 2000; i++) {
      const p = Array.from({ length: 1 + rnd(4) }, piece).join('');
      for (const ci of [false, true]) {
        let re; try { re = compileMatches(p, ci); } catch { continue; }
        if (!re) continue;
        expect((re as unknown as { re2(): { prefilter: unknown } }).re2().prefilter, p).toBeNull();
        for (let j = 0; j < 5; j++) {
          const v = Array.from({ length: 1 + rnd(8) }, () => A[rnd(A.length)]).join('');
          expect(safeTest(re, v, true), `${ci} ${p} ${JSON.stringify(v.slice(0, 12))}`).toBe(fresh(p, v, ci));
        }
      }
    }
  });

  it('charge pins: a passing AND adds 3 x L, an OR miss costs 2 x L + 64', () => {
    const v = 'ab' + 'x'.repeat(98) + 'cd';
    expect(charge('ab.*cd', v)).toEqual({ hit: true, spent: 2837 });   // 2531 without the pre-check + 3 x 102 (fold, 'ab', 'cd')
    expect(charge('(?:foo|bar|baz)', 'x'.repeat(100))).toEqual({ hit: false, spent: 2 * 100 + 64 });   // fold + one Aho-Corasick pass
  });

  it('an AND of only non-ASCII literals gets no pre-check and no fold charge', () => {
    expect(charge('é[^/]*ü', BENIGN)).toEqual({ hit: fresh('é[^/]*ü', BENIGN), spent: 1720 });   // the DFA's own charge for this value; no fold term (a pre-check would add 421)
  });

  it('tripwire on re2js internals: the prefilter tree has the shape compileMatches reads', () => {
    const a = RE2JS.compile('abc').re2().prefilter;
    expect(a.type).toBe(1);
    expect(a.str).toBe('abc');
    const o = RE2JS.compile('(?:foo|bar)').re2().prefilter;
    expect(o.type).toBe(3);
    expect(o.subs.every((s: { type: number }) => s.type === 1)).toBe(true);
    expect(typeof o.eval).toBe('function');
    expect(typeof o.automaton16().searchUTF16).toBe('function');
  });
});

describe('xata: case-sensitive literal pre-check is charged', () => {
  const TOKEN_PATH = '/download/' + 'a'.repeat(400) + '/report.pdf';   // 421 characters
  const C36 = '0123456789abcdefghijklmnopqrstuvwxyz', lits = Array.from({ length: 32 }, (_, i) => 'a' + C36[i + 1]);
  const P_MISS = lits.slice(0, 31).join('.') + '.zz', tail = lits.join('.'), UA = 'a'.repeat(2048 - tail.length) + tail;

  it('charge pins', () => {
    const v = 'ab' + 'x'.repeat(98) + 'cd', cs = (p: string, s: string) => charge(p, s, false);
    expect(cs(WIDE, TOKEN_PATH)).toEqual({ hit: false, spent: 906 });   // 2L + 64: the '.' scan and one pass, rejected
    expect(cs('ab.*cd', v)).toEqual({ hit: true, spent: 2535 });   // 2331 + 2 x 102
    expect(cs('(?:foo|bar|baz)', 'x'.repeat(100))).toEqual({ hit: false, spent: 164 });   // 1 AC pass + 64
    expect(cs('sqlmap', 'x'.repeat(100))).toEqual({ hit: false, spent: 164 });   // prefix-complete: no tree
    expect(cs('é[^/]*ü', TOKEN_PATH)).toEqual({ hit: false, spent: 485 });   // one scan of a non-ASCII literal
    expect(cs(P_MISS, UA)).toEqual({ hit: false, spent: 65600 });   // 32 x 2048 + 64
    expect(cs(lits.join('.'), UA).spent).toBeGreaterThanOrEqual(33 * 2048 + 64);
  });

  it('memo hazard: CI, CS, CI on one value charges the CI scans at the folded length, the CS at the raw one', () => {
    const v = 'İ'.repeat(8) + '/x.phq', fold = v.toLowerCase().replace(/ſ/g, 's').length, ci = compileMatches('\\.php', true)!, cs = compileMatches('x\\.p.r', false)!;
    expect(fold).not.toBe(v.length);
    const out = [charge(ci, v), charge(cs, v), charge(ci, v)];
    expect(out.map((o) => o.spent)).toEqual([2 * fold + 64, 2 * v.length + 64, 2 * fold + 64]);   // CI: fold + '.php' at the folded length; CS: its two literals at the raw length; each rejected
    expect(out.map((o) => o.hit)).toEqual([false, false, false]);
  });

  it('tripwires on re2js internals', () => {
    expect(Object.hasOwn(RE2JS.compile('a').re2(), 'prefilter')).toBe(true);
    expect((RE2JS.compile('sqlmap').re2() as { prefixComplete?: boolean }).prefixComplete).toBe(true);
    const c = RE2JS.compile('^curl/').re2() as { prefixComplete?: boolean; prefilter: { type: number } };
    expect(c.prefixComplete).toBe(false);
    expect(c.prefilter.type).toBe(1);
    const src = String((RE2JS.compile('a').re2().constructor as { prototype: { executeEngine: unknown } }).prototype.executeEngine);
    expect(src).toMatch(/prefixComplete[\s\S]*this\.prefilter\.eval\(/);
  });

  it('HU2: 200 rules x one 31-of-32 miss on a 2048-char ua spend the budget and fire rules[128]', () => {
    const rules = many(200, 'ua', P_MISS);
    expect(run(rules, { path: '/', ua: UA })).toBe(rules[128].id);
  });
});

// camada-all-e20y: compileMatches trims a pattern's top-level edge repeats; the answers must not change
describe('e20y: trimEdgeRepeats is exact for a test', () => {
  it.each(V.test_rewrite)('test_rewrite %s', (from, to) => {
    expect(trimEdgeRepeats(jsToRe2(from))).toBe(to);
  });

  it('\\Q anywhere leaves the source unchanged (camada-all-fsnv)', () => {
    for (const q of ['(?:\\Q)*(\\Q\\E)', 'a*\\Qb\\E']) expect(trimEdgeRepeats(q)).toBe(q);
  });
  it('a lookaround opener is not a group: its inside is not trimmed', () => {
    for (const q of ['(?=a*)b', '(?<=a*)b', '(?!a*)b', 'b(?<!a*)']) expect(trimEdgeRepeats(q)).toBe(q);
  });
  it('a long top-level alternation does not grow the stack (camada-all-6vhn)', () => {
    expect(trimEdgeRepeats('a*|'.repeat(20000) + 'b')).toBe('|'.repeat(20000) + 'b');
  });

  it('a refusal stays a refusal: the rewrite never rescues a pattern re2js refuses', () => {
    expect(compileMatches('a{0,1001}b', false)).toBeNull();
  });

  it('3000 seeded patterns answer as the untrimmed compile', () => {
    let seed = 20240611;
    const rnd = (n: number) => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed % n; };
    const pick = <T,>(a: T[]): T => a[rnd(a.length)]!;
    const atoms = ['a', 'b', '[ab]', '[^ ]', '(?:ab)', '(a|b)', '\\d', '.', '^', '$', '\\b', '#', '\\x{62}', '\\pL', '\\141', '[]a]', '{', '(?i:a)', '(a*b)', '(?:b|a+)', '(?i:a?b)'], quants = ['', '*', '+', '?', '{0,3}', '{2}', '{1,3}', '{2,}', '*?', '+?'];
    const unit = () => pick(atoms) + pick(quants);
    const seq = () => Array.from({ length: 1 + rnd(4) }, unit).join('');
    const chars = 'ab 1#\n';
    let compiled = 0, trimmed = 0;
    for (let i = 0; i < 3000; i++) {
      const body = rnd(6) ? seq() : `${seq()}|${seq()}`;
      const p = pick([body, `(?:${body})`, `(${body})`, body, `(?:${body})${seq()}`, `${seq()}(${body})`]);   // some whole-group-wrapped, some an edge group beside more atoms
      const ins = Array.from({ length: 4 }, () => Array.from({ length: rnd(13) }, () => chars[rnd(chars.length)]).join(''));
      let src: string;
      try { src = jsToRe2(p); } catch { continue; }
      for (const ci of [false, true]) {
        let orig: RE2JS;
        try { orig = RE2JS.compile(src, ci ? RE2JS.CASE_INSENSITIVE : 0); } catch { continue; }
        compiled++;
        if (trimEdgeRepeats(src) !== src) trimmed++;
        const re = compileMatches(p, ci)!;
        for (const s of ins) expect(re.test(s), `${p} ${ci} ${JSON.stringify(s)}`).toBe(orig.test(s));
      }
    }
    expect(compiled).toBeGreaterThan(3000);
    expect(trimmed).toBeGreaterThan(1000);   // the fuzz does exercise the rewrite
  });

  it.each(['[^ ]{0,500}[#%]', '(?:[^ ]{0,500}[#%])', '([^ ]{0,500}[#%])', '[#%]|[^ ]{0,500}[#%]', '[^ ]{0,500}[#%]|zzz', '(?:[^ ]{0,500}[#%])+', '(?:[^ ]{0,500}[#%]|zzz)x?', '(?:[^ ]{0,500})[#%]', '(?i:[^ ]{0,500}[#%])', '(?:[^ ]{0,500}[#%]){1}'])('round 4: six wide header rules (%s) no longer spend the request budget, so the next rule is not a false deny', (wide: string) => {
    const cookie = 'a'.repeat(1536);
    const spent = withRegexBudget(() => { for (let i = 0; i < 6; i++) safeTest(compileMatches(wide, false)!, cookie, true); return REQUEST_REGEX_WORK - regexWorkLeft(); });
    expect(spent).toBeLessThan(100_000);
    const c = (v: string) => ({ f: 'header', op: 'matches', name: 'cookie', v });
    const rules = [...Array.from({ length: 6 }, (_, i) => ({ id: `cr_w${i}`, action: 'block', conds: [c(wide)] })), { id: 'cr_zzz', action: 'block', conds: [c('zzz')] }];
    expect(new Matcher(parseSnapshot(empty, { ...emptyMeta, rules } as never)).match({ ip: '8.8.8.8', path: '/', ua: 'x', header: (n: string) => (n === 'cookie' ? cookie : null) } as never).rule).toBeUndefined();
  });
});

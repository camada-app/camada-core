// Contract regex-limit v1 (camada-all-2pap): customer `matches` regexes run on a linear-time engine (re2js), so a
// pathological pattern costs bounded time. The vectors are a byte-identical copy shared with the other repos.
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { RE2JS } from 're2js';
import { parseSnapshot, Matcher } from '../src/index.js';
import { compileMatches, jsToRe2, MAX_MATCH_INPUT, REGEX_STATE_WORK, REGEX_STEP_WORK, REQUEST_REGEX_WORK, safeTest, withRegexBudget } from '../src/snapshot/path.js';

const REGEX_LIMIT_VECTORS_SHA256 = '9a953df1c928148a7cb5b9ab421d409945f05f27d92e147aac742bc7b4f0a987';
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
  refused: Array<{ id: string; pattern: string; cases: Array<{ ua: Val; hit: { native: boolean } }> }>;
  refused_rule: { id: string; action: string; field: string };
  accepted: string[];
  translate: Array<[string, string]>;
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

describe('regex-limit vectors', () => {
  it('are the pinned bytes', () => {
    expect(createHash('sha256').update(raw).digest('hex')).toBe(REGEX_LIMIT_VECTORS_SHA256);
  });

  it('constants match', () => {
    expect(MAX_MATCH_INPUT).toBe(V.constants.MAX_MATCH_INPUT);
    expect(JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).dependencies.re2js).toBe(V.constants.RE2JS_VERSION);
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
  it.each(V.refused.flatMap((r) => r.cases.map((c, i) => [`${r.id}#${i} ${r.pattern}`, r, c] as const)))('refused %s falls back to native', (_l, r, c) => {
    expect(() => RE2JS.compile(jsToRe2(r.pattern))).toThrow();
    expect(hits({ id: rr.id, action: rr.action, conds: [{ f: rr.field, op: 'matches', v: r.pattern }] }, { ip: '8.8.8.8', ua: c.ua })).toBe(c.hit.native);
  });

  it.each(V.accepted.map((p) => [p] as const))('accepted %s compiles on re2js', (p) => {
    expect(() => RE2JS.compile(jsToRe2(p))).not.toThrow();
    expect(compileMatches(p, false)).toBeInstanceOf(RE2JS);
  });

  it('a - next to a class escape is refused (never translated); a stored pattern runs on the native RegExp', () => {
    for (const p of ['[\\s-z]', '[a-\\d]', '[\\s-a-b-e]', '[\\s-\\x41-z]']) {
      expect(() => jsToRe2(p), p).toThrow(SyntaxError);
      expect(() => RE2JS.compile(jsToRe2(p)), p).toThrow();
      const re = compileMatches(p, false);
      expect(re instanceof RegExp, p).toBe(true);
      for (const t of ['a', 'b', 'c', 'e', 'z', 'A', '-', ' ', '5', '_']) expect(re!.test(t), `${p} ${t}`).toBe(new RegExp(p).test(t));
    }
    for (const p of ['[-\\sz]', '[\\s-]', '[a-z\\s]']) {
      expect(() => RE2JS.compile(jsToRe2(p)), p).not.toThrow();
      expect(compileMatches(p, false) instanceof RegExp, p).toBe(false);
    }
  });

  it.each(V.translate)('translate %s', (from, to) => {
    expect(jsToRe2(from)).toBe(to);
  });
});

// camada-all-1oqz: a per-request regex work budget (mirrors edge-analyst blocklist.js).
describe('1oqz: per-request regex work budget', () => {
  const UA_HIT = 4;   // the ua is one form: rules 0-3 run, rule 4 finds the budget spent
  const LT1 = V.linear_time.find((r) => r.id === 'LT1')!.rule.conds[0].v;
  const LT2 = V.linear_time.find((r) => r.id === 'LT2')!.rule.conds[0].v;
  const H1 = '/' + 'a'.repeat(2047), H3 = '/A/./' + 'a'.repeat(2043);   // 1 and 3 distinct path forms
  const P8 = '(?:a[^ ]{0,500}dQ|b[^ ]{0,500}kQ|c[^ ]{0,500}mQ|e[^ ]{0,500}pQ|f[^ ]{0,500}rQ|g[^ ]{0,500}tQ|h[^ ]{0,500}vQ|j[^ ]{0,500}xQ)';   // 8 branches of ~1000 instructions each, never gives up on a short path
  const UA_BENIGN = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0';
  const mk = (action: string, f: string, v: string, i: number): Rule => ({ id: `cr_${action}${f}${i}`, action, conds: [{ f, op: 'matches', v }] });
  const many = (n: number, f: string, v: string) => Array.from({ length: n }, (_, i) => mk('block', f, v, i));
  const run = (rules: Rule[], input: { path?: string; ua?: string }) =>
    new Matcher(parseSnapshot(empty, { ...emptyMeta, rules })).match({ ip: '8.8.8.8', ...input } as never).rule;

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
    expect(first).toBe(rules[31].id);   // the budget engaged (deterministic: seeded UA, charges are counts): rules 0-30 run and miss, rule 31 finds it spent and hits
    const ms = best(() => m.match({ ip: '8.8.8.8', path: '/', ua } as never));
    expect(ms).toBeLessThan(500);
  }, 60_000);

  it('the worst shape found stays under the stated bound', () => {
    const m = new Matcher(parseSnapshot(empty, { ...emptyMeta, rules: many(200, 'path', LT2) }));
    const ms = best(() => m.match({ ip: '8.8.8.8', path: '/A/./' + 'a'.repeat(95) }));
    expect(ms).toBeLessThan(500);   // bounded vs unbounded; loose for slow CI runners
  }, 60_000);
});

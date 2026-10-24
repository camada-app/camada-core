// Contract regex-limit v1 (camada-all-2pap): customer `matches` regexes run on a linear-time engine (re2js), so a
// pathological pattern costs bounded time. The vectors are a byte-identical copy shared with the other repos.
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { RE2JS } from 're2js';
import { parseSnapshot, Matcher } from '../src/index.js';
import { compileMatches, jsToRe2, MAX_MATCH_INPUT, REGEX_STATE_WORK, REQUEST_REGEX_WORK, safeTest, withRegexBudget } from '../src/snapshot/path.js';

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
    let best = Infinity, got = !r.hit;
    for (let i = 0; i < 3; i++) {   // best of 3 fresh compiles: still measures the cold DFA build
      const t = performance.now();
      got = hits(r.rule, r.input);
      best = Math.min(best, performance.now() - t);
    }
    expect(got).toBe(r.hit);
    expect(best).toBeLessThan(r.max_ms);
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
  const LT1 = V.linear_time.find((r) => r.id === 'LT1')!.rule.conds[0].v;
  const LT2 = V.linear_time.find((r) => r.id === 'LT2')!.rule.conds[0].v;
  const H1 = '/' + 'a'.repeat(2047), H3 = '/A/./' + 'a'.repeat(2043);   // 1 and 3 distinct path forms
  const mk = (action: string, f: string, v: string, i: number): Rule => ({ id: `cr_${action}${f}${i}`, action, conds: [{ f, op: 'matches', v }] });
  const many = (n: number, f: string, v: string) => Array.from({ length: n }, (_, i) => mk('block', f, v, i));
  const run = (rules: Rule[], input: { path?: string; ua?: string }) =>
    new Matcher(parseSnapshot(empty, { ...emptyMeta, rules })).match({ ip: '8.8.8.8', ...input } as never).rule;

  it('REQUEST_REGEX_WORK is 4194304 and a DFA state costs 64', () => {
    expect(REQUEST_REGEX_WORK).toBe(4194304);
    expect(REGEX_STATE_WORK).toBe(64);
  });

  it('one wide test fits a request, the rest answer over-budget', () => {
    const res = Array.from({ length: 200 }, () => compileMatches(LT1, true)!);
    expect(withRegexBudget(() => res.map((re) => safeTest(re, H1, true)))).toEqual([false, ...Array(199).fill(true)]);
  }, 30_000);

  it('outside a request walk nothing is budgeted', () => {
    const res = Array.from({ length: 3 }, () => compileMatches(LT1, true)!);
    expect(res.map((re) => safeTest(re, H1, true))).toEqual([false, false, false]);
  }, 30_000);

  it('withRegexBudget restores the previous budget (nesting-safe), even when f throws', () => {
    const re = compileMatches('a', true)!, left = () => withRegexBudget(() => safeTest(compileMatches(LT1, true)!, H1, true));
    expect(left()).toBe(false);
    expect(() => withRegexBudget(() => { withRegexBudget(() => { throw new Error('x'); }); })).toThrow('x');
    expect(safeTest(re, 'a', false)).toBe(true);
    expect(withRegexBudget(() => withRegexBudget(() => left()) )).toBe(false);
  }, 30_000);

  it('N stored LT1 rules: a bounded walk that answers like over-cap', () => {
    const rules = many(200, 'path', LT1), uas = many(200, 'ua', '[^/]{1000}x');   // a ua rule compiles case-sensitive, where LT1 on 'a's is cheap (re2js skips a value lacking the literal z); this one costs ~20 ms on UA below
    for (let i = 0; i < 2; i++) {   // twice, same answer: the budget is per request
      expect(run(rules, { path: H1 })).toBe(rules[1].id);
      expect(run(rules, { path: H3 })).toBe(rules[0].id);
      expect(run(uas, { path: '/', ua: 'a'.repeat(1500) + '/' + 'a'.repeat(546) + 'x' })).toBe(uas[1].id);
    }
  }, 30_000);

  it('over the budget a skip rule misses and cheap rules below still run', () => {
    const a = mk('block', 'path', LT1, 0), b = mk('skip', 'path', LT1, 1), c = mk('block', 'path', '^/', 2);
    expect(run([a, b, c], { path: H1 })).toBe(c.id);
  }, 30_000);

  it('cheap rules never reach the budget', () => {
    expect(run(many(200, 'path', 'sqlmap|nikto'), { path: H3 })).toBeUndefined();
  }, 30_000);

  it('the clear counter sees re2js clearing its cache', () => {
    const re = compileMatches(LT1, true) as RE2JS;
    expect(Object.hasOwn(re.re2().dfa, 'clearCache')).toBe(true);
    const re2 = compileMatches(LT1, true)!;
    expect(withRegexBudget(() => [safeTest(re, H1, true), safeTest(re2, H1, true)])).toEqual([false, true]);
  }, 30_000);

  const best = (f: () => unknown) => {   // best of 3 wall-clock ms
    let b = Infinity;
    for (let i = 0; i < 3; i++) { const t = performance.now(); f(); b = Math.min(b, performance.now() - t); }
    return b;
  };

  it('200 LT1 rules x 3 path forms cost one bounded walk', () => {
    const rules = many(200, 'path', LT1);
    const m = new Matcher(parseSnapshot(empty, { ...emptyMeta, rules }));
    let rule: string | undefined;
    const ms = best(() => { rule = m.match({ ip: '8.8.8.8', path: H3 }).rule; });
    console.log(`1oqz case 9: best of 3 = ${ms.toFixed(1)} ms`);
    expect(rule).toBe(rules[0].id);
    expect(ms).toBeLessThan(100);
  }, 60_000);

  it('the worst shape found stays under the stated bound', () => {
    const m = new Matcher(parseSnapshot(empty, { ...emptyMeta, rules: many(200, 'path', LT2) }));
    const ms = best(() => m.match({ ip: '8.8.8.8', path: '/A/./' + 'a'.repeat(95) }));
    console.log(`1oqz case 10: best of 3 = ${ms.toFixed(1)} ms`);
    expect(ms).toBeLessThan(150);
  }, 60_000);
});

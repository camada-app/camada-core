// Contract regex-limit v1 (camada-all-2pap): customer `matches` regexes run on a linear-time engine (re2js), so a
// pathological pattern costs bounded time. The vectors are a byte-identical copy shared with the other repos.
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { RE2JS } from 're2js';
import { parseSnapshot, Matcher } from '../src/index.js';
import { compileMatches, jsToRe2, MAX_MATCH_INPUT } from '../src/snapshot/path.js';

const REGEX_LIMIT_VECTORS_SHA256 = 'a12286c407435d1578200bb842ab7415c8a9501f4c9dbb83eed4f74794202bcb';
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

  it.each(V.translate)('translate %s', (from, to) => {
    expect(jsToRe2(from)).toBe(to);
  });
});

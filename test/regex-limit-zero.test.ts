// mx0h/sl00 (camada-all-mx0h, camada-all-sl00): leading-zero counts and the per-pattern DFA bound, in path.ts.
import { describe, it, expect } from 'vitest';
import { RE2JS } from 're2js';
import { jsToRe2, compileMatches, RE2_DFA_MAX_MEM } from '../src/snapshot/path.js';

const MiB = 1048576;
const LT1 = '(?:a{99}|a{99})'.repeat(12) + 'z';
const translate: Array<[string, string]> = [
  ['a{02}', 'a{2}'], ['a{0,03}', 'a{0,3}'], ['a{00}', 'a{0}'], ['a{02,}', 'a{2,}'], ['a{01001}', 'a{1001}'],
  ['[{02}]', '[{02}]'], ['\\{02}', '\\{02}'], ['\\x{02}', 'x{2}'],
];

describe('mx0h: a count written with a leading zero is read as its decimal value, as JS reads it', () => {
  it.each(translate)('jsToRe2(%j) = %j', (src, want) => { expect(jsToRe2(src)).toBe(want); });
  it('a{02} is aa, not the text', () => {
    const re = compileMatches('^a{02}$', false)!;
    expect(re.test('aa')).toBe(true);
    expect(re.test('a{02}')).toBe(false);
  });
  it('a{0,03}, a{00} and a{02,}', () => {
    expect(compileMatches('^a{0,03}$', false)!.test('aaa')).toBe(true);
    expect(compileMatches('^a{00}b$', false)!.test('b')).toBe(true);
    expect(compileMatches('^a{02,}$', false)!.test('aaaa')).toBe(true);
  });
  it('a{01001} is refused by re2js, so it falls back to the native RegExp', () => {
    const re = compileMatches('a{01001}', false)!;
    expect(re).toBeInstanceOf(RegExp);
    expect(re.test('a'.repeat(1001))).toBe(true);
    expect(re.test('a')).toBe(false);
    expect(RE2JS.compile.bind(RE2JS, 'a{1001}')).toThrow();
  });
});

describe('sl00: re2js lazy-DFA cache is bounded at 64 KiB per pattern', () => {
  it('RE2_DFA_MAX_MEM is 65536', () => { expect(RE2_DFA_MAX_MEM).toBe(65536); });
  it('200 wide rules stay within 64 KiB each and 12.5 MiB accounted in total', () => {
    const input = '/' + 'a'.repeat(2047);
    let sum = 0;
    for (let k = 0; k < 200; k++) {
      const re = compileMatches(LT1, true) as RE2JS;
      expect(re.test(input)).toBe(false);
      const d = re.re2().dfa;
      expect(d.maxMem).toBe(RE2_DFA_MAX_MEM);
      const used = d.stateBudget - d.memBudget;
      expect(used).toBeLessThanOrEqual(RE2_DFA_MAX_MEM);
      sum += used;
    }
    console.log(`sl00 accounted DFA bytes for 200 rules: ${sum} (${(sum / MiB).toFixed(2)} MiB)`);
    expect(sum).toBeLessThanOrEqual(12.5 * MiB);
  }, 60_000);
  it('a bounded engine answers like the default one (LT1, an API prefix, a[ab]{20}x; 50 seeded inputs)', () => {
    let seed = 7; const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
    const pick = (alpha: string, n: number) => Array.from({ length: n }, () => alpha[Math.floor(rnd() * alpha.length)]).join('');
    const cases: Array<[string, number, () => string]> = [
      [LT1, RE2JS.CASE_INSENSITIVE, () => '/' + 'a'.repeat(1 + Math.floor(rnd() * 2047)) + (rnd() < 0.3 ? 'z' : '')],
      ['^/api/v[0-9]+/', 0, () => (rnd() < 0.5 ? '/api/v' + pick('0123456789', 1 + Math.floor(rnd() * 5)) + '/x' : '/' + pick('abc/v1', 20))],
      ['a[ab]{20}x', 0, () => pick('ab', 10 + Math.floor(rnd() * 100)) + (rnd() < 0.5 ? 'x' : '')],
    ];
    for (const [p, fl, gen] of cases) {
      const dflt = RE2JS.compile(jsToRe2(p), fl);
      const bounded = compileMatches(p, fl !== 0) as RE2JS;
      for (let j = 0; j < 50; j++) { const v = gen(); expect(bounded.test(v), p + ' on ' + v.slice(0, 40)).toBe(dflt.test(v)); }
    }
  }, 60_000);
});

// Contract regex-limit v1 (camada-all-2pap): customer `matches` regexes run on a linear-time engine (re2js), so a
// pathological pattern costs bounded time. The vectors are a byte-identical copy shared with the other repos.
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { RE2JS } from 're2js';
import { parseSnapshot, Matcher } from '../src/index.js';
import { compileMatches, foldCase, foldedPrefilter, jsToRe2, MAX_MATCH_INPUT, REGEX_STATE_WORK, REGEX_STEP_WORK, REQUEST_REGEX_WORK, pathPred, safeTest, withRegexBudget, RE2_DFA_MAX_MEM } from '../src/snapshot/path.js';

const REGEX_LIMIT_VECTORS_SHA256 = '79cd3686277fd9630592338a65d24e49f791aba5f1a182e7eef598eacae2fd24';
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

const LT1 = V.linear_time.find((r) => r.id === 'LT1')!.rule.conds[0].v;
const H1 = '/z' + 'a'.repeat(2046), H3 = '/Z/./' + 'a'.repeat(2043);   // 1 and 3 distinct path forms; both carry the literal z, or the CI pre-check (z8p7) would skip LT1
const mk = (action: string, f: string, v: string, i: number): Rule => ({ id: `cr_${action}${f}${i}`, action, conds: [{ f, op: 'matches', v }] });
const many = (n: number, f: string, v: string) => Array.from({ length: n }, (_, i) => mk('block', f, v, i));
const res = (rules: Rule[], input: { path?: string; ua?: string }) => new Matcher(parseSnapshot(empty, { ...emptyMeta, rules })).match({ ip: '8.8.8.8', ...input } as never);
const run = (rules: Rule[], input: { path?: string; ua?: string }) => res(rules, input).rule;

describe('regex-limit vectors', () => {
  it('are the pinned bytes', () => {
    expect(createHash('sha256').update(raw).digest('hex')).toBe(REGEX_LIMIT_VECTORS_SHA256);
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

  it.each(V.accepted.map((p) => [p] as const))('accepted %s compiles on re2js', (p) => {
    expect(() => RE2JS.compile(jsToRe2(p))).not.toThrow();
    expect(compileMatches(p, false)).toBeInstanceOf(RE2JS);
  });

  it('a - next to a class escape is refused (never translated); a stored pattern never matches (rfyr)', () => {
    for (const p of ['[\\s-z]', '[a-\\d]', '[\\s-a-b-e]', '[\\s-\\x41-z]']) {
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

  it.each(V.translate)('translate %s', (from, to) => {
    expect(jsToRe2(from)).toBe(to);
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
    expect(run([mk('block', 'path', '[^/]{1000}x', 0)], { path: '/Static/./x' + 'b'.repeat(2029) })).toBeUndefined();
    expect(run(many(3, 'path', '^/.{1000}z'), { path: '/z' + 'b'.repeat(2039) })).toBeUndefined();
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
    ['P8 on a path carrying a branch letter and its Q literal out of order (one form: three forms spend the budget at rule 183)', 'path', P8, { path: '/xq/Shop/Products/Item-123/Reviews/j' }],
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
    const ms = best(() => m.match({ ip: '8.8.8.8', path: '/Z/./' + 'a'.repeat(95) }));
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

// camada-all-z8p7: a path (case-insensitive) pattern gets re2js's required-literal pre-check, case-folded.
describe('z8p7: case-folded required-literal pre-check for path rules', () => {
  const W256 = '[^/]{256}\\.(?:php|aspx?|jsp)';
  const TOKEN = 'aB3_-xYz9Qw'.repeat(40).slice(0, 400);   // the same value edge-analyst uses
  const PB = '/download/' + TOKEN + '/report.pdf';

  it('a CI path rule skips a value without its required literal, charged like CS', () => {
    const rs = Array.from({ length: 200 }, () => compileMatches(W256, true)!);
    expect(withRegexBudget(() => rs.map((re) => safeTest(re, PB, true)))).toEqual(Array(200).fill(false));   // none over (today 60 run, then over)
    const v = '/' + 'b'.repeat(2046), want = Math.ceil(REQUEST_REGEX_WORK / (2047 + REGEX_STATE_WORK));
    const ran = (re: { test(s: string): boolean }) => withRegexBudget(() => { let n = 0; for (let i = 0; i < 4000; i++) if (!safeTest(re, v, true)) n++; return n; });
    expect(ran(compileMatches(W256, true)!)).toBe(want);
    expect(ran(compileMatches(W256, false)!)).toBe(want);
    expect(want).toBe(3974);
  });

  it('round 3: wide CI rules do not spend a benign long path budget', () => {
    const rules = [...many(30, 'path', W256), mk('block', 'path', '\\.env$', 30)];
    const m = new Matcher(parseSnapshot(empty, { ...emptyMeta, rules }));
    let r: string | undefined = 'x';
    const ms = best(() => { r = m.match({ ip: '8.8.8.8', path: PB }).rule; });
    expect(r).toBeUndefined();   // today rule 30, a false block
    expect(ms).toBeLessThan(20);   // measured 0.1 ms; today 74 ms
  });

  it('the pre-check folds case as re2js does', () => {
    const t = (p: string, v: string) => safeTest(compileMatches(p, true)!, v, true);
    expect(t('secret', '/\u017fecret')).toBe(true);
    expect(t('kelvin', '/\u212aelvin')).toBe(true);
    expect(t('/Wp-Admin/X\\.php', '/WP-ADMIN/x.PHP')).toBe(true);
    expect(t('\u00e9', '/\u00c9')).toBe(compileMatches('\u00e9', true)!.test('/\u00c9'));   // non-ASCII literal: no pre-check
    expect(foldCase('A\u017fK\u212a')).toBe('askk');
    const rows: Array<[string, string]> = [
      ['sqlmap|nikto', '/x/SQLMap/y'], ['\\.env$', '/app/.ENV'], ['^/admin', '/Admin/x'], ['wp-(?:admin|login)', '/WP-Login.php'],
      ['[^/]{3}\\.php', '/abc.PHP'], ['.{0,300}\\.php', '/a/B.Php'], ['/api/v[0-9]+/Users', '/API/v2/users'], ['(?:foo|bar)baz', '/x/FOOBAZ'],
      ['etc/passwd', '/..%2f/ETC/PASSWD'], ['select.+from', '/SELECT%20a FROM b'], ['\\.(?:git|svn)/', '/x/.GIT/'], ['phpmyadmin', '/PhpMyAdmin/'],
      ['a.c', '/ABC'], ['(?i)xyz', '/XyZ'], ['cgi-bin', '/CGI-BIN/'], ['\\.bak$', '/a.BaK'], ['login|signin', '/SignIn'], ['[a-c]d', '/Bd'],
      ['x{2,3}y', '/XXY'], ['shell\\.(?:php|asp)', '/Shell.ASP'],
    ];
    for (const [p, v] of rows) {
      const re = compileMatches(p, true);
      if (re) expect(safeTest(re, v, true), `${p} on ${v}`).toBe(re.test(v));
    }
    expect(rows.filter(([p, v]) => compileMatches(p, true)?.test(v)).length).toBeGreaterThanOrEqual(15);
  });

  it('the pre-check never changes an answer (2000 seeded patterns x 6 values)', () => {
    let seed = 20261024;
    const rnd = (n: number) => ((seed = (Math.imul(seed, 1103515245) + 12345) & 0x7fffffff) >>> 16) % n;
    const pick = <T,>(a: T[]) => a[rnd(a.length)];
    const LIT = ['php', 'Admin', 'wp', 'env', 'secret', 'kelvin', 'a', 'b', 'Z', 's', 'k', 'x1', 'sql', 'é'];
    const atom = (): string => pick([() => pick(LIT), () => pick(LIT), () => '[^/]{2,5}', () => '.{0,4}', () => '[a-c]', () => '\\.', () => '(?:' + pick(LIT) + '|' + pick(LIT) + ')', () => pick(LIT) + '?', () => '[^a-z]', () => '\\W', () => '[A-Za-z]+'])();
    const val = (): string => '/' + Array.from({ length: 1 + rnd(5) }, () => { const w = pick([...LIT, 'ſ', 'K', '.', '/', '-', 'Ab9']); return rnd(2) ? w : [...w].map((c) => (rnd(2) ? c.toUpperCase() : c.toLowerCase())).join(''); }).join('');
    const t0 = performance.now();
    let n = 0;
    for (let i = 0; i < 2000; i++) {
      const p = (rnd(4) === 0 ? '^' : '') + Array.from({ length: 1 + rnd(4) }, atom).join('') + (rnd(5) === 0 ? '$' : '');
      const re = compileMatches(p, true);
      if (!re) continue;
      for (let j = 0; j < 6; j++) { const v = val(); const got = safeTest(re, v, true); if (got !== re.test(v)) throw new Error(`${p} on ${v}: ${got}`); n += got ? 1 : 0; }
    }
    expect(n).toBeGreaterThan(100);   // the generator exercises matches, not only misses
    expect(performance.now() - t0).toBeLessThan(2000);
  });

  it('z8p7: an OR of literals is one pre-check pass, however wide', () => {
    const D = '0123456789abcdefghijklmnopqrstuvwxyz';   // scattered first characters, so re2js does not factor the alternation into a shared prefix
    const alt = (n: number) => '(?:' + Array.from({ length: n }, (_, i) => D[i % 36] + D[(i * 7 + 3) % 36] + (i >= 36 ? 'z' : '')).join('|') + ')';
    const leaves = (x: { type: number; subs?: unknown[] }): number => (x.type === 1 ? 1 : (x.subs as Array<{ type: number }> ?? []).reduce((k, y) => k + leaves(y as never), 0));
    for (const n of [32, 40]) {
      const p = alt(n);
      const tw = RE2JS.compile(p, 0).re2().prefilter;
      expect(tw.type).toBe(3);   // OR
      expect(leaves(tw)).toBe(n);
      expect(tw.allExact).toBe(true);
      const pf = foldedPrefilter(p);
      expect(pf).toBeInstanceOf(Function);
      expect(pf!('/-.-.-')).toBe(false);
      expect(pf!(foldCase('/xx/A1/yy'))).toBe(true);
      const re = compileMatches(p, true)!;
      for (const v of ['/-.-.-', '/xx/A1/yy', '/A1', '/Q5', '', '/zzz']) expect(safeTest(re, v, true), `${n}: ${v}`).toBe(re.test(v));
    }
  });

  it('tripwire: re2js prefilter internals', () => {
    expect(RE2JS.compile('.{0,300}\\.php', 0).re2().prefilter).toMatchObject({ type: 1, str: '.php' });
    expect(RE2JS.compile(W256, 0).re2().prefilter.type).toBe(2);
  });
});

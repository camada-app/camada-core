// camada-all-zhf5: snapshot meta `pathsRegex` runs on re2js inside the request's regex budget, shared with the rule walk.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseSnapshot, Matcher } from '../src/index.js';

const at = (f: string) => new URL(`./fixtures/blk5/${f}`, import.meta.url);
const raw = readFileSync(at('v5-empty.bin'));
const bin = new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength);
const meta = JSON.parse(readFileSync(at('v5-empty.meta.json'), 'utf8'));
const V = JSON.parse(readFileSync(new URL('./fixtures/regex-limit/regex-limit-vectors.json', import.meta.url), 'utf8'));
const LT1: string = V.linear_time.find((r: { id: string }) => r.id === 'LT1').rule.conds[0].v;   // the 1oqz wide pattern: re2js gives up to the NFA on a path of 'a's
const H1 = '/' + 'a'.repeat(2047);
const mk = (extra: object) => new Matcher(parseSnapshot(bin, { ...meta, ...extra }));
const skipLt1 = (n: number) => Array.from({ length: n }, (_, i) => ({ id: `cr_${i}`, action: 'skip', conds: [{ f: 'path', op: 'matches', v: LT1 }] }));

describe('meta pathsRegex on re2js', () => {
  it('a pattern re2js refuses never matches', () => {
    const m = mk({ pathsRegex: ['^/a(?=b)'] });
    expect(m.match({ ip: '8.8.8.8', path: '/ab' }).block).toBe(false);
    expect(m.match({ ip: '8.8.8.8', path: '/a' }).block).toBe(false);
  });

  it('is case-insensitive and blocks with reason path', () => {
    const m = mk({ pathsRegex: ['^/api/v[0-9]+/dump$'] });
    expect(m.match({ ip: '8.8.8.8', path: '/API/v2/dump' })).toMatchObject({ block: true, reason: 'path' });
    expect(m.match({ ip: '8.8.8.8', path: '/api/vx/dump' }).block).toBe(false);
  });

  it('a path over 2048 characters answers block', () => {
    const m = mk({ pathsRegex: ['^/never$'] });
    expect(m.match({ ip: '8.8.8.8', path: '/' + 'a'.repeat(2048) })).toMatchObject({ block: true, reason: 'path' });
    expect(m.match({ ip: '8.8.8.8', path: H1 }).block).toBe(false);
  });

  it('shares the request budget with the rule walk', () => {
    const alone = mk({ pathsRegex: ['^/never$'] });
    expect(alone.match({ ip: '8.8.8.8', path: H1 }).block).toBe(false);
    // 200 LT1 skip rules spend the budget (each misses); the meta regex then finds none left and answers deny
    const m = mk({ rules: skipLt1(200), pathsRegex: ['^/never$'] });
    expect(m.match({ ip: '8.8.8.8', path: H1 })).toMatchObject({ block: true, reason: 'path' });
  });

  it('200 heavy meta entries on a 2 KiB path stay bounded', () => {
    const m = mk({ pathsRegex: Array(200).fill(LT1) });
    let ms = Infinity;
    for (let i = 0; i < 3; i++) { const t = performance.now(); m.match({ ip: '8.8.8.8', path: H1 }); ms = Math.min(ms, performance.now() - t); }
    expect(ms).toBeLessThan(500);
  }, 60_000);
});

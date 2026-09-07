import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseSnapshot, Matcher, type SnapshotRuleMeta, type SnapshotCondMeta } from '../src/index.js';

const raw = readFileSync(new URL('./fixtures/blk3/v3-basic.bin', import.meta.url));
const meta = JSON.parse(readFileSync(new URL('./fixtures/blk3/v3-basic.meta.json', import.meta.url), 'utf8'));

describe('parseSnapshot input handling', () => {
  it('rejects a wrong magic word', () => {
    const bad = new Uint8Array(raw);
    bad[0] = 0x00;
    expect(() => parseSnapshot(bad, meta)).toThrow(/BLK3/);
  });

  it('rejects a truncated container', () => {
    expect(() => parseSnapshot(new Uint8Array(raw.subarray(0, 16)), meta)).toThrow(/truncated|BLK3/);
  });

  it('realigns an unaligned Uint8Array view', () => {
    const padded = new Uint8Array(raw.byteLength + 1);
    padded.set(new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength), 1);
    const view = new Uint8Array(padded.buffer, 1, raw.byteLength);   // byteOffset 1: unaligned
    const m = new Matcher(parseSnapshot(view, meta));
    expect(m.match({ ip: '203.0.113.66' }).reason).toBe('ip4');
  });

  it('accepts a bare ArrayBuffer', () => {
    const buf = raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength) as ArrayBuffer;
    const m = new Matcher(parseSnapshot(buf, meta));
    expect(m.match({ ip: '203.0.113.66' }).reason).toBe('ip4');
    expect(m.match({ ip: '203.0.113.67' }).block).toBe(false);
  });
});

const fx = (f: string) => new URL(`./fixtures/blk3/${f}`, import.meta.url);
const bin = (f: string) => readFileSync(fx(f));
const json = (f: string) => JSON.parse(readFileSync(fx(f), 'utf8'));

describe('BLK3 v4 container', () => {
  it('reports format 4 and fills the allow/challenge sides', () => {
    const s = parseSnapshot(bin('v4-basic.bin'), json('v4-basic.meta.json'));
    expect(s.format).toBe(4);
    expect(s.allow.asn.has(14061)).toBe(true);
    expect(s.allow.country.has('RU')).toBe(true);
    expect(s.allow.pathsExact.has('/locked/allowed')).toBe(true);
    expect(s.allow.pathsPrefix.has('/locked/public/')).toBe(true);
    expect(s.challenge.asn.has(64512)).toBe(true);
    expect(s.challenge.country.has('CN')).toBe(true);
    expect(s.challenge.pathsExact.has('/checkout')).toBe(true);
    expect(s.challenge.pathsPrefix.has('/admin/')).toBe(true);
    expect(s.allow.empty).toBe(false);
    expect(s.challenge.empty).toBe(false);
  });

  // Pins the INTERLEAVING itself: a [s,s,e,e] layout, or start/end swapped, would still give
  // the right lengths but decode to different ranges here.
  it('decodes the side sections as interleaved start/end pairs', () => {
    const s = parseSnapshot(bin('v4-basic.bin'), json('v4-basic.meta.json'));
    for (let i = 0; i + 1 < s.allow.r4.length; i += 2) expect(s.allow.r4[i]).toBeLessThanOrEqual(s.allow.r4[i + 1]);
    for (let i = 2; i + 1 < s.allow.r4.length; i += 2) expect(s.allow.r4[i - 2]).toBeLessThanOrEqual(s.allow.r4[i]);
    expect(s.allow.r4.length % 2).toBe(0);
    expect(s.allow.r6.length).toBe(s.allow.n6 * 8);
    expect(s.challenge.r6.length).toBe(s.challenge.n6 * 8);
  });

  it('reads a v3 container as format 3 with empty sides', () => {
    const s = parseSnapshot(bin('v3-basic.bin'), json('v3-basic.meta.json'));
    expect(s.format).toBe(3);
    expect(s.allow.empty).toBe(true);
    expect(s.challenge.empty).toBe(true);
    expect(s.allow.r4.length).toBe(0);
  });

  // The version byte is advisory: sections 10-13 are read whenever they are present, so the
  // SDK still honours allow/challenge if the server ever ships them under the v3 magic.
  it('reads the v4 sections even under a v3 version byte', () => {
    const patched = new Uint8Array(bin('v4-basic.bin'));
    patched[0] = 0x33;   // little-endian: byte 0 is the magic's version digit
    const s = parseSnapshot(patched, json('v4-basic.meta.json'));
    expect(s.format).toBe(3);
    expect(s.allow.empty).toBe(false);
    expect(s.challenge.empty).toBe(false);
  });

  it('rejects a foreign magic', () => {
    const junk = new Uint32Array([0x11223344, 0]);
    expect(() => parseSnapshot(junk.buffer, { version: 'x' })).toThrow(/not a BLK3 snapshot/);
  });
});

const fx5 = (f: string) => new URL(`./fixtures/blk5/${f}`, import.meta.url);
const bin5 = (f: string) => readFileSync(fx5(f));
const json5 = (f: string) => JSON.parse(readFileSync(fx5(f), 'utf8'));

describe('BLK5 container', () => {
  const snap = () => parseSnapshot(bin5('v5-rules.bin'), json5('v5-rules.meta.json'));

  it('reports format 5 and still fills the v4 sides', () => {
    const s = snap();
    expect(s.format).toBe(5);
    expect(s.allow.empty).toBe(false);
    expect(s.challenge.empty).toBe(false);
    expect(s.pathsRegex.length).toBe(1);
  });

  // meta.rules is a list, not a map: the built-ins compile to one rule per entry kind, so an id
  // repeats. Keying by id would silently drop four of the five Allow-list rows.
  it('compiles meta.rules in evaluation order, repeated ids and all', () => {
    const published = json5('rules.json').published as Array<{ id: string; action: string }>;
    const s = snap();
    expect(s.rules.map((r) => r.id)).toEqual(published.map((p) => p.id));
    expect(s.rules.map((r) => r.action)).toEqual(published.map((p) => p.action));
    expect(s.rules.filter((r) => r.id === 'builtin:allow').length).toBeGreaterThan(1);
  });

  it('leaves the disabled, expired and entity-plane rules out (the server never published them)', () => {
    const ids = new Set(snap().rules.map((r) => r.id));
    expect(ids.has('cr_000000000011')).toBe(false);   // disabled
    expect(ids.has('cr_000000000013')).toBe(false);   // expired
    expect(ids.has('cr_000000000012')).toBe(false);   // bot.verified: entity plane only
  });

  // One 14 + one 15 per ip condition, in condition order. Reading the two pairs of
  // cr_000000000014 as one set would let the exempt sub-range through as a block.
  it('gives a rule with two ip conditions both of its section pairs', () => {
    const m = new Matcher(snap());
    expect(m.match({ ip: '100.64.1.1' })).toMatchObject({ block: true, rule: 'cr_000000000014' });
    expect(m.match({ ip: '100.64.7.9' }).rule).toBeUndefined();          // inside the not_in exemption
    expect(m.match({ ip: '2001:db8:beef::1' })).toMatchObject({ block: true, rule: 'cr_000000000014' });
  });

  it('carries no rules on a v3 or v4 container', () => {
    expect(parseSnapshot(bin('v3-basic.bin'), json('v3-basic.meta.json')).rules).toEqual([]);
    expect(parseSnapshot(bin('v4-basic.bin'), json('v4-basic.meta.json')).rules).toEqual([]);
  });
});

// meta rides beside the container, so the compiler can be exercised on its own over the
// rule-free v5 body: everything below is about meta.rules, not about sections.
describe('rule compilation', () => {
  const empty = json5('v5-empty.meta.json');
  const withRules = (rules: SnapshotRuleMeta[]) => new Matcher(parseSnapshot(bin5('v5-empty.bin'), { ...empty, rules }));
  const block = (conds: SnapshotCondMeta[], id = 'cr_test'): SnapshotRuleMeta => ({ id, action: 'block', conds });

  it('never matches on a pattern this runtime rejects', () => {
    const m = withRules([block([{ f: 'path', op: 'matches', v: '^/(unclosed' }])]);
    expect(m.snap.rules).toHaveLength(1);                                // compiled, but inert
    expect(m.match({ ip: '8.8.8.8', path: '/(unclosed' }).block).toBe(false);
  });

  // 'allow' is in that set now: round 2 collapsed it into skip, and a server still publishing
  // the old word is a server this SDK does not understand — dropping the rule is the fail-open
  // answer, and the migration means it cannot happen anyway.
  it.each(['quarantine', 'allow'])('drops a rule whose action this SDK does not know (%s)', (action) => {
    const m = withRules([block([{ f: 'path', op: 'is', v: '/x' }], 'cr_ok'), { id: 'cr_new', action, conds: [{ f: 'path', op: 'is', v: '/x' }] }]);
    expect(m.snap.rules.map((r) => r.id)).toEqual(['cr_ok']);
  });

  it('drops a rule with no conditions rather than matching everything', () => {
    const m = withRules([block([])]);
    expect(m.snap.rules).toEqual([]);
    expect(m.match({ ip: '8.8.8.8', path: '/anything' }).block).toBe(false);
  });

  // A field the request cannot answer is false for EVERY op, negatives included — the rule does
  // not fire. Fail open, never guess: node/next see no asn, country or tlsx at all.
  const countryOps: Array<[string, string | string[]]> = [['is', 'US'], ['is_not', 'US'], ['is_in', ['US']], ['not_in', ['US']]];
  it.each(countryOps)('does not fire a country %s condition when the request has no country', (op, v) => {
    const m = withRules([block([{ f: 'country', op, v }])]);
    expect(m.match({ ip: '8.8.8.8' }).block).toBe(false);
    expect(m.match({ ip: '8.8.8.8', country: 'DE' }).block).toBe(op === 'is_not' || op === 'not_in');
  });

  it('does not fire a ua condition on a request without a user agent', () => {
    const m = withRules([block([{ f: 'ua', op: 'contains', v: 'curl/' }]), block([{ f: 'ua', op: 'is_not', v: 'curl/8.4.0' }], 'cr_neg')]);
    expect(m.match({ ip: '8.8.8.8' }).block).toBe(false);
    expect(m.match({ ip: '8.8.8.8', ua: '' }).block).toBe(false);
    expect(m.match({ ip: '8.8.8.8', ua: 'curl/8.4.0' })).toMatchObject({ block: true, rule: 'cr_test' });
    expect(m.match({ ip: '8.8.8.8', ua: 'Mozilla/5.0' })).toMatchObject({ block: true, rule: 'cr_neg' });
  });

  it('reads the asn as a string, the way the server publishes the values', () => {
    const m = withRules([block([{ f: 'asn', op: 'is_in', v: ['64500', '64501'] }])]);
    expect(m.match({ ip: '8.8.8.8', asn: 64500 }).block).toBe(true);
    expect(m.match({ ip: '8.8.8.8', asn: 64502 }).block).toBe(false);
  });

  it('strips the query before a path condition, as the block side does', () => {
    const m = withRules([block([{ f: 'path', op: 'is', v: '/dump' }])]);
    expect(m.match({ ip: '8.8.8.8', path: '/dump?all=1' }).block).toBe(true);
  });

  // An ip condition whose sections are absent has an empty set: it matches nothing, and its
  // negation matches every request that has an address (the reference reader does the same).
  it('treats an ip condition with no sections as an empty set', () => {
    const isIn = withRules([block([{ f: 'ip', op: 'is_in', set: true }])]);
    expect(isIn.match({ ip: '8.8.8.8' }).block).toBe(false);
    const notIn = withRules([block([{ f: 'ip', op: 'not_in', set: true }])]);
    expect(notIn.match({ ip: '8.8.8.8' }).block).toBe(true);
    expect(notIn.match({}).block).toBe(false);                           // no address: false for every op
  });

  // §A4/§D3 header conditions. The getter is always called with a lower-cased name, so the
  // spelling the rule was written with (and the spelling on the wire) stop mattering here.
  describe('header conditions', () => {
    const hdr = (headers: Record<string, string>) => ({ ip: '8.8.8.8', header: (n: string) => headers[n] ?? null });

    it('lower-cases the condition name once, at compile time', () => {
      const m = withRules([block([{ f: 'header', op: 'is', name: 'X-Api-Key', v: 'leaked-key-1' }])]);
      const seen: string[] = [];
      expect(m.match({ ip: '8.8.8.8', header: (n) => { seen.push(n); return n === 'x-api-key' ? 'leaked-key-1' : null; } }).block).toBe(true);
      expect(seen).toEqual(['x-api-key']);
    });

    it('matches the value, and only under its own name', () => {
      const m = withRules([block([{ f: 'header', op: 'is', name: 'x-api-key', v: 'leaked-key-1' }])]);
      expect(m.match(hdr({ 'x-api-key': 'leaked-key-1' })).block).toBe(true);
      expect(m.match(hdr({ 'x-api-key': 'a-good-key' })).block).toBe(false);
      expect(m.match(hdr({ 'x-other': 'leaked-key-1' })).block).toBe(false);
    });

    it('reads contains and matches off the header too', () => {
      const c = withRules([block([{ f: 'header', op: 'contains', name: 'via', v: 'squid' }])]);
      expect(c.match(hdr({ via: '1.1 squid-proxy (squid/6.6)' })).block).toBe(true);
      expect(c.match(hdr({ via: '1.1 varnish' })).block).toBe(false);
      const re = withRules([block([{ f: 'header', op: 'matches', name: 'x-app-version', v: '^1\\.[0-2]\\.' }])]);
      expect(re.match(hdr({ 'x-app-version': '1.2.9' })).block).toBe(true);
      expect(re.match(hdr({ 'x-app-version': '2.0.0' })).block).toBe(false);
    });

    // Fail open, twice over: a tap that cannot read headers hands over no getter at all, and a
    // request that simply lacks the header answers null. Neither may fire the rule.
    it('never fires without a getter, or on a header the request does not carry', () => {
      const m = withRules([block([{ f: 'header', op: 'is', name: 'x-api-key', v: 'leaked-key-1' }])]);
      expect(m.match({ ip: '8.8.8.8' }).block).toBe(false);
      expect(m.match(hdr({})).block).toBe(false);
      expect(m.match(hdr({ 'x-api-key': 'leaked-key-1' })).block).toBe(true);   // the same matcher does fire when it can see it
    });

    it('never fires a header condition the server sent without a name', () => {
      const m = withRules([block([{ f: 'header', op: 'is', v: 'leaked-key-1' }])]);
      expect(m.snap.rules).toHaveLength(1);                                     // compiled, but inert
      expect(m.match({ ip: '8.8.8.8', header: () => 'leaked-key-1' }).block).toBe(false);
    });

    // The getter is the app's code. A throw, or an `undefined` where null was meant (the shape
    // `req.headers[n]` hands back for a missing header), must read as "no header" — the rule
    // stays quiet and match() still answers for every other rule and side.
    it('reads a throwing getter, or one that answers undefined, as no header', () => {
      const m = withRules([block([{ f: 'header', op: 'contains', name: 'x-api-key', v: 'leaked' }])]);
      expect(m.match({ ip: '8.8.8.8', header: () => { throw new Error('boom'); } }).block).toBe(false);
      expect(m.match({ ip: '8.8.8.8', header: () => undefined as unknown as string }).block).toBe(false);
      expect(m.match({ ip: '8.8.8.8', header: () => 'leaked-key-1' }).block).toBe(true);   // and the same matcher still fires on a real value
    });

    it('does not leak the getter into the next request', () => {
      const m = withRules([block([{ f: 'header', op: 'is', name: 'x-api-key', v: 'leaked-key-1' }])]);
      expect(m.match(hdr({ 'x-api-key': 'leaked-key-1' })).block).toBe(true);
      expect(m.match({ ip: '8.8.8.8' }).block).toBe(false);                     // scratch R is reused: a stale getter would still block
    });
  });

  it('takes the first match and stops', () => {
    const m = withRules([
      { id: 'cr_skip', action: 'skip', conds: [{ f: 'path', op: 'starts_with', v: '/health' }] },
      block([{ f: 'path', op: 'is', v: '/healthz' }], 'cr_block'),
    ]);
    expect(m.match({ ip: '8.8.8.8', path: '/healthz' })).toMatchObject({ allowed: true, action: 'skip', rule: 'cr_skip', reason: 'rule' });
  });
});

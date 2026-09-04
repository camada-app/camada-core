import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseSnapshot, Matcher } from '../src/index.js';

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

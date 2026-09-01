import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseSnapshot, Matcher } from '../src/index.js';

const raw = readFileSync(new URL('./fixtures/snap-basic.bin', import.meta.url));
const meta = JSON.parse(readFileSync(new URL('./fixtures/snap-basic.meta.json', import.meta.url), 'utf8'));

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

import { expect, it } from 'vitest';
import { beaconRow, REQUEST_ROW_KEYS, TAP_NODE } from '../src/index.js';

it('builds a beacon row with server-stamped fields and only allowed body keys', () => {
  const body = Object.freeze({
    ...Object.fromEntries(REQUEST_ROW_KEYS.map((key) => [key, 'forged'])),
    rid: 'abc', tz: 'UTC', sig: 0, ip: '1.1.1.1', tap: 'proxy', rts: 1,
  });
  const before = Date.now();
  const row = beaconRow(body, null, TAP_NODE);

  expect(row).toStrictEqual({ rid: 'abc', tz: 'UTC', sig: 1, ip: null, tap: TAP_NODE, rts: expect.any(Number) });
  expect(row.rts).toBeGreaterThanOrEqual(before);
  expect(row.rts).toBeLessThanOrEqual(Date.now());
});

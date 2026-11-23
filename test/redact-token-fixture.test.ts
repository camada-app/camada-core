import { describe, it, expect } from 'vitest';
import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';

interface TokenCase { id: string; key: string; credential: string | null; tk: string | null }
const fixture = JSON.parse(readFileSync(new URL('./fixtures/redact/token.json', import.meta.url), 'utf8')) as { cases: TokenCase[] };

describe('token hash fixture (fixtures/redact/token.json)', () => {
  it('has at least five cases with unique IDs', () => {
    expect(fixture.cases.length).toBeGreaterThanOrEqual(5);
    expect(new Set(fixture.cases.map(({ id }) => id)).size).toBe(fixture.cases.length);
  });

  it.each(fixture.cases)('$id', ({ key, credential, tk }) => {
    if (credential === null) {
      expect(tk).toBeNull();
    } else {
      expect(tk).toMatch(/^[0-9a-f]{32}$/);
      expect(tk).toBe(createHmac('sha256', key).update('tok:' + credential, 'utf8').digest('hex').slice(0, 32));
    }
  });
});

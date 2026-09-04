import { describe, it, expect } from 'vitest';
import { createHash, createHmac } from 'node:crypto';
import {
  createChallenge, createChallengeAsync, challengePage, challengeCookie, safeReturnTo,
  wantsHtml, parseFormBody, CHALLENGE_COOKIE, CHALLENGE_TTL_MS, POW_BITS,
} from '../src/index.js';

const SECRET = 'tok-acme.snap-acme';
const kit = createChallenge({
  secret: SECRET,
  hmac: (s, m) => createHmac('sha256', s).update(m).digest('hex'),
  sha: (m) => createHash('sha256').update(m).digest('hex'),
});
const solve = (nonce: string): string => {
  for (let n = 0; ; n++) if (createHash('sha256').update(`${nonce}.${n}`).digest('hex').startsWith('0000')) return String(n);
};

describe('nonce', () => {
  const now = Date.UTC(2026, 8, 4, 12, 0, 0);

  it('is deterministic per (ip, UTC day) and 32 hex chars', () => {
    const a = kit.nonce('1.2.3.4', now);
    expect(a).toMatch(/^[0-9a-f]{32}$/);
    expect(kit.nonce('1.2.3.4', now + 60_000)).toBe(a);
    expect(kit.nonce('1.2.3.5', now)).not.toBe(a);
  });

  it('accepts today and yesterday, rejects two days back and forgeries', () => {
    const day = 86_400_000;
    expect(kit.nonceValid('1.2.3.4', now, kit.nonce('1.2.3.4', now))).toBe(true);
    expect(kit.nonceValid('1.2.3.4', now, kit.nonce('1.2.3.4', now - day))).toBe(true);
    expect(kit.nonceValid('1.2.3.4', now, kit.nonce('1.2.3.4', now - 2 * day))).toBe(false);
    expect(kit.nonceValid('1.2.3.4', now, kit.nonce('9.9.9.9', now))).toBe(false);
    expect(kit.nonceValid('1.2.3.4', now, 'f'.repeat(32))).toBe(false);
    expect(kit.nonceValid('1.2.3.4', now, null)).toBe(false);
  });
});

describe('token', () => {
  const now = 1_800_000_000_000;

  it('round-trips within the hour and expires after it', () => {
    const t = kit.issue('1.2.3.4', now);
    expect(kit.tokenValid('1.2.3.4', now, t)).toBe(true);
    expect(kit.tokenValid('1.2.3.4', now + CHALLENGE_TTL_MS - 1, t)).toBe(true);
    expect(kit.tokenValid('1.2.3.4', now + CHALLENGE_TTL_MS + 1, t)).toBe(false);
  });

  it('is bound to the ip and unforgeable', () => {
    const t = kit.issue('1.2.3.4', now);
    expect(kit.tokenValid('9.9.9.9', now, t)).toBe(false);
    const [exp] = t.split('.');
    expect(kit.tokenValid('1.2.3.4', now, `${exp}.${'0'.repeat(64)}`)).toBe(false);
    expect(kit.tokenValid('1.2.3.4', now, 'garbage')).toBe(false);
    expect(kit.tokenValid('1.2.3.4', now, null)).toBe(false);
  });

  it('refuses a token minted with an expiry further out than the TTL allows', () => {
    const exp = now + CHALLENGE_TTL_MS * 24;
    const mac = createHmac('sha256', SECRET).update(`camada-challenge-token|1.2.3.4|${exp}`).digest('hex');
    expect(kit.tokenValid('1.2.3.4', now, `${exp}.${mac}`)).toBe(false);
  });
});

describe('proof of work', () => {
  it('accepts a 16-bit solution and rejects anything else', () => {
    const nonce = kit.nonce('1.2.3.4', Date.now());
    const sol = solve(nonce);
    expect(kit.solutionOk(nonce, sol)).toBe(true);
    expect(kit.solutionOk(nonce, String(Number(sol) + 1))).toBe(false);
    expect(kit.solutionOk(nonce, '')).toBe(false);
    expect(kit.solutionOk(nonce, null)).toBe(false);
    expect(kit.solutionOk(nonce, 'x'.repeat(64))).toBe(false);
    expect(POW_BITS).toBe(16);
  });
});

describe('async kit', () => {
  it('agrees with the sync kit byte for byte', async () => {
    const a = createChallengeAsync({ secret: SECRET });
    const now = 1_800_000_000_000;
    expect(await a.nonce('1.2.3.4', now)).toBe(kit.nonce('1.2.3.4', now));
    expect(kit.tokenValid('1.2.3.4', now, await a.issue('1.2.3.4', now))).toBe(true);
    expect(await a.tokenValid('1.2.3.4', now, kit.issue('1.2.3.4', now))).toBe(true);
    const nonce = await a.nonce('1.2.3.4', now);
    expect(await a.solutionOk(nonce, solve(nonce))).toBe(true);
    expect(await a.solutionOk(nonce, 'nope')).toBe(false);
  });
});

describe('helpers', () => {
  it('builds the cookie', () => {
    expect(challengeCookie('abc', false)).toBe(`${CHALLENGE_COOKIE}=abc; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax`);
    expect(challengeCookie('abc', true)).toContain('; Secure');
  });

  it('sanitises the return target to a same-site path', () => {
    expect(safeReturnTo('/cart?x=1')).toBe('/cart?x=1');
    expect(safeReturnTo('//evil.test/x')).toBe('/');
    expect(safeReturnTo('/\\evil.test/x')).toBe('/');
    expect(safeReturnTo('https://evil.test')).toBe('/');
    expect(safeReturnTo('/a\nb')).toBe('/');
    expect(safeReturnTo(null)).toBe('/');
    expect(safeReturnTo('/' + 'a'.repeat(4000))).toBe('/');
  });

  it('tells HTML navigations from everything else', () => {
    expect(wantsHtml('text/html,application/xhtml+xml', 'document')).toBe(true);
    expect(wantsHtml('text/html', null)).toBe(true);
    expect(wantsHtml('application/json', null)).toBe(false);
    expect(wantsHtml('text/html', 'empty')).toBe(false);
    expect(wantsHtml(null, null)).toBe(false);
  });

  it('parses a urlencoded body', () => {
    expect(parseFormBody('nonce=ab&solution=42&to=%2Fcart%3Fx%3D1')).toEqual({ nonce: 'ab', solution: '42', to: '/cart?x=1' });
    expect(parseFormBody('')).toEqual({});
  });
});

describe('page', () => {
  const html = challengePage({ nonce: 'abc123', action: '/__camada/challenge', to: '/cart?a="b' });
  const js = /<script>([\s\S]*)<\/script>/.exec(html)![1];

  it('is self-contained and no-JS-safe', () => {
    expect(html).toContain('<!doctype html>');
    expect(html).not.toMatch(/<script[^>]+src=/);
    expect(html).not.toMatch(/<link[^>]+href=/);
    expect(html).toContain('<noscript>');
  });

  it('escapes what it interpolates', () => {
    expect(html).toContain('value="/cart?a=&quot;b"');
    expect(html).toContain('value="abc123"');
    expect(html).toContain('action="/__camada/challenge"');
  });

  it('ships a solver whose SHA-256 matches node:crypto', () => {
    const probe = new Function(`${js}\nreturn __camadaSha256Hex;`) as () => (m: string) => string;
    const sha = probe();
    for (const msg of ['', 'abc.7', 'a'.repeat(55), 'a'.repeat(56), 'a'.repeat(64), 'abc123.65535']) {
      expect(sha(msg)).toBe(createHash('sha256').update(msg).digest('hex'));
    }
  });

  it('the solver finds a counter the server accepts', () => {
    const words = (new Function(`${js}\nreturn __camadaSha256Words;`) as () => (m: string) => number[])();
    let n = 0;
    while ((words(`abc123.${n}`)[0] >>> 16) !== 0) n++;
    expect(kit.solutionOk('abc123', String(n))).toBe(true);
  });
});

describe('hardening', () => {
  const now = 1_800_000_000_000;

  it('refuses a null ip outright rather than binding a token to nothing', () => {
    expect(kit.nonceValid(null, now, kit.nonce('1.2.3.4', now))).toBe(false);
    expect(kit.tokenValid(null, now, kit.issue('1.2.3.4', now))).toBe(false);
    expect(kit.verify(null, now, kit.nonce('1.2.3.4', now), '0')).toBe(false);
  });

  it('verify() demands our own nonce, not just any nonce with work done on it', () => {
    const forged = 'a'.repeat(32);
    expect(kit.solutionOk(forged, solve(forged))).toBe(true);       // the work really is done
    expect(kit.verify('1.2.3.4', now, forged, solve(forged))).toBe(false);   // but the nonce is not ours
    const mine = kit.nonce('1.2.3.4', now);
    expect(kit.verify('1.2.3.4', now, mine, solve(mine))).toBe(true);
  });

  it('rejects a non-ASCII return target (a Location header cannot carry it)', () => {
    expect(safeReturnTo('/café')).toBe('/');
    expect(safeReturnTo('/a b')).toBe('/');
    expect(safeReturnTo('/caf%C3%A9')).toBe('/caf%C3%A9');   // percent-encoded survives
  });

  it('cannot be made to close the inline script element early', () => {
    const html = challengePage({ nonce: '</script><script>alert(1)</script>', action: '/x', to: '/' });
    expect(html.match(/<script>/g)).toHaveLength(1);
    expect(html).not.toContain('alert(1)</script>');
  });

  it('clamps the difficulty so the solver shift stays in range', () => {
    expect(challengePage({ nonce: 'ab', action: '/x', to: '/', bits: 99 })).toContain('shift=0');
    expect(challengePage({ nonce: 'ab', action: '/x', to: '/', bits: 0 })).toContain('shift=31');
  });

  it('parses a form body without inherited keys', () => {
    const parsed = parseFormBody('__proto__=x&a=1');
    expect(Object.getPrototypeOf(parsed)).toBeNull();
    expect(parsed.a).toBe('1');
  });
});

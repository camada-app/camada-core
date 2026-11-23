import { describe, expect, it, vi } from 'vitest';
import { hashToken, hashUserId, requestTokenHash, resolveTokenHash, tokenCredential, tokenHashKey } from '../src/index.js';

describe('resolveTokenHash', () => {
  const on = { header: null, ignoredHeader: false };
  const envOn = { CAMADA_TOKEN_HASH: '1' };

  it('enables hashing only through the option or exact env flag', () => {
    expect(resolveTokenHash({}, {})).toBeNull();
    expect(resolveTokenHash({}, envOn)).toEqual(on);
    expect(resolveTokenHash({ tokenHash: true }, {})).toEqual(on);
    expect(resolveTokenHash({ tokenHash: false }, envOn)).toBeNull();
    for (const value of ['true', ' 1', '0']) {
      expect(resolveTokenHash({}, { CAMADA_TOKEN_HASH: value })).toBeNull();
    }
  });

  it('normalizes the header and prefers the option over the env', () => {
    const env = { ...envOn, CAMADA_TOKEN_HEADER: 'X-Api-Key' };
    expect(resolveTokenHash({}, env)).toEqual({ ...on, header: 'x-api-key' });
    expect(resolveTokenHash({ tokenHeader: 'X-Token' }, env)).toEqual({ ...on, header: 'x-token' });
    expect(resolveTokenHash({ tokenHeader: 'x'.repeat(64) }, env)).toEqual({ ...on, header: 'x'.repeat(64) });
  });

  it('falls back to the env when the header option is empty', () => {
    expect(resolveTokenHash({ tokenHeader: '' }, { ...envOn, CAMADA_TOKEN_HEADER: 'X-Api-Key' }))
      .toEqual({ ...on, header: 'x-api-key' });
  });

  it.each(['Authorization', 'Cookie', 'Set-Cookie', 'x_api_key', ' x-key', 'x'.repeat(65)])('ignores %s', (tokenHeader) => {
    expect(resolveTokenHash({ tokenHeader }, envOn)).toEqual({ header: null, ignoredHeader: true });
  });
});

describe('tokenCredential', () => {
  it('strips only SP and HTAB at the edges and after the Authorization scheme', () => {
    expect(tokenCredential(() => '\t Bearer \t fake1234\t ', null)).toBe('fake1234');
    for (const suffix of ['\v', '\0', '\r', '\n', '\tX']) {
      expect(tokenCredential(() => 'Bearer fake1234' + suffix, null)).toBeNull();
    }
  });
});

it('gives the dash header a different cache key from disabled hashing', () => {
  expect(tokenHashKey({ header: '-', ignoredHeader: false })).not.toBe(tokenHashKey(null));
});

describe('requestTokenHash', () => {
  const credential = 'fake-token-0001-not-a-real-credential';
  const cfg = { header: null, ignoredHeader: false };
  const key = 'ct_test_fixture_key';

  it('uses a different HMAC label from hashUserId', async () => {
    expect(await hashToken(credential, key)).not.toBe(await hashUserId(credential, key));
  });

  it('fails open without logging the credential when signing fails or subtle is unavailable', async () => {
    const get = () => `Bearer ${credential}`;
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const sign = vi.spyOn(crypto.subtle, 'sign').mockRejectedValue(new Error(credential));
    try {
      await expect(requestTokenHash(get, cfg, key)).resolves.toBeNull();
      expect(sign).toHaveBeenCalledOnce();
      expect(error).toHaveBeenCalledWith(expect.any(String), 'token hash failed; event ships without tk');
      vi.stubGlobal('crypto', {});
      await expect(requestTokenHash(get, cfg, key)).resolves.toBeNull();
      expect(JSON.stringify(error.mock.calls)).not.toContain(credential);
    } finally {
      vi.unstubAllGlobals();
      sign.mockRestore();
      error.mockRestore();
    }
  });
});

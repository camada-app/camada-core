import { authScheme } from './events/build.js';
import { guarded, logRateLimited } from './guarded.js';
import { hashToken } from './redact.js';

/** Reads the first value when the runtime exposes repeated headers separately. */
export type HeaderGet = (lowerName: string) => string | null | undefined;
export interface TokenHashOptions { tokenHash?: boolean; tokenHeader?: string | null }
export interface TokenHashConfig { header: string | null; ignoredHeader: boolean }

export function normalizeTokenHeader(raw: string | null | undefined): string | null {
  if (typeof raw !== 'string') return null;
  const name = raw.toLowerCase();
  return /^[a-z0-9-]{1,64}$/.test(name) && !['authorization', 'cookie', 'set-cookie'].includes(name) ? name : null;
}

export function resolveTokenHash(opts: TokenHashOptions, env: Record<string, string | undefined>): TokenHashConfig | null {
  if ((opts.tokenHash ?? (env.CAMADA_TOKEN_HASH === '1')) !== true) return null;
  const raw = opts.tokenHeader || env.CAMADA_TOKEN_HEADER;
  const header = normalizeTokenHeader(raw);
  return { header, ignoredHeader: Boolean(raw) && header === null };
}

export function tokenHashKey(cfg: TokenHashConfig | null): string {
  return cfg === null ? 'off' : 'on:' + (cfg.header ?? '');
}

export function warnIgnoredTokenHeader(cfg: TokenHashConfig | null): void {
  if (cfg?.ignoredHeader) guarded(() => console.warn('[camada] token header ignored; using Authorization only'), undefined);
}

// Keep everything from the first through the last non-SP/HTAB character.
const stripOWS = (value: string | null | undefined): string => value?.match(/[^ \t](?:[\s\S]*[^ \t])?/)?.[0] ?? '';
const credentialRE = /^[\x20-\x7e]{8,}$/;

export function tokenCredential(get: HeaderGet, tokenHeader: string | null): string | null {
  if (tokenHeader) {
    const extra = stripOWS(get(tokenHeader));
    if (credentialRE.test(extra)) return extra;
  }
  const value = stripOWS(get('authorization'));
  const scheme = authScheme(value);
  const credential = scheme ? stripOWS(value.slice(scheme.length + 1)) : value;
  return credentialRE.test(credential) ? credential : null;
}

export async function requestTokenHash(get: HeaderGet, cfg: TokenHashConfig | null, ingestToken: string, subtle?: SubtleCrypto): Promise<string | null> {
  if (!cfg) return null;
  try {
    const credential = tokenCredential(get, cfg.header);
    return credential === null ? null : await hashToken(credential, ingestToken, subtle);
  } catch {
    logRateLimited(new Error('token hash failed; event ships without tk'));
    return null;
  }
}

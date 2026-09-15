// Options and environment for the Web-fetch adapters (@camada/sveltekit, nuxt, remix, bun, deno).
// The host hands env per request (a Workers binding) or per process (process.env / Bun.env /
// Deno.env) — the adapter merges whichever it has with the options the app passed in code.
import { parseKey } from '../config.js';
import { parseTrustedProxyEnv, type TrustedProxyConfig } from '../ip.js';
import type { SnapshotVersion } from '../constants.js';

export interface ResolvedFetchEnv {
  ingestToken: string;
  snapToken: string;
  secret: string;                            // HMAC key for the challenge nonce/cookie — never leaves the process
  ingestUrl: string;
  snapshotUrl: string;
  trustedProxy: TrustedProxyConfig | null;   // null = defer to server-delivered config
  mode: 'lazy' | 'timer';                    // lazy: ensureFresh per request (edge/serverless); timer: unref'd poll (long-lived)
}

export interface FetchCamadaOptions {
  key?: string;
  ingestUrl?: string;
  snapshotUrl?: string;
  trustedProxy?: TrustedProxyConfig | string | null;
  challenge?: boolean;            // enforce `challenge` verdicts with the first-party page (default true)
  challengePath?: string;         // where that page posts its solution (default /__camada/challenge)
  snapshotVersion?: SnapshotVersion;   // 5 (default) also carries the tenant's ordered custom rules; 4 the allow/challenge sides only; 3 opts out of both
  scriptPath?: string;            // where the first-party beacon script is served (default /_cam/b.js)
  fpPath?: string;                // where that script posts the beacon (default /_cam/fp; must share scriptPath's directory — the script derives it)
  mode?: 'lazy' | 'timer';        // the adapter's default for its host; CAMADA_SERVERLESS=1 forces lazy
  env?: Record<string, string | undefined>;   // overrides the host env (tests, and apps that read config themselves)
  fetchImpl?: typeof fetch;
}

const asProxy = (v: FetchCamadaOptions['trustedProxy']): TrustedProxyConfig | null =>
  typeof v === 'string' ? parseTrustedProxyEnv(v) : v ?? null;

/** Returns null (the adapter stays inert, one log line) rather than throwing on bad config. */
export function resolveFetchEnv(opts: FetchCamadaOptions, env: Record<string, string | undefined>): ResolvedFetchEnv | null {
  const raw = opts.key || env.CAMADA_KEY;
  const key = parseKey(raw);
  const ingestToken = key?.ingestToken ?? env.CAMADA_TOKEN;
  const snapToken = key?.snapToken ?? env.CAMADA_SNAPSHOT_TOKEN;
  if (!ingestToken || !snapToken) return null;
  const ingestUrl = (opts.ingestUrl || env.CAMADA_INGEST_URL || 'https://in.camada.app').replace(/\/$/, '');   // PLACEHOLDER default — confirm the production ingest domain before any npm publish
  return {
    ingestToken, snapToken,
    secret: raw || `${ingestToken}.${snapToken}`,
    ingestUrl,
    snapshotUrl: opts.snapshotUrl || env.CAMADA_SNAPSHOT_URL || `${ingestUrl}/snapshot`,
    trustedProxy: asProxy(opts.trustedProxy) ?? parseTrustedProxyEnv(env.CAMADA_TRUSTED_PROXY),
    mode: env.CAMADA_SERVERLESS === '1' ? 'lazy' : opts.mode ?? 'lazy',
  };
}

import type { TrustedProxyConfig } from './ip.js';

/** What GET /snapshot hands back in x-camada-config (whitelisted server-side). */
export interface CamadaRemoteConfig {
  tenant: string;
  beacon: boolean;
  sample: number;
  exclude: string[];
  trusted_proxy: TrustedProxyConfig;
  poll_seconds: number;
}

export interface CamadaKey { ingestToken: string; snapToken: string }

/** CAMADA_KEY is `<ingest_token>.<snap_token>` (printed by reconcile instructions and seed). */
export function parseKey(key: string | null | undefined): CamadaKey | null {
  if (!key) return null;
  const dot = key.indexOf('.');
  if (dot <= 0 || dot === key.length - 1) return null;
  return { ingestToken: key.slice(0, dot), snapToken: key.slice(dot + 1) };
}

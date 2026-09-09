// Tap identifiers this SDK family may claim on the wire. The server validates against its own
// enum and derives the capability mask itself (edge-analyst src/capabilities.js) — an SDK can
// never grant itself capability bits, only name its position.
export const TAP_NODE = 'sdk-node';
export const TAP_NEXT = 'sdk-next';
export const TAP_HONO = 'sdk-hono';
// SDK-G04: the five @camada/core/fetch adapters. Each sits in-app (edge-analyst TAP_CAPS IN_APP).
export const TAP_SVELTEKIT = 'sdk-sveltekit';
export const TAP_NUXT = 'sdk-nuxt';
export const TAP_REMIX = 'sdk-remix';
export const TAP_BUN = 'sdk-bun';
export const TAP_DENO = 'sdk-deno';
export type Tap =
  | typeof TAP_NODE | typeof TAP_NEXT | typeof TAP_HONO
  | typeof TAP_SVELTEKIT | typeof TAP_NUXT | typeof TAP_REMIX | typeof TAP_BUN | typeof TAP_DENO;

export const DEFAULT_REFRESH_MS = 30_000;

/** Snapshot containers this SDK family can read (§D3). 5 carries the tenant's ordered custom
 *  rules on top of v4's allow/challenge sides; a tenant without one is answered with the next
 *  container down, so asking for 5 is always safe. */
export type SnapshotVersion = 3 | 4 | 5;
export const DEFAULT_SNAPSHOT_VERSION: SnapshotVersion = 5;
export const KILL_SWITCH_ENV = 'CAMADA_DISABLED';

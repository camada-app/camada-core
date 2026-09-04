// Tap identifiers this SDK family may claim on the wire. The server validates against its own
// enum and derives the capability mask itself (edge-analyst src/capabilities.js) — an SDK can
// never grant itself capability bits, only name its position.
export const TAP_NODE = 'sdk-node';
export const TAP_NEXT = 'sdk-next';
export const TAP_HONO = 'sdk-hono';
export type Tap = typeof TAP_NODE | typeof TAP_NEXT | typeof TAP_HONO;

export const DEFAULT_REFRESH_MS = 30_000;
export const KILL_SWITCH_ENV = 'CAMADA_DISABLED';

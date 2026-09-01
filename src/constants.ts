// Tap identifiers this SDK family may claim on the wire. The server validates against its own
// enum and decides itself what each tap can see — an SDK can
// never grant itself more than that, only name its position.
export const TAP_NODE = 'sdk-node';
export const TAP_NEXT = 'sdk-next';
export type Tap = typeof TAP_NODE | typeof TAP_NEXT;

export const DEFAULT_REFRESH_MS = 30_000;
export const KILL_SWITCH_ENV = 'CAMADA_DISABLED';

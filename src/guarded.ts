// The fail-open envelope: a camada bug must never 5xx the customer. Every public entry point
// of the backend SDKs runs inside guarded(); failures fall back and log at most once a minute.

let lastLog = 0;

export function logRateLimited(err: unknown): void {
  const now = Date.now();
  if (now - lastLog < 60_000) return;
  lastLog = now;
  try { console.error('[camada] suppressed error (SDK fails open):', err instanceof Error ? err.message : err); } catch { /* even logging must not throw */ }
}

export function guarded<T>(fn: () => T, fallback: T): T {
  try { return fn(); } catch (err) { logRateLimited(err); return fallback; }
}

export async function guardedAsync<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  try { return await fn(); } catch (err) { logRateLimited(err); return fallback; }
}

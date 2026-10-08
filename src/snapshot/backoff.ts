// Pacing of the snapshot poll after a failed answer (camada-all-pbv9, contract v2).
// Internal: not re-exported from src/index.ts.

const FLOOR_SECONDS = 5;

/** delta-seconds only (`^[0-9]+$` after trimming SP/HTAB). Anything else, HTTP-dates included, reads as 0
 *  so the floor applies. An all-digit value too long to be exact reads as huge (the cap then wins). */
function parseRetryAfter(v: string | null): number {
  const s = (v ?? '').replace(/^[ \t]+|[ \t]+$/g, '');
  if (!/^[0-9]+$/.test(s)) return 0;
  return s.length > 9 ? 1e9 : Number(s);
}

/** Seconds to wait before the next self-initiated poll; null when the answer was 200/204/304 (the
 *  normal cadence governs). Status 0 = no answer. The refresh cap wins over the 5 s floor. */
export function nextPollDelay(status: number, retryAfter: string | null, refreshSeconds: number): number | null {
  if (status === 200 || status === 204 || status === 304) return null;
  return Math.min(Math.max(parseRetryAfter(retryAfter), FLOOR_SECONDS), Math.max(refreshSeconds, 0));
}

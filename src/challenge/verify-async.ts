// The WebCrypto twin of verify.ts, for runtimes with no synchronous HMAC (@camada/next,
// @camada/hono). Same messages, same token format — the two kits are interchangeable on the wire.
import {
  CHALLENGE_TTL_MS, NONCE_HEX, nonceMessage, tokenMessage, safeEqual, splitToken, powOk,
  solutionShapeOk, utcDay,
} from './format.js';

const enc = new TextEncoder();

const toHex = (buf: ArrayBuffer): string => {
  const b = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
};

function subtle(): SubtleCrypto {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c?.subtle) throw new Error('camada: WebCrypto subtle is unavailable — the challenge needs it');
  return c.subtle;
}

export async function hmacHex(secret: string, msg: string): Promise<string> {
  const s = subtle();
  const key = await s.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return toHex(await s.sign('HMAC', key, enc.encode(msg)));
}

export async function sha256Hex(msg: string): Promise<string> {
  return toHex(await subtle().digest('SHA-256', enc.encode(msg)));
}

export interface AsyncChallengeKit {
  nonce(ip: string, now: number): Promise<string>;
  nonceValid(ip: string | null, now: number, nonce: string | null | undefined): Promise<boolean>;
  issue(ip: string, now: number): Promise<string>;
  tokenValid(ip: string | null, now: number, cookieValue: string | null | undefined): Promise<boolean>;
  /** Proof of work ONLY — see ChallengeKit.solutionOk. Use verify(). */
  solutionOk(nonce: string, solution: string | null | undefined): Promise<boolean>;
  verify(ip: string | null, now: number, nonce: string | null | undefined, solution: string | null | undefined): Promise<boolean>;
}

export function createChallengeAsync({ secret }: { secret: string }): AsyncChallengeKit {
  const at = async (ip: string, day: number) => (await hmacHex(secret, nonceMessage(ip, day))).slice(0, NONCE_HEX);
  const kit: AsyncChallengeKit = {
    nonce: (ip, now) => at(ip, utcDay(now)),
    // Same replay and null-ip rules as the sync kit — see verify.ts.
    async nonceValid(ip, now, nonce) {
      if (!ip || !nonce || nonce.length !== NONCE_HEX) return false;
      const day = utcDay(now);
      return safeEqual(nonce, await at(ip, day)) || safeEqual(nonce, await at(ip, day - 1));
    },
    async issue(ip, now) {
      const exp = now + CHALLENGE_TTL_MS;
      return `${exp}.${await hmacHex(secret, tokenMessage(ip, exp))}`;
    },
    async tokenValid(ip, now, cookieValue) {
      if (!ip) return false;
      const t = splitToken(cookieValue);
      if (!t || t.exp <= now || t.exp > now + CHALLENGE_TTL_MS) return false;
      return safeEqual(t.mac, await hmacHex(secret, tokenMessage(ip, t.exp)));
    },
    async solutionOk(nonce, solution) {
      return solutionShapeOk(solution) ? powOk(await sha256Hex(`${nonce}.${solution}`)) : false;
    },
    async verify(ip, now, nonce, solution) {
      return (await kit.nonceValid(ip, now, nonce)) && (await kit.solutionOk(nonce as string, solution));
    },
  };
  return kit;
}

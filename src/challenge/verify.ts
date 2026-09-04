// The synchronous challenge kit. @camada/node builds it over node:crypto so its handle() can
// stay a synchronous boolean; the async twin (verify-async.ts) is the same logic over WebCrypto.
import {
  CHALLENGE_TTL_MS, NONCE_HEX, nonceMessage, tokenMessage, safeEqual, splitToken, powOk,
  solutionShapeOk, utcDay,
} from './format.js';

export interface ChallengeCryptoSync {
  secret: string;
  hmac: (secret: string, msg: string) => string;   // hex
  sha: (msg: string) => string;                    // hex SHA-256
}

export interface ChallengeKit {
  /** Stateless per-(ip, UTC day) nonce; the verify endpoint recomputes it, nothing is stored. */
  nonce(ip: string, now: number): string;
  nonceValid(ip: string | null, now: number, nonce: string | null | undefined): boolean;
  issue(ip: string, now: number): string;
  tokenValid(ip: string | null, now: number, cookieValue: string | null | undefined): boolean;
  /** Proof of work ONLY. Never call it without a passing nonceValid() for the same nonce —
   *  otherwise the work is done over a nonce the caller chose. Use verify() instead. */
  solutionOk(nonce: string, solution: string | null | undefined): boolean;
  /** The whole submission: the nonce is ours and unexpired, and the work is done. */
  verify(ip: string | null, now: number, nonce: string | null | undefined, solution: string | null | undefined): boolean;
}

export function createChallenge({ secret, hmac, sha }: ChallengeCryptoSync): ChallengeKit {
  const at = (ip: string, day: number) => hmac(secret, nonceMessage(ip, day)).slice(0, NONCE_HEX);
  const kit: ChallengeKit = {
    nonce: (ip, now) => at(ip, utcDay(now)),
    // Yesterday still passes: a solve started before midnight UTC must not be thrown away.
    // So one solved (nonce, solution) pair is replayable from its own IP for up to ~48 h,
    // minting a fresh 1 h cookie each time. That is the price of a stateless nonce (§D2) and
    // it is deliberate — do not "fix" it into something that needs shared server state.
    nonceValid(ip, now, nonce) {
      if (!ip || !nonce || nonce.length !== NONCE_HEX) return false;
      const day = utcDay(now);
      return safeEqual(nonce, at(ip, day)) || safeEqual(nonce, at(ip, day - 1));
    },
    issue(ip, now) {
      const exp = now + CHALLENGE_TTL_MS;
      return `${exp}.${hmac(secret, tokenMessage(ip, exp))}`;
    },
    // A null ip is refused outright: without one the token is bound to nothing, so a single
    // solve would mint a cookie every other unidentified client could present. Adapters must
    // fail open (serve no challenge) rather than challenge a client they cannot identify.
    tokenValid(ip, now, cookieValue) {
      if (!ip) return false;
      const t = splitToken(cookieValue);
      if (!t || t.exp <= now || t.exp > now + CHALLENGE_TTL_MS) return false;
      return safeEqual(t.mac, hmac(secret, tokenMessage(ip, t.exp)));
    },
    solutionOk: (nonce, solution) => (solutionShapeOk(solution) ? powOk(sha(`${nonce}.${solution}`)) : false),
    verify: (ip, now, nonce, solution) => kit.nonceValid(ip, now, nonce) && kit.solutionOk(nonce as string, solution),
  };
  return kit;
}

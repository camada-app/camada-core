// @camada/core/fetch — the request pipeline every Web-fetch adapter shares (SDK-G04). It is
// @camada/hono's middleware with the host-specific parts lifted out: the adapter supplies the
// socket peer (or an already-resolved client ip), any geo/TLS facts its runtime vouches for, a
// `waitUntil` where the isolate needs holding open, and the env; it stores the returned vars in
// its framework's per-request slot and calls `after()` once the response has settled. Everything
// runs inside camada's fail-open envelope: a camada bug, a dead ingest or a corrupt snapshot
// costs telemetry, never the app's response.
import { SnapshotClient } from '../snapshot/client.js';
import { EventQueue } from '../events/queue.js';
import { buildWireEvent, type WireEvent } from '../events/build.js';
import { resolveClientIp, type TrustedProxyConfig } from '../ip.js';
import { hashUserId } from '../redact.js';
import { guarded, guardedAsync, logRateLimited } from '../guarded.js';
import { createChallengeAsync, type AsyncChallengeKit } from '../challenge/verify-async.js';
import { challengePage } from '../challenge/page.js';
import { challengeCookie, safeReturnTo, wantsHtml, parseFormBody, CHALLENGE_COOKIE } from '../challenge/format.js';
import { DEFAULT_SNAPSHOT_VERSION, type Tap } from '../constants.js';
import { resolveFetchEnv, type FetchCamadaOptions, type ResolvedFetchEnv } from './env.js';

const DEFAULT_CHALLENGE_PATH = '/__camada/challenge';
const SCRIPT_PATH = '/_cam/b.js';   // the beacon IIFE; its auto-init posts to the sibling `fp` and reads the rid from ?r=
const FP_PATH = '/_cam/fp';
const FP_MAX = 32 * 1024;        // matches the analyst's /fp cap: never accept what ingest will 413
export const SESSION_COOKIE = '_sfp';   // the same session cookie as every other tap: sid/ns stay comparable
export const SESSION_MAX_AGE = 2592000;   // 30 days; exported so an adapter setting the cookie through its framework API matches
const BODY_MAX = 4 * 1024;       // the verify form is ~120 bytes; anything larger is not ours
const encoder = new TextEncoder();

export type WaitUntil = (p: Promise<unknown>) => void;
const noWait: WaitUntil = () => {};

/** Who this adapter is on the wire: its tap, its `x-camada-sdk` value, and the beacon it serves. */
export interface FetchIdentity {
  tap: Tap;
  sdk: string;      // '<package>/<version>'
  iife: string;     // @camada/browser's iife-string — injected so core keeps no runtime dependency
}

/** What the host knows about this request that the Request object cannot say. */
export interface FetchRequestContext {
  /** The socket address the runtime vouches for (Bun `server.requestIP`, Deno `remoteAddr`,
   *  SvelteKit `getClientAddress`). Combined with X-Forwarded-For under the trusted-proxy rules. */
  peer?: string | null;
  /** An already-resolved client address (a Workers-class host's own header). Wins when set. */
  ip?: string | null;
  asn?: number | null;
  country?: string | null;
  tlsx?: string | null;
  httpVersion?: string | null;   // the client's own protocol, e.g. '2' — only when the host really knows it
  waitUntil?: WaitUntil;
  env?: Record<string, string | undefined>;
}

export interface Engine {
  tap: Tap;
  env: ResolvedFetchEnv;
  snap: SnapshotClient;
  queue: EventQueue;
  kit: AsyncChallengeKit;
}

interface Facts { asn: number | null; country: string | null; tlsx: string | null; httpVersion: string | null }

/** Per-request state the adapter keeps in its framework's slot: `after()`, `track()` and `scriptTag()` read it. */
export interface FetchVars {
  eng: Engine;
  rid: string;                    // the request id the page event carries; the beacon and track() join on it
  sid: string | null;             // the `_sfp` session — the one just minted when the request arrived without it
  newSession: boolean;
  sessionCookie: string | null;   // the `set-cookie` value to send when the session is new; null otherwise
  ip: string | null;
  warnRule: string | null;        // §D3: the warn rule that let this request through
  scriptPath: string;
  waitUntil: WaitUntil;
  facts: Facts;
}

export type BeforeResult = { response: Response; vars?: undefined } | { response?: undefined; vars: FetchVars } | null;

export interface FetchCamada {
  /** Runs everything that must happen before the app: config, verdict, block, challenge, the
   *  beacon endpoints. `{ response }` = camada answered; `{ vars }` = let the app run and call
   *  `after()`; `null` = inert for this request (no key, or CAMADA_DISABLED). */
  before(req: Request, ctx?: FetchRequestContext): Promise<BeforeResult>;
  /** Ships the wire event with the settled status (`null` where the host cannot see it). Never throws. */
  after(req: Request, vars: FetchVars, status: number | null): void;
  /** Test/reset hook: stops and drops every cached engine. */
  reset(): void;
}

const cookieValue = (cookie: string, name: string): string | null => {
  const src = '; ' + cookie;
  const i = src.indexOf('; ' + name + '=');
  if (i === -1) return null;
  const start = i + name.length + 3;
  const j = src.indexOf(';', start);
  return src.slice(start, j === -1 ? undefined : j);
};

const trustedProxy = (e: Engine): TrustedProxyConfig | null =>
  e.env.trustedProxy ?? e.snap.config?.trusted_proxy ?? null;

const beaconEnabled = (e: Engine): boolean => e.snap.config?.beacon !== false;   // tenant switch; a cold engine serves

/** Push then flush through `waitUntil` — the one rule every row (wire event, beacon, track()) follows. */
function ship(e: Engine, ev: unknown, waitUntil: WaitUntil): void {
  e.queue.push(ev);
  e.queue.flush(waitUntil);
}

/** Appends a `set-cookie` to a response, rebuilding it when its headers are immutable
 *  (`Response.redirect()`, a `fetch()` result). The body stream and status are kept as they are. */
export function withSetCookie(res: Response, cookie: string): Response {
  try {
    res.headers.append('set-cookie', cookie);
    return res;
  } catch {
    const out = new Response(res.body, res);
    out.headers.append('set-cookie', cookie);
    return out;
  }
}

/**
 * Records an outcome the app knows and the wire cannot show: `login_failed`, `login_succeeded`,
 * `signup`, `password_reset`, `mfa_failed`, `payment_failed`, `payment_succeeded`, `coupon_failed`
 * (free-form; that vocabulary is what the analyst's rules read). Joined to this request's event
 * through its rid and session. The user identifier is HMAC-hashed in-process with the ingest
 * token — the raw value never reaches the queue. Never throws, never rejects; awaiting it is
 * optional (the flush rides `waitUntil`), so a handler may fire and forget. A no-op without vars,
 * so an adapter forwards its slot lookup as it is.
 */
export function track(vars: FetchVars | undefined, event: string, data?: { user?: string }): Promise<void> {
  if (!vars) return Promise.resolve();
  const p = guardedAsync(async () => {
    const uid = data?.user ? await hashUserId(data.user, vars.eng.env.ingestToken) : null;
    ship(vars.eng, { tap: vars.eng.tap, et: event, uid, rid: vars.rid, sid: vars.sid, ip: vars.ip, ts: Date.now() }, vars.waitUntil);
  }, undefined);
  vars.waitUntil(p);   // the isolate may freeze right after the response: hold it open for the flush
  return p;
}

/** The `<script>` tag for an HTML response — `''` without vars (camada did not run for this request) or when the tenant turned the beacon off. */
export function scriptTag(vars: FetchVars | undefined): string {
  return guarded(() => {
    if (!vars || !beaconEnabled(vars.eng)) return '';
    return `<script src="${vars.scriptPath}?r=${vars.rid}" async></script>`;
  }, '');
}

export function createFetchCamada(id: FetchIdentity, opts: FetchCamadaOptions = {}): FetchCamada {
  const challengePath = opts.challengePath ?? DEFAULT_CHALLENGE_PATH;
  const scriptPath = opts.scriptPath ?? SCRIPT_PATH;
  const fpPath = opts.fpPath ?? FP_PATH;
  const tap = id.tap;

  // One engine per resolved configuration, not per module: a host can mount several apps in one
  // process, and a shared singleton would enforce the first tenant's snapshot on the second and
  // sign its `_cch` cookies with the first tenant's secret. An unconfigured request is never
  // cached — a warm-up or a differently-keyed mount must not leave the process inert for good.
  const engines = new Map<string, Engine>();

  function ensure(env: Record<string, string | undefined>): Engine | null {
    const resolved = resolveFetchEnv(opts, env);
    if (!resolved) {
      logRateLimited(new Error('CAMADA_KEY not set — camada is inactive'));
      return null;
    }
    const snapshotVersion = opts.snapshotVersion ?? DEFAULT_SNAPSHOT_VERSION;
    const key = `${resolved.ingestToken}|${resolved.ingestUrl}|${resolved.snapshotUrl}|${snapshotVersion}|${resolved.mode}`;
    const cached = engines.get(key);
    if (cached) return cached;
    const injected = opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {};   // never pass an explicit undefined key
    const engine: Engine = {
      tap, env: resolved,
      snap: new SnapshotClient({ url: resolved.snapshotUrl, token: resolved.snapToken, mode: resolved.mode, sdk: id.sdk, snapshotVersion, ...injected }),
      queue: new EventQueue({ url: resolved.ingestUrl, token: resolved.ingestToken, sdk: id.sdk, ...injected }),
      kit: createChallengeAsync({ secret: resolved.secret }),
    };
    if (resolved.mode === 'timer') { engine.snap.start(); engine.queue.installNodeExitFlush(); }   // long-lived host: poll on a timer, drain on exit (both self-guarding)
    engines.set(key, engine);
    return engine;
  }

  const factsOf = (ctx: FetchRequestContext): Facts =>
    ({ asn: ctx.asn ?? null, country: ctx.country ?? null, tlsx: ctx.tlsx ?? null, httpVersion: ctx.httpVersion ?? null });

  /** The host's own resolution wins; otherwise the vouched peer and X-Forwarded-For under the
   *  trusted-proxy rules — never a bare header, which any client can forge. */
  const clientIp = (e: Engine, req: Request, ctx: FetchRequestContext): string | null =>
    ctx.ip || resolveClientIp(ctx.peer ?? null, req.headers.get('x-forwarded-for'), trustedProxy(e));

  function buildEvent(
    req: Request, path: string, query: string, ip: string | null, sid: string | null, facts: Facts,
    rid: string = crypto.randomUUID(), newSession = false,   // the capture path passes the ids it shared with the app; camada's own answers need none
  ): WireEvent {
    const headers: Array<[string, string]> = [];
    req.headers.forEach((v, k) => headers.push([k, v]));   // Headers normalise order: no HEADER_ORDER signal at this position
    const ev = buildWireEvent(
      { method: req.method, host: req.headers.get('host') ?? new URL(req.url).host, path, query, headers, ip, httpVersion: facts.httpVersion },
      { tap, rid, sid, newSession },
    );
    if (facts.asn) ev.asn = facts.asn;
    if (facts.country) ev.cc = facts.country;
    if (facts.tlsx) ev.tlsx = facts.tlsx;
    return ev;
  }

  /** 204 and a `sig: 1` row on the event batch — one request per flush at the analyst, not one per page view. */
  async function relayBeacon(eng: Engine, req: Request, ip: string | null, waitUntil: WaitUntil): Promise<Response> {
    const noContent = () => new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } });
    if (Number(req.headers.get('content-length')) > FP_MAX) return new Response(null, { status: 413 });
    const body = await req.text();
    if (encoder.encode(body).byteLength > FP_MAX) return new Response(null, { status: 413 });
    let parsed: unknown;
    try { parsed = JSON.parse(body); } catch { return noContent(); }   // not a beacon: drop it, never ship junk
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return noContent();
    // Spread first: the ip and the tap are the server's to say, whatever the body claimed.
    ship(eng, { ...(parsed as Record<string, unknown>), sig: 1, ip, tap }, waitUntil);
    return noContent();
  }

  /** 403 + the proof-of-work page (HTML navigations) or 403 JSON, plus the `blk: "challenge"` event. */
  async function serve(eng: Engine, req: Request, ip: string, sid: string | null, facts: Facts, target: string, waitUntil: WaitUntil): Promise<Response> {
    const url = new URL(req.url);
    const ev = buildEvent(req, url.pathname, url.search, ip, sid, facts);
    ev.st = 403;
    ev.blk = 'challenge';
    ship(eng, ev, waitUntil);
    if (!wantsHtml(req.headers.get('accept'), req.headers.get('sec-fetch-dest'))) {
      return new Response('{"error":"challenge_required"}', {
        status: 403, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-camada-challenge': '1' },
      });
    }
    const html = challengePage({ nonce: await eng.kit.nonce(ip, Date.now()), action: challengePath, to: safeReturnTo(target) });
    return new Response(html, {
      status: 403, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-camada-challenge': '1' },
    });
  }

  /** POST from the page: validate, set `_cch`, 302 back, ship `{ st: 200, ch: 1 }`. */
  async function verify(eng: Engine, req: Request, ip: string, sid: string | null, facts: Facts, waitUntil: WaitUntil): Promise<Response> {
    const url = new URL(req.url);
    // camada answers this path before the app runs, so it must not become a place to post
    // hundreds of megabytes at an unauthenticated endpoint.
    if (Number(req.headers.get('content-length')) > BODY_MAX) return new Response(null, { status: 413 });
    const body = await req.text();
    if (body.length > BODY_MAX) return new Response(null, { status: 413 });
    const form = parseFormBody(body);
    const to = safeReturnTo(form.to);
    const now = Date.now();
    if (!(await eng.kit.verify(ip, now, form.nonce, form.solution))) {
      const html = challengePage({ nonce: await eng.kit.nonce(ip, now), action: challengePath, to });
      return new Response(html, { status: 403, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
    }
    const ev = buildEvent(req, url.pathname, '', ip, sid, facts);
    ev.st = 200;
    ev.ch = 1;   // challenge passed (contract §A3 ingest field)
    ship(eng, ev, waitUntil);
    return new Response(null, {
      status: 302,
      headers: { location: to, 'set-cookie': challengeCookie(await eng.kit.issue(ip, now), url.protocol === 'https:'), 'cache-control': 'no-store' },
    });
  }

  async function before(req: Request, ctx: FetchRequestContext = {}): Promise<BeforeResult> {
    // Reading the env and building the engine are inside the guard too: a host env can carry
    // non-string bindings, and a throw here would 5xx the app on its very first request.
    const env = guarded(() => ({ ...ctx.env, ...opts.env }), {} as Record<string, string | undefined>);
    const eng = guarded(() => (env.CAMADA_DISABLED === '1' ? null : ensure(env)), null);
    if (!eng) return null;
    const challengeOn = opts.challenge !== false && env.CAMADA_CHALLENGE !== '0';
    const waitUntil = ctx.waitUntil ?? noWait;
    const facts = factsOf(ctx);

    const answered = await guardedAsync(async (): Promise<BeforeResult> => {
      eng.snap.ensureFresh(waitUntil);
      const url = new URL(req.url);
      const path = url.pathname;
      const cookies = req.headers.get('cookie') || '';
      const ip = clientIp(eng, req, ctx);
      const sid = cookieValue(cookies, SESSION_COOKIE);

      const v = eng.snap.verdict({
        ip, path, ua: req.headers.get('user-agent'),   // §D3: without ua every `ua` rule is false
        // `header` conditions read the request through this getter; `Headers.get` is case-insensitive,
        // so the lower-cased name the matcher asks with finds whatever spelling the client sent.
        header: (n) => req.headers.get(n),
        asn: facts.asn, country: facts.country, tlsx: facts.tlsx,
      });
      const warnRule = v.warn ? v.rule ?? null : null;

      if (v.block) {
        const ev = buildEvent(req, path, url.search, ip, sid, facts);
        ev.st = 403;
        ev.blk = v.reason;   // SDK-01: the analyst counts SDK blocks apart from the app's own 403s ('rule' when a rule decided)
        if (v.rule) ev.rl = v.rule;
        ship(eng, ev, waitUntil);
        const headers: Record<string, string> = { 'content-type': 'text/plain', 'x-block-reason': String(v.reason ?? ''), 'x-block-version': v.version ?? '' };
        if (v.rule) headers['x-block-rule'] = v.rule;   // a custom rule blocked: name it, so the customer knows which row to edit
        return { response: new Response('Forbidden', { status: 403, headers }) };
      }

      // A challenge needs a resolved client ip: the nonce and the `_cch` cookie are bound to it.
      // Without one, fail open rather than mint a cookie every unidentified client could use.
      if (challengeOn && ip) {
        // The verify endpoint answers first — a challenged client must be able to reach it.
        if (req.method === 'POST' && path === challengePath) return { response: await verify(eng, req, ip, sid, facts, waitUntil) };
        const token = cookieValue(cookies, CHALLENGE_COOKIE);
        if (v.challenge && !(await eng.kit.tokenValid(ip, Date.now(), token))) {
          return { response: await serve(eng, req, ip, sid, facts, path + url.search, waitUntil) };
        }
      }

      // The beacon endpoints come after enforcement (a blocked or challenged client gets neither
      // the script nor a relay) and before the app (they are camada's, not its). With the tenant's
      // beacon off they fall through to the app, which 404s them — @camada/node's order.
      if (beaconEnabled(eng)) {
        if (req.method === 'GET' && path === scriptPath) {
          return { response: new Response(id.iife, { status: 200, headers: { 'content-type': 'application/javascript', 'cache-control': 'public, max-age=3600' } }) };
        }
        if (req.method === 'POST' && path === fpPath) return { response: await relayBeacon(eng, req, ip, waitUntil) };
      }

      // Capture: mint the ids the app, the beacon and the post-response event all share. The
      // session is decided here rather than after the app so track() inside a handler and the
      // event both carry the sid a first visit is about to be given.
      const newSession = !sid;
      const mintedSid = sid ?? crypto.randomUUID();
      const secure = url.protocol === 'https:' ? '; Secure' : '';
      const sessionCookie = newSession ? `${SESSION_COOKIE}=${mintedSid}; Path=/; Max-Age=${SESSION_MAX_AGE}; HttpOnly; SameSite=Lax${secure}` : null;
      return { vars: { eng, rid: crypto.randomUUID(), sid: mintedSid, newSession, sessionCookie, ip, warnRule, scriptPath, waitUntil, facts } };
    }, undefined);

    // The guard threw before deciding: let the app run and still ship its event, with fresh ids
    // and the client address resolved again — a camada bug costs the join, never the telemetry
    // or its attribution (@camada/hono's rule). No session is minted: nothing was decided.
    if (answered) return answered;
    const ip = guarded(() => clientIp(eng, req, ctx), null);
    return { vars: { eng, rid: crypto.randomUUID(), sid: null, newSession: false, sessionCookie: null, ip, warnRule: null, scriptPath, waitUntil, facts } };
  }

  function after(req: Request, vars: FetchVars, status: number | null): void {
    void guardedAsync(async () => {
      const eng = vars.eng;
      const url = new URL(req.url);
      const path = url.pathname;
      const cfg = eng.snap.config;
      if ((cfg?.exclude || []).some((x) => path.startsWith(x))) return;
      if (Math.random() >= (cfg?.sample ?? 1)) return;
      const ev = buildEvent(req, path, url.search, vars.ip, vars.sid, vars.facts, vars.rid, vars.newSession);
      ev.st = status;
      if (vars.warnRule) ev.wrn = vars.warnRule;   // §D3: the warn rule that let this request through
      ship(eng, ev, vars.waitUntil);
    }, undefined);
  }

  function reset(): void {
    for (const e of engines.values()) { e.snap.stop(); e.queue.stop(); }
    engines.clear();
  }

  return { before, after, reset };
}

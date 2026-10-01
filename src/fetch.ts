// @camada/core/fetch — the shared pipeline for adapters on Web-fetch hosts (SDK-G04):
//   const cam = createFetchCamada({ tap: TAP_BUN, sdk: '@camada/bun/0.1.0', iife }, opts);
//   const r = await cam.before(req, { peer, waitUntil, env });   // { response } | { vars } | null
//   … run the app, then return cam.finish(req, r.vars, withSetCookie(res, r.vars.sessionCookie))   // ships now, or once an SSE body is sent
//   (cam.after(req, r.vars, status) where only a status is known: a thrown handler, a websocket upgrade)
//   track(vars, 'login_failed', { user }) / scriptTag(vars): the app-facing helpers, keyed on the vars the adapter kept
// A second tsup entry: in the CJS build shared modules are duplicated per entry, so the rate
// limiter behind `logRateLimited` is per-entry there. Harmless — it only spaces log lines.
export {
  createFetchCamada, track, scriptTag, withSetCookie, SESSION_COOKIE, SESSION_MAX_AGE,
  type FetchCamada, type FetchIdentity, type FetchRequestContext, type FetchVars, type BeforeResult, type Engine, type WaitUntil,
} from './fetch/camada.js';
export { type FetchCamadaOptions, type ResolvedFetchEnv } from './fetch/env.js';

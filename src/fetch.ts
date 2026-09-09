// @camada/core/fetch — the shared pipeline for adapters on Web-fetch hosts (SDK-G04):
//   const cam = createFetchCamada({ tap: TAP_BUN, sdk: '@camada/bun/0.1.0', iife }, opts);
//   const r = await cam.before(req, { peer, waitUntil, env });   // { response } | { vars } | null
//   … run the app, then cam.after(req, r.vars, res.status) and withSetCookie(res, r.vars.sessionCookie)
// A second tsup entry: in the CJS build shared modules are duplicated per entry, so the rate
// limiter behind `logRateLimited` is per-entry there. Harmless — it only spaces log lines.
export {
  createFetchCamada, withSetCookie, beaconEnabled, SESSION_COOKIE,
  type FetchCamada, type FetchIdentity, type FetchRequestContext, type FetchVars, type BeforeResult, type Engine, type WaitUntil,
} from './fetch/camada.js';
export { resolveFetchEnv, type FetchCamadaOptions, type ResolvedFetchEnv } from './fetch/env.js';

# @camada/core

The shared substrate of the camada backend SDKs: the BLK snapshot parser and matcher (a 1:1
port of the edge collector's `blocklist.js`, pinned by golden conformance fixtures generated
from the reference implementation), the `/snapshot` polling client, the batched event queue,
the redaction layer, and trusted-proxy client-IP resolution.

Applications don't install this directly — use [`@camada/node`](../camada-node),
[`@camada/next`](../camada-next), [`@camada/hono`](../camada-hono), or one of the Web-fetch
adapters (`@camada/sveltekit`, `@camada/nuxt`, `@camada/remix`, `@camada/bun`, `@camada/deno`).
Not yet published to npm; consumed via `file:` dependencies from sibling checkouts.

## What's inside

- **`parseSnapshot(bin, meta)` / `Matcher`** — sub-microsecond checks (IPv4/IPv6 ranges,
  ASN, country, TLS fingerprint, path, user agent, request headers). At the SDK position only
  `ip`, `path`, `ua` and the headers are normally known, so ASN/country/TLS entries and
  conditions simply never match there: the SDK enforces what it can see and **fails open** on
  everything else. ~5 MB of typed arrays resident per loaded snapshot.
- **Custom rules (snapshot v5)** — the tenant's ordered rule list travels in the container
  (sections 14/15 + `meta.rules`) and is compiled into predicates at parse time. `match()` walks
  the rules first and the **order is the precedence**: first match wins, and only if nothing
  matched does it fall through to the allow → block → challenge sides. The four actions:
  `skip` passes (`allowed: true`), `block` 403s, `challenge` serves the proof-of-work page,
  `warn` passes and stamps the event. A rule outcome carries `action`, `rule` (the id) and
  `reason: 'rule'`; at most one of `allowed` / `block` / `challenge` / `warn` is ever true. A
  condition the request cannot answer (no `ua`, no header getter, no `asn`/`country`/`tlsx` off
  Cloudflare) is false for every operator, negatives included — the rule then does not fire.
- **Header conditions** — a rule may read one request header (`is`, `contains`, `matches`).
  Pass `header: (name) => string | null` on the `MatchInput`; it is always called with a
  lower-cased name, so the name a rule was written with never has to match the wire spelling.
  Headers are the request plane's alone: the analyst cannot judge one and treats such a rule as
  not matching, so a header rule is enforced by v5 SDKs only.
- **`SnapshotClient`** — polls `GET /snapshot` (Bearer snapshot token) every 30 s off the
  request path with `If-None-Match`; 304 keeps the snapshot and still refreshes tenant config;
  204 means "nothing published" (enforce nothing); any error keeps the previous snapshot.
  `snapshotVersion` is 3 | 4 | 5 (default 5, sent as `x-camada-snapshot`); a tenant whose
  analyst has not published that container is answered with the next one down.
  `timer` mode for long-lived Node processes, `lazy` mode for serverless/edge (`ensureFresh`
  per request; cold start fails open). With the `sdk` option every poll carries
  `x-camada-sdk: <package>/<version>` so the analyst can show versions and nudge upgrades.
- **`EventQueue`** — batched fire-and-forget shipping to `POST /e` (≤1000 per POST), bounded
  queue with drop-oldest, interval + size-triggered flush, opt-in Node exit drain. The same `sdk`
  option stamps `x-camada-sdk` on every batch. Nothing in the queue may ever throw into the
  request path.
- **`buildWireEvent`** — the collector-compatible wire shape, including the pinned `HDRS`
  header-bitmask order and the wire header order (`hord`) only an in-app SDK can see.
- **Redaction (non-configurable-off)** — `Authorization`/`Cookie` values never leave (scheme
  and count only; a schemeless `Authorization` value ships nothing at all), credential-looking
  query values become `~r`, and user identifiers are HMAC-hashed in-process (`hashUserId`).
  `bodyShape` and `REDACT_ALLOWLIST` are staging for app-context body capture (a later phase);
  no SDK captures request bodies today. This package is open source so these claims are
  auditable.
- **`resolveClientIp`** — socket peer by default; `X-Forwarded-For` is only consulted under an
  explicit trusted-proxy config (`hops` / `cidrs` / `vercel`), so a spoofed XFF can't reach the
  analysis or the blocklist.

## `@camada/core/fetch` — the shared Web-fetch pipeline

Since 0.3.0 (SDK-G04) the request pipeline every Web-`Request`/`Response` adapter needs lives
here, as a second entry point, so a new runtime is a thin binding rather than a copy of
`@camada/hono`:

```ts
import { createFetchCamada, withSetCookie } from '@camada/core/fetch';
const cam = createFetchCamada({ tap: TAP_BUN, sdk: '@camada/bun/0.1.0', iife }, opts);
const r = await cam.before(req, { peer, waitUntil, env });   // { response } | { vars } | null (inert)
if (r?.response) return r.response;                          // 403, the challenge, the beacon endpoints
const res = await app(req);                                  // keep r.vars in the framework's per-request slot
if (r) { cam.after(req, r.vars, res.status); return r.vars.sessionCookie ? withSetCookie(res, r.vars.sessionCookie) : res; }
```

The client address is an already-resolved `ip` the host vouches for, else the socket `peer`
and `X-Forwarded-For` under the trusted-proxy rules — never a bare header. `track(vars, …)` and
`scriptTag(vars)` are the app-facing helpers, keyed on the vars the adapter kept. `mode: 'timer'`
polls on an unref'd interval and installs the exit flush (long-lived hosts); the default `lazy`
refreshes per request through `waitUntil` (edge and serverless); `CAMADA_SERVERLESS=1` forces
lazy. The full pipeline is contracts.md §D.

## Conformance fixtures

`test/fixtures/` is copied from `edge-analyst/fixtures/` (`npm run fixtures` there): the
expected match results are computed by running the reference `blocklist.js` itself. `blk3/`
holds v3 + v4, `blk5/` holds v5 with its ordered custom rules (`rules.json` is the tenant list
behind the container). Re-copy whenever the BLK format, the rule vocabulary or the HDRS order
changes.

## Develop

```
npm install && npm run build && npm test && npm run check
```

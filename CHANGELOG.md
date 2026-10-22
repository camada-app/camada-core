# Changelog

## Unreleased

### Fixed

- A signalled response (`x-camada-challenge: 1`) now also sets `cdn-cache-control`,
  `surrogate-control`, `cloudflare-cdn-cache-control`, `vercel-cdn-cache-control` and
  `netlify-cdn-cache-control` to `no-store`, overriding the app's. CDNs read those ahead of
  `cache-control`, so an app-set one could still let a shared cache keep the per-client copy.
  (camada-all-5pog)
- The first-party beacon relay (`/_cam/fp`) drops SDK-attested keys (`tlsx`, `ja4`, `asn`,
  `cc`, `sid`, `ns`, `st`, `dur`, `rt`, `blk`, `rl`, `wrn`, `chs`, `ch`, `et`, `uid`) from the
  visitor's body before queuing the `sig: 1` row, so a visitor cannot forge them; the analyst
  joins those from the request row. (camada-all-q617)

### Added

- `REQUEST_ROW_KEYS` (frozen) is exported from `@camada/core`: the one list of SDK-attested keys
  the beacon relays strip, shared by `@camada/core/fetch` and `@camada/node`. (camada-all-0hh5)

## 0.5.3 (2026-10-19; follows 0.5.2)

### Security

- Custom-rule `matches` regex input is capped at 2048 chars (UTF-16 units), fail-closed: an
  over-cap ua, header or path value is a hit for block/challenge/warn and a miss for skip/allow,
  never truncated (truncation would fail a deny rule open). (camada-all-q980)
- Control characters never reach the matcher alone: a ua/header value carrying `[\x00-\x1f\x7f]`
  is tested raw and stripped for deny rules (a pattern that targets a control char still fires,
  `sql<TAB>map` still meets `sqlmap`), and never matches a skip/allow rule, so stripping cannot
  widen an exemption. The raw path form %-encodes the same characters. (camada-all-q980,
  camada-all-wh9m)
- A regex engine failure fails closed: a `RangeError` from `RegExp.test` in a custom-rule
  `matches` condition or a path predicate is a hit for deny rules and a miss for skip, instead of
  escaping or reading as a miss. (camada-all-5jpb)
- blk5 conformance fixtures (RC01-RC47) carry the shared vectors for all of the above
  (contract regex-cap-sdk v3).

## 0.5.2 (2026-10-12; follows 0.5.1)

### Fixed

- `EventQueue` honours a 429 `Retry-After` given as an HTTP-date (RFC 9110), not only
  delta-seconds, with the same 1 s floor / 60 s cap. The snapshot poll's pacing is unchanged
  (dates still read as 0 there). (camada-all-a4m9)
- `EventQueue.stop()` called while a drain is in flight no longer lets that drain's 429 start a hold
  timer after stop() resolved (rows retried forever, never counted). The 429'd rows are re-queued
  without a timer and stop()'s promise covers the in-flight drain plus one forced retry (sent, or
  counted in `dropped`). (camada-all-a4m9)
- Block responses (path, ip, asn, country, tls and rule blocks, the `Forbidden` 403) now send `cache-control: no-store`, like the challenge answers, so a shared cache cannot serve one visitor's block to others. (also remix, sveltekit, nuxt, bun, deno, which answer through it) (camada-all-8lp6)
- `EventQueue.stop()` during a 429 hold no longer throws the held rows away with the retry timer:
  it force-drains them like the exit flush (sent, or counted in `dropped` if the send still fails)
  and returns a promise that settles when that drain does. (camada-all-a4m9)
- A `waitUntil` that throws (called outside its request, say) no longer makes `EventQueue.flush()`
  throw synchronously, which in the fetch adapters' `ship()` could fail a block or challenge open.
  The rows still ship. (camada-all-a4m9)
- The fetch adapters' challenge page (`@camada/core/fetch`: served, and re-issued after a wrong
  answer) sends `Content-Security-Policy: challengePageCsp()`, the page's own policy allowing only
  its inline solver and style by hash. bun, deno, nuxt, remix and sveltekit get it from here.
  (camada-all-mwpo)
- `EventQueue.flush()` called while a drain is finishing (its last send answered, the in-flight
  promise not yet cleared) no longer hands back the finishing promise and leaves the new row in the
  queue until the next 15 s tick, or for good in a serverless isolate that freezes after the
  response. It now drains again once the running drain settles, and a `waitUntil` holds the whole
  chain. (camada-all-a4m9, camada-all-7u3r)
- `resolveClientIp` in `cidrs` mode (also the dashboard's Cloudflare option) no longer believes
  `X-Forwarded-For` from a socket peer that is not a trusted proxy: such a peer is the client.
  Before this, anyone reaching the origin directly could pick their own client IP, slip past an
  IP block or get another IP blocked. A loopback peer (127.0.0.0/8, `::1`, `::ffff:127.x.x.x`)
  counts as a trusted hop, so local front ends (App Engine) keep working unchanged. With no peer
  (`resolveClientIp(null, …)`) the walk is unchanged and trusts the host's edge. (camada-all-yfc6)
- `X-Forwarded-For` entries with a port (`203.0.113.66:51234`, `[2001:db8::66]:51234`, as Azure
  Application Gateway writes them) now resolve to the address in every mode instead of falling
  back to the proxy's own IP. A malformed entry still falls back to the peer. (camada-all-0vho)
- The `ref` field no longer ships the Referer verbatim: its query and fragment go through the same
  credential scrub as the request query (`~r`), so a reset token or OAuth `code` on the previous
  page stays in the process. New export `scrubUrl`. (camada-all-ijsa)
- `resolveClientIp` reads an IPv4-mapped XFF entry (`::ffff:203.0.113.66`, as dual-stack proxies
  write it) as the IPv4 address, so it no longer fails validation (every client was resolved to the
  proxy) and a mapped Cloudflare hop is recognised as trusted. The peer's `::ffff:` prefix is now
  removed only when a dotted quad follows (`::ffff:7f00:1` is no longer cut to `7f00:1`).
  (camada-all-0vho, camada-all-yfc6)
- The query scrub (request `q` and Referer `ref`) no longer leaks a bare credential part
  (`?eyJ…`), a nested query (`next=/reset?token=…`, raw or percent-encoded, an encoded
  `redirect_uri` carrying a `code`) or a percent-encoded credential name (`%74oken=`): names and
  values are percent-decoded (up to 4 passes) before testing, bare parts are tested as values, and a
  value that decodes to contain `?` or `=` is replaced whole. (camada-all-ijsa)
- The nested-query rule no longer drops every value that decodes to contain `?` or `=`, which hid
  SQLi/XSS payloads (`id=1' or '1'='1`, `<img src=x onerror=…>`) from the analysis: such a value is
  split on `?`/`&` and replaced only when one of its segments is a credential. It now also catches a
  credential behind an encoded `&` (`x=foo%26<JWT>`). (camada-all-ijsa)
- `resolveClientIp` always returns a valid IP or null: a peer that is not a valid IP (`/run/app.sock`,
  `ip:port`, `@`, a zone id) now gives null instead of being returned verbatim. XFF entries are
  trimmed of space and tab only (an NBSP-padded entry is invalid), an IPv6 address with a single
  leading or trailing `:` is invalid, and an invalid XFF entry is never a trusted hop.
  (camada-all-yfc6, camada-all-0vho)
- Shared conformance fixtures for these cases, for every server SDK: `test/fixtures/ip/resolve.json`,
  `test/fixtures/redact/referer.json` and `test/fixtures/redact/query.json` (contract C6 v3).
- `@camada/core/fetch`: a chunked POST to `/_cam/fp` or the challenge path is cut off at the 32 KB /
  4 KB cap instead of being read whole first. The client sees `413`, or a connection reset where the
  host server stops reading the upload (Node). The challenge cap now counts bytes, not UTF-16 units
  (camada-all-4u4i).

### Added

- `FetchCamada.active(ctx?)`: whether `before()` would act on a request with this context (a key or
  the token pair, no `CAMADA_DISABLED=1`), for an adapter path that is camada's only while it is
  active. (camada-all-wjln)
- `challengePageCsp(bits?)`: the `Content-Security-Policy` to send with `challengePage({ bits })`.
  It allows only the page's inline solver and style, by `'sha256-…'` hash (computed
  synchronously, cached per `bits`), plus `default-src 'none'; base-uri 'none';
  frame-ancestors 'self'`. It has no `form-action`, because browsers apply that to the redirects
  after the verify POST too. Send it as the page's only CSP and remove any
  `Content-Security-Policy` / `Content-Security-Policy-Report-Only` the app set earlier
  (camada-all-mwpo).
- `readBodyCapped(req, max)`: the body as text when it is at most `max` bytes, else `null`. A body
  without Content-Length is read through a reader and its stream cancelled once the byte count
  passes the cap, so at most cap + one chunk is held. A client that aborts mid-upload also gives
  `null`, without a log line.

### Changed

- The challenge page's inline solver no longer embeds the nonce. It reads it from the form's
  hidden `nonce` input (`id="camada-n"`), so the script is the same for every request at a given
  `bits` and a CSP hash can allow it. Ports that copy the page or pin its script hash must follow
  (camada-all-mwpo).

- `EventQueue` reads the status of the `/e` answer. A non-2xx logs `camada: /e answered <status>` (once a minute, like a thrown error), adds the batch to `dropped` and cancels the body; before, a 401 or 5xx was silent. A 429 puts the batch back at the head and holds delivery until `retry-after` (1 s to 60 s) without blocking `push()`; `maxQueue` still drops the oldest. (camada-all-a4m9)
- `SnapshotClient` logs `camada: /snapshot answered <status>` when the poll gets a non-2xx. Pacing, keep-current and the body cancel are unchanged. (camada-all-a4m9)
- `@camada/core/fetch`: in `timer` mode with no `waitUntil`, rows are only queued and the 15 s interval or exit flush ships them in batches, instead of one POST per request. A real `waitUntil` or `lazy` mode still flushes per row. (camada-all-7u3r)
- `EventQueue` hardening: a `fetchImpl` that resolves to a non-`Response` no longer rejects `flush()`; a 429 hold ends on its timer, so a backward clock step cannot stall sending; the exit flush (`beforeExit`, SIGTERM, SIGINT) ignores a hold and counts rows still refused in `dropped`; 2xx bodies are cancelled too. (camada-all-a4m9)
- The `exports` map now gives `require` its own `.d.cts` declarations (`import` and `require` each carry a `types` condition), so a CommonJS TypeScript app on `moduleResolution: node16` compiles; CI runs `@arethetypeswrong/cli`. (camada-all-vuzm)

## 0.5.1 (2026-10-09; follows 0.5.0)

### Fixed

- `SnapshotClient` no longer re-polls back to back when `/snapshot` fails. On any answer other than
  200, 204 or 304 (and on a thrown fetch), it keeps its blocks and holds the next self-initiated
  poll back by max(`retry-after`, 5 s), capped at the refresh interval. `start()` goes through the
  same gate (`ensureFresh`); core has no separate refresh method. The failed response body is now
  cancelled, and a backward clock step no longer stalls polling. (camada-all-pbv9)

## 0.5.0 (2026-10-04; follows 0.4.0)

### Added

- `onBodyDone(res, done, { method, waitUntil })`. It calls `done` once a `text/event-stream`
  body has gone out: the last chunk was pulled, the client cancelled, or the body errored. Any
  other response calls `done` at once and comes back as the same object.
- `@camada/core/fetch`: `finish(req, vars, res)` on `createFetchCamada()`. An adapter hands it
  the app's response and it ships the event (see `dur` below). `after(req, vars, status)` is still
  there for paths that only know a status, such as a thrown handler or a WebSocket upgrade.

- `@camada/core/fetch`: `finish()` sets `x-rid` (the rid of the request's event row) on the
  response, or on a faithful copy when its headers are immutable. Never on a 101. Exported as
  `withRid(res, vars)` for adapters that do not go through `finish()`.

### Changed

- `ts` is the request start, so `[ts, ts + dur]` is when the request ran. It used to be stamped
  when the event shipped.
- `dur` for a `text/event-stream` response runs to its last byte, or until the client leaves.
  Only that kind of response (status 200 or more, not 204/205/304, not `HEAD`, no
  Content-Length) is re-wrapped, in a pass-through stream with the same status and headers that
  buffers nothing. Every other response goes out as the app returned it, and `dur` is the time to
  first byte: the moment the handler returned.
- `after(req, vars, null)` ships `dur: null` along with `st: null`. A host that cannot see the
  response cannot say when it settled.
- `before()` builds the wire event, and `after()` no longer reads the request. Deno closes the
  request after `Deno.upgradeWebSocket`, and the upgrade used to ship no event.

### Fixed

- Path rules match the canonical path. A percent-encoded, upper-cased or trailing-slash spelling
  (`/%62locked`, `/BLOCKED`, `/blocked/`) used to slip past a path block while the framework still
  routed it to the blocked handler. Block rules match any form of the path; allow and skip rules
  need both the literal and the decoded form to match, as the edge analyst does.
  `RuleRequest.path` is now `RuleRequest.paths`.
- Deno 2.9 `fetch()` responses with a gzip body: a copy (the session cookie on an immutable
  response, the SSE re-wrap) drops the stale `Content-Encoding` and `Content-Length`, as Deno.serve
  does for the original. The decoded bytes used to go out cut to the compressed length, labelled
  gzip.
- Under `@hono/node-server`, a copied response gets headers of its own, so the session cookie can
  be added to a `fetch()` result.
- The exit flush no longer throws `NotCapable` on Deno without `--allow-run`.
- `SnapshotClient` stays cold until the first snapshot is in place. It used to report "loaded"
  while the body was still being read, so a request served meanwhile failed open with no reason
  instead of `cold`.

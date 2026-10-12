# Changelog

## Unreleased

### Fixed

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
- Shared conformance fixtures for these cases, for every server SDK: `test/fixtures/ip/resolve.json`
  and `test/fixtures/redact/referer.json` (contract C6 v2).

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

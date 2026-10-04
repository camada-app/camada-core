# Changelog

## 0.5.0 (unreleased; follows 0.4.0)

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

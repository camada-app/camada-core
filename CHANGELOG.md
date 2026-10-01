# Changelog

## 0.5.0 (unreleased; follows 0.4.0)

### Added

- `onBodyDone(res, done, { method, waitUntil })`. It calls `done` once a `text/event-stream`
  body has gone out: the last chunk was pulled, the client cancelled, or the body errored. Any
  other response calls `done` at once and comes back as the same object.
- `@camada/core/fetch`: `finish(req, vars, res)` on `createFetchCamada()`. An adapter hands it
  the app's response and it ships the event (see `dur` below). `after(req, vars, status)` is still
  there for paths that only know a status, such as a thrown handler or a WebSocket upgrade.

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

- Deno 2.9 `fetch()` responses with a gzip body: a copy (the session cookie on an immutable
  response, the SSE re-wrap) drops the stale `Content-Encoding` and `Content-Length`, as Deno.serve
  does for the original. The decoded bytes used to go out cut to the compressed length, labelled
  gzip.
- Under `@hono/node-server`, a copied response gets headers of its own, so the session cookie can
  be added to a `fetch()` result.
- The exit flush no longer throws `NotCapable` on Deno without `--allow-run`.

// Response timing that covers a streamed body. A fetch-style handler returns its Response before
// a streamed body has been sent, so "the handler returned" is time-to-first-byte. `onBodyDone`
// re-wraps a server-sent-events body in a pass-through stream and calls `done` once the host has
// pulled the last chunk, the client went away (cancel), or the source stream errored — whichever
// comes first, exactly once. Nothing is buffered: each chunk is handed on as soon as it is read.
//
// Every other response is returned untouched and `done` runs at once, so its dur is the time to
// first byte (for a buffered body, effectively the whole response). The decision reads only the
// method, the status and the headers, never `res.body`, because re-wrapping, or even reading
// `.body`, changes what the client receives on some hosts:
//   - workerd, Bun and Deno send a string, Blob, file, R2 or FixedLengthStream body with a
//     Content-Length that is not in res.headers; a JS stream goes out chunked.
//   - Bun keeps the implicit Content-Type of a string or Blob body outside res.headers and drops
//     it once `.body` is read; Deno 2.2 drops Content-Length once `.body` is read.
//   - Bun < 1.2.10 sends a re-wrapped empty body as a bare 200; Deno < 2.6 rejects a copied 101.
// None of that is visible from JS, so a fixed-length body cannot be told apart. An explicit
// `text/event-stream` with no Content-Length is a JS stream the host already sends chunked, and
// wrapping it leaves the status and headers byte-identical (checked on workerd, Bun and Deno).
//
// On workerd a JS stream cannot see the client leave: after a disconnect the runtime neither pulls
// nor cancels it (wrangler 4.128+), so a pass-through wrapper would never call `done`, and a
// `waitUntil` promise waiting on it has no I/O behind it, which workerd reports as "your Worker's
// code had hung" and cancels, the event lost. There the body is piped through the native
// IdentityTransformStream instead: its writable errors once the client is gone, the pipe cancels
// the source (a proxied upstream closes one chunk behind camada-off, which notices on its own next
// write), and the pipe's promise, settled by I/O, is what `waitUntil` holds. With the
// `enable_request_signal` flag, `request.signal` cancels it at once.

export interface BodyDoneOptions {
  /** The request method: a HEAD's body is discarded unread, so it is done at once. */
  method?: string;
  /** The host's waitUntil, where the isolate must be held open until the body is done (Workers). */
  waitUntil?: (p: Promise<unknown>) => void;
  /** The request's signal: on workerd it aborts on a client disconnect (`enable_request_signal`).
   *  Read only on workerd, so a caller may pass it as a getter. */
  signal?: AbortSignal;
}

// workerd's native identity stream; absent on every other runtime.
type Its = new () => TransformStream<Uint8Array, Uint8Array>;

/** True for a response whose body is a stream worth waiting for: an explicit server-sent-events
 *  body of unknown length. Reads the method, status and headers only, never `res.body`. */
function isStreamed(res: Response, method?: string): boolean {
  if (method === 'HEAD') return false;
  const s = res.status;
  if (s < 200 || s === 204 || s === 205 || s === 304) return false;   // 1xx (a 101 upgrade) and the null-body statuses
  if (res.headers.has('content-length')) return false;
  return /^\s*text\/event-stream\s*(;|$)/i.test(res.headers.get('content-type') ?? '');
}

/**
 * Returns the Response to send. A streamed response (see `isStreamed`) comes back with its body
 * re-wrapped so that `done()` runs once the body has been fully read, cancelled or has errored;
 * the status and headers are the same. Any other response comes back as the very same object, and
 * `done()` runs now. `done` must not throw; it is called exactly once.
 */
export function onBodyDone(res: Response, done: () => void, opts: BodyDoneOptions = {}): Response {
  if (!isStreamed(res, opts.method)) { done(); return res; }
  const src = res.body;
  if (!src || res.bodyUsed) { done(); return res; }
  const ITS = (globalThis as { IdentityTransformStream?: Its }).IdentityTransformStream;
  if (ITS) {
    if (src.locked) throw new TypeError('locked body');   // pipeTo would reject and leave the copy open forever
    const ts = new ITS();
    // pipeTo settles once, on the end, a client disconnect or a source error; `done` runs then.
    const piped = src.pipeTo(ts.writable, { signal: opts.signal }).then(done, done);
    opts.waitUntil?.(piped);
    return copyResponse(res, ts.readable);
  }
  let fired = false;
  let settle = () => {};
  const fire = () => { if (!fired) { fired = true; done(); settle(); } };
  const reader = src.getReader();
  // ponytail: a body the host drops unread (never closed, never cancelled) holds this until the platform's waitUntil limit; Node, Bun and Deno cancel a body the client left.
  opts.waitUntil?.(new Promise<void>((r) => { settle = r; }));
  const body = new ReadableStream<Uint8Array>({
    async pull(ctrl) {
      try {
        const { done: end, value } = await reader.read();
        if (end) { ctrl.close(); fire(); } else ctrl.enqueue(value);
      } catch (err) {
        fire();
        ctrl.error(err);
      }
    },
    cancel(reason) {
      fire();
      return reader.cancel(reason);
    },
  });
  return copyResponse(res, body);
}

/**
 * `new Response(body, res)` that the host serves the way it would serve `res`. A Response as the
 * init copies status, statusText and headers (and, on workerd, `cf`/`webSocket`), but not host
 * state: Deno 2.9's fetch() decodes a gzip/br body yet keeps the upstream Content-Encoding and
 * Content-Length, and Deno.serve drops both for that response only, through an internal
 * `bodyDecoded` flag a copy does not inherit. A plain copy would send the decoded bytes under the
 * stale headers (cut to the compressed length, labelled gzip), so the copy drops them as Deno would.
 * Deno <= 2.6 strips them at fetch() time already; Bun, Node and workerd copy faithfully as is.
 */
export function copyResponse(res: Response, body: BodyInit | null): Response {
  let out = new Response(body, res);
  // @hono/node-server's global Response keeps the init's own Headers object for a stream body,
  // and a fetch() result's is immutable: the copy could not take a header. Give it its own.
  if (out.headers === res.headers) out = new Response(body, { status: res.status, statusText: res.statusText, headers: new Headers(res.headers) });
  if (denoBodyDecoded(res)) {
    out.headers.delete('content-encoding');
    out.headers.delete('content-length');
  }
  return out;
}

// ponytail: reads a Deno internal (Symbol("response").bodyDecoded); if Deno renames it the copy
// keeps the stale headers again, which the gzip-upstream e2e on the latest Deno catches.
function denoBodyDecoded(res: Response): boolean {
  const inner = Object.getOwnPropertySymbols(res).find((s) => s.description === 'response');
  return inner !== undefined && (res as unknown as Record<symbol, { bodyDecoded?: unknown } | undefined>)[inner]?.bodyDecoded === true;
}

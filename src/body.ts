// Response timing that covers the body. A fetch-style handler returns its Response before a
// streamed body has been sent, so "the handler returned" is time-to-first-byte. `onBodyDone`
// re-wraps the body in a pass-through stream and calls `done` once the host has pulled the last
// chunk, the client went away (cancel), or the source stream errored — whichever comes first,
// exactly once. Nothing is buffered: each chunk is handed on as soon as it is read.
//
// On Workers the body must also be kept alive: when the client disconnects mid-stream, workerd
// keeps pumping the body only while the request has a pending `waitUntil`, and otherwise drops it
// with no close and no cancel, so `done` would never run. A promise that settles with `done` goes
// to `waitUntil` up front.

export interface BodyDoneOptions {
  /** The request method: a HEAD's body is discarded unread, so it is done at once. */
  method?: string;
  /** The host's waitUntil, where the isolate must be held open until the body is done (Workers). */
  waitUntil?: (p: Promise<unknown>) => void;
}

/**
 * Returns a Response that sends the same status, headers and bytes as `res`, calling `done()`
 * once its body has been fully read, cancelled or has errored. With no body to wait for (a null
 * body, or a HEAD request, whose body the host discards unread) `done()` runs now and `res`
 * comes back as it is. `done` must not throw; it is called at most once.
 */
export function onBodyDone(res: Response, done: () => void, opts: BodyDoneOptions = {}): Response {
  const src = res.body;
  if (!src || opts.method === 'HEAD' || res.bodyUsed) { done(); return res; }
  let fired = false;
  let settle = () => {};
  const fire = () => { if (!fired) { fired = true; done(); settle(); } };
  const reader = src.getReader();
  // ponytail: a body the host drops unread (never closed, never cancelled) holds this until the platform's waitUntil limit (30 s on Workers).
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
  // A Response as the init copies status, statusText and headers (and, on workerd, `cf`/`webSocket`).
  return new Response(body, res);
}

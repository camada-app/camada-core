// A size cap that really bounds memory (camada-all-4u4i). camada answers a few endpoints before
// the app, for any client (the beacon relay, the challenge verify POST), so their caps must hold
// whatever the client sends: a Content-Length check alone lets a chunked body through, and
// `req.text()` buffers all of it before any byte count can be taken. This reads the body through
// a reader, counts bytes as they arrive and cancels the source once the count passes the cap, so
// at most cap + one chunk is ever held — @camada/node's streaming rule, for Web-fetch hosts.

const cancelQuietly = (s: { cancel(): Promise<void> } | null | undefined): void => {
  try { void s?.cancel().catch(() => {}); } catch { /* locked or already disturbed: nothing to release */ }
};

/**
 * The request body as UTF-8 text when it is at most `max` bytes, else `null` (answer 413; also
 * when the client aborts mid-upload, which is not logged). A
 * declared Content-Length over `max` is rejected before any byte is read; a body without one is
 * cut off, and its stream cancelled, as soon as the running byte count passes `max`.
 */
export async function readBodyCapped(req: Request, max: number): Promise<string | null> {
  const declared = req.headers.get('content-length');
  if (declared !== null && Number(declared) > max) {
    cancelQuietly(req.body);
    return null;
  }
  const body = req.body;
  if (!body) return '';
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let n = 0;
  for (;;) {
    let r: ReadableStreamReadResult<Uint8Array>;
    try { r = await reader.read(); } catch {
      // The client went away mid-upload: nothing to answer and nothing worth a log line.
      cancelQuietly(reader);
      return null;
    }
    const { done, value } = r;
    if (done) break;
    n += value.byteLength;
    if (n > max) {
      cancelQuietly(reader);
      return null;
    }
    chunks.push(value);
  }
  const all = new Uint8Array(n);
  let at = 0;
  for (const c of chunks) { all.set(c, at); at += c.byteLength; }
  return new TextDecoder().decode(all);
}

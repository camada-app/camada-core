// Allocation-free IP parsers, ported 1:1 from edge-analyst src/blocklist.js (the reference
// implementation the conformance fixtures are generated from). Behavior must not drift:
// ip4 returns -1 on anything unusual; ip6 rejects zone ids and v4-mapped forms.

/** Dotted-quad IPv4 to uint32, or -1 when the string is not a plain IPv4 address. */
export function parseIp4(s: string): number {
  let n = 0, part = 0, digits = 0, dots = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 46) { if (digits === 0 || part > 255 || ++dots > 3) return -1; n = n * 256 + part; part = 0; digits = 0; }
    else if (c >= 48 && c <= 57) { part = part * 10 + (c - 48); if (++digits > 3) return -1; }
    else return -1;
  }
  if (dots !== 3 || digits === 0 || part > 255) return -1;
  return (n * 256 + part) >>> 0;
}

/** Parses IPv6 into W (4 uint32 words, big-endian word order) using G as group scratch. */
export function parseIp6Into(s: string, W: Uint32Array, G: Uint16Array): boolean {
  const len = s.length;
  let n = 0, val = 0, digits = 0, dbl = -1, i = 0;
  if (len > 1 && s.charCodeAt(0) === 58 && s.charCodeAt(1) === 58) { dbl = 0; i = 2; }
  for (; i <= len; i++) {
    const c = i < len ? s.charCodeAt(i) : 58;
    if (c === 58) {
      if (digits > 0) { if (n >= 8) return false; G[n++] = val; val = 0; digits = 0; }
      else if (i < len) { if (dbl !== -1) return false; dbl = n; }
    } else {
      let d;
      if (c >= 48 && c <= 57) d = c - 48; else if (c >= 97 && c <= 102) d = c - 87; else if (c >= 65 && c <= 70) d = c - 55; else return false;
      val = (val << 4) | d; if (++digits > 4) return false;
    }
  }
  if (dbl === -1) { if (n !== 8) return false; }
  else {
    if (n >= 8) return false;
    const shift = 8 - n;
    for (let k = 7; k >= dbl + shift; k--) G[k] = G[k - shift];
    for (let k = dbl; k < dbl + shift; k++) G[k] = 0;
  }
  W[0] = ((G[0] << 16) | G[1]) >>> 0; W[1] = ((G[2] << 16) | G[3]) >>> 0;
  W[2] = ((G[4] << 16) | G[5]) >>> 0; W[3] = ((G[6] << 16) | G[7]) >>> 0;
  return true;
}

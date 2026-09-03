# SDK Phase A (SDK-01 blk, SDK-03 sdk header) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Blocked events carry `blk: <reason>`; every `/e` batch and `/snapshot` poll carries `x-camada-sdk: <package>/<version>`; all SDK packages build + test green.

**Architecture:** `@camada/core` gains one optional `sdk` string on `EventQueue` and `SnapshotClient` that becomes the `x-camada-sdk` request header. `@camada/node` and `@camada/next` compute their id from their own `package.json` (bundled inline by tsup/esbuild at build time, so the dist carries a literal) and pass it through. Block paths in node engine, next middleware and next beacon route set `ev.blk = verdict.reason` next to `st: 403`; the next beacon route, which today 403s silently, now ships that event too.

**Tech Stack:** TypeScript, tsup, vitest, esbuild (edge-safety bundle).

**Spec:** /Users/gabe/Github/camada/docs/orchestration/contracts.md §D; /Users/gabe/Github/camada/docs/superpowers/specs/2026-09-02-saas-requirements.md SDK-01, SDK-03.

## Global Constraints

- `blk` values: `ip4|ip6|path|asn|tls|country` (= core `BlockReason`). Only set when `st: 403`.
- Header name exactly `x-camada-sdk`, value `<package>/<version>` e.g. `@camada/node/0.0.1`.
- BLK3 format unchanged; no fixture regen.
- Middleware import graph must stay edge-safe (no `node:` imports); `test/edge-safety.test.ts` proves it.
- Never edit ORCH/contracts.md, other repos, edge-analyst. Never push. Branch `saas-phase-a` in each touched repo (core, node, next).
- Build order: core → browser → react → node → next → examples (`npm run build` in each; examples `npm install`).
- Every task ends with: code-simplifier agent on the diff, requesting-code-review, fix, conventional commit.

---

### Task 1: core — `sdk` option → `x-camada-sdk` header on `/e` and `/snapshot`

**Files:**
- Modify: `camada-core/src/events/queue.ts`
- Modify: `camada-core/src/snapshot/client.ts`
- Modify: `camada-core/README.md` (one bullet under EventQueue/SnapshotClient)
- Test: `camada-core/test/queue.test.ts`, `camada-core/test/client.test.ts`

**Interfaces:**
- Produces: `EventQueueOptions.sdk?: string`, `SnapshotClientOptions.sdk?: string`. When set, every fetch adds header `x-camada-sdk: <sdk>`. When unset, no header.

- [ ] **Step 1: Failing tests**

`test/queue.test.ts`, inside `describe('EventQueue')`:
```ts
  it('sends x-camada-sdk when an sdk id is configured, and omits it otherwise', async () => {
    let hdr: string | null = 'unset';
    const capture = async (_u: unknown, init?: RequestInit) => { hdr = new Headers(init?.headers).get('x-camada-sdk'); return new Response(null, { status: 202 }); };
    const withId = q(capture, { sdk: '@camada/node/0.0.1' });
    withId.push({}); await withId.flush(); withId.stop();
    expect(hdr).toBe('@camada/node/0.0.1');
    const without = q(capture);
    without.push({}); await without.flush(); without.stop();
    expect(hdr).toBeNull();
  });
```
`test/client.test.ts`, inside `describe('SnapshotClient')`:
```ts
  it('sends x-camada-sdk on every poll when an sdk id is configured', async () => {
    let hdr: string | null = null;
    const c = new SnapshotClient({ url: 'https://a.test/snapshot', token: 'st', mode: 'lazy', refreshMs: 0, sdk: '@camada/next/0.0.1',
      fetchImpl: async (_u, init) => { hdr = new Headers(init?.headers).get('x-camada-sdk'); return ok200(); } });
    c.ensureFresh();
    await settle();
    expect(hdr).toBe('@camada/next/0.0.1');
  });
```

- [ ] **Step 2: Run** `cd camada-core && npx vitest run test/queue.test.ts test/client.test.ts` → FAIL (header null / TS excess property).

- [ ] **Step 3: Implement**

`queue.ts`: add `sdk?: string;   // "<package>/<version>": the x-camada-sdk header (SDK-03)` to `EventQueueOptions`. Options type: `Required<Omit<EventQueueOptions, 'fetchImpl' | 'sdk'>> & { fetchImpl: typeof fetch; sdk?: string }`. In `flush()` build headers:
```ts
const headers: Record<string, string> = { 'x-tenant': this.opts.token, 'content-type': 'application/json' };
if (this.opts.sdk) headers['x-camada-sdk'] = this.opts.sdk;
```
`client.ts`: same option on `SnapshotClientOptions`; same `Required<Omit<..., 'fetchImpl' | 'sdk'>>` adjustment; in `load()` after building `headers`: `if (this.opts.sdk) headers['x-camada-sdk'] = this.opts.sdk;`.

- [ ] **Step 4: Run** `npm test && npm run check && npm run build` in camada-core → green.
- [ ] **Step 5: README bullet** under `SnapshotClient` and `EventQueue`: "`sdk` option → `x-camada-sdk: <package>/<version>` header on every poll / batch (SDK-03)."
- [ ] **Step 6: Simplifier + review, then commit** `feat(core): sdk option sends x-camada-sdk on /e and /snapshot`.

---

### Task 2: node — `blk` on blocked events, sdk id from package.json

**Files:**
- Create: `camada-node/src/version.ts`
- Modify: `camada-node/src/camada.ts`, `camada-node/tsconfig.json` (`"resolveJsonModule": true`), `camada-node/README.md` (step 3 + header mention)
- Test: `camada-node/test/engine.test.ts`, `camada-node/test/harness.ts`

**Interfaces:**
- Consumes: core `sdk` option (Task 1).
- Produces: `SDK_ID` const `'@camada/node/<version>'`; blocked wire events have `blk: BlockReason`.

- [ ] **Step 1: Harness records the header.** In `FakeAnalyst` add `sdkHeaders: string[]` (init `[]`); in the `/e` and `/snapshot` branches push `new Headers(init?.headers).get('x-camada-sdk') ?? ''` before returning.

- [ ] **Step 2: Failing tests** in `engine.test.ts` `describe('inline blocking')` first test add after `expect(evs[0].st).toBe(403);`:
```ts
    expect(evs[0].blk).toBe('ip4');
```
New test in a new `describe('sdk identity')`:
```ts
  it('sends x-camada-sdk = @camada/node/<package version> on snapshot polls and event batches', async () => {
    const a = fakeAnalyst();
    const engine = engineWith(a);
    await loaded(engine);
    const app = await appWith(engine);
    await fetch(`${app.url}/`);
    await engine.queue!.flush();
    const version = JSON.parse(readFileSync(join(process.cwd(), 'package.json'), 'utf8')).version;
    expect(new Set(a.sdkHeaders)).toEqual(new Set([`@camada/node/${version}`]));
    expect(a.sdkHeaders.length).toBeGreaterThanOrEqual(2);   // ≥1 poll + 1 batch
  });
```
(import `readFileSync` from `node:fs`, `join` from `node:path`.) Also a normal-request test: `expect(evs[0].blk).toBeUndefined()` in the existing "ships one event" test.

- [ ] **Step 3: Run** `npx vitest run test/engine.test.ts` → FAIL.

- [ ] **Step 4: Implement**

`src/version.ts`:
```ts
// The SDK's wire identity (SDK-03): x-camada-sdk: <package>/<version>. package.json is inlined
// by tsup at build, so dist carries a literal — no runtime fs read.
import pkg from '../package.json';
export const SDK_ID = `${pkg.name}/${pkg.version}`;
```
tsconfig: add `"resolveJsonModule": true` to compilerOptions.
`camada.ts`: import `SDK_ID`; pass `sdk: SDK_ID` to both `new SnapshotClient({...})` and `new EventQueue({...})`. In the block branch after `ev.st = 403;` add `ev.blk = v.reason;   // SDK-01: the block reason rides the event so the analyst counts SDK blocks, not the app's own 403s`.

- [ ] **Step 5: Run** `npm test && npm run check && npm run build` → green. Verify `grep -c '@camada/node/' dist/index.js` ≥ 1.
- [ ] **Step 6: README:** step 3 becomes "Blocked ip/path → `403` with `x-block-reason` before your app; the event still ships with `st: 403` and `blk: <reason>`." Add to step 1: "every poll and batch carries `x-camada-sdk: @camada/node/<version>`."
- [ ] **Step 7: Simplifier + review, commit** `feat(node): blk on blocked events; x-camada-sdk identity header`.

---

### Task 3: next — shared event builder, `blk` in middleware + beacon-route denies, sdk id

**Files:**
- Create: `camada-next/src/event.ts` (move `buildEvent` out of middleware.ts; accept `Request`)
- Create: `camada-next/src/version.ts`
- Modify: `camada-next/src/middleware.ts`, `camada-next/src/route.ts`, `camada-next/src/engine.ts`, `camada-next/tsconfig.json`, `camada-next/README.md`
- Test: `camada-next/test/middleware.test.ts`, `camada-next/test/route.test.ts`, `camada-next/test/harness.ts`

**Interfaces:**
- Produces: `buildEvent(req: Request, path: string, ip: string | null, rid: string, sid: string | null, newSession: boolean): WireEvent` in `src/event.ts`; `SDK_ID` in `src/version.ts`.

- [ ] **Step 1: Harness** — same `sdkHeaders: string[]` capture as node harness (on `/snapshot` and `/e`).

- [ ] **Step 2: Failing tests**

`middleware.test.ts` block test: add `expect(evs[0].blk).toBe('ip4');`. New test:
```ts
  it('identifies itself as @camada/next/<version> on polls and batches', async () => {
    const a = fakeAnalyst();
    const handler = await primed(a, {});
    const ev = fakeEvent();
    handler(req('/'), asEvent(ev));
    await ev.settled();
    const version = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
    expect(new Set(a.sdkHeaders)).toEqual(new Set([`@camada/next/${version}`]));
  });
```
(`readFileSync` from `node:fs` — the test file runs under edge-runtime env; if `node:fs` fails there, put this test in `route.test.ts` (node env) instead, using `camadaRoute().GET` to prime + a `POST fp` to produce a batch.)

`route.test.ts` route-level test: after the two 403 asserts add:
```ts
    await settle();
    const evs = a.events.flat() as Array<Record<string, unknown>>;
    expect(evs).toHaveLength(2);
    for (const e of evs) { expect(e.st).toBe(403); expect(e.blk).toBe('ip4'); expect(e.tap).toBe('sdk-next'); expect(e.p).toMatch(/^\/api\/camada\//); }
```

- [ ] **Step 3: Run** `npm test` in camada-next → FAIL.

- [ ] **Step 4: Implement**

`src/event.ts`:
```ts
// One wire-event builder for every @camada/next entry (middleware + beacon route). Web APIs only.
import { buildWireEvent, TAP_NEXT, type WireEvent } from '@camada/core';

export function buildEvent(req: Request, path: string, ip: string | null, rid: string, sid: string | null, newSession: boolean): WireEvent {
  const url = new URL(req.url);
  return buildWireEvent(
    {
      method: req.method,
      host: req.headers.get('host') ?? url.host,
      path,
      query: url.search,
      // The edge runtime sorts header names, so hord is alphabetical at this tap — still
      // shipped; the scorer knows sdk-next lacks the raw-wire-order signal (capability mask).
      headers: [...req.headers.entries()],
      ip,
      httpVersion: null,   // not observable here
    },
    { tap: TAP_NEXT, rid, sid, newSession, ja4: req.headers.get('x-vercel-ja4-digest') },
  );
}
```
`middleware.ts`: delete local `buildEvent`, import from `./event`; after `ev.st = 403;` add `ev.blk = v.reason;   // SDK-01`.
`route.ts` `blocked()`: on block, build + ship the event before returning 403:
```ts
  if (!v.block) return null;
  const ev = buildEvent(req, path, ip, crypto.randomUUID(), null, false);
  ev.st = 403; ev.blk = v.reason;   // SDK-01: a beacon-route deny is a block like any other
  engine.queue.push(ev);
  void engine.queue.flush();
  return new Response('Forbidden', { status: 403, headers: { 'x-block-reason': String(v.reason ?? ''), 'x-block-version': v.version ?? '' } });
```
`src/version.ts`: same as node (`import pkg from '../package.json'`). tsconfig `resolveJsonModule: true`. `engine.ts`: `sdk: SDK_ID` on both `SnapshotClient` and `EventQueue`.

- [ ] **Step 5: Run** `npm test && npm run check && npm run build` (edge-safety suite must stay green: json import is inlined by esbuild). Verify `grep -c '@camada/next/' dist/index.js` ≥ 1.
- [ ] **Step 6: README:** "Blocked requests ship with `st: 403`" → "… with `st: 403` and `blk: <reason>`; the beacon route handlers ship the same event when they deny." Mention `x-camada-sdk`.
- [ ] **Step 7: Simplifier + review, commit** `feat(next): blk on blocked events incl. beacon-route denies; x-camada-sdk identity header`.

---

### Task 4: full bottom-up build, examples smoke against edge-analyst dev, status + e2e proposal

**Files:**
- Modify: `/Users/gabe/Github/camada/docs/orchestration/status/sdk.md`

- [ ] **Step 1:** `for r in core browser react node next; do (cd ~/Github/camada-$r && npm run build && npm test && npm run check); done`; `(cd ~/Github/camada-node-example && npm install)`; `(cd ~/Github/camada-next-example && npm install)`.
- [ ] **Step 2:** Start edge-analyst dev (`cd ~/Github/camada/edge-analyst && npm run dev`, then `npm run seed`), start node example with `CAMADA_KEY=tok-acme.snap-acme CAMADA_INGEST_URL=http://localhost:8787 CAMADA_TRUSTED_PROXY=hops:1`, curl `/` with `X-Forwarded-For: 203.0.113.66`, wait 16 s, `GET /admin/events?tenant=acme&kind=events&minutes=5` (`authorization: Bearer dev`). Look for `st: 403`. `blk` visible only once stream ea's ingest keeps it (EA-10) — note in status either way. Repeat for next example on :3001.
- [ ] **Step 3:** Status file with Done/In progress/Blocked/Interface changes (e2e-sdk.mjs diff proposal + `x-camada-sdk` sample)/Runnable (build order + commands). End with "available".

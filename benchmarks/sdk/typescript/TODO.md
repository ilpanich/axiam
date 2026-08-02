# TypeScript SDK benchmark — wired, validated at p0

`bench.mjs` is wired to the real SDK (`axiam-sdk`, Node persona —
`axiam-sdk/node`'s `createNodeClient`). It times the four canonical
CONTRACT.md §1 ops — `login`, `refresh`, `checkAccess`, `batchCheck` — with a
warm-up + measured loop, then prints one `axiam.sdk-bench/v1` JSON record to
stdout (see `../HARNESS-SPEC.md`). `run.sh` builds the sibling checkout (npm
install + `tsup`) if its `dist/` is missing, then `npm install`s it here as a
`file:` dependency (see `package.json`).

## H8 status (verified in this environment)

- **p0-plaintext: validated.** `ok`, double-run-clean, zero errors on every
  op, against a live seeded target.
- **p2-tls13: blocked by an unrelated, pre-existing SDK bug**, not a harness
  gap. `BENCH_CA_CERT` is wired (`bench.mjs` reads the PEM file and passes
  it as `customCa` to `createNodeClient`), but the Node persona's
  `maybeBuildHttpsAgent` (`axiam-typescript-sdk/src/rest/session.ts`) builds
  the `https.Agent` via a lazily-`require()`d `node:https` — a deliberate
  pattern so a *browser* bundle of the same shared file never tries to
  statically resolve a Node-only builtin. tsup's ESM output (`dist/node/
  index.mjs`, what `axiam-sdk/node`'s `import` condition resolves to) ships
  a `require` shim that throws `Dynamic require of "https" is not
  supported` because genuine Node ESM has no `require` global. Every call
  that needs `customCa` (i.e. every p2 call) fails with that error.

  **Not fixed here**: the safe fix (e.g. `node:module`'s `createRequire`, or
  restructuring so the Node-only agent-building code lives in a file that's
  never part of the browser bundle's import graph) needs to preserve the
  browser-bundle-safety property the current lazy-`require` was written for
  — verifying that needs a downstream bundler test this sandbox can't run.
  A naive static `import { Agent } from 'node:https'` at the top of
  `session.ts` would "fix" this bench but silently reintroduce exactly the
  problem the lazy pattern exists to avoid for real browser consumers of
  this package (its `.`/`./rest` exports are shared with `./node`).

## Running

```
cd benchmarks && just sdk=typescript sdk-bench
```

## p3-mtls (CONTRACT.md §6.1) — bench wired, SDK still blocked

`readClientIdentity()` reads `BENCH_CLIENT_CERT`/`BENCH_CLIENT_KEY` (file
paths) and passes them as `clientCert`/`clientKey` PEM strings to every
`createNodeClient(...)` this bench builds. Phase A of
`just sdk-bench-test typescript` passes: a half-configured pair produces the
contractual `status:"error"` record naming both variables.

**Phase B still fails**, for exactly the reason documented above: the Node ESM
bundle's `require`-shim throws `Dynamic require of "https" is not supported`
before any handshake, so `customCa` and `clientCert` are both unusable. That is
an SDK-side fix (see the H8 status section) — the harness side is complete. The
test lists `typescript` in its `KNOWN_BLOCKED` set so this does not fail the
run; drop it from that list (or run `STRICT=1 just sdk-bench-test`) once the
SDK fix lands, and this should go green with no bench change.

A second, unrelated staleness bug was fixed while wiring this: `run.sh` only
built the sibling SDK when its `dist/` was *missing*, never when it was merely
*older than* `src/`. Since npm resolves the `file:` dependency to a symlink,
the bench ran a bundle built 2026-07-12 against sources from 2026-07-18 — which
predated `org_slug` in the login body and produced
`Validation error: must provide org_id or org_slug`.

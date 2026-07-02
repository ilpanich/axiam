# Phase 17 (TypeScript SDK) — Captured Discussion Seed

**Status:** Pre-discussion input (NOT a locked CONTEXT.md). Captured 2026-07-01 from a
user Q&A while wrapping up Phase 16. `/gsd-discuss-phase 17` should incorporate/confirm
these, not treat them as already-locked decisions.

**Requirement:** TS-01 — TypeScript SDK: browser (REST-only) + Node (REST + gRPC + AMQP)
personas; browser authz via the FND-04 REST endpoint; Express + Fastify middleware; npm publish.
Binding contract: `sdks/CONTRACT.md` §1–§10. Reference implementation: Phase 16 `sdks/rust/`.

## Browser-persona decisions the user selected

- **CSRF token source → Cookie double-submit, matching the live frontend.**
  Read the `axiam_csrf` cookie via `document.cookie` and echo it as `X-CSRF-Token` on
  POST/PUT/PATCH/DELETE — exactly as `frontend/src/lib/api.ts` does today (proven against the
  real server). NOTE: CONTRACT.md §3's wording appears to say "capture from response header";
  this diverges from the working frontend. **Action for discuss/plan: reconcile CONTRACT §3 —
  update the contract note to match the cookie double-submit reality, or justify the difference.**

- **Browser token model → Cookie-session only; NO local token read, NO local JWKS verify, NO `Sensitive<T>`.**
  Browsers cannot read httpOnly tokens, so the browser client relies on `withCredentials`
  cookies + a reactive single-flight 401→refresh. No JS token reading (keeps httpOnly XSS
  posture intact), no raw tokens in JS. Local JWKS verification and the `Sensitive<T>` analog
  apply to the **Node persona only**. Mirrors the frontend.

- **Single-flight refresh (browser) → module-level shared Promise (per CONTRACT §9).**
  One in-flight refresh Promise held in a module variable; concurrent 401s await the same
  Promise. Directly satisfies the "5 concurrent fetches → 1 refresh" success criterion.
  Functionally equivalent to the frontend's `isRefreshing` + `failedQueue`, but cleaner.

- **Authz caching (browser) → none built in; expose `can()` + `batchCheck()`.**
  SDK stays stateless on authz. Callers gate a whole page in one round-trip via `batchCheck`
  and cache in their own layer (e.g. React Query). Avoids the SDK owning cache-invalidation /
  staleness. Matches how the frontend already works.

## Still to resolve in discuss/plan (not covered by the above)
- Node-persona specifics (gRPC via @grpc/grpc-js, AMQP via amqplib, `jose` for JWKS, `Sensitive<T>` analog).
- Package/entry-point split: separate `axiam-sdk/rest` / `axiam-sdk/grpc` / `axiam-sdk/amqp` export
  conditions so browser bundlers tree-shake Node-only code (per TS-01 acceptance criteria).
- axios 1.7 vs fetch for the REST layer; ts-proto 2.x stub generation; Express + Fastify middleware.
- npm publish pipeline (`axiam-sdk`).

*This file is advisory capture only — start Phase 17 with `/gsd-discuss-phase 17`.*

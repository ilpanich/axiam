---
phase: 17-typescript-sdk
plan: 06
subsystem: sdk
tags: [typescript, sdk, ci-cd, npm-publish, esbuild, csrf, contract-docs]

# Dependency graph
requires:
  - phase: 17-typescript-sdk
    plan: 01
    provides: "Build/test tooling (tsup dual ESM+CJS, vitest), package.json exports map for ./ /rest /grpc /amqp"
  - phase: 17-typescript-sdk
    plan: 02
    provides: "AxiamClient REST core (login/verifyMfa/can/batchCheck) the bundle-grep fixture imports"
  - phase: 17-typescript-sdk
    plan: 03
    provides: "Node persona + dynamic import('jose') JWKS guard the CJS-require smoke gate proves"
  - phase: 17-typescript-sdk
    plan: 05
    provides: "axiam-sdk/middleware public entry (Express/Fastify) the CJS-require smoke gate also proves"
provides:
  - "sdks/typescript/scripts/bundle-grep.mjs — esbuild --platform=browser bundle-and-grep proof of SC#1 (no @grpc/grpc-js|amqplib in the /rest browser bundle)"
  - ".github/workflows/sdk-ci-typescript.yml — full test job (build/typecheck/test/bundle-grep/CJS-require smoke/token-leak/TLS-lint/dry-run) + tag-triggered publish job (regenerate-and-bundle stubs, npm publish --provenance)"
  - "CONTRACT.md §3 canonical browser cookie double-submit + AximaClient->AxiamClient corrected repo-wide in the shared contract"
  - "Complete sdks/typescript/README.md: CONTRACT conformance statement, both personas, all 4 subpath entries, install, per-persona usage, error handling, security notes, release-tag convention"
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "tsup outExtension forced explicitly (ESM=.mjs, CJS=.js) to match the exports map's import/require condition paths — package.json's type:module otherwise makes tsup default to the opposite (ESM=.js/CJS=.cjs), which would make require('./dist/grpc/index.js') silently load real ESM syntax instead of a true CJS build"
    - "Bundle-and-grep CI gate (esbuild platform:browser) as an end-to-end proof of a dependency-boundary invariant, not just a config/comment assertion — the same pattern generalizes to any other cross-persona leak check"
    - "Post-build CJS-require smoke gate as a category of test that unit/typecheck/bundle tooling structurally cannot catch (only surfaces at first require() of the compiled entry)"

key-files:
  created:
    - sdks/typescript/scripts/bundle-grep.mjs
  modified:
    - .github/workflows/sdk-ci-typescript.yml
    - sdks/typescript/package.json
    - sdks/typescript/tsup.config.ts
    - sdks/typescript/README.md
    - sdks/CONTRACT.md

key-decisions:
  - "Fixed tsup.config.ts with an explicit outExtension (ESM=.mjs, CJS=.js) — found while validating the plan's own CJS-require acceptance criterion: without the fix, require('./dist/grpc/index.js') was loading a file containing real `import`/`export` ESM syntax, which only worked in this sandbox because Node 22 has experimental require(esm) support, not because it was a genuine CJS build (Rule 1 bug, not an intentional feature of the 17-01 scaffold)"
  - "bufbuild/buf-action@v1.4.0 kept unpinned to its floating tag, matching the plan's explicit exception and the repo's pre-existing sdk-buf-gates.yml precedent; verified via the action's own action.yml (fetched from GitHub) that `setup_only: true` is a real documented input before relying on it to install just the buf CLI without running lint/breaking"
  - "CONTRACT.md §3 restructured into two labeled subsections (canonical browser cookie double-submit; non-browser response-header capture) rather than a single ambiguous numbered list, so the two conformant client shapes for one server-side mechanism are unambiguous to every downstream SDK author (D-28)"
  - "README documents Fastify middleware usage in addition to the plan's explicitly-required Express snippet — both integrations already ship from 17-05's axiam-sdk/middleware entry and CONTRACT.md §10 requires per-framework coverage, so omitting Fastify would have left the README incomplete relative to what actually ships"

patterns-established: []

requirements-completed: [TS-01]

coverage:
  - id: D1
    description: "bundle-grep.mjs bundles a /rest fixture with esbuild --platform=browser and fails (non-zero exit) if @grpc/grpc-js or amqplib appear in the output, proving SC#1 end-to-end rather than trusting config alone"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "cd sdks/typescript && npm run build && npm run bundle-grep — verified locally via a real tsup build (dist/rest/index.mjs): clean build exits 0 with an OK message; a deliberately-broken dist/rest/index.mjs re-exporting @grpc/grpc-js correctly fails the esbuild platform:browser build (Could not resolve events/stream/fs/tls/etc., not a silent polyfill) and the script surfaces it as a FAIL exit 1"
        status: pass
    human_judgment: false
  - id: D2
    description: "After npm run build produces dist/, a CJS-require smoke gate (node -e require('./dist/grpc/index.js') and the CJS middleware entry) both exit 0 with no ERR_REQUIRE_ESM, proving the dynamic import('jose') guard (17-03) lets a CommonJS consumer require the built entry"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "cd sdks/typescript && node -e \"require('./dist/grpc/index.js')\" && node -e \"require('./dist/middleware/index.js')\" — both verified locally against a real tsup build; required the tsup.config.ts outExtension fix (see key-decisions) to make ./dist/grpc/index.js an actual CJS file rather than ESM syntax that only happened to work via Node 22's require(esm)"
        status: pass
    human_judgment: false
  - id: D3
    description: "npm publish --dry-run succeeds and the packed tarball includes dist/ and excludes src/gen and node_modules (SC#5)"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "cd sdks/typescript && npm publish --dry-run — verified locally: 39-file tarball, all entries under dist/, LICENSE, README.md, package.json; no src/gen or node_modules entries"
        status: pass
    human_judgment: false
  - id: D4
    description: ".github/workflows/sdk-ci-typescript.yml has a test job with bundle-grep/CJS-require/leak/TLS-lint/dry-run steps and a publish job gated on refs/tags/sdks/typescript/v with id-token: write and npm publish --provenance"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "python3 -c \"import yaml; d=yaml.safe_load(open('.github/workflows/sdk-ci-typescript.yml')); assert set(d['jobs'])=={'test','publish'}\" — YAML parses; publish job permissions include id-token: write; publish step uses --access public --provenance"
        status: pass
    human_judgment: false
  - id: D5
    description: "Every uses: in the workflow is pinned to a commit SHA except the already-established bufbuild/buf-action@v1.4.0 floating-tag exception used elsewhere in the repo"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "grep -n 'uses:' .github/workflows/sdk-ci-typescript.yml — checkout and setup-node both SHA-pinned (matching ci.yml's existing setup-node pin and sdk-ci-rust.yml's checkout pin); only bufbuild/buf-action retains its floating @v1.4.0 tag, matching sdk-buf-gates.yml's pre-existing pattern"
        status: pass
    human_judgment: false
  - id: D6
    description: "TLS-lint gate (rejectUnauthorized:false|NODE_TLS_REJECT_UNAUTHORIZED|insecureskipverify) returns empty against sdks/typescript/src/"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "grep -rniE 'rejectUnauthorized\\s*:\\s*false|NODE_TLS_REJECT_UNAUTHORIZED|insecureskipverify' sdks/typescript/src/ — returns empty (exit 1 / no matches)"
        status: pass
    human_judgment: false
  - id: D7
    description: "CONTRACT.md §3 states cookie double-submit as canonical browser CSRF behavior (read axiam_csrf cookie -> echo X-CSRF-Token) and scopes response-header capture to non-browser SDKs (D-28); AximaClient corrected to AxiamClient repo-wide in CONTRACT.md (D-14); only §3 and class-name typos changed"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "grep -q 'axiam_csrf' and 'double-submit' within CONTRACT.md §3 — both present; grep -q 'AximaClient|AximClient' sdks/CONTRACT.md sdks/typescript/README.md returns no match; git diff sdks/CONTRACT.md reviewed — only §3 content and 7 class-name occurrences changed, §1/§2/§4-§10 method vocabulary and behavioral rules untouched"
        status: pass
    human_judgment: false
  - id: D8
    description: "README states the exact conformance sentence and documents both personas, the four subpath entries, npm install axiam-sdk, and the sdks/typescript/vX.Y.Z release-tag convention"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "grep -q 'This SDK conforms to CONTRACT.md §1–§10.' sdks/typescript/README.md — matches exactly; grep -q 'npm install axiam-sdk' and 'sdks/typescript/vX.Y.Z' both present; README documents axiam-sdk/rest, /grpc, /amqp, /middleware in a table plus a usage snippet per persona"
        status: pass
    human_judgment: false

# Metrics
duration: 15min
completed: 2026-07-01
status: complete
---

# Phase 17 Plan 06: TypeScript SDK CI/Publish Pipeline + Shared Contract Docs Summary

**Full TypeScript SDK CI/publish pipeline (SC#1 bundle-and-grep, CJS-require smoke, token-leak, TLS-lint, dry-run + tag-triggered npm publish with provenance) and the scoped CONTRACT.md §3 canonical-browser CSRF + AxiamClient naming edits (D-28/D-14), plus a completed README — with a real tsup `outExtension` bug fix discovered while validating the plan's own CJS-require acceptance criterion.**

## Performance

- **Duration:** 15 min
- **Started:** 2026-07-01T12:38:30Z
- **Completed:** 2026-07-01T12:53:00Z
- **Tasks:** 2
- **Files modified:** 6 (1 created, 5 modified)

## Accomplishments
- Built `scripts/bundle-grep.mjs`: writes a temp fixture importing `{ AxiamClient }` from `dist/rest/index.mjs`, bundles it with esbuild's programmatic API using `platform: 'browser'`/`format: 'esm'`/`bundle: true`, and fails (exit 1) if the output matches `@grpc/grpc-js|amqplib` — proved end-to-end locally against both a clean `dist/rest/index.mjs` (exits 0, OK message) and a deliberately-broken one re-exporting `@grpc/grpc-js` (esbuild correctly hard-fails resolving `events`/`stream`/`fs`/`tls`/etc. under `platform:browser`, not a silent polyfill — exactly the mechanism RESEARCH Area 1 describes)
- Rewrote `.github/workflows/sdk-ci-typescript.yml` from the scaffold-check-only stub into a full `test` (PR-only) + `publish` (tag-only) pipeline modeled on `sdk-ci-rust.yml`: install → buf generate → build → typecheck → test → bundle-grep (SC#1) → CJS-require smoke (grpc + middleware entries, T-17-27) → token-leak (`grep 'eyJ' dist/`) → TLS-lint (`src/`) → `npm publish --dry-run` (SC#5); publish job gated on `refs/tags/sdks/typescript/v*`, `id-token: write`, regenerate-and-bundle (`buf generate && npm run build`, D-20), `npm publish --access public --provenance`
- **Found and fixed a real Rule-1 bug while validating the plan's own acceptance criteria:** `package.json`'s `type: module` makes tsup 8.5.1's default extension mapping ESM=`.js`/CJS=`.cjs` — the reverse of the `exports` map's `import`/`require` condition paths (which point at `.mjs` for ESM and `.js` for CJS/require, per the map established in 17-01). Without a fix, `require('./dist/grpc/index.js')` was loading a file containing real `import`/`export` ESM syntax; it only "worked" in this sandbox because Node 22 ships experimental `require(esm)` support — not a reliable CJS entry on the package's documented `engines.node: >=18` floor. Added an explicit `outExtension` to `tsup.config.ts` (ESM→`.mjs`, CJS→`.js`) so `require()` genuinely resolves a CJS build; re-verified with real `require`/`exports` syntax in the rebuilt `dist/grpc/index.js` and both CJS-require smoke commands passing for real
- Added the `bundle-grep` npm script
- Edited `sdks/CONTRACT.md` §3 (scoped edit): cookie double-submit (read `axiam_csrf` cookie → echo `X-CSRF-Token`) is now the canonical **browser** behavior, matching the server's actual mechanism and `frontend/src/lib/api.ts`'s proven implementation; response-header capture is explicitly scoped to non-browser SDKs (D-28) — restructured into two labeled subsections so the contract is unambiguous rather than describing behavior no client uses
- Fixed all 7 `AximaClient` occurrences in `CONTRACT.md` (§4/§5/§6, including the §6 TypeScript builder sample) to `AxiamClient` (D-14); diff-reviewed to confirm §1/§2/§4–§10's locked method vocabulary and behavioral rules are otherwise untouched
- Completed `sdks/typescript/README.md`: the exact "This SDK conforms to CONTRACT.md §1–§10." sentence, both personas + all four subpath entries in a table with the tree-shaking guarantee, `npm install axiam-sdk`, `AxiamClient` construction, a usage snippet per persona (browser login discriminated union + `can`/`batchCheck`, Node gRPC `checkAccess`, AMQP `consume` with `Sensitive` signing key, Express middleware, Fastify plugin), an error-handling guide (`AuthError`/`AuthzError`/`NetworkError`), security notes (`Sensitive<T>`, TLS policy, AMQP HMAC), Apache-2.0 license, and the `sdks/typescript/vX.Y.Z` release-tag convention

## Task Commits

Each task was committed atomically:

1. **Task 1: SC#1 bundle-grep gate + token-leak gate + TLS-lint gate + TypeScript CI workflow with dry-run + tag publish (D-02/D-20/D-21, SC#1/SC#5)** - `1d76b01` (feat)
2. **Task 2: README fill-in + scoped CONTRACT.md §3 canonical-browser + AxiamClient naming edits (D-28/D-14)** - `c893322` (docs)

**Plan metadata:** (pending — final docs commit follows this summary)

## Files Created/Modified
- `sdks/typescript/scripts/bundle-grep.mjs` - SC#1 bundle-and-grep helper (esbuild programmatic API, `platform: 'browser'`)
- `.github/workflows/sdk-ci-typescript.yml` - Full `test` + `publish` jobs replacing the scaffold-check-only stub
- `sdks/typescript/package.json` - New `bundle-grep` script
- `sdks/typescript/tsup.config.ts` - Explicit `outExtension` (ESM=`.mjs`, CJS=`.js`) fixing a real extension-mapping bug
- `sdks/typescript/README.md` - Complete: conformance statement, personas, entries, install, usage, error handling, security, license, release convention
- `sdks/CONTRACT.md` - §3 canonical browser cookie double-submit (D-28); `AximaClient`→`AxiamClient` (D-14)

## Decisions Made
- Fixed `tsup.config.ts` with an explicit `outExtension` — discovered while locally validating the plan's own CJS-require acceptance criterion (`require('./dist/grpc/index.js')` must genuinely be a CJS file, not ESM that happens to load via a Node-22-specific feature). This is scoped strictly to the extension-mapping bug; no other build config changed.
- Kept `bufbuild/buf-action@v1.4.0` unpinned to its floating tag per the plan's explicit exception, but verified this session (fetched the action's own `action.yml` from GitHub) that `setup_only: true` is a real, documented input before relying on it — not assumed from memory.
- Restructured CONTRACT.md §3 into two clearly labeled subsections (canonical browser cookie double-submit vs. non-browser response-header capture) rather than editing the single numbered list in place, so the D-28 direction reads as one coherent contract rather than an awkward retrofit.
- Documented Fastify middleware usage in the README in addition to the plan's explicitly-named Express snippet — both ship from 17-05's `axiam-sdk/middleware` entry and CONTRACT.md §10 requires per-framework coverage; omitting Fastify would have left the README incomplete relative to the actual shipped surface.

## Deviations from Plan

### Auto-fixed Issues (Rule 1 — bug)

**1. [Rule 1] tsup CJS/ESM extension mapping was backwards relative to the exports map**
- **Found during:** Task 1, locally validating the plan's own acceptance criterion (`node -e "require('./dist/grpc/index.js')"` must exit 0 with no `ERR_REQUIRE_ESM`)
- **Issue:** `package.json` declares `"type": "module"`; tsup 8.5.1's default extension mapping under `type:module` is ESM=`.js`/CJS=`.cjs` — but the `exports` map (established in 17-01) declares `import.default: "./dist/grpc/index.mjs"` and `require.default: "./dist/grpc/index.js"`, the opposite convention. Building with the unmodified config produced `dist/grpc/index.js` containing real ESM `import`/`export` syntax. `require('./dist/grpc/index.js')` only succeeded in this sandbox because Node 22.22 has experimental synchronous `require(esm)` support — not because it was a genuine CJS build, and not guaranteed on the package's documented `engines.node: >=18` floor.
- **Fix:** Added an `outExtension({ format })` function to `tsup.config.ts` returning `.js` for `cjs` and `.mjs` for `esm`, forcing tsup's output to match the exports map's existing condition paths.
- **Files modified:** `sdks/typescript/tsup.config.ts`
- **Verification:** Rebuilt with `npx tsup`; confirmed `dist/grpc/index.js` now starts with `'use strict'; ... require(...)` and ends with `exports.foo = foo` (real CJS); `node -e "require('./dist/grpc/index.js')"` and the middleware equivalent both exit 0; `npm run typecheck` and `npm test -- --run` (77/77) still clean; `npm run bundle-grep` and `npm publish --dry-run` still pass against the corrected build.
- **Commit:** `1d76b01`

---

**Total deviations:** 1 auto-fixed (Rule 1 bug)
**Impact on plan:** Necessary to make the plan's own CJS-require acceptance criterion a genuine proof rather than an artifact of this sandbox's specific Node version. No scope creep — the fix is scoped to the extension-mapping config only.

## Issues Encountered
`buf` CLI remains unavailable in this sandbox (pre-existing gap since 17-01, documented again in 17-05). `npm run build`'s `prebuild` step (`buf generate`) fails with `buf: not found`. Since `src/grpc/client.ts` uses local `Wire*` types mirroring `authorization.proto` rather than importing generated `src/gen` stubs (17-03's design, confirmed by reading the file), a direct `npx tsup` build (bypassing only the `prebuild` script) produces a fully faithful `dist/` for every entry this plan's acceptance criteria touch. All of Task 1's local verification — `bundle-grep`, the CJS-require smoke gate, the token-leak gate, `npm publish --dry-run`, `npm run typecheck`, `npm test -- --run` (77/77), and `npx tsc --noEmit -p examples/tsconfig.json` — was run and passed against this `tsup`-only build. The real `buf generate` step is exercised for the first time in CI (`.github/workflows/sdk-ci-typescript.yml`'s `test` job), which is the documented deferral this plan's environment notes anticipated.

## User Setup Required

**External services require manual configuration.** The plan's frontmatter declares `user_setup` for npm publishing:
- **NPM_TOKEN** (GitHub Actions secret): a granular automation token for the `axiam-sdk` package from npmjs.com → Access Tokens (or configure npm Trusted Publisher/OIDC so no token is needed). Required only for the tag-triggered `publish` job — PR-triggered `test` job runs `npm publish --dry-run`, which needs no credential.
- **Dashboard verification:** confirm the `axiam-sdk` package name is claimed/owned on npm before the first `sdks/typescript/vX.Y.Z` tag push.

No action was taken on these in this plan (side-effecting service configuration is explicitly out of scope for an autonomous executor); documented here per the plan's `user_setup` frontmatter for the human maintainer to complete before the first real release tag.

## Next Phase Readiness
- The TypeScript SDK's CI/publish pipeline is complete and locally verified end-to-end (modulo the `buf`-generate step, which only runs in CI where the toolchain is available, per this plan's own environment notes and design)
- `sdks/CONTRACT.md` §3 and naming are now internally consistent with what the TypeScript SDK (and future SDKs) actually implement — no divergence note needed, no follow-up doc debt
- `sdks/typescript/README.md` is publish-ready prose; `npm publish --dry-run`'s tarball contents (39 files, `dist/` + `LICENSE` + `README.md`, no `src/gen`/`node_modules`) match what a real npm consumer will receive
- This is the final plan of Phase 17 (typescript-sdk) — the SDK surface (`axiam-sdk`, `/rest`, `/grpc`, `/amqp`, `/middleware`), CONTRACT §1–§10 conformance, and CI/release pipeline are all complete; ready for Phase 17 to close and the next per-language SDK phase (18+) to proceed independently

---
*Phase: 17-typescript-sdk*
*Completed: 2026-07-01*

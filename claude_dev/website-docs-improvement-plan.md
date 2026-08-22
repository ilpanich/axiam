# Website documentation section — improvement plan

> **Audience: the next Claude session working on `website/src/docs/`.** This
> document is a self-contained brief: what the docs section is today, why its
> current depth is not enough, which pages need what, where the source material
> lives, and the mechanics and pitfalls of editing it. Written 2026-08-22
> against `1.0.0-alpha38` / SDK contract 1.28. Verify claims against the code
> before repeating them — this brief points at sources, it is not itself one.

## 1. The problem, in one example

The maintainer's own framing: *"it documents many features but at a basic
level."* The Reactors page is the canonical case. It says a listener can hear
"Any event in the reactor registry, **including non-interceptable ones**" — but
to learn what those events *are* you have to call
`GET /api/v1/reactors/events`. The registry is five entries of pure data
sitting in `crates/axiam-core/src/models/reactor.rs` (`EVENT_REGISTRY`): name,
interceptability, mutable-field allow-list, default failure policy, one-line
description. That is a table the page should simply contain.

The same pattern — an accurate paragraph where a table, a wire example or a
walkthrough should be — repeats across most of the 28 pages. The fix is not
more prose; it is **surfacing the data that already exists** in the repo
(registries, endpoint maps, config keys, error taxonomies, conformance
matrices) and adding **runnable examples** where today there is only a
description.

## 2. Ground rules (do not break these)

1. **The site is the readable front door, not the normative source.**
   `CLAUDE.md` is explicit: do not duplicate normative detail; link out to
   `docs/`, `sdks/CONTRACT.md` and the specs for anything binding. Inlining the
   reactor event registry table is fine (it is discoverability, and the API
   remains the live source); transcribing §22's signing rules is not. When you
   inline data, say where it comes from and that the API/contract governs.
2. **Do not invent.** Every endpoint, config key, event name, default and limit
   you write must be copied from code, `sdks/openapi.json`, or CONTRACT — not
   remembered. The Security section's discipline ("a plausible extra bullet is
   the one thing on the page that nothing verifies") applies to Docs too.
3. **The Security section is out of scope here.** It has its own source
   (`claude_dev/threat-modeling-and-security.md`) and its own keep-in-step
   rules. Docs pages may *link* to it.
4. **Check the currency of what you touch.** Docs were last rebuilt around
   alpha33 ("Rebuild the documentation section for a production IAM"); the
   server is at alpha38. While improving a page, verify its claims still hold —
   e.g. anything about passkey sign-in must reflect that the `finish` endpoints
   now set session cookies (alpha38 fix).

## 3. Mechanics of the docs section

- Content lives in `website/src/docs/*.ts`, one module per sidebar group,
  assembled by `website/src/docs/index.ts` — **which is also the source of
  truth for page order**. `docSectionsAreComplete()` asserts navigation and
  content agree; adding a page means adding its slug there or the assert fires.
- A page is a `DocPage` (slug, section, navLabel, title, intro, blocks). The
  block vocabulary (`website/src/docs/types.ts`): `h`, `p`, `list`, `code`,
  `note`, `warn`, `table` (with `proseFirstCol`), `cards`, `links`, `steps`
  (numbered procedures), `api` (method-coloured endpoint tables), `codegroup`
  (tabbed multi-language samples). **`steps`, `api` and `codegroup` are the
  under-used ones** — most of the depth this plan asks for is these three.
- Inline renderer quirk: it splits on backticks **before** it handles `**`, so
  a bold span enclosing a code span bleeds bold over the rest of the sentence.
  Keep `**…**` and `` `…` `` non-overlapping.
- Cross-page links are `#/docs/<slug>` (see the reactors cross-link in
  `integrate.ts` for the shape). Repo links point at
  `https://github.com/ilpanich/axiam/blob/main/...`.
- Verify with: `cd website && npm ci && npm run build && npm run lint` (build
  runs `tsc -b` first). CI also runs `scripts/check-website-links.py` on a
  schedule — every external URL you add will be link-checked, and npmjs.com is
  already known bot-hostile (do not add more links there without checking the
  script's allowances).

## 4. Page-by-page audit and what to add

Priorities: **P1** = biggest reader-value gap, do first. P2 = solid win. P3 =
nice to have.

### APIs & integration (`integrate.ts`)

- **Reactors — P1.** Add: (a) the event registry as a table (name,
  intercept/listen, what a patch may touch, default failure policy, one-line
  purpose) from `EVENT_REGISTRY` in `crates/axiam-core/src/models/reactor.rs`;
  note `token.pre_issue` may only add claims under `ext.` and why (`sub` is
  immutable to hooks), and that `grant.pre_assign`/`login.post_auth` default
  fail-closed while `token.pre_issue` defaults fail-open — that asymmetry is
  the most instructive fact on the page. (b) A wire example: one event message
  and one signed reply (shapes from CONTRACT §22.3–§22.4 — illustrative, link
  for normative). (c) Timeout/budget semantics in brief (§22.8) and the
  hot-path exclusion (§22.7: reactors never sit on the authz check path). (d)
  A `codegroup` showing the declarative handler binding (§22.14) in two or
  three languages, plus the Swift/C/C++ posture: protocol core over a
  caller-supplied transport, `amqpsEndpoint`-style §8b guard (contract 1.28,
  §22.11). (e) Resolve the "non-interceptable" wording: the registry's five
  events are all interceptable today; listeners additionally hear domain
  events. Check `GET /api/v1/reactors/events`'s handler
  (`crates/axiam-api-rest/src/handlers/reactors.rs`) and state precisely what
  the registry returns.
- **Webhooks — P1.** Add the event catalog (source:
  `crates/axiam-core/src/models/webhook.rs` and wherever event types are
  emitted — verify the actual list, the docs example shows `user.created`,
  `auth.login`), retry/backoff/DLQ parameters with their config keys, and a
  `codegroup` of `verify_webhook(...)` in TS/Python/Go against CONTRACT §13.
  Document secret rotation (multiple `v1` signatures) as a procedure (`steps`).
- **REST API — P1.** The server exposes ~177 operations across ~117 paths
  (`sdks/openapi.json`) and the site shows only a handful. Do not hand-write
  177 rows: either (a) generate per-domain `api` blocks from `openapi.json`
  with a small script in `website/scripts/` (committed output, like
  `gen:threat-model`), or (b) at minimum add per-domain endpoint tables for
  the big surfaces (users, roles/permissions/resources, certificates,
  webhooks, service accounts, tenants/orgs) with a link to the served Swagger
  UI. Option (a) is strongly preferred — it is the same "page cannot drift"
  pattern the Security section already uses.
- **gRPC API — P2.** Mine `docs/api/grpc.md` and `proto/axiam/v1/`: list the
  services and RPCs (`api` table equivalent), show one `CheckAccess` call as a
  `codegroup` (grpcurl + two SDK languages), state the deadline/retry rules
  from CONTRACT §16 briefly, and the sender-constrained-token-over-gRPC rule
  (§10.3) as a note.
- **AMQP & async — P2.** Show one signed message (v2 envelope: nonce,
  `issued_at`, HMAC) and the four queues/exchanges actually declared; document
  `amqps://`-only with the CA-bundle option. Source: `crates/axiam-amqp/`,
  CONTRACT §8/§8b.
- **SCIM — P2.** Turn `docs/api/scim-provisioning.md` into a walkthrough:
  mint a provisioning token (`steps`), configure Okta and Entra (two short
  procedures), what the token can and cannot do, deprovision behaviour
  (sessions revoked). Today's page is a summary of a summary.
- **Error reference — P3.** Good bones already. Add the gRPC status mapping
  column and the §2 error taxonomy's retryability flags; cross-link §16 retry
  policy.

### Authentication (`authentication.ts`)

- **Passkeys & WebAuthn — P1.** This page predates contract 1.28. Add: the
  two ceremonies as `steps` (register; authenticate — and usernameless
  discoverable sign-in as its own flow, per §24.2 they are different flows);
  a note that completed ceremonies set the same cookie triple as password
  login (alpha38); the per-tenant attestation policy knobs surfaced from
  `docs/admin/authenticator-policies.md` (X1–X3, MDS3, staleness bound); and
  the SDK story: §24's JSON bridge means any SDK can run the AXIAM half —
  show a `codegroup` (browser JS + one backend SDK). End-user material exists
  in `docs/user/passkeys.md`.
- **Multi-factor auth — P1.** Document the **two enrolment paths** (§25.2):
  voluntary (`mfa_enroll`/`mfa_confirm`, session-authenticated) vs forced
  during login (`403` + `mfa_setup_required` + `setup_token` →
  `mfa_setup_enroll`/`mfa_setup_confirm`), as two `steps` procedures — the
  contract calls confusing them "locks users out", which makes it exactly what
  integrators need spelled out. Note `login`'s three outcomes (success / MFA
  required / MFA **setup** required).
- **Passwords & sessions — P2.** Add the account-lifecycle endpoints (§25.1
  `api` table: verify-email, resend, reset request/confirm/context), the
  OPAQUE interaction on reset (`password_reset_context` before
  `confirm_password_reset` when OPAQUE is required), and the enumeration-safe
  behaviour as a `note` (uniform `200`, undistinguishable `404`s) — framed as
  "what your UI must not undo".
- **OPAQUE — P2.** Mostly fine; add the per-SDK availability line (native vs
  FFI vs WASM, CONTRACT §23.8) and a registration + login `codegroup`.
- **Federation & SSO — P3.** Add a SAML and an OIDC setup procedure (`steps`)
  with the attribute-to-role mapping rules, and the JIT-provisioning modes
  (`linked_only` default) from the federation crate.
- **Service accounts — P3.** Add mTLS and `private_key_jwt` registration
  examples; machine-vs-user audience split as a `note` (it explains otherwise
  baffling 401s).

### Authorization (`authorization.ts`)

- **Authorization engine — P2.** Add a worked resolution example: a tree of
  resources, a role granted at the parent, a deny at a child — show the
  answer at each node. The deny-override precedence table exists in
  `claude_dev/deny-override-design.md`; distil, link. Document the optional
  decision/session caches (off by default, invalidation guarantees) from the
  Security prose at reader level.
- **UMA 2.0 — P3.** Add the ticket dance as a sequence (`steps`) with the
  `WWW-Authenticate: UMA` challenge, from CONTRACT §20 / `docs/api/uma.md`.

### OAuth2 & OIDC (`oauth2.ts`)

- **PAR page — P1, currently missing entirely.** RFC 9126 shipped server-side
  and in all eleven SDKs (contract 1.28 §26). New page: what PAR changes (the
  browser carries only an opaque `request_uri`), the `201` response, client
  auth required, single-use redemption, `require_par` on FAPI 2.0 clients,
  one `codegroup` (`oidc_par` in two languages). Sources: §26,
  `crates/axiam-oauth2/src/par.rs`.
- **Authorization server — P2.** Add a full Authorization Code + PKCE
  sequence walkthrough (`steps` with the actual endpoints and parameters) and
  a token-anatomy table (claims, lifetimes, audiences, `cnf`). RFC 9207 `iss`
  and DPoP deserve a visible bullet each.
- **Device grant / Token exchange / Logout — P3.** Each has a deep
  `docs/api/*.md` counterpart; lift one example flow from each.

### Getting started (`getting-started.ts`)

- **P2.** The missing artifact is an end-to-end tutorial: protect one small
  app (login + route guard + a permission check) with one SDK, from
  `docker compose up` to a passing request, as `steps` + `codegroup`. Core
  concepts and quickstart exist; the bridge between them does not.

### Configuration & operations (`configuration.ts`, `operate.ts`)

- **Configuration — P2.** The page is already the strongest one. Gaps: a
  complete key reference is still missing (decide: generate from the config
  structs, or state explicitly which subset the page covers); add
  `AXIAM__AUTH__VAULT_CA_CERT_PATH` (recent, in CHANGELOG [Unreleased]) and
  the MDS staleness knobs; state per-key defaults consistently.
- **Operate — P2.** Surface `docs/deployment/rate-limit-sizing.md` and
  `docs/deployment/authz-read-path.md` (both currently invisible on the
  site); expand Troubleshooting from real failure modes (the `just prod-up`
  fixes in the CHANGELOG are a ready-made list); show a `GET /health/jobs`
  response body and what `stalled` means.
- **PKI & certificates — P3.** An IoT device enrolment walkthrough (issue
  cert → configure device → mTLS token) would tie the whole story together;
  material in `docs/pki/README.md` and `crates/axiam-pki/`.

### Reference (`reference.ts`)

- **Client SDKs — P1.** This is the page integrators land on and it has no
  code. Add: (a) a conformance matrix — eleven SDKs × the named contract
  sections (§12–§26), from each SDK README's conformance statement; today the
  split is: full §1–§11 surface incl. gRPC/AMQP for Rust/TS/Python/Java/C#/PHP/Go;
  REST surface for Kotlin/Swift/C/C++ — but §22 reactors are carried by all
  **eight managed runtimes** (Kotlin included) with a bundled AMQP client, and
  by Swift/C/C++ since 1.28 as the protocol core over a caller-supplied
  transport (§22.11). Copy the matrix from the conformance statements, not
  from memory. (b) Install + login + route-guard `codegroup` for at
  least TS, Python, Go, Java. (c) Canonical package names per registry —
  this is also a supply-chain control (T-135) and CONTRACT documents them.
- **Standards & compliance — P3.** Link each claim to its evidence file in
  `docs/compliance/` rather than asserting flatly.

## 5. Cross-cutting improvements

- **Generated, not transcribed.** Where the page shows data that exists as
  machine-readable truth (`openapi.json`, `EVENT_REGISTRY`, proto files, the
  webhook catalog), prefer a committed generator in `website/scripts/` over
  hand-typed tables — the Security section's `gen:threat-model` is the
  pattern, and CI's drift gates are the argument.
- **Version stamp.** Add "verified against 1.0.0-alphaNN" to each page's intro
  or a shared footer component, so staleness is visible instead of silent.
- **`codegroup` everywhere a claim is about code.** The block type exists and
  is barely used. Every "the SDK does X" sentence is better as five lines of
  code in two tabs.
- **Deep links into CONTRACT.** When referring to a contract section, link the
  GitHub anchor (`sdks/CONTRACT.md` heading anchors), not just the file.
- **Search** does not exist on the docs section. A client-side index (the
  content is already structured data — titles, headings, block text) is a
  contained, high-leverage feature; treat as its own task, after content.

## 6. Suggested execution order

1. Reactors + Webhooks + Client SDKs (the three pages where "basic" hurts
   integrators most; all data already exists).
2. Passkeys/WebAuthn + MFA + lifecycle endpoints (contract 1.28 made the
   current pages incomplete, not just shallow).
3. New PAR page; REST endpoint reference (with the generator decision).
4. Tutorial ("protect an app"); SCIM walkthrough; gRPC/AMQP deepening.
5. Operate/Configuration completeness; PKI walkthrough; search.

Work page-by-page, build (`npm run build`) after each module, and keep each
commit to one section so review stays tractable. Do not renumber or reorder
existing slugs — external links may point at them; new pages append to their
group in `index.ts`.

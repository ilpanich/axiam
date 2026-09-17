# AXIAM as an MCP authorization server — implementation plan

**Status:** planning document, written 2026-09-16 against `1.0.0-beta15`
(`main` at `d20293a`). Nothing described here exists yet.
**Audience:** first the maintainer, who asked how far AXIAM is from what
[Keycloak's MCP guide](https://www.keycloak.org/securing-apps/mcp-authz-server)
describes and gets the answer in §0; then the executing sessions, one per task
in §4, each of which must read §1 (invariants), §4.0 (definition of done) and
§5 (the regression gate) before touching code; §8 is the prompt that starts the
executing session.
**Companion documents:**
[`token-exchange-design.md`](token-exchange-design.md) (the only place the
`resource` parameter is honoured today, and the SEC-089 note that this plan
finally resolves), [`crate-layering.md`](crate-layering.md) (why the CIMD fetch
in T5 needs no new crate edge) and [`threat-model-stride.md`](threat-model-stride.md)
(the surfaces T4 and T5 add are new entries for it; T8 writes them).

Everything below is derived from what is in this repository at this commit.
Where the code and a plausible expectation disagree, the code wins and the
disagreement is called out with a `file:line` reference.

---

## 0. The gap, stated once

The Model Context Protocol (MCP) authorization specification makes the MCP
server an OAuth 2.0 resource server and delegates everything else to an
ordinary authorization server. What it demands of that server is a short list,
and Keycloak's guide rates itself against it. AXIAM against the same list:

| Requirement (MCP 2025-06-18 and later) | Keycloak | AXIAM today | Closed by |
| --- | --- | --- | --- |
| OAuth 2.1 core — code grant, PKCE S256, no implicit | Supported | Supported. PKCE is S256-only and advertised; mandatory only for public clients (`crates/axiam-oauth2/src/authorize.rs:311`) | — |
| RFC 8414 authorization-server metadata | Supported | Document complete (`crates/axiam-oauth2/src/oidc.rs:88`), served only at `/.well-known/openid-configuration`; the RFC 8414 path is not routed (`crates/axiam-api-rest/src/server.rs:554`) | **T1** |
| Public clients with PKCE (VS Code, Claude Code, MCP Inspector) | Supported | **Not usable.** `ClientAuthMethod` has no `none` (`crates/axiam-core/src/models/oauth2_client.rs:122`); a missing secret is `invalid_client` at the token endpoint (`crates/axiam-oauth2/src/token.rs:1037`) | **T2** |
| Loopback redirect with a random port (RFC 8252 §7.3) | Supported | Absent — exact match only (`authorize.rs:301`) | **T2** |
| RFC 8707 resource indicators, `aud` bound to the MCP server | **Not supported** (scope + audience-mapper workaround) | Partial. `resource` is read only by the RFC 8693 exchange grant (`crates/axiam-oauth2/src/token_exchange.rs:586`); every other grant ignores it and mints `aud: axiam:user` or `axiam:m2m` (`token.rs:1756`) | **T3** |
| RFC 7591 dynamic client registration | Supported | Absent. Only the admin-authenticated `POST /oauth2-clients` exists; discovery has no `registration_endpoint` | **T4** |
| OAuth Client ID Metadata Document (CIMD) | Experimental (`--features=cimd`) | Absent. `client_id` is an opaque tenant-scoped string | **T5** |
| RFC 9207 `iss` on authorization responses | Supported | Supported, unconditionally | — |
| RFC 7662 introspection | Supported | Supported | — |
| An issuer an MCP client can discover for the right tenant | n/a (one realm = one issuer) | The issuer is one fixed root URL; the tenant travels as `?tenant_id=` on every endpoint URL (`oidc.rs:251`). RFC 8414 forbids a query in an issuer, so an MCP client that derives discovery from the protected-resource metadata always lands on the deployment's default tenant. Path-based issuers are refused at boot (`crates/axiam-server/src/main.rs:2824`) | **T6** |

Two consequences drive the ordering below. First, T1 to T4 reach the
"Partially Supported" rating Keycloak gives itself for MCP 2025-11-25, and T3
alone puts AXIAM ahead of Keycloak on the one MUST it lacks. Second, T5 and T6
are what a **multi-tenant** deployment fronting Claude Code or VS Code needs;
a single-tenant deployment is served by T1 to T4 plus the T7 documentation.

The MCP server side — the RFC 9728 protected-resource metadata document, the
`WWW-Authenticate: Bearer resource_metadata="…"` challenge, the audience check
on inbound tokens — is not AXIAM's to implement. It is documented in T7, and
the SDKs' resource-server middleware already verifies a configured `aud`
(`sdks/CONTRACT.md` §10.1 row 6), so an MCP server built on an AXIAM SDK gets
the audience check by configuration once T3 mints the claim. What the SDKs do
**not** have is the resource-server half of the MCP handshake — publishing the
RFC 9728 document and emitting the challenge — and T9 adds it to all eleven.

---

## 1. Invariants — nothing existing changes shape

The maintainer's condition for this work is that **new developments must not
affect existing features and flows**. Every task below is therefore additive
and opt-in, and each session must be able to demonstrate the following before
it pushes:

- **I1 — Default behaviour is byte-identical.** With no new flag set, no new
  tenant setting enabled, no `resource` parameter sent and no client registered
  with a new auth method, every existing request produces the same response it
  produces today. The regression gate in §5 is how this is shown.

  **Maintainer ruling, 2026-09-17 — I1 admits additive capability
  advertisements.** T2a is the first task to collide with I1 as written, and
  the collision is real: the plan's own T2a item 6 orders `none` into
  `token_endpoint_auth_methods_supported`, which changes
  `GET /.well-known/openid-configuration` for every deployment with no flag
  set, so the response is not byte-identical. T2a changed the existing
  assertion that pinned the old behaviour
  (`crates/axiam-api-rest/tests/oidc_conformance.rs`,
  `discovery_advertises_every_implemented_client_auth_method`, which asserted
  `!methods.contains(&"none")`) rather than stopping, and the question went to
  the maintainer. The ruling: **an addition is allowed where it does not
  impact the OIDF conformance tests — Basic OP and FAPI 2.0.** I1 therefore
  binds the *behaviour of existing flows*, not the exact bytes of a capability
  statement. What is still forbidden is unchanged: no existing request may
  take a different path, be refused where it succeeded, or succeed where it
  was refused.

  **The condition is not yet discharged, and one module carries the risk.**
  All three FAPI 2.0 plans run
  `fapi2-security-profile-final-discovery-end-point-verification`
  (`docs/conformance/2026-09-15-fapi2-*.md`). FAPI 2.0 §5.3.1.1 admits only
  `private_key_jwt` and mTLS, and `none` is not a weak credential but the
  absence of one, so a suite that tolerates a weak method may still object to
  this. The evidence in hand is encouraging but circumstantial: AXIAM already
  advertises `client_secret_post` **and** `client_secret_basic` (row 140 of
  `docs/compliance/oidc-conformance.md`), and that module passed on every
  plan in the 2026-09-15 sweep — so it plainly does not require the advertised
  set to be FAPI-strong-only. It is not proof, because a check may single out
  `none`. No repository asset asserts on this field, and the suite cannot be
  run from the orchestrator sandbox (no Docker daemon), so the verification
  belongs to the first environment that has one. **T8 must run that module
  first, before the rest of its harness**, and report it explicitly rather
  than folding it into "the same result as the 2026-09-15 sweep". If it
  objects, the fallback is to advertise `none` only for a tenant that permits
  public clients — which costs I7's "capability statement, never per-tenant
  state" and is the maintainer's call, not the executing session's.

- **I2 — Existing tokens keep their audience.** A request without `resource`
  still mints `aud: axiam:user` / `axiam:m2m`. The SDK contract's expectation
  (`CONTRACT.md` §10.1 row 6) holds unchanged.
- **I3 — AXIAM's own APIs keep refusing foreign audiences.** The REST and gRPC
  extractors accept only the two built-in audiences
  (`crates/axiam-api-rest/src/extractors/auth.rs:1032`,
  `crates/axiam-api-grpc/src/middleware/auth.rs:61`), and
  `validate_access_token` pins the audience set
  (`crates/axiam-auth/src/token.rs:1523`). A token minted for an MCP server
  must be **rejected** by AXIAM's own resource endpoints. T3 must add a test
  that proves this, not relax it.
- **I4 — Confidential clients cannot become public by accident.** The `none`
  auth method is a registration decision, never a fallback: a client registered
  for `client_secret_post` that omits its secret stays `invalid_client`.
- **I5 — FAPI posture is untouched.** `fapi.rs` refuses `none` on any FAPI
  profile and refuses DCR/CIMD-sourced clients from ever carrying a FAPI
  profile. The conformance runbook (`fapi-conformance-runbook.md`) needs no
  amendment.
- **I6 — Loopback matching applies only to registered loopback URIs.** Every
  `https://` redirect URI keeps exact matching; the port-agnostic rule is
  scoped to registered URIs whose host is `127.0.0.1`, `[::1]` or `localhost`.
- **I7 — Discovery stays a capability statement.** Per-client posture is
  never published (the existing rule for `require_par` and certificate
  binding, `oidc.rs:103`). `registration_endpoint` is advertised per tenant,
  exactly as the sensitive-scope members already are.
- **I8 — Crate layering holds.** `scripts/check-crate-layering.py` passes;
  T5 reuses the existing `axiam-oauth2 → axiam-federation` edge
  (`crates/axiam-oauth2/Cargo.toml:40`) rather than adding one.
- **I9 — Public paths and OpenAPI stay in parity.** Every new unauthenticated
  route is added to `PUBLIC_PATHS` (`crates/axiam-api-rest/src/permissions.rs:283`)
  and to the OpenAPI document in the same commit.

---

## 2. Model assignment — the rule and the price

Two models are eligible: **Claude Opus 5** (`claude-opus-5`, $5 / $25 per
million input / output tokens) and **Claude Sonnet 5** (`claude-sonnet-5`,
$2 / $10). Both carry a 1M context window, so context is never the deciding
factor; judgement under ambiguity and security-sensitivity are.

The rule this plan applies, consistent with
[`sdk-oidc-sso-plan.md`](sdk-oidc-sso-plan.md) §4 and
[`benchmark-improvement-plan.md`](benchmark-improvement-plan.md):

- **Opus 5** when the task touches token minting or client authentication,
  adds an unauthenticated write endpoint, performs outbound fetches (SSRF), or
  has to reconcile an RFC's wording with existing behaviour across several
  crates. A wrong call here is a security finding, and the difference in price
  is smaller than the cost of a remediation round.
- **Sonnet 5** when the task is a bounded port of a pattern that already
  exists in the repository: a route alias, an admin form field, a documentation
  page, a contract paragraph. Run it at effort `high`; the spec in this
  document is the whole brief.

Where a task has both kinds of work it is split into lettered sub-tasks so the
cheaper model does the bounded part.

| Task | Model | Why |
| --- | --- | --- |
| T1 discovery alias | **Sonnet 5** | Route + list entries + tests, pattern exists (`uma2-configuration`) |
| T2a public clients at the token endpoint, loopback matcher | **Opus 5** | Client authentication and redirect matching are the two classic attack surfaces of a code grant |
| T2b admin UI for public clients | **Sonnet 5** | One option and one validation rule in an existing form |
| T3 RFC 8707 end to end | **Opus 5** | Changes what `aud` means across five grants, introspection and AXIAM's own extractors |
| T4a registration endpoint and policy | **Opus 5** | Unauthenticated write endpoint with abuse controls |
| T4b admin UI, settings form, audit viewer filter | **Sonnet 5** | Bounded forms over the policy T4a defines |
| T5 Client ID Metadata Document | **Opus 5** | Outbound fetch of attacker-chosen URLs, cache bounds, trust policy |
| T6 per-tenant issuers | **Opus 5** | Cross-cutting: issuer validation, discovery, `iss` claims, route prefixes |
| T7 documentation, example, website | **Sonnet 5** | Writing against a finished implementation; the example imitates `examples/b5-rp-logout-app` |
| T8 end-to-end MCP harness and security review | **Opus 5** | Adversarial review of everything above |
| T9a CONTRACT §28 — MCP resource-server helpers | **Opus 5** | Normative text every SDK port inherits |
| T9b TypeScript reference implementation | **Opus 5** | Establishes the file, test and doc pattern the ten ports imitate |
| T9c ten SDK ports (Rust, Python, Java, Kotlin, C#, PHP, Go, Swift, C, C++) | **Sonnet 5** | Well-specified ports with a reference to copy and a compiler to answer to |
| T9d cross-SDK conformance review | **Opus 5** | Adversarial cross-repo review; catches semantic drift between ports |

---

## 3. Design decisions that span tasks

**D1 — One `resource` per request.** RFC 8707 allows several; MCP requires
exactly one (the MCP server the token is for). v1 accepts one value and answers
`invalid_target` to a second, and says so in the documentation. The access
token's `aud` stays a single string (`crates/axiam-auth/src/token.rs:118`),
which is what the SDK middleware and both extractors already parse.

**D2 — Resources are an allow-list on the client.** A new
`allowed_resources: Vec<String>` on `OAuth2Client` is the only source of truth
for what a client may name in `resource`. It replaces the SEC-089 workaround
where the token-exchange grant treats registered redirect URIs as audiences
(`token_exchange.rs:611`). During one release the exchange grant accepts the
union of both lists and logs a deprecation warning when the redirect-URI branch
is the one that matched; the code grant never consults redirect URIs.

**D3 — Externally registered clients share one resource policy.** Clients
that arrive through DCR (T4) or CIMD (T5) cannot declare their own
`allowed_resources` — an unrelated party must not be able to mint tokens for
arbitrary audiences. They inherit the tenant's
`oidc.external_client_allowed_resources`, the list of MCP servers this tenant
fronts. An empty list means an externally registered client can only obtain
today's `axiam:user` tokens, which AXIAM's own APIs accept — so the
documentation in T7 tells operators to set the list before enabling either
mechanism, and T4a refuses to enable anonymous registration while it is empty.

**D4 — Externally registered clients always get a consent screen.** A client
an administrator did not create is an unrelated party. The first authorization
per user for a client whose `managed_by` is `dcr` or `cimd` must pass the
existing consent hop (`authorize.rs:440`, the W7 gate) regardless of scope; the
grant is recorded through the existing OIDC-scope consent records
(`/account/consents/oidc-scopes`), so withdrawal works through the account
page unchanged.

**D5 — A `managed_by` discriminator on clients.** `admin` (default, every
existing row), `dcr`, `cimd`. Admin UI shows the latter two read-only, the
sweeper in T4a only ever touches `dcr`, and `fapi.rs` refuses a FAPI profile on
anything but `admin`.

**D6 — Tenant selection is unchanged until T6.** T1 to T5 keep the
`?tenant_id=` convention and therefore describe the default tenant to any
client that derives discovery from an issuer. T6 makes the per-tenant issuer an
opt-in path form. Nothing in T1 to T5 may assume T6.

**D7 — Schema changes are additive `DEFINE FIELD … DEFAULT` migrations.** The
`oauth2_client` table is `SCHEMAFULL` (`crates/axiam-db/src/schema.rs:577`);
each new field ships as a numbered migration with a default so existing rows
need no backfill.

---

## 4. Tasks

### 4.0 Definition of done — every task, no exceptions

A task is done when all four of the following are in the same PR. The
maintainer asked for docs, examples and tests explicitly; a task that ships
code alone is not done.

1. **Tests.** Unit tests in the crate that owns the logic; an integration test
   under `crates/axiam-api-rest/tests/` for every new endpoint, parameter or
   policy; every negative case the task's acceptance list names; the parity
   test for every new public path (I9); frontend tests for T2b and T4b; the
   regression gate of §5 green. A test that asserts the new behaviour is
   *absent* when the flag or policy is off is mandatory (I1).
2. **Docs.** The page or section named in the task's "Docs" line, in the voice
   of the existing `docs/api/*.md` and `docs/admin/*.md`; utoipa annotations on
   every new handler and field so `docs/api/openapi.json` and
   `sdks/openapi.json` regenerate with the repository tooling; every new tenant
   setting or environment variable in `docs/deployment/` where the others are
   listed. Each client-visible parameter gets a curl snippet on its page.
3. **Examples.** T7 owns the runnable example tree entry
   (`examples/b7-mcp-server/`); every other task adds to it the request shape
   it introduces, so the example's walkthrough script exercises the whole
   feature by the time T8 runs it.
4. **Release notes.** A `CHANGELOG.md` entry under the unreleased heading,
   one line per user-visible change, naming the flag or policy that enables it.
5. **SDK fan-out.** T9 owns SDK code. Every other task that changes
   `sdks/CONTRACT.md`, `sdks/openapi.json` or `proto/` records the change in
   the contract's version trailer and lists the eleven downstream repositories
   that must re-sync (`CLAUDE.md` names them), so T9c's ports pick it up.

Each task is one session. Each names its model, its files, its acceptance
criteria and the invariants from §1 it must demonstrate. "Push" means the
branch convention in `CLAUDE.md`: a feature branch, a signed commit, a PR
opened by the agent on behalf of the maintainer.

### T1 — Serve the RFC 8414 well-known path — **Sonnet 5**

**What.** `GET /.well-known/oauth-authorization-server` returns the same
document, built by the same handler, with the same optional `?tenant_id=`, as
`/.well-known/openid-configuration` (`crates/axiam-api-rest/src/handlers/oauth2.rs:2465`).
MCP clients probe the RFC 8414 path first; the 2025-11-25 specification allows
the OIDC path as a fallback, but several client libraries do not implement the
fallback.

**Where.**
- `crates/axiam-api-rest/src/server.rs:554` — second route on the same handler.
- `crates/axiam-api-rest/src/permissions.rs:283` — `PUBLIC_PATHS` entry with
  the same comment as the OIDC one.
- `crates/axiam-api-rest/src/middleware/authz.rs:221` — the `is_public_path`
  test gains the new path.
- `crates/axiam-api-rest/src/openapi.rs` — the path enters the OpenAPI
  document so the parity check holds (I9); `docs/api/openapi.json` and
  `sdks/openapi.json` are regenerated with the repository's tooling, never by
  hand.

**Docs.** A paragraph in `docs/api/README.md` beside the discovery entry, and
the utoipa annotation on the route.

**Acceptance.**
- New integration test `crates/axiam-api-rest/tests/oauth2_discovery_alias_test.rs`:
  the two paths return byte-identical JSON, with and without `tenant_id`, and
  both carry `Cache-Control` and `Content-Type` identical to today.
- The existing conformance tests (`oidc_conformance.rs`, `oauth2_conformance.rs`)
  pass unchanged.
- I1, I9.

### T2 — Public clients and loopback redirects

#### T2a — Token-endpoint `none` and the loopback matcher — **Opus 5**

**What.**
1. `ClientAuthMethod::None` (wire value `none`) in
   `crates/axiam-core/src/models/oauth2_client.rs:122`, with `as_str`,
   `from_wire`, and a `is_public()` helper. `authorize.rs:310` derives
   `is_public_client` from the method, not from an empty hash.
2. Admin creation with `token_endpoint_auth_method: none` mints no secret,
   stores an empty `client_secret_hash`, returns no `client_secret`, and is
   refused when `grant_types` contains `client_credentials` or any
   token-exchange grant, when the profile is FAPI (I5), or when any mTLS or
   `private_key_jwt` binding is also set.
3. `authenticate_client_credential` (`token.rs:998`) gains a `None` arm that
   accepts no credential and **rejects a presented one** (`invalid_client`):
   a secret on a public client is a misconfiguration, not a bonus. The
   `client_secret_post` arm is untouched, so I4 holds by construction.
4. PKCE is required for public clients at the token endpoint as well as at
   authorize: a code without a stored challenge redeemed by a `none` client is
   `invalid_grant`.
5. Loopback matching (RFC 8252 §7.3). A new `redirect_uri_matches(registered,
   presented)` in `axiam-oauth2` used by authorize (`authorize.rs:301`), PAR
   and code redemption: when the registered URI's host is `127.0.0.1`, `[::1]`
   or `localhost`, the presented port is ignored; scheme, host, path and query
   must still be identical. `localhost` and `127.0.0.1` are not interchangeable
   (VS Code registers one, Claude Code the other; each registers what it
   uses). The authorization code keeps storing the **presented** URI, so the
   token request's `redirect_uri` comparison stays exact against what was
   actually used.
6. Discovery adds `none` to `token_endpoint_auth_methods_supported`
   (additive, I7).
7. Rate limiting: public-client token requests are keyed on
   `client_id + client IP` through the existing rate-limit configuration
   (`crates/axiam-api-rest/src/config/rate_limit.rs`).

**Docs.** `docs/admin/public-clients.md`: when to register a public client,
the refusals, the loopback rule with VS Code's and Claude Code's URIs as the
worked example; the token-endpoint page's auth-method table gains `none`.

**Acceptance.**
- Unit tests for the matcher: random port accepted on each loopback host;
  path or query difference refused; `https://` URIs still exact; a registered
  loopback URI with an explicit port also accepts any port (the RFC's rule).
- Integration: full code + PKCE flow for a `none` client with no secret;
  `client_credentials` refused for `none`; secret presented to a `none` client
  refused; missing secret on a `client_secret_post` client still
  `invalid_client` (I4); FAPI profile with `none` refused at registration (I5).
- `crates/axiam-api-rest/tests/oauth2_conformance.rs` and `par_test.rs`
  unchanged and green.
- I1, I4, I5, I6.

**Amendment, recorded by the executing session (2026-09-16).** Item 6
(advertise `none`) cannot be landed without changing the expectation of two
existing tests, which §5 says to stop and report rather than relax. Both are
**premise** assertions rather than behaviour ones — each pins, in its own
comment, the fact that no public-client story existed — and T21.2 is the task
that builds the story:

- `crates/axiam-api-rest/tests/oidc_conformance.rs:365`
  (`discovery_advertises_every_implemented_client_auth_method`) asserts the
  advertised list **exhaustively** and then asserts `none` is absent, with the
  reason "there is no public-client story; advertising `none` would claim
  one". The exhaustive half is the gate doing exactly its job: it exists so
  that a method added to `ClientAuthMethod` and wired into
  `authenticate_client_credential` cannot go unadvertised. Its expectation is
  therefore *extended* (`none`, pinned in last place, so a future change that
  advertised it first would still fail), and the absence assertion is
  removed — the only line in this task that a reader could call a relaxation,
  and the one the plan's item 6 explicitly asks for.
- `crates/axiam-core/src/models/oauth2_client.rs`
  (`an_unrecognised_auth_method_is_refused`) listed `"none"` among the wire
  values `from_wire` must refuse. Keeping it would make a stored `none` row
  unreadable. The precedent is in the test's own comment: W8 moved
  `client_secret_basic` from that list to the accepted one when the server
  implemented it, calling it "a deliberate, reviewed reversal". This is the
  same reversal, recorded the same way.

Nothing else in §5's gate changed, and no existing test's *behavioural*
expectation did. I1 holds for every request except the discovery document,
which gains one array element — which item 6 mandates and I7 classifies as
additive.

Two further decisions the task's text did not settle, both taken toward the
stricter answer and documented in `docs/admin/public-clients.md`:

- **Introspection is refused to public clients** (RFC 7662 §2.1 requires an
  authenticated caller; a `client_id` that appears in every browser redirect
  is not one), as are the **uma-ticket** and **token-exchange** grants at
  request time. Revocation is *not* refused — RFC 7009 §2.1 contemplates
  public clients, and a revocation only reaches a token the caller holds.
- **`is_public_client` at `authorize.rs` is the union** of "registered for
  `none`" and "empty `client_secret_hash`", not a replacement of the second by
  the first. SEC-025 has required PKCE of an empty-hash row since long before
  `none` existed; dropping that arm would quietly stop requiring it for any
  deployment that reached that state another way. The union is fail-closed and
  identical to today's answer for every client that exists.

#### T2b — Admin UI — **Sonnet 5**

**What.** `frontend/src/services/oauth2clients.ts` gains the `none` method;
`validateClientPosture` (`oauth2clients.ts:216`) encodes the refusals from
T2a §2 client-side; the client form shows "Public client (no secret)" and hides
the secret reveal for it. Tests in the existing service test file.

### T3 — RFC 8707 resource indicators, end to end — **Opus 5**

**What.**
1. `allowed_resources: Vec<String>` on `OAuth2Client`, `CreateOAuth2Client`,
   `UpdateOAuth2Client`; migration per D7; admin API and OpenAPI; each entry is
   an absolute URI without fragment (RFC 8707 §2), compared after RFC 3986
   syntax-based normalisation, never by prefix.
2. `resource` accepted on `/oauth2/authorize` (`AuthorizeQuery`,
   `handlers/oauth2.rs:73`, and `AuthorizeRequest`, `authorize.rs:19`), on PAR
   (stored with the pushed request), on device authorization, and on the token
   endpoint for the `authorization_code`, `refresh_token`,
   `client_credentials` and `device_code` grants. `TokenRequest` already
   carries the field (`token.rs:123`); today only `exchange_request()` reads it.
3. Validation: absent → today's behaviour (I2). Present and not in
   `allowed_resources` → `invalid_target` (RFC 8707 §2), redirected on
   authorize, JSON on token. Two values → `invalid_target` (D1).
4. Persistence: `resource: Option<String>` on `AuthorizationCode`
   (`oauth2_client.rs:698`), on the device-code record, and on the
   refresh-token record so that a refresh re-mints the **same** audience. A
   refresh request may repeat the stored `resource` or omit it; a different
   value is `invalid_target`. A token cannot be widened by refreshing it.
5. Minting: `AccessTokenSpec::aud()` (`crates/axiam-auth/src/token.rs:702`)
   already takes any string; the grants pass the resource where they pass
   `AUD_USER` / `AUD_M2M` today (`token.rs:1756`, `token.rs:2273`).
6. Introspection and revocation must accept resource-bound tokens.
   `validate_access_token` (`token.rs:1523`) pins the audience set for
   AXIAM's own consumers and must **stay pinned** (I3); introspection gets a
   sibling decode that verifies signature, `iss`, `exp` and binding but treats
   `aud` as data, and the introspection response gains `aud` (RFC 7662 §2.2)
   if it does not carry it yet.
7. Token exchange: `is_builtin_audience(t) || client.redirect_uris.contains(t)`
   at `token_exchange.rs:611` and `:858` becomes the D2 union with the
   deprecation log; `docs/api/token-exchange.md#audience` is rewritten to
   describe `allowed_resources`.
8. DPoP and mTLS binding are orthogonal and must keep working on
   resource-bound tokens (a bound token for an MCP server is the recommended
   posture; T7 says so).

**Docs.** `docs/api/resource-indicators.md`: the parameter on each grant, the
`allowed_resources` registration field, `invalid_target`, the refresh rule,
the I3 consequence for AXIAM's own APIs; `docs/api/token-exchange.md#audience`
redrafted for D2.

**Acceptance.**
- Integration tests per grant: `resource` echoed as `aud`; unregistered
  resource → `invalid_target` at authorize and at token; refresh cannot change
  it; PAR carries it; device flow carries it.
- **I3 test:** a resource-bound token presented to `GET /users/me` (REST) and
  to `CheckAccess` (gRPC) is refused with 401 / `UNAUTHENTICATED`.
- **I2 test:** every existing token test still asserts `axiam:user` /
  `axiam:m2m` without modification.
- Token-exchange tests (`token_exchange_test.rs`,
  `external_token_exchange_test.rs`,
  `keycloak_cross_vendor_token_exchange_test.rs`) green; a new one shows the
  redirect-URI branch still works and logs the deprecation.
- `scripts/check-crate-layering.py` clean (I8).

**Amendments, recorded by the executing session (2026-09-17).** Three, none of
which changed an existing test's expectation.

1. **RFC 3986 §6.2.2 is applied as far as the `url` crate applies it, and no
   further.** Item 1 says entries are "compared after RFC 3986 syntax-based
   normalisation". The `url` crate performs §6.2.2.1 (case normalisation of
   scheme and host), §6.2.2.3 (dot segments) and §6.2.3 (default port), and
   **does not** perform §6.2.2.2's decoding of a percent-encoded *unreserved*
   character in the path: `https://h/%6Dcp` and `https://h/mcp` serialise
   differently. Measured, not assumed — the first draft of
   `crates/axiam-oauth2/src/resource.rs`'s own test asserted the collapse and
   failed.

   Hand-rolling the decoder was rejected. `redirect_uri.rs`'s standing argument
   applies unchanged — a normalising comparison in front of a security check is
   where the decoder bug becomes an authorisation bug — and the direction of
   the error settles it: skipping §6.2.2.2 keeps two spellings **distinct**, so
   a request is refused that would otherwise have been admitted. Under-matching
   fails closed; over-matching widens an allow-list on the operator's behalf.
   The module documents exactly what it normalises and what it does not, the
   test asserts both halves, and `docs/api/resource-indicators.md` tells
   operators to register the form their resource server publishes.

2. **D1's refusal is structural; only its error code needed code.**
   `serde_urlencoded` refuses a repeated key for a non-sequence field
   (`duplicate field \`resource\``), so a second `resource` never reaches a
   handler on any of the four endpoints — verified against 0.7.1, the version
   in `Cargo.lock`. Two values are therefore refused by construction, with no
   path on which they are silently narrowed to one. What the plan's
   `invalid_target` needed was a `QueryConfig`/`FormConfig` error handler on
   `/oauth2/authorize` and `/oauth2/token` that answers **only** that case and
   delegates every other deserialization failure to `err.into()` — byte-identical
   to today's response, which is what keeps I1 (`/oauth2/par` already had a JSON
   error handler, so only one member of an existing shape changed). The string
   match on serde's message is pinned by a test and is not load-bearing: if it
   ever stops matching, the answer degrades to today's `400`, which is still a
   refusal.

   One consequence worth stating: at `/oauth2/authorize` a repeated `resource`
   is answered **directly**, not by redirecting. The extractor fails before the
   handler runs, so no client has been looked up and no `redirect_uri` has been
   validated — and RFC 6749 §4.1.2.1 forbids redirecting an error to a URI that
   has not been. A single unregistered `resource` *is* redirected, as the plan
   requires, because by then both have been.

3. **No contract version was taken.** §4.0 item 5 requires the `openapi.json`
   change to be recorded in the contract's version trailer; the task's
   constraints reserve 1.48 for T9a. The entry is therefore recorded
   **unnumbered** ("contract version pending, T21.3") with the full fan-out
   list, for T9a to fold into the version it publishes. Flagged on the PR.

### T4 — RFC 7591 dynamic client registration

#### T4a — Endpoint, policy, abuse controls — **Opus 5**

**What.**
1. Tenant policy in `OidcPolicy` (`crates/axiam-core/src/models/settings.rs`,
   beside `sensitive_scopes_enabled`), resolved through
   `get_effective_settings` like every other policy:
   - `dynamic_registration: disabled | initial_access_token | anonymous`
     (default `disabled` — I1);
   - `dcr_allowed_scopes: Vec<String>`;
   - `dcr_allowed_redirect_hosts: Vec<String>` (glob on host, plus the
     loopback hosts always allowed);
   - `external_client_allowed_resources: Vec<String>` (D3, shared with T5);
   - `dcr_max_clients: u32`, `dcr_unused_client_ttl_days: u32`.
   Enabling `anonymous` with an empty `external_client_allowed_resources` is
   refused by the settings handler with a message that names D3.
2. `POST /oauth2/register?tenant_id=` (RFC 7591 §3.1), in `PUBLIC_PATHS` and
   OpenAPI (I9), answering `403 invalid_request`-shaped JSON when the tenant's
   policy is `disabled`, so the path exists but the feature does not leak.
   `initial_access_token` mode requires a bearer minted by a new admin
   endpoint `POST /oauth2-clients/registration-tokens` (single-use, TTL).
3. Request validation: `redirect_uris` through the existing
   `validate_redirect_uris` (`handlers/oauth2_clients.rs:323`) plus the host
   glob; `grant_types ⊆ {authorization_code, refresh_token}`;
   `token_endpoint_auth_method ∈ {none, client_secret_basic,
   client_secret_post, private_key_jwt}` with the existing `jwks` / `jwks_uri`
   exclusivity from `fapi.rs:199`; `scope ⊆ dcr_allowed_scopes`;
   `software_statement` → `invalid_software_statement` (not supported, said
   plainly rather than ignored); profile forced to standard (I5, D5
   `managed_by: dcr`); `allowed_resources` forced to the tenant list (D3).
4. Response per §3.2.1: `client_id`, `client_secret` unless `none`,
   `client_id_issued_at`, `client_secret_expires_at: 0`, and the echoed
   metadata. RFC 7592 (`registration_access_token`, `registration_client_uri`)
   is **deferred**: neither MCP Inspector nor the two desktop clients need it.
5. Abuse controls: per-IP rate limit through the existing configuration;
   `dcr_max_clients` enforced per tenant; a background sweep (registered with
   the existing job runner behind `/health/jobs`) deletes `managed_by: dcr`
   clients with no authorization in `dcr_unused_client_ttl_days`; every
   registration is an audit event.
6. Discovery advertises `registration_endpoint` only when the described
   tenant's policy is not `disabled` (I7; the sensitive-scope members at
   `handlers/oauth2.rs:2543` is the pattern).
7. D4: the consent gate is forced for `managed_by != admin` clients.

**Docs.** `docs/admin/dynamic-client-registration.md`: the three modes, every
policy field with its default, the D3 warning, the MCP Inspector values from
Keycloak's guide translated to AXIAM settings, the sweeper.

**Acceptance.**
- Integration tests: disabled tenant → refused and not advertised; anonymous
  registration of an MCP-Inspector-shaped request succeeds and the client can
  complete a code + PKCE + `resource` flow; initial-access-token mode refuses
  without and accepts with; each validation negative; `dcr_max_clients`; rate
  limit; consent forced on first authorization; sweeper removes an unused
  client and leaves an `admin` one.
- `oauth2_client_test.rs` unchanged and green (admin creation path untouched).
- I1, I5, I7, I9.

#### T4b — Admin surfaces — **Sonnet 5**

**What.** Settings form fields for the T4a policy in the tenant settings page;
registration-token issuance in the OAuth2 clients page; a `managed_by` badge
and filter in the client list, read-only detail for `dcr` clients; audit
viewer recognises the new event. Frontend tests as for the existing settings
sections.

### T5 — OAuth Client ID Metadata Document — **Opus 5**

**What.** Implement `draft-ietf-oauth-client-id-metadata-document` (the
executing session pins the draft revision current at execution time in the
module header and in `docs/api/mcp.md`). Keycloak's validation list is the
reference behaviour: `https` only unless the tenant allows `http` for
development; a path component is required; no `.` / `..` segments, no
fragment, no userinfo, no query.

1. Tenant policy beside T4a's: `cimd.enabled` (default `false`, I1),
   `cimd.allow_http`, `cimd.trusted_client_id_domains` (glob),
   `cimd.trusted_redirect_domains`, `cimd.restrict_same_domain`,
   `cimd.confidential_only`, `cimd.min_cache_secs` (300),
   `cimd.max_cache_secs` (259200), `cimd.max_metadata_bytes` (5000). Enabling
   it with an empty `external_client_allowed_resources` is refused (D3).
2. Client resolution: in the authorize, PAR and token paths, when `client_id`
   parses as an absolute URL **and** the tenant's `cimd.enabled` is true, the
   CIMD resolver runs; in every other case the existing repository lookup runs
   untouched, so a URL-shaped `client_id` on a tenant without CIMD is exactly
   today's "unknown client".
3. Fetching: a `ClientMetadataCache` modelled on `JwksCache`
   (`crates/axiam-federation/src/jwks_cache.rs:112`) — same SEC-054 SSRF
   guard, same TTL and stale-while-revalidate discipline, clamped to the
   policy's cache bounds, size-capped, content-type checked, timeout-bounded.
   The `axiam-oauth2 → axiam-federation` edge already exists (I8).
4. Document validation: `client_id` inside the document equals the URL;
   `redirect_uris` are `https` or loopback and within
   `trusted_redirect_domains`; `token_endpoint_auth_method` is `none` or
   `private_key_jwt` with `jwks` / `jwks_uri` (a shared secret cannot exist);
   `confidential_only` refuses `none`; `restrict_same_domain` compares the
   `client_id` host with every redirect host (the T7 guidance for Claude Code
   and VS Code turns it off, as Keycloak's does, because both use loopback
   callbacks).
5. Materialisation: an upserted shadow row with `managed_by: cimd` (D5),
   keyed by the URL as `client_id`, refreshed from the document on every
   successful fetch; `allowed_resources` from the tenant list (D3); the
   consent gate forced (D4); the T2a loopback matcher applies.
6. Discovery: `client_id_metadata_document_supported: true` when the
   described tenant enables it (I7).

**Docs.** `docs/admin/client-id-metadata-documents.md`: the draft revision
implemented, every policy field, the URL validation list, and the VS Code and
Claude Code profiles with `restrict_same_domain` off and why.

**Acceptance.**
- `wiremock`-based tests (as `crates/axiam-federation/src/oidc.rs` already
  uses): happy path for a VS-Code-shaped and a Claude-Code-shaped document;
  every URL validation negative; SSRF negatives (private address, redirect to
  private address, non-https); oversize document; cache bounds honoured;
  document change picked up after TTL; tenant with `cimd.enabled = false`
  treats the URL as an unknown client (I1).
- Full code + PKCE + `resource` flow for a CIMD client with a loopback
  callback on a random port.
- I1, I5, I8.

### T6 — Per-tenant path-based issuers — **Opus 5**

**What.** An opt-in issuer form that an MCP server can name in its
protected-resource metadata and that a client can turn into a discovery URL by
the RFC 8414 §3 rule without any query string.

1. `AXIAM__AUTH__TENANT_ISSUER_PATHS=true` (default `false`, I1). When set,
   the issuer for tenant `T` is `{root}/t/{T}` and:
   - discovery is served at `/.well-known/oauth-authorization-server/t/{T}`
     and `/.well-known/openid-configuration/t/{T}` (RFC 8414 §3.1 path
     insertion) **and** at `/t/{T}/.well-known/openid-configuration` (OIDC
     Discovery §4 appends), all three returning a document whose `issuer` is
     the tenant issuer and whose endpoints are `{root}/t/{T}/oauth2/…` with
     **no** `tenant_id` query;
   - an Actix scope `/t/{tenant_id}` injects the tenant and delegates to the
     existing handlers, so no handler is duplicated;
   - the `iss` claim of tokens minted through the tenant path, the RFC 9207
     `iss` response parameter, the ID token `iss`, and the logout token `iss`
     all equal the tenant issuer;
   - AXIAM's own extractors accept the root issuer and any `{root}/t/{uuid}`
     issuer, and the JWKS is shared (one key set, many issuers — RFC 8414
     permits it; the document says so).
2. The boot assertion at `main.rs:2824` is narrowed: a root issuer is still
   required; the tenant path is derived, never configured.
3. With the flag off, nothing above is mounted and the existing `?tenant_id=`
   documents are byte-identical (T1's test is re-run in both modes).

**Docs.** The issuer section of `docs/deployment/` gains the flag, the three
discovery forms, the shared-JWKS statement, and what an MCP server puts in
`authorization_servers` in each mode.

**Acceptance.**
- `oidc_conformance.rs` and `oauth2_conformance.rs` run in both modes in CI
  (a second job with the flag set), green in both.
- New tests: the three discovery forms agree; `iss` consistency across
  access, ID and logout tokens; a token minted under `/t/{A}` is refused by a
  request scoped to tenant `B` (tenant isolation is not weakened by the path).
- I1, I3.

### T7 — Documentation, example, website — **Sonnet 5**

**What.**
- `docs/api/mcp.md`: fronting an MCP server with AXIAM — the RFC 9728
  document the MCP server publishes (`authorization_servers`,
  `scopes_supported`, `bearer_methods_supported`), the
  `WWW-Authenticate: Bearer resource_metadata="…"` challenge, the SDK
  middleware configuration (`expected audience` = the MCP server URL, the
  T9 `resource_metadata_url` option, DPoP or mTLS recommended), the tenant
  settings from T4a/T5 with the exact values Keycloak's guide gives for MCP
  Inspector, VS Code and Claude Code, and the D3 warning. One worked example
  per mode: pre-registered, DCR, CIMD. Links to the per-task pages below
  rather than repeating them.
- Per-task pages the earlier tasks drafted and T7 finishes:
  `docs/admin/public-clients.md` (T2), `docs/api/resource-indicators.md`
  (T3), `docs/admin/dynamic-client-registration.md` (T4),
  `docs/admin/client-id-metadata-documents.md` (T5), the issuer section in
  `docs/deployment/` (T6), and `docs/api/token-exchange.md#audience`
  rewritten for `allowed_resources` (T3 drafts it).
- `examples/b7-mcp-server/`: a runnable MCP server, TypeScript on the
  official `@modelcontextprotocol/sdk` streamable-HTTP transport, guarded by
  the AXIAM TypeScript SDK middleware from T9b, publishing its RFC 9728
  document with the T9 helper, fronted by a bootstrapped AXIAM. Ships with
  `walkthrough.sh` (Bash + curl, protocol-level, in the style of
  `examples/b1-deny-override`) driving 401 → discovery → DCR → PKCE +
  `resource` → token → tool call, a `smoke-test.sh` as `b5-rp-logout-app`
  has, and a README with the copy-paste configuration for MCP Inspector,
  Claude Code and VS Code. A row in `examples/README.md`.
- `sdks/CONTRACT.md` §10.1 row 6: the expected-audience sentence gains "or the
  resource URL an MCP server fronts, once minted through RFC 8707". The new
  §28 is T9a's, not T7's.
- `website/src/docs/oauth2.ts`: an "MCP servers" block linking to
  `docs/api/mcp.md`; `docSectionsAreComplete()` stays true.
- `claude_dev/roadmap.md`: Phase 21 marked with the commits.

**Acceptance.** `walkthrough.sh` and `smoke-test.sh` pass against
`docker/docker-compose.e2e.yml` with `scripts/e2e-bootstrap.sh`; every link
in `docs/api/mcp.md` resolves; the website build and its section-completeness
assertion pass.

### T8 — End-to-end MCP harness and security review — **Opus 5**

**What.**
1. `crates/axiam-api-rest/tests/mcp_authorization_test.rs` driving the exact
   client sequence from the MCP specification against a real server: a stub
   MCP server (wiremock) answering 401 with `resource_metadata`; discovery via
   `/.well-known/oauth-authorization-server`; registration (DCR in one case,
   CIMD in the other); authorize with PKCE, `resource` and a loopback callback
   on a random port; token; the stub validating `aud`; introspection; and the
   I3 refusal at an AXIAM endpoint. Run in both T6 modes.
2. A `/security-review` pass over the new surfaces, recorded as
   `claude_dev/security-review-mcp-<date>.md`: unauthenticated write endpoint
   (T4a), outbound fetch (T5), audience confusion (T3), open-redirect via the
   loopback matcher (T2a), tenant isolation under path issuers (T6). Findings
   fixed in the same session or filed as issues with the plan's task id.
3. `threat-model-stride.md` gains the new surfaces.

---

### T9 — SDK fan-out: the resource-server half of the handshake

The eleven SDKs live in their own repositories (`ilpanich/axiam-<lang>-sdk`)
and vendor `sdks/CONTRACT.md`, `sdks/openapi.json` and `proto/`. Their
middleware already verifies a configured audience; what an MCP server also
needs from its SDK is to **publish** the RFC 9728 document and to **emit** the
challenge that starts the MCP client's discovery. Same structure as
[`sdk-oidc-sso-plan.md`](sdk-oidc-sso-plan.md): one normative amendment, one
reference implementation, ten ports, one review.

#### T9a — CONTRACT §28 "MCP resource-server helpers" (contract 1.48) — **Opus 5**

**What.** A new §28 in `sdks/CONTRACT.md`, in the register of §12 and §20:
1. **Canonical operation set** (per-language naming map, as §12.2 does):
   - `protected_resource_metadata(resource, authorization_servers,
     scopes_supported, bearer_methods_supported = ["header"],
     resource_documentation?)` → the RFC 9728 §2 document, validated (every
     `authorization_servers` entry an issuer without query or fragment,
     `resource` equal to the URL the middleware is configured to expect);
   - `serve_protected_resource_metadata(...)` → a framework-idiomatic route
     at `/.well-known/oauth-protected-resource` and, for a resource with a
     path, the RFC 9728 §3.1 path-suffixed form;
   - `bearer_challenge(resource_metadata_url, error?, error_description?,
     scope?)` → the `WWW-Authenticate` value, RFC 6750 §3 quoting rules;
   - middleware option `resource_metadata_url`: when set, every 401 the
     middleware emits carries the challenge, and a route guarded by §11
     scope helpers that fails on scope emits 403 with
     `error="insufficient_scope"` and the `scope` it needed.
2. **Normative rules**: `expected_audience` MUST be set when
   `resource_metadata_url` is (a resource that announces itself must check
   `aud`); the document MUST be served without authentication; the challenge
   MUST NOT leak the failure reason beyond the RFC 6750 error codes; DPoP
   (§10.3) and the revocation posture (§10.2) apply unchanged.
3. **Required tests, per SDK** (as §8b §"Required tests" does): document
   shape and validation negatives; challenge quoting; 401 with challenge; 403
   `insufficient_scope`; a token whose `aud` is not the resource refused.
4. Version trailer bumped to **1.48** with the re-sync note for all eleven repos
   (T2a took 1.47 for the additive `openapi.json` change — the `none` enum value
   and `client_secret` becoming optional — so §28 is the next number);
   `sdks/openapi.json` regenerated from T1–T6.

#### T9b — TypeScript reference implementation — **Opus 5**

**What.** In `axiam-typescript-sdk`: the §28 operations on the Express and
Fastify middleware surfaces, tests per §28.3, README section, `CHANGELOG.md`
entry, vendored contract re-synced. This is the SDK `examples/b7-mcp-server`
(T7) depends on, so it lands before T7's example is written.

#### T9c — Ports — **Sonnet 5**, one session per repository, all in parallel

| Repo | Surface (from §10) |
| --- | --- |
| `axiam-rust-sdk` | Actix-Web extractor + a `web::resource` for the document |
| `axiam-python-sdk` | FastAPI dependency + router; Django middleware + view |
| `axiam-java-sdk` | Spring Boot filter + `@RestController` for the document |
| `axiam-kotlin-sdk` | Ktor plugin + route; Spring Boot reuses the Java port |
| `axiam-csharp-sdk` | ASP.NET Core middleware + minimal-API endpoint |
| `axiam-php-sdk` | Laravel middleware + route; Symfony subscriber + controller |
| `axiam-go-sdk` | `net/http` handler wrapper + `http.HandlerFunc` |
| `axiam-swift-sdk` | Vapor `AsyncMiddleware` + route |
| `axiam-c-sdk` | `axiam_protected_resource_metadata_json()` and `axiam_bearer_challenge()` returning owned strings; CivetWeb adapter documented |
| `axiam-cplusplus-sdk` | `AxiamGuard` gains the challenge; a `protectedResourceMetadata()` builder; Crow / Pistache adapters documented |

Each port: the §28 operations under the language's §28 naming row, the five
required tests, README section, `CHANGELOG.md` entry, vendored `CONTRACT.md`,
`openapi.json` and `proto/` re-synced from `axiam` after T9a merges. The
seven full-surface SDKs also expose `bearer_challenge` to their gRPC and
AMQP guards' error mapping where a transport-appropriate equivalent exists;
the four REST-surface SDKs (Kotlin, Swift, C, C++) implement REST only, per
`CLAUDE.md`.

#### T9d — Cross-SDK conformance review — **Opus 5**

**What.** Read all eleven implementations against §28 and against T9b; record
divergences in a conformance table appended to §28 (the §12 review's format);
fix or file each; re-run every SDK's §28 tests. The review is what makes the
eleven ports one product rather than eleven interpretations.

**Acceptance for T9 as a whole.** `examples/b7-mcp-server` runs on T9b; each
SDK repository has a green CI on its port; the conformance table has no open
row.

## 5. Regression gate — run before every push, in every task

The gate is the maintainer's condition made executable. Per the disk-hygiene
rules in `CLAUDE.md`, scope every cargo invocation and `cargo clean` between
sessions, and export the swagger placeholder first:

```bash
export SWAGGER_UI_DOWNLOAD_URL="file://$(scripts/make-swagger-ui-placeholder.sh)"
cargo fmt --all -- --check
cargo clippy -p axiam-core -p axiam-auth -p axiam-oauth2 -p axiam-api-rest --no-default-features -- -D warnings
cargo test -p axiam-oauth2 --lib
cargo test -p axiam-auth --lib
cargo test -p axiam-api-rest --no-default-features \
  --test oauth2_conformance --test oidc_conformance --test oauth2_flow_test \
  --test par_test --test device_flow_test --test token_exchange_test \
  --test external_token_exchange_test --test oauth2_client_test
python3 scripts/check-crate-layering.py
```

**Gate erratum, 2026-09-16 (orchestrator), found by T1.** The block above is
incomplete: it never regenerates the OpenAPI artifacts, although §4.0 item 2
requires it. `.github/workflows/sdk-openapi-drift.yml` builds `axiam-server`
with `--no-default-features` and `diff`s a fresh `--dump-openapi` export against
the committed `sdks/openapi.json`, so **any** task that touches
`crates/axiam-api-rest/src/openapi.rs` — T1 through T6 all do — pushes a red CI
with a green §5. T1 pushed exactly that. Every task that changes the OpenAPI
surface therefore appends to the gate:

```bash
apt-get install -y protobuf-compiler            # absent from the sandbox; see below
export SWAGGER_UI_DOWNLOAD_URL="file://$(scripts/make-swagger-ui-placeholder.sh)"
cargo build -p axiam-server --no-default-features
./target/debug/axiam-server --dump-openapi > sdks/openapi.json
python3 scripts/check-spec-digest.py            # the exporter already stamps the digest
python3 scripts/gen-management-registry.py      # re-derive; it pins the spec digest
python3 scripts/gen-management-registry.py --check
diff <(./target/debug/axiam-server --dump-openapi) sdks/openapi.json
```

Three things this block learned the hard way, each of which cost T1 a CI cycle:

- **`protoc` is not installed.** `axiam-server` depends on `axiam-api-grpc`,
  whose build script dies with `Could not find \`protoc\``, so the build above
  cannot complete as the sandbox ships. CI never notices because
  `sdk-openapi-drift.yml` installs `protobuf-compiler` first. Now recorded in
  `CLAUDE.md`'s build-hygiene section.
- **`sdks/management-registry.json` pins the spec digest.** Regenerating the
  spec leaves it stale and fails the **Architecture Invariants** job, which is a
  different job from the drift gate and reports a different message. Re-derive
  it in the same commit. For a route that is not a management operation the only
  change is the digest pointer, and `operation_count` must not move.
- **`docs/api/openapi.json` is a symlink** to `sdks/openapi.json`. There is one
  file, not two; §4.0 item 2 and T1's "Where" line both read as if there were.

The `--no-default-features` is load-bearing: the drift workflow builds with SAML
off on purpose, so an export carrying SAML paths will not match whatever the
local toolchain can build.

**Second gate erratum, 2026-09-16 (orchestrator), also found by T1.** The gate
never compiles `axiam-api-rest`'s own unit tests. Its `cargo test` lines cover
`-p axiam-oauth2 --lib`, `-p axiam-auth --lib` and `-p axiam-api-rest --test
<named>` — the integration binaries — but never `-p axiam-api-rest --lib`, and
`cargo clippy` without `--all-targets` does not build `#[cfg(test)]` code
either. §4.0 item 1 asks for "unit tests in the crate that owns the logic", so
the gate is silent on precisely the tests it asks for. T1's two new unit tests
in `crates/axiam-api-rest/src/openapi.rs` did not compile at all
(`assert_eq!` on `utoipa::openapi::PathItem`, which implements neither `Debug`
nor `PartialEq`); §5 was green and the Coverage job, which builds
`--workspace --tests`, failed on the first push. Add to the gate:

```bash
cargo test -p axiam-api-rest --lib --no-default-features
cargo clippy -p axiam-api-rest --all-targets --no-default-features -- -D warnings
```

Note also that the Coverage workflow builds with **default features on**
(`--cfg feature="saml"`), while §5 builds `--no-default-features` throughout. A
task whose code is feature-gated must satisfy both; the gate as written proves
only one.

Plus, per task, the tests the task adds, and for T2b / T4b the frontend suite.
The end-of-phase gate (after T8) is the full `just check` and the FAPI
conformance runbook, which must report the same result as the 2026-09-15 sweep
(`fa15769`).

A task whose gate is red does not push. A task that needs to change an
existing test's expectation has found either a bug in this plan or a violation
of §1, and stops to say which.

---

## 6. Order and waves

Dependencies: T2a before T3 (public clients exercise the `resource` path);
T3 before T4a and T5 (D3 needs `allowed_resources`); T4a before T5 (shared
policy and `managed_by`); T6 independent of T4/T5 but after T3 (issuer in
`aud`-bearing tokens); T9a after T3 (the contract names the audience rule);
T9b after T9a; T7's example after T9b; T9c after T9a, in parallel with T7;
T8 and T9d last.

| Wave | Tasks | Parallel? |
| --- | --- | --- |
| 1 | T1, T2a | yes — disjoint files |
| 2 | T2b, T3 | yes |
| 3 | T4a, T6 | yes — T6 touches server/handlers, T4a touches settings/registration |
| 4 | T4b, T5, T9b | yes — T9b is in another repository |
| 5 | T7, T9c (ten sessions) | yes — the ports need only T9a and T9b |
| 6 | T8, T9d | T8 starts once T7's example exists, so the harness follows the documented flow; T9d once every port's CI is green |

**Execution amendment, 2026-09-16 (orchestrator).** Two things the wave table
above does not say, recorded here before any task starts:

- **T9a is missing from the table.** §6's dependency list places it ("T9a after
  T3; T9b after T9a") but no wave carries it, and T9b sits in wave 4. T9a is
  therefore executed in **wave 3**, beside T4a and T6, which is the earliest
  wave its stated dependency allows and the latest that leaves T9b where the
  table puts it. Nothing else moves.
- **Where each task branches from.** The plan says "a fresh branch" without
  saying from what, and the waves are dependent, so the branches stack: T1 and
  T2a from `main`; T2b and T3 from `claude/t21-2a-public-clients`; T4a, T6 and
  T9a from `claude/t21-3-resource-indicators`; T4b and T5 from
  `claude/t21-4a-dynamic-registration`. Each PR's base is the branch its task
  was cut from, so each PR shows only its own task's diff and no PR is closed
  by another's landing. T7 needs the union of T4b, T5, T6 and T9a, which no
  single task branch carries, so the orchestrator joins those lines on
  `claude/phase-21-mcp-auth-8te9sx` and T7 is cut from — and targets — that
  branch; T8 stacks on T7. Nothing is merged through GitHub at any point.

Each wave ends with `cargo clean`. Each task ends with a signed commit on its
own branch and a PR referencing this plan and the roadmap task id (Phase 21);
SDK tasks open their PR in the SDK repository and reference the contract
version they implement.

---

## 7. What is explicitly out of scope

- **RFC 7592** client configuration endpoint (deferred from T4a; add when a
  client that needs it appears).
- **Multiple `resource` values** per request (D1).
- **RFC 9728 on AXIAM's own APIs** — AXIAM publishing protected-resource
  metadata for itself is a separate, small task once T6 defines the issuer
  forms; it is not needed for MCP.
- **Tenant slugs** in the T6 path (`/t/{slug}` instead of `/t/{uuid}`); the
  UUID form is enough for discovery and avoids a new uniqueness constraint.
- **Step-up via `WWW-Authenticate` `scope` / `insufficient_scope`** on the MCP
  server side — resource-server behaviour, documented in T7 as the SDK
  middleware's existing 403 shape, not implemented here.
- **MCP *client* helpers in the SDKs** (discovering an authorization server
  from a 401, running DCR or CIMD from the client side). The SDKs guard MCP
  servers; MCP clients are Claude Code, VS Code, MCP Inspector and their
  peers, which already implement the client side.

---

## 8. The kick-off prompt for the executing session

Start a new session on `ilpanich/axiam`, on a fresh feature branch, and paste
this as the first message. The session orchestrates the waves of §6 in this
repository and starts one child session per SDK repository for T9b and T9c.

```text
Read CLAUDE.md and boot per its instructions before anything else.

You are executing claude_dev/mcp-authorization-server-plan.md — Phase 21 of
claude_dev/roadmap.md. Read the plan in full, then its companion documents
(token-exchange-design.md, crate-layering.md, threat-model-stride.md), before
writing a single file. The plan is the specification: its §1 invariants are
non-negotiable; its §3 decisions hold unless you find on evidence that an
assumption behind one is false, in which case record the evidence and the
revised reasoning in the plan before acting; its §4.0 definition of done
applies to every task (tests, docs, the example, the SDK fan-out record); its
§5 regression gate runs before every push.

Work the six waves of §6 in order. One task is one session: for each task in
a wave, start a child session on this repository with the model the plan's
§2 table assigns (Opus 5 or Sonnet 5, never another), a fresh branch named
claude/t21-<n>-<slug>, and a prompt that names the task, quotes its "What",
"Where" and "Acceptance" blocks verbatim, and repeats §1, §4.0 and §5. For
T9b and T9c, start the child session on the SDK repository instead
(ilpanich/axiam-<lang>-sdk), with the CONTRACT §28 text and the T9b reference
as its brief. Run the tasks of a wave in parallel, wait for all of them, run
cargo clean, then start the next wave.

Every task pushes only when its gate is green, opens a PR that references this
plan and its T21.x id, and subscribes to that PR; drive each PR to green and
address review comments. Never merge. When a task cannot be completed under
§1 without changing an existing test's expectation, stop that task and report
which invariant conflicts, with the file and line — do not relax the test.

Constraints: no push to main; no change to FAPI behaviour or the conformance
runbook; no secrets or real identifiers in the tree; every new unauthenticated
route in PUBLIC_PATHS and OpenAPI in the same commit; follow the disk-hygiene
rules in CLAUDE.md (scoped cargo commands, cargo clean between waves, the
swagger placeholder export). Write in the voice of the existing
docs/api/*.md and claude_dev/*.md.

When wave 6 is done, update the plan's status header to EXECUTED with the
commit of each task, mark Phase 21 in the roadmap, and report: the PR list,
the security-review findings and their state, the SDK conformance table, and
anything the plan got wrong.
```

For a single SDK port started by hand rather than by the orchestrator, the
child prompt is the same text with the first two paragraphs replaced by:

```text
Read CLAUDE.md. You are executing T9c of
ilpanich/axiam:claude_dev/mcp-authorization-server-plan.md for this
repository. Read sdks/CONTRACT.md §28 from the axiam main branch and the
TypeScript reference implementation (T9b) before writing code; re-sync the
vendored CONTRACT.md, openapi.json and proto/ first, then implement the §28
operations under this language's naming row, the five required tests, the
README section and the CHANGELOG entry. Model: Sonnet 5.
```

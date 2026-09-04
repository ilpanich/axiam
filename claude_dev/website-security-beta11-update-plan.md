# Website — the 1.0.0-beta11 security and docs catch-up pass

> **Who this is for.** A fresh Claude session (Opus 5) tasked with bringing the
> website's **Security** section, and the **Docs**, **News** and **Roadmap**
> content the same releases touched, up to `1.0.0-beta11`. It is the entry point:
> read this, then work the waves in §8. When the pass is done, add an
> **EXECUTED** blockquote at the top of this file in the style of
> [`website-docs-beta06-improvement-plan.md`](website-docs-beta06-improvement-plan.md),
> recording what landed, what was deliberately left, and the stamps.
>
> **The headline.** The threat model moved and the website did not. The Threat
> Dragon model is at **2.11.0 — 236 threats, 219 mitigated / 17 open**; the
> generated files under `website/src/` still render **211 / 196 / 15**, the
> Security prose is at `1.0.0-beta06`, and `SECURITY_VERIFIED_RELEASE` says so.
> Two of the three waves that moved the model were *already written into the
> STRIDE document at beta08* without ever reaching the JSON, which is why the
> site has been behind its own source for three releases. This pass closes that
> gap and carries the beta09…beta11 changes with it.

**Sources of truth, in order.** [`threat-modeling-and-security.md`](threat-modeling-and-security.md)
(the website section's source, current as of 2026-09-04 — its handoff block
records what this wave changed and why), [`threat-model-stride.md`](threat-model-stride.md)
(the STRIDE model, mirroring the JSON), `ThreatDragonModels/Axiam/Axiam.json`
(the model the generator reads), and for the Docs pages the design and admin
documents named per item in §6. The website is the readable front door; it links
out for anything binding and **never carries a claim these documents do not**.

---

## 1. What moved between beta07 and beta11

| Release | Security-relevant change | Threats |
|---|---|---|
| beta08 | Backend exposed at `/api` on the public origin, terminating its own TLS 1.3; hot-reloaded leaf (`SIGHUP` + hourly poll); `TRUSTED_HOPS` = proxies − 1; health endpoints not routed at the edge; `X-Client-Certificate` trusted only with `AXIAM__AUTH__TRUST_FORWARDED_CLIENT_CERT=true` (default off); Raft-backed Vault with a scoped token; the cleartext nginx → server hop removed | T-212…T-217 (T-216 open) |
| beta08 | Public login-provider surface: unauthenticated providers listing, "Sign in with X" buttons, plain-OAuth2 variant (GitHub, Facebook), 60-second single-use handoff codes confined to the deployment's SPA origin (`AXIAM__AUTH__SSO_SPA_ORIGINS`), Entra templated issuer with `allowed_issuer_tenants`, organization→tenant inheritance, raster-only icons; contract 1.37 and 1.38 | T-218…T-225 (renumbered from T-163…T-170 — see §2) |
| beta09 | An assignment naming no resource is tenant-wide, not inert (upgrade note); scoped grants inherit down the resource lineage without widening sideways; the authorization-check endpoints resolve the acting tenant through the shared reach check; effective-access preview lists the tenant's own permissions | T-226…T-228 |
| beta09 | `webauthn_user_verification` security setting (org baseline, tenant tighten-only, default `preferred`; usernameless and attested ceremonies keep `required`; enrolled credentials keep their policy); schema v53; OpenAPI regenerated | T-229, T-230 |
| beta10 | Vault policy as one file (`docker/vault/axiam-policy.hcl`: read on the startup path, `create`/`update` on `ca-keys/*`); `just vault-policy`; `just vault-status` reports missing capabilities; a 403 prints the missing HCL | T-232 (amends T-180, T-216) |
| beta11 | Vault seeder waits for an active node, treats only 200/404 as answers, pins writes with `cas`, refuses to replace a stored secret; seeder tests in CI; `prod-up` waits for health | T-231 |
| beta11 | gRPC may be published — only through the edge, path-matched, as a service allowlist; `AXIAM__GRPC_TLS_*`; `STRICT_REVOCATION`; the tonic listener has no certificate reload (restart in the deploy hook) | T-233, T-234 (open) |
| beta11 | `mass-tag.sh` regenerates each SDK's §27 surface after re-vendoring the spec | T-235 |
| beta11 | npm-audit outage handling; `-D advisory-not-detected`; audit-only declarations; Docker build-context gate | T-236 |

Nine existing entries gained cross-referencing clauses: T-43, T-127, T-180,
T-193, T-199, T-201, T-212, T-214, T-216. The open register loses T-118 (closed
at beta03; the overview's copy of the table had never been refreshed) and gains
T-216 and T-234. AXIAM's own request path still carries **no open Critical or
High** finding — keep that sentence, it is still true.

## 2. Ground rules (unchanged; they are why the pass has value)

- **Do not upgrade the hedges.** "No open Critical or High finding *in AXIAM's
  own request path*", "self-assessment, not a certified audit", and the beta
  caution are load-bearing. T-234 is open, Medium, on the deployment diagram; it
  does not touch that sentence.
- **Do not add claims.** Every sentence in `threat-modeling-and-security.md` is
  backed by code or a design document this pass verified. Copy its prose; do not
  improve it. A plausible extra bullet is the one thing on the page that would not
  be backed.
- **Keep the shared-responsibility section**, and keep the open register
  generated. The four new platform bullets there (auto-unseal, `TRUSTED_HOPS`,
  header stripping, gRPC through the edge) are deployment responsibilities, not
  product claims.
- **Mirror, do not paraphrase.** `src/security.ts` mirrors the Markdown section
  for section; the three bullets whose bold markers deliberately differ (the
  `redirect_uri` bullet, the mounted-Secret-files clause, the SurrealDB
  storage-engine bullet) stay as they are, for the reason recorded in the
  handoff block: the inline renderer splits on backticks before it handles `**`.
- **The renumbering is not yours to undo.** The login-provider threats were first
  published (in the STRIDE document only) as T-163…T-170 and collided with
  numbers the model already held (§5.3's single-use credentials, §5.9's `cnf`
  threats, §5.8's storage-engine threat). They are T-218…T-225 now, in the JSON,
  the STRIDE document and the four code comments that cite them. Nothing on the
  website ever pointed at the old numbers, so no redirect or alias is needed.
- **Stamps record verification, not releases.** `SECURITY_VERIFIED_RELEASE`
  moves only with the Security section; `DOCS_VERIFIED_RELEASE` is one constant
  stamped on 30 pages, so bumping it re-asserts every one of them — §7 says what
  that costs.

## 3. Current state (verified 2026-09-04, at beta11)

| What | Where | State |
|---|---|---|
| Security stamp | `website/src/version.ts` | `SECURITY_VERIFIED_RELEASE = "1.0.0-beta06"`, `SECURITY_VERIFIED_DATE = "2026-08-30"` |
| Docs stamp | `website/src/version.ts` | `DOCS_VERIFIED_RELEASE = "1.0.0-beta07"` |
| Generated model | `website/src/threatModel.ts`, `threatModelSummary.ts` | 211 threats / 196 / 15, model 2.10.0 — `npm run gen:threat-model` was run against 2.11.0 in this pass to confirm it parses and yields `9 diagrams, 236 threats (219 mitigated, 17 open)`, then **reverted** so the generated files and the prose move together |
| Security prose | `website/src/security.ts` | At beta06: nothing on the login-provider surface, the public backend, the authorization-reach fixes, the WebAuthn policy, the Vault seeder/policy, or gRPC at the edge |
| Contract anchors | `website/src/contractAnchors.ts` | `CONTRACT_VERSION = "1.38"` — already current (updated with the handoff-origin rule); expect `gen:contract-anchors` to be a no-op |
| API index | `website/src/apiIndex.ts` | Behind `sdks/openapi.json`, which gained `WebauthnPolicy` and `webauthn_user_verification` on the settings schemas at beta09 (`8ae510d`) |
| News | `website/src/data.ts` — post `beta-phase` ("AXIAM reaches beta") | Says "grew to 211 threats … 196 mitigated and 15 recorded openly" |
| Roadmap | `website/src/data.ts` — phase 20 "Beta line — stabilisation toward 1.0" | `focus` names E2E hardening, SDK fan-out and federation/SAML/OIDC/SCIM testing; nothing about beta08…beta11 |
| Docs pages already touched since beta07 | `configuration.ts` (`AXIAM__AUTH__SSO_SPA_ORIGINS`, `TRUSTED_HOPS`), `operate.ts` (`TRUSTED_HOPS`; the Vault policy and seeder steps on `secrets`, updated at beta10 and beta11) | Ahead of their stamp — verify rather than rewrite |

The explorer (`src/components/ThreatModelExplorer.tsx`) needs no functional
change. Two cosmetic notes: its comment still says "over 186 threats", and two
mitigations now carry paragraph breaks (`\n\n` in T-219 and T-220, ported from
the STRIDE document's multi-paragraph blocks) which the current renderer will
collapse into one paragraph. `white-space: pre-line` on the mitigation node is
the one-line fix if it reads badly; it is optional.

## 4. Wave 0 — regenerate

Run from `website/`, in this order, and commit the generated files together with
the prose that describes them (Wave 1), never alone:

```sh
npm run gen:threat-model     # expect: threatModel.ts: 9 diagrams, 236 threats (219 mitigated, 17 open)
npm run gen:api-index        # expect: the two settings request schemas and SecuritySettings gain the WebAuthn policy field
npm run gen:contract-anchors # expect: no diff (1.38)
```

Read the `threatModel.ts` diff once: the federation diagram gains three
processes (`Public providers listing`, `OAuth2 RP (userinfo variant)`,
`Federation config inheritance`) and five flows including `SSO handoff code`;
the deployment diagram gains the `IoT device / service account` actor and its
flow, and the `proxied requests` flow is now `proxy → axiam-server` (TLS 1.3).
The generator lays these out from the model's coordinates; if a new node
overlaps a label, adjust the coordinates in the JSON and regenerate — never edit
`threatModel.ts` by hand.

`GET /health/jobs` is still absent from `sdks/openapi.json` (a server-side
omission recorded in the beta06 plan); it is not this pass's problem.

## 5. Wave 1 — the Security section

Mirror `threat-modeling-and-security.md` into `src/security.ts`, section by
section. The table below is the checklist; the Markdown is the text.

| `security.ts` section | Change |
|---|---|
| Security at a glance | "STRIDE threat model of **236** threats" |
| The threat model | Table: 236 threats, 219 / 17. The coverage tables are generated — confirm the page renders 236 / 17 from `threatModelSummary.ts`, and that the "Coverage by area" rows match §Appendix A |
| Trust boundaries | The **Public Internet ↔ AXIAM** row's third column gains the "terminated by the server itself", "keyed on a peer address derived by a stated rule" and "forwarded headers trusted only from a proxy the deployment runs" clauses |
| Authentication & sessions | New bullet: **User verification on a WebAuthn ceremony is a policy, not a library constant** |
| Authorization & tenant isolation | Two new bullets: **What a grant reaches is what the model says it reaches**; **One acting-tenant resolution, for every extractor** |
| Federation (SAML & OIDC) | Three new bullets: **The public login surface is designed for the fact that it is public**; **Cross-site returns get a session through a handoff code that can only be delivered home**; **The plain-OAuth2 variant states its downgrade instead of hiding it** |
| Transport, secrets & the SDKs | Two new bullets after the TLS 1.3 bullet: **The backend can sit on the public origin, terminating its own TLS**; **Vault is run as the production secret store it is**. One new bullet at the end: **A release ships the surface it derives from the spec it vendors** |
| Compliance posture | The dependency-gating paragraph gains the "tells a registry outage apart from a clean audit and fails on a suppression that no longer matches anything" clause |
| Shared responsibility | "17 of 236". The register is generated — confirm T-118 is gone and T-216 and T-234 appear. The **Run Vault in production mode** bullet's "read-only token scoped to that path" becomes the policy-file sentence. Four new platform bullets before **Run SurrealDB on a persistent storage engine**: auto-unseal; deriving `TRUSTED_HOPS`; stripping `X-Forwarded-For` / `X-Client-Certificate`; gRPC only through the edge |
| How security is maintained | Closing sentence: last re-derived at **`1.0.0-beta11`** on 2026-09-04, and the reworded sentence about the website's own stamp |

Then `src/version.ts`: `SECURITY_VERIFIED_RELEASE = "1.0.0-beta11"`,
`SECURITY_VERIFIED_DATE = "2026-09-04"`. That constant is what the page quotes;
it moves in the same commit as the prose, never earlier.

## 6. Wave 2 — Docs pages the same releases changed

Each row names the page by slug, the claim to make, and the document the claim
comes from. Read the source before writing; the wording on the page should be
recognisably that document's, shortened.

| Page (slug) | What to add or correct | Source |
|---|---|---|
| `rbac` | **Assignment reach.** An assignment that names no resource is tenant-wide; `is_global` is a property of the *role* and still applies when the assignment does name a resource — two independent ways to say "everywhere". Tenant-wide, not organization-wide. **Scopes inherit down the hierarchy**: a grant on a scope constrains the resource that scope lives on and is inherited whole beneath it; denies inherit by the same rule; a grant never widens sideways (`billing` does not reach `payroll`) or to a scope on an unrelated resource; name resolution is nearest-first. The existing "an empty list means all scopes" sentence stays. Add the **upgrade note**: assignments that were inert become live tenant-wide grants; link `docs/admin/README.md` § *Assigning roles* for how to find them first | `docs/admin/README.md` §*Defining roles and permissions* → *Scopes inherit down the resource hierarchy*, §*Assigning roles*; commits `cf65372`, `ccd8fb6`; T-226, T-227 |
| `organization-scope` | The evaluation-rule table's first row, "Global (`is_global`, no resource)", conflates the two. Split it: "Role is `is_global`" and "Assignment names no resource (tenant-wide)", each with where it lives and what it reaches — an unscoped assignment in the organization scope reaches the organization scope only, not member tenants. Add one sentence on the authorization-check endpoints resolving the acting tenant through the same reach check as every other route | T-226, T-228; `dc36213` |
| `authz` | The effective-access preview (if the page mentions the admin UI's preview) lists the tenant's own permissions rather than a fixed vocabulary | `cf65372` |
| `passkeys` | The *Enrolling a passkey* step says the server chooses `userVerification`. It now chooses it **from policy**: `webauthn_user_verification`, organization baseline, tenant may only tighten, `required` > `preferred` > `discouraged`, default `preferred`; a PIN-less key enrols as a second factor and the server records whether verification happened; usernameless sign-in and attested registration keep `required`; a credential keeps the policy it was enrolled under. Link `docs/admin/authenticator-policies.md` | `docs/admin/authenticator-policies.md`; `0a2ca17`; T-229, T-230 |
| `settings` | Add `webauthn_user_verification` to the security-settings rows (organization baseline, tenant tighten-only, alongside the OPAQUE and privacy settings), and the note that the organization settings `PUT` replaces the whole row so the field is required | same |
| `federation` | A new section, **Sign-in buttons and the public login surface**: the unauthenticated providers listing (`200 []` for unknown and unconfigured alike — an organization-slug oracle is deliberately not offered); the `oauth2` protocol for providers that issue no ID token, its stated downgrade, the provider kinds it is refused for, mandatory server-side PKCE, endpoints only from configuration, verified email only; handoff codes for the cross-site returns (SAML, Apple) — 60 s, single use, hash-only, confined to the deployment's own origin plus `AXIAM__AUTH__SSO_SPA_ORIGINS`; organization→tenant inheritance (user provisioned in the *requesting* tenant; a tenant's own config of the same kind shadows the inherited one, including a disabled one); templated issuers require `allowed_issuer_tenants`; custom icons raster-only, 16 KiB. Endpoints: the four contract §12.1 operations. Link `docs/` and contract §12.1 rather than restating rules | `claude_dev/federation-sso-login-design.md`; `sdks/CONTRACT.md` §12.1 (1.37, 1.38); T-218…T-225 |
| `secrets` | Verify the beta10/beta11 wording already on the page against T-231 and T-232 (policy file, seeder refusing to write on a refused read). Add: `just vault-policy` applies the policy to a running deployment without restart or re-seed; `just vault-status` reports **missing** capabilities as well as excess ones; KV v2 keeps ten versions and `docs/deployment/vault.md` §8.1 restores a replaced key without password resets; both Vault deployments use Raft, and the prod Compose stack chowns the Raft volume in a one-shot init container rather than running Vault as root | `docs/deployment/vault.md` §4, §5.3–5.4, §8.1; `84d8b44`, `51e81f6`, `01297e6` |
| `deploy`, `hardening` | **The public-backend topology** (check what `7ba2fa1` already put here before adding): edge routes by path, server terminates TLS 1.3, leaf hot-reloaded on `SIGHUP` and hourly (`AXIAM__SERVER__TLS__RELOAD_INTERVAL_SECS`), health endpoints not routed at the edge, `TRUSTED_HOPS` = proxies − 1 with the per-topology table, `X-Client-Certificate` off by default and stripped at the edge, auto-unseal as the one step AXIAM cannot take. **gRPC**: "Keep 50051 off the Ingress" (`hardening`) becomes *loopback by default; publish only through the edge on 443, path-matched, as an allowlist of services — never a port-forward*, with why (a client would key its own rate-limit bucket), `AXIAM__GRPC__STRICT_REVOCATION=true` for a public listener, and the deploy-hook restart because the tonic listener has no certificate reload (T-234, open) | `claude_dev/public-backend-tls-design.md` §1–§8, §13; `claude_dev/rpi5-prod-google-federation-guide.md` §14; `docs/deployment/README.md`; T-212…T-217, T-233, T-234 |
| `troubleshooting` | "Its port is published on loopback only" (gRPC) gains "unless you publish it through the edge — see Hardening"; add the two Vault signatures from `docs/deployment/vault.md` §8 (`AES-GCM decrypt: aead::Error` after a `prod-up` = the seeder rotated a key, restore per §8.1; Raft `permission denied` on `/vault/data`) | `docs/deployment/vault.md` §8 |
| `configuration` | Environment rows to add or verify: `AXIAM__AUTH__TRUST_FORWARDED_CLIENT_CERT` (default `false`); `AXIAM__SERVER__TLS__RELOAD_INTERVAL_SECS`; `AXIAM__GRPC_TLS_CERT_PATH` / `AXIAM__GRPC_TLS_KEY_PATH` (**flat** names read with `std::env::var`; the nested spelling is silently ignored and yields a plaintext listener — say so); `AXIAM__GRPC__STRICT_REVOCATION`; `AXIAM__AUTH__SSO_SPA_ORIGINS` (present — verify); `AXIAM__RATE_LIMIT__TRUSTED_HOPS` (present — verify it says proxies − 1). The gRPC bind-address row keeps "set `0.0.0.0` to serve in-cluster" and adds "never port-forward it to the internet" | `crates/axiam-server/src/tls.rs`, `crates/axiam-api-grpc/src/server.rs`, `crates/axiam-api-rest/src/extractors/rate_limit.rs` |
| `grpc` | One short subsection, *Publishing gRPC outside the mesh*, pointing at `hardening` for the edge-only rule and the allowlist; the grpcurl example is unaffected | design §13 |
| `sdks` | One sentence under the release or conformance notes: tagging an SDK regenerates its §27 management surface from the re-vendored spec, and a missing generator stops the release | `scripts/mass-tag.sh`; T-235 |
| `compliance` | No matrix changed. If the page repeats the CI-gating sentence, add the outage/stale-suppression clause from the overview | T-236 |

Pages **not** to touch for this pass: `opaque`, `mfa`, `service-accounts`, the
OAuth2 group, `scim`, `webhooks`, `reactors`, `errors`, `pki`, `audit`,
`observability`, `getting-started` (its quickstart still bootstraps the same
way). Re-read them in Wave 4; do not rewrite them in Wave 2.

## 7. Wave 3 — News and Roadmap

- **News.** Do not rewrite "AXIAM reaches beta". Give it a dated addendum
  (2026-09-04) in the style the `seven-sdks` post already has: the model is now
  236 threats, 219 mitigated / 17 open; the four releases since — the backend on
  the public origin with its own TLS, sign-in buttons and the public login
  surface, the authorization-reach fixes, a WebAuthn user-verification policy,
  and Vault run as a production secret store — each in one sentence, with the
  threat identifiers as links into `#/security/diagram/…`. The existing "grew to
  211 threats" sentence stays as written; it was true when it was written.
- **Roadmap.** Phase 20 stays `ongoing`. Extend its `focus` (or add a short
  milestone line if the data model has one) with the beta08…beta11 headline:
  public-origin deployment, login providers, authorization-reach fixes, Vault
  hardening. Do not close anything and do not add a phase.

## 8. Wave 4 — sweep and stamp

`DOCS_VERIFIED_RELEASE` is stamped on 30 pages through one constant, so bumping
it to `1.0.0-beta11` asserts that every one of them was re-read against beta11.
Either do that — most pages are a five-minute read, and the beta06 pass found
four real errors this way — or leave the constant at beta07 and say so in the
EXECUTED note. Do not bump it because Wave 2 touched some pages.

Claims most likely to have gone stale, to check first on every page that carries
them: "gRPC is never public / loopback only"; "read-only Vault token"; "the
server chooses `userVerification`"; any statement that an unscoped assignment
"grants nothing" or that scopes do not inherit; any count of threats, mitigated
or open; the environment-variable tables.

## 9. Verification

```sh
cd website
npm ci
npm run gen:threat-model && npm run gen:api-index && npm run gen:contract-anchors
git diff --stat                      # only the files this plan names
npm run build                        # tsc -b && vite build
npm run lint                         # oxlint
grep -rn "211 threats\|196 mitigated\|15 open\|beta06" src/ | grep -v threatModel.ts   # expect only the historical news sentence
cd .. && scripts/check-doc-links.sh  # the two archived-phase links in gdpr-compliance.md are known and not yours
```

`docSectionsAreComplete()` in `website/src/docs/index.ts` asserts navigation and
content agree; the build runs it. The threat-model explorer's URL anchors
(`#/security/diagram/3/T-219`) are how the news addendum links a threat — open
two of them in the built site.

## 10. Out of scope

- The gRPC certificate reload (T-234, open) and the TLS-1.3-only gRPC leg: a
  server change (`tokio-rustls` accept loop with `ReloadableCertResolver`), with
  its own tests. The website records it as open; it does not fix it.
- `GET /health/jobs` missing from `sdks/openapi.json`: server-side.
- Running the eight SDK repositories' §27 drift-checks on tag pushes (T-235's
  residual): SDK-repository CI.
- Threat Dragon diagram aesthetics beyond what the generator lays out from the
  model's coordinates.

---

## Appendix A — the numbers (model 2.11.0, 2026-09-04)

Headline: **236 threats, 219 mitigated / 17 open**, 9 diagrams, `threatTop` 236.

| Area | Threats | Open |
|---|---|---|
| System context | 29 | 2 |
| Authentication & session management | 32 | 1 |
| OAuth2 / OIDC authorization server | 24 | 0 |
| Federation (SAML SP & OIDC RP) | 31 | 1 |
| Authorization engine (RBAC, hierarchy, scopes) | 26 | 0 |
| PKI, certificates & IoT device identity | 24 | 1 |
| Audit, webhooks, email & notifications | 18 | 2 |
| Deployment & platform (Kubernetes) | 26 | 6 |
| Client SDKs & admin-UI integration surface | 26 | 4 |

By STRIDE category: Spoofing 58, Tampering 49, Repudiation 5, Information
disclosure 57, Denial of service 22, Elevation of privilege 45. By severity:
Critical 28 (1 open), High 113 (8), Medium 88 (7), Low 7 (1). The open items are
T-148, T-18, T-94, T-124, T-133, T-135, T-146, T-216, T-180, T-9, T-39, T-110,
T-123, T-134, T-143, T-161, T-234. Every one of these numbers is emitted by the
generator; they are here so a wrong regeneration is noticed, not so they can be
typed in.

## Appendix B — the prompt for the session that executes this plan

> Read `claude_dev/website-security-beta11-update-plan.md` in the `ilpanich/axiam`
> repository and execute it, waves 0 to 4 in order, on a feature branch. The
> sources of truth are `claude_dev/threat-modeling-and-security.md` (mirror it
> into `website/src/security.ts` section by section), `claude_dev/threat-model-stride.md`
> and `ThreatDragonModels/Axiam/Axiam.json` (regenerate, never hand-edit the
> generated files), and the design and admin documents the plan names per Docs
> page. Do not add claims the source documents do not make, do not weaken the
> hedges the plan lists, keep the open risk register generated, and move
> `SECURITY_VERIFIED_RELEASE` to `1.0.0-beta11` only in the same commit as the
> Security prose. Bump `DOCS_VERIFIED_RELEASE` only if you re-read every stamped
> page. Verify with the commands in §9, then add the EXECUTED blockquote at the
> top of the plan recording what landed and what was left, and open a PR that
> references this plan.

# Which OpenID certification should AXIAM achieve first?

**Status:** decision document, 2026-09-06.
**Question asked:** given that AXIAM's purpose is IAM for microservices and IoT,
and given that FAPI 2.0 work is already in the tree, which OpenID Foundation
certification is the right *first* one — and is FAPI 2.0 too ambitious a
starting point?

**Answer, in one line:** keep FAPI 2.0. It is not the ambitious choice here; by
the only measure that decides cost — *distance from the code that exists to a
passing test plan* — it is the **nearest** certification AXIAM can reach, and
the nominally entry-level OpenID Connect **Basic OP** profile is **further
away**, not closer.

That conclusion is counter-intuitive enough that the rest of this document is
mostly the evidence for it.

---

## 1. The premise, and why it inverts

The intuition behind "FAPI 2.0 is maybe too much to start with" is a reasonable
one and it is usually correct: FAPI 2.0 is a *hardening* profile layered on top
of OAuth 2.0, it is aimed at open-banking-grade deployments, and it mandates
mechanisms (PAR, sender-constrained tokens, strong client authentication) that
an ordinary OpenID Provider does not need. For a greenfield server, "get Basic
OP first, then climb" is the right order.

AXIAM is not greenfield with respect to this question, and that changes the
answer. The two certification families make **disjoint** demands:

| | What it actually tests | What it needs from the server |
|---|---|---|
| **FAPI 2.0 Security Profile (Final)** | that the *machine-to-machine* half of OAuth is hardened correctly | PAR, PKCE S256, strong client auth (mTLS or `private_key_jwt`), sender-constrained tokens, RFC 9207 `iss`, code-only |
| **OpenID Connect Basic OP** | that the *browser SSO* half of OIDC interoperates | `client_secret_basic`, `prompt`, `max_age`, `acr_values`, `display`, `ui_locales`, `login_hint`, RS256 ID tokens, the full UserInfo claim surface |

These are almost non-overlapping surfaces. FAPI 2.0 is *not* "Basic OP plus
extra rules" — it is a different axis. So "start with the easier one" is only
sound advice if the easier one is also the one you have already built. AXIAM has
built the first column and, deliberately, not the second.

---

## 2. The evidence: distance to each certification

Measured against the tree at `e54df40` (`main`, 1.0.0-beta12).

### 2.1 FAPI 2.0 Security Profile (Final) — OP

Every mechanism the profile mandates is implemented, and the harness to prove it
is committed:

| Profile requirement | State in tree | Where |
|---|---|---|
| PAR mandatory | landed | `crates/axiam-oauth2/src/par.rs`, per-client `require_par` |
| PKCE S256 mandatory | landed | `crates/axiam-oauth2/src/pkce.rs` |
| `response_type=code` only, no token in any URL | landed, enforced | `authorize.rs:128` rejects anything but `code` |
| Client auth — mutual TLS family (RFC 8705 §2.1 **and** §2.2) | landed | `mtls.rs`; `ClientAuthMethod::{TlsClientAuth, SelfSignedTlsClientAuth}` |
| Client auth — `private_key_jwt` family (RFC 7523 §2.2) | landed 2026-08-14 | `private_key_jwt.rs`, single-use `jti`, SSRF-guarded JWKS fetch |
| Sender-constrained tokens — mTLS binding (`cnf.x5t#S256`) | landed | `token.rs`, `axiam_auth::token::verify_token_binding` |
| Sender-constrained tokens — DPoP (RFC 9449, `cnf.jkt`) | landed | `dpop.rs` |
| RFC 9207 `iss` in authorization responses | landed, unconditional | `handlers::oauth2::append_issuer` |
| Resource servers verify the binding, REST **and** gRPC | landed (contract 1.17) | introspection carries `cnf` + `token_type` on both transports |
| Profile enforcement as one switch | landed | per-client `profile: "fapi2"` — `crates/axiam-oauth2/src/fapi.rs` |

And the certification machinery itself:

- `conformance/suite.env` — the OIDF suite pinned at `release-v5.1.34`, with a
  written policy for moving the pin.
- Three committed plan templates covering **both** client-authentication
  families across **three** methods:
  `fapi2-security-profile-final-{mtls,self-signed,private-key-jwt}.json`.
- `conformance/scripts/{gen-certs,register-clients,render-plan,run-plan,report}` —
  the suite driven through its HTTP API rather than by clicking, because a
  result nobody else can regenerate is not evidence.
- `just conformance-{certs,up,register,run,report,down}`.
- Two runbooks: [`fapi-conformance-runbook.md`](fapi-conformance-runbook.md)
  (how to run and read it) and
  [`fapi-certification-submission.md`](fapi-certification-submission.md) (the
  operator's submission sequence).
- A fee-waiver letter drafted at [`extra-B-track-features.md`](extra-B-track-features.md) §X5.4.

**Distance remaining: one green run.** `docs/conformance/` does not exist yet —
the plans have never been executed to completion in an environment with a docker
daemon and an mTLS listener. That is the whole gap. Not a line of protocol code.

**Availability check:** the Foundation announced FAPI 2.0 Security Profile Final
conformance tests and certifications on **07 August 2026** — one month ago. The
certification AXIAM is aimed at is open for submissions *now*.

### 2.2 OpenID Connect Basic OP — the nominal "easy" one

The Basic OP test plan
(`oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]`)
exercises the OIDC Core interactive surface. AXIAM's discovery document and
authorize handler say plainly how much of that surface exists:

| Basic OP expects | AXIAM today | Evidence |
|---|---|---|
| `client_secret_basic` at the token endpoint (RFC 6749 §2.3.1) | **not implemented, deliberately** | `ClientAuthMethod` has no such variant; `oauth2_client.rs:861` documents the refusal; `sdks/CONTRACT.md:1590` tells SDKs never to send `Authorization: Basic` |
| `prompt` (`none`, `login`, `consent`) | **absent** | no occurrence anywhere in `axiam-oauth2` |
| `max_age` + `auth_time` | **absent** | ditto |
| `acr_values` / `acr` claim | **absent** | ditto |
| `display`, `ui_locales`, `login_hint` | **absent** | ditto |
| RS256 ID token signing | **EdDSA only** | `oidc.rs:93` — `id_token_signing_alg_values_supported: ["EdDSA"]` |
| `scope=address`, `scope=phone` claims | **absent** | `oidc.rs:94` — `["openid","profile","email"]` |
| Request object (`request` / `request_uri`) support-or-reject modules | not implemented | no request-object handling in the crate |
| `nonce` | **landed** | `AuthorizeRequest::nonce` |

That is nine work items, several of which touch the login UI and the session
model, not just the protocol crate. Two of them are *policy reversals*: adding
`client_secret_basic` means implementing an auth method the tree currently
refuses on purpose and that the SDK contract forbids across eleven SDKs, and
adding RS256 means widening a signing-algorithm policy that CLAUDE.md states as
a security standard.

**Basic OP is a bigger, more invasive project than finishing FAPI 2.0.** That is
the inversion, and it is the whole argument.

### 2.3 The other OP profiles

| Profile | Reachable? | Why |
|---|---|---|
| **Config OP** | **yes, essentially free** | discovery document and JWKS both exist and are well-formed; the plan drives no flow, registers no client and needs no browser |
| **Dynamic OP** | no | no OIDC Dynamic Client Registration endpoint exists (`registration_endpoint` is absent from `oidc.rs`; the only `*_registration_endpoint` in the tree is UMA's resource registration) |
| **Implicit OP** | no — and should stay no | `response_type=code` only. Implementing implicit would mean putting tokens in a URL fragment, reversing a FAPI 2.0 requirement AXIAM currently enforces |
| **Hybrid OP** | no — same reason | ditto |
| **FAPI 2.0 Message Signing** | not yet | JAR/JARM signing beyond current scope; the Foundation only finalised its tests alongside Security Profile in Aug 2026 |
| **FAPI-CIBA** | no | no CIBA backchannel endpoint; and CIBA's decoupled-device model is a *consumer banking* pattern, not AXIAM's |

Implicit and Hybrid deserve one extra sentence, because "more certifications is
better" is a trap here: certifying them would require *degrading* the security
posture that the FAPI certification exists to attest. They are not deferred,
they are declined.

---

## 3. Why FAPI 2.0 is also the *right* claim for an IoT product

The argument so far is only about cost. It would be a weak recommendation if the
cheapest certification were also the least relevant one. It is not — it happens
to be the most relevant one, for a reason specific to AXIAM's domain.

The OpenID Foundation certifies no "IoT profile". The question is therefore which
existing profile attests the properties an IoT deployment actually depends on.
FAPI 2.0 mandates exactly two mechanisms that are the IoT story:

1. **Mutual-TLS client authentication (RFC 8705).** An IoT device does not have a
   browser, a user, or a safe place to keep a shared secret. It has an X.509
   identity, provisioned at manufacture. AXIAM is built around that: per-tenant
   certificates signed by an organization CA (`axiam-pki`), native in-process
   client-certificate verification with no proxy-header identity assertion
   (`docs/security-profiles.md`). FAPI 2.0 is the profile that says a server
   *must* do this properly.

2. **Sender-constrained access tokens.** A bearer token exfiltrated from a field
   device is a bearer token an attacker can use from anywhere. Certificate
   binding makes it useless off the device's own TLS connection. This is the
   single highest-value property in a fleet deployment, and it is the one an
   external certification can actually attest.

The measured cost supports leading with the mTLS variant rather than DPoP:
certificate binding adds **≈4 µs per token and no per-request asymmetric
cryptography**, because the handshake already proved possession once for the
whole connection; DPoP adds one signature verification per request. (Figures
from `crates/axiam-auth/benches/auth_bench.rs`; the end-to-end percentage claim
is still withdrawn pending `bench-quick` — do not restate it.)

Basic OP, by contrast, attests browser-SSO interoperability. That is genuinely
valuable to AXIAM — for the admin console and for federation partners — but it
is a claim about the *human* half of the product, and it is not the half the
project leads with.

**So the ordering is not a compromise between cost and relevance.** The cheapest
certification and the most on-message certification are the same one.

---

## 4. Recommendation

### Primary — **FAPI 2.0 Security Profile (Final), OpenID Provider**

Submit for all three committed variants, covering both client-authentication
families:

| Variant | Client auth | Sender-constraining |
|---|---|---|
| `mtls` | `tls_client_auth` (RFC 8705 §2.1) | mTLS certificate binding |
| `self-signed` | `self_signed_tls_client_auth` (RFC 8705 §2.2) | mTLS certificate binding |
| `private-key-jwt` | `private_key_jwt` (RFC 7523 §2.2) | DPoP (RFC 9449) |

Remaining work: obtain a green run on a digest-pinned release image. No protocol
implementation.

### Secondary — **OpenID Connect Config OP**, if and only if it runs clean

Add it to the same waiver request. The rationale is proportionality: the plan
reads the discovery document and the JWKS, drives nothing, and needs no browser,
so the marginal effort is one command. It gives AXIAM a presence on the OpenID
Connect certification list — which is where implementers look first — without
pretending to a Basic OP conformance the tree does not have.

Plan config and recipe are committed with this document:

```bash
just conformance-run-config    # oidcc-config-certification-test-plan
```

**Honest caveat, stated because this document would be worthless without it:**
Config OP has *not* been run. `subject_types_supported` is `["public"]` only and
`id_token_signing_alg_values_supported` is `["EdDSA"]` only, both of which are
legal but unusual, and the plan may object to a metadata field that is absent
rather than merely narrow. Run it before naming it in the letter. If it is red,
send the letter for FAPI 2.0 alone — a waiver request that names a profile the
sender then withdraws is a worse first impression than a narrower one.

### Deferred — **OpenID Connect Basic OP**

The right *second* certification, not the first, and worth doing as a deliberate
roadmap item rather than a side effect. Its prerequisites are §2.2's table, of
which two are policy decisions the maintainer must take explicitly:

1. Does AXIAM add `client_secret_basic`? It is required for Basic OP and
   currently refused on purpose, with the refusal written into the SDK contract
   that eleven SDKs implement.
2. Does AXIAM add RS256 ID token signing? Required by OIDC Core §15.1 for OPs
   that return ID tokens from the authorization endpoint; AXIAM's code-only flow
   means the mandate's own exception may apply, but the Basic plan's expectations
   should be checked against a real run before assuming relief.

Neither should be answered as a by-product of chasing a certification badge.

### Declined — Implicit OP, Hybrid OP, Dynamic OP

The first two would require reversing security properties FAPI 2.0 certifies.
The third needs an endpoint that does not exist and whose absence is not
currently costing anything.

---

## 5. Fees

**Sourcing caveat, first.** `openid.net` is blocked by this environment's egress
proxy, so the figures below come from search-result summaries of the
Foundation's fee page rather than from the page itself. **Re-read
<https://openid.net/certification/fees/> before acting on any number here.**

| Item | Member | Non-member |
|---|---:|---:|
| OpenID Connect certification, per new deployment, per calendar year — covers **multiple profiles** (e.g. Basic OP + Config OP, then Implicit/Hybrid/Dynamic added later at no extra cost) | $700 | $3,500 |
| FAPI certification (illustrative: one FAPI-CIBA fee covers all Ping/Poll × MTLS/private-key-JWT combinations) | $1,000 | — |

Two structural points that matter more than the exact numbers:

1. **OP and RP deployments are billed separately.** AXIAM is certifying as an OP;
   the SDKs are RP-shaped and would be a separate line if ever certified.
2. **A single OpenID Connect payment covers multiple profiles in the same
   calendar year.** This is what makes deferring Basic OP cheap rather than
   wasteful: if Basic OP is done later in the same year as Config OP, the
   Foundation's own pricing absorbs it.

AXIAM is not an OpenID Foundation member, so the non-member column applies —
which is exactly the situation the Foundation's **Open Source Project
Certification Policy** (board-approved, June 2021) exists to address. It provides
for **no-cost certification for qualifying open-source projects**, evaluated
case by case, requested by writing to `certification@oidf.org`.

**Do not pay anything before the waiver answer arrives.**

---

## 6. Fee-waiver request — ready to send

This supersedes the draft at [`extra-B-track-features.md`](extra-B-track-features.md)
§X5.4 in one respect only: it names the Config OP profile alongside FAPI 2.0, and
it cites the Open Source Project Certification Policy by name. The §X5.4 scope
sentence about covering both client-authentication families remains accurate as
drafted and is carried over unchanged.

> **To:** certification@oidf.org
> **Cc:** director@oidf.org
> **Subject:** Open-source fee waiver request — FAPI 2.0 Security Profile (Final) OP certification for AXIAM
>
> Dear OpenID Foundation Certification Team,
>
> I am writing to request a certification fee waiver under the Foundation's
> **Open Source Project Certification Policy** for **AXIAM**, an open-source
> identity and access management server, ahead of our planned **FAPI 2.0
> Security Profile (Final)** OpenID Provider certification.
>
> **About the project.** AXIAM (Access eXtended Identity and Authorization
> Management, <https://github.com/ilpanich/axiam>) is an Apache-2.0-licensed
> IAM platform written in Rust, targeting microservices and IoT deployments. It
> implements OAuth 2.0, OpenID Connect, native in-process mutual TLS, and
> hierarchical RBAC, and it is developed fully in the open — including our
> benchmark methodology: we publish complete, reproducible performance
> comparisons against incumbent products, *including our own regressions and
> failing test tables*, as a matter of project culture. We intend to treat
> conformance the same way. Our conformance-suite results will be published in
> full alongside the certification, green and red alike, under `docs/conformance/`
> in the public repository, generated by a committed harness that pins the suite
> version so that any third party can regenerate them.
>
> **What we intend to certify.**
>
> 1. **FAPI 2.0 Security Profile (Final), OpenID Provider** — the primary
>    request. We will submit the full OP test plan across three variants,
>    covering **both** of the profile's client-authentication families:
>    `tls_client_auth` and `self_signed_tls_client_auth` (RFC 8705 §2.1 and
>    §2.2, with mutual-TLS certificate-bound access tokens), and
>    `private_key_jwt` (RFC 7523 §2.2, with DPoP-bound access tokens per
>    RFC 9449).
> 2. **OpenID Connect Config OP** — a secondary request, covering our discovery
>    metadata and JWKS. We would be glad to have this considered together with
>    the above; if the Foundation would prefer to treat it as a separate
>    application, please tell us and we will follow that process.
>
> **Why FAPI 2.0 for an IoT-oriented server.** We think this is the part most
> worth explaining, because the pairing is unusual. FAPI 2.0 mandates two
> mechanisms that are, in our domain, the load-bearing ones: mutual-TLS client
> authentication and sender-constrained access tokens. A constrained IoT device
> has no browser and no safe place for a shared secret, but it does have an
> X.509 identity provisioned at manufacture; and a bearer token exfiltrated from
> a field device is usable from anywhere, whereas a certificate-bound one is not.
> The profile written for financial-grade APIs turns out to describe, almost
> exactly, what a fleet of devices needs. We would like to be able to point to a
> third-party attestation of it rather than to our own documentation.
>
> **Why a waiver.** AXIAM is an independent community project with no corporate
> sponsor and no commercial revenue. The fee, modest for a vendor, is material
> for us — and certification is precisely the kind of ecosystem signal an
> open-source security project should lead with rather than defer. A waiver
> converts directly into engineering time spent meeting the profile rather than
> funding access to it.
>
> **What we commit to.** (1) Completing the full conformance test plan against a
> tagged, digest-pinned release image before submission — not a working tree.
> (2) Maintaining certification across future releases per the Foundation's
> re-certification policy. (3) Publicly documenting our conformance process, in
> the repository, so that other open-source implementers can follow it; our
> runbook and harness are already public for exactly this reason. (4) Using the
> certification mark prominently and accurately, per the Foundation's guidelines,
> and never beyond the scope actually certified.
>
> We are glad to provide any supporting information the evaluation requires —
> project governance, licensing, funding, or release process. Please also tell us
> if you would prefer the conformance report attached to this request rather than
> submitted afterwards; we can supply it either way.
>
> Thank you for the work the Foundation and the certification programme do for
> the ecosystem. The openly available conformance suite has already made our
> implementation measurably better before any formal submission — which is, we
> assume, part of the point.
>
> Kind regards,
> [Full name]
> Maintainer, AXIAM — <https://github.com/ilpanich/axiam>
> [Contact email]

**Operator checklist before sending**

- [ ] Fill the two `[placeholders]`.
- [ ] Get a green FAPI 2.0 run first (§7) and attach the report — a completed
      test plan materially strengthens the request.
- [ ] Run `just conformance-run-config`. If Config OP is not clean, **delete
      item 2** from the letter and the sentence introducing it.
- [ ] Re-verify the fee figures in §5 against the live page.
- [ ] Do not pay anything until the waiver answer arrives.

---

## 7. How to run the certification tests

Full detail lives in [`fapi-conformance-runbook.md`](fapi-conformance-runbook.md),
including the failure-interpretation table. This section is the ordered
procedure; read the runbook's **Known gaps** before treating any green run as
submission-ready.

### 7.1 Prerequisites

- `docker` + `docker compose`, `python3`, `jq`, `curl`, `openssl`.
- **A running AXIAM with an mTLS listener.** FAPI 2.0 requires mutual-TLS client
  authentication, so a plain-TLS deployment fails at client authentication in
  *every* module — which reads like forty failures and is one configuration
  problem. Quickest route:
  ```bash
  cd benchmarks && just target=axiam profile=p3-mtls bench-up
  ```
- **The listener must trust the conformance CA.** Otherwise the client
  certificate is rejected during the TLS handshake, *before* AXIAM sees a
  request: AXIAM's logs show nothing and the suite reports a transport error.
- An admin bearer token for the tenant under test.

### 7.2 First run, in order

```bash
# 1. Throwaway client certificates for both mTLS variants.
just conformance-certs

# 2. Point AXIAM's client-CA bundle at conformance/certs/ca.crt and restart:
#      AXIAM__SERVER__TLS__CLIENT_CA_PATH=conformance/certs/ca.crt
#      AXIAM__SERVER__TLS__CLIENT_AUTH=optional
#    Then set AXIAM_ISSUER and AXIAM_TENANT_ID in conformance/suite.env.

# 3. Start the pinned suite (release-v5.1.34; ~60s to ready).
just conformance-up

# 4. Provision the three fapi2 clients and rewrite suite.env in place.
export AXIAM_ADMIN_TOKEN=...
just conformance-register

# 5. Drive all three FAPI 2.0 plans.
just conformance-run

# 6. Optional secondary: the Config OP plan (no browser, no client needed).
just conformance-run-config

# 7. Render docs/conformance/*.md — failures first, by design.
just conformance-report

# 8. Tear down.
just conformance-down
```

### 7.3 Things that will surprise you on the first run

- **`conformance-run` exits non-zero on any non-passing module, deliberately** —
  so it can be wired into a manually triggered CI job without silently going
  green on a red plan. All three variants always run; it does not stop at the
  first red one.
- **Several modules are interactive by construction.** They need a human with a
  browser to complete an authorization, and cannot be driven from the API. The
  script marks them `WARNING`/`REVIEW`/`TIMEOUT` and a human finishes them in the
  suite UI at `https://localhost.emobix.co.uk:8442`. That is a property of the
  profile, not a gap in the harness.
- **Registration is the structural gate.** `conformance-register` creates clients
  with `profile: "fapi2"`, and AXIAM *refuses* the registration unless it also
  carries `require_par`, a strong `token_endpoint_auth_method`, and some
  sender-constraining. If registration succeeds, the clients satisfy the
  profile's structural requirements by construction — you cannot have forgotten
  one.
- **The third variant is a diagnostic.** `private_key_jwt` + DPoP needs no mTLS
  listener. If the first two variants fail at client authentication and the third
  passes, the problem is the listener's client-CA bundle, not AXIAM.
- **The suite's JWKS is registered inline, not as a `jwks_uri`.** A locally-run
  suite publishes on a loopback address, which AXIAM's SSRF-guarded JWKS cache
  correctly refuses. `conformance-register` reads the key set out of the suite
  and registers it inline for exactly this reason.

### 7.4 Before submitting

Per [`fapi-certification-submission.md`](fapi-certification-submission.md):

1. The final run must target a **digest-pinned release image**, not a working
   tree. A result produced from an untagged build is not evidence.
2. Commit the reports under `docs/conformance/` — **alongside** earlier ones
   rather than over them. A suite-version bump that changes a verdict is itself
   a finding worth keeping.
3. Send the waiver letter (§6) and **wait for the answer before paying**.

---

## 8. Summary

| | Recommendation |
|---|---|
| **First certification** | FAPI 2.0 Security Profile (Final), OP — all three variants |
| **Bundled with it, if clean** | OpenID Connect Config OP |
| **Second, as a deliberate project** | OpenID Connect Basic OP, after the nine-item gap in §2.2 |
| **Declined** | Implicit OP, Hybrid OP (would reverse FAPI properties); Dynamic OP (endpoint absent) |
| **Fees** | Waiver request under the Open Source Project Certification Policy; pay nothing before the answer |
| **Work remaining for the primary** | one green run — no protocol implementation |

The short version of the whole argument: FAPI 2.0 *sounds* like the ambitious
target and *is* the cheap one, because AXIAM already built the machine-to-machine
half of OAuth to financial-grade and has not built the browser-SSO half at all.
Certify what you have. It also happens to be the thing worth certifying.

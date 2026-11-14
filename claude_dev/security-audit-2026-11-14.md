# Security audit: AXIAM server and the eleven client SDKs (2026-11-14)

**Method.** I followed the security-audit skill workflow, a defensive audit grounded in source code:
- reconnaissance;
- coverage-led hunting with a deterministic coverage ledger;
- a post-wave coverage critic;
- independent Phase 3 validation of every candidate;
- schema-validated findings.

**Execution policy.** I ran it as *sandboxed source-and-local-only*:
- No deployed endpoint, registry, IdP, broker or shared service was probed.
- Every executed check ran in an OS sandbox, `bin/sandbox.sh`. It used user, net and mount namespaces, so there was no network. It had a read-only root, masked home and run directories, `env -i`, rlimits and a 300 s wall clock.
- Artifacts were promoted through a descriptor-based, no-follow helper.

**Run artifacts.** All run artifacts live outside the repository in `/opt/security-audit/axiam/run-1/`:
- `findings.json`
- `coverage-ledger.json`
- `run-metadata.json`
- `architecture.md`
- the `agents/*/artifacts/` local evidence

This document is the human-readable report.

> **This is a partial pass (`run_status: incomplete`).**
>
> **What did not run:**
> - Wave 1 covered 53 coverage units, and the post-wave critic then accepted 6 new units and reopened 2.
> - Those 8 units, plus the Swift/C/C++ SDK token and transport units, were **deferred** and not hunted.
> - The *final-clean* critic and *Phase 5* (a second independent verification of each final record) were **not run**.
>
> **Why:**
> - Two agent turns were stopped by the platform's safety classifier.
> - The Swift/C/C++ hunter returned no result, so its units have no coverage claim.
> - I stopped expanding the run there.
>
> **What this means for the records:**
> - Every record below has passed **one** independent verifier that did not hunt it (Phase 3), but not the second pass the workflow calls for.
> - Treat the severities as calibrated but not double-checked.
> - Nothing in this report claims complete coverage.

## 1. Scope, sources and limits

| Item | Value |
|---|---|
| Profile | `standard` (self-set budget 60 agent invocations; 34 used: 4 recon, 21 hunters, 1 critic, 8 verifiers) |
| Server | `ilpanich/axiam` @ `45851a3` (clean): 19 crates, ~604 k lines of Rust, plus `frontend/`, `website/`, `.github/workflows`, `docker/`, `k8s/`, `infra/` |
| SDKs (all clean) | rust `97a4984`, go `8390600`, typescript `ca0701e`, python `484c824`, java `f41dd76`, kotlin `79abe2b`, csharp `959ffce`, php `11233f6`, swift `d659ae9`, c `fabecd3`, cplusplus `7c23264` |
| Prior runs | No compatible prior coverage ledger exists. The ~60 prose reviews in `claude_dev/security-review-*.md` were used only to recognise documented accepted risks, never as coverage. |
| Biggest evidentiary limit | `~/.cargo/registry` is empty and fetching is prohibited, so **no workspace crate could be built or tested**. Server-side claims that need an observed HTTP/gRPC result are therefore `needs_validation` unless the decisive logic is std-only and could be extracted into a `rustc` harness. SDK dependencies (npm, pip, maven, composer, nuget) are also absent, so SDK checks ran the SDK's own source files against small stubs. |
| Execution incident | One verifier ran `go version` **outside** the sandbox inside the Go SDK checkout. That triggered the Go command's automatic toolchain download (go1.26.0). No AXIAM endpoint or target service was contacted, and all target code still ran inside the sandbox. It is reported here for transparency. |

## 2. Security posture in one paragraph

The server is mature and heavily reviewed:
- The hunters closed SSRF, CSRF, the public-path matcher, SAML IdP signing, redirect validation, the OAuth2 code/PKCE/refresh/token-exchange bindings, SurrealQL injection, LDAP escaping, mTLS chain and organisation binding, and webhook and crypto primitives as **covered**, without findings.
- The weak spots are **boundaries between principals that the code assumes are separated elsewhere**:
  - purpose JWTs signed with the access-token key and admitted wherever no session check runs;
  - organisation-level actions that are seeded to ordinary tenant admins and lack the `require_organization_principal` guard;
  - unsigned internal AMQP queues;
  - a bootstrap gate that downgrades to an email match.
- The SDKs verify tokens and webhooks correctly at the primitive level. Their **framework glue** is where the confirmed defects are:
  - login-state binding;
  - post-login redirects;
  - role-versus-scope semantics;
  - unknown-`kid` refetch;
  - one canonicalisation differential in the Go AMQP consumer.

## 3. Confirmed findings

Each confirmed record has a complete source trace plus a bounded local observation, reproduced independently by a verifier that did not hunt it.

| # | Severity | Title | Boundary | Observed result (local, dummy data) |
|---|---|---|---|---|
| C1 | **medium** | Setting `AXIAM_BOOTSTRAP_ADMIN_EMAIL` replaces the setup token with a guessable email | Anonymous network client → first super-admin | A gate replica reading the real env: configured email with no or garbage token → *Proceed*. The upstream test `bootstrap_test.rs:255` asserts 201 for an email-only request. |
| C2 | **medium** | Go SDK AMQP `Consume` verifies HMAC over a case-folded struct but hands the handler a case-sensitive parse of the raw body | Broker publisher without HMAC key → application handler | On byte-identical SDK code, a re-keyed body verified, was acked, and the handler saw unsigned `subject_id`/`action`/`tenant_id`. The plain-tamper control was nacked. |
| C3 | low | Dummy Argon2 hash parameters (m=65536,t=3,p=4) differ from production (m=19456,t=2,p=1), so login timing reveals account existence | Anonymous → account enumeration (SEC-026) | Reference libargon2: about 24 ms vs about 176 ms CPU (7.4×). The analytic work ratio is 5.05×, and the linked argon2 0.6.0 is single-threaded. |
| C4 | low | C++ SDK: a malformed JWT header makes the "non-throwing" `try_authenticate` throw `nlohmann::json::type_error` | Anonymous HTTP caller → C++ resource server | Four hostile headers all escaped as `type_error.302/306` before any network or crypto work. The guard still fails closed. |
| C5 | low | PHP and C# SDK `JwksVerifier` refetch the JWKS for every unknown `kid` (no cooldown, against CONTRACT §12.4 rule 2) | Anonymous → outbound request amplification | PHP, run unmodified: 20 forged kids → 40 outbound requests. C#: same predicate, confirmed from source only. |
| C6 | low | Python, PHP and C# login glue redirect to an unvalidated `?return_to=` after login | Phishing link → open redirect | Django and PHP flows run unmodified: 302 to the foreign absolute URL. |
| C7 | low | Login state in the TS, Python, Java, Kotlin, C# and PHP SDKs is not bound to the browser that started the login (login CSRF) | Attacker's own account → victim browser signed in as attacker | TS, Django and PHP run unmodified: the callback in browser B with browser A's state reached `onSuccess` as A. Java, Kotlin and C# were checked from source only. |

## 4. Needs validation (no severity)

Each lead below has a verified source trace and an exact blocker. Almost all are blocked only because the Rust workspace cannot be built here, or because a deployment fact such as an IdP policy, broker ACLs or environment variables decides the outcome. The order is my suggested priority for the owner, based on boundary value and how much of the chain is already established.

| Priority | Lead | Why it matters | Decisive blocker |
|---|---|---|---|
| 1 | **WebAuthn ceremony state JWTs validate as access tokens** (`axiam-auth/webauthn-state-token-accepted-as-access-token`). Found independently by four hunters. | `discoverable/start` (public) mints a token that the default gRPC interceptor, gRPC `ValidateToken`, token exchange and the UMA `claim_token` accept as a user token. The anonymous variant has sub = nil UUID. The password-only variant has sub = victim, which bypasses MFA on those surfaces. | Build-and-run of `validate_access_token`. Holds only when `jwt_issuer == root_issuer()` (the default, and the k8s example). |
| 2 | **Sibling-tenant audit export** (`tenants.export_audit`) | A Standard-tenant admin can stream another tenant's full audit trail. The handler lacks `require_organization_principal_for_tenant`, and the permission is seeded to tenant admins (re-checked in the sandbox). | Two-tenant integration run. |
| 3 | **Org security baseline writable by tenant admins** (`set_org_settings`) | Weakening MFA, password or lockout policy propagates to every sibling tenant. An existing test pins the 200 response. | Two-tenant integration run. |
| 4 | **System audit partition readable by any tenant admin** (`audit_logs:list_system`) | The nil-tenant partition holds other tenants' unauthenticated, SCIM and expired-token request IPs and paths. | Integration run with the audit middleware. |
| 5 | **`/oauth2/authorize` accepts a client-minted user token** | An RP holding a user's 15-minute token can mint a code, and with it a refresh token, for another public client. The T-447 `minted_for_client` rule is not applied here. | End-to-end run, plus the existence of a suitable public client. |
| 6 | **gRPC `UserService.GetUser` / `ValidateCredentials` have no RBAC** | Any same-tenant token reads any user's email and status. REST requires `users:get`. An existing test pins the behaviour. | Owner intent ("inter-service use") and a test run. |
| 7 | **Unsigned mail, webhook and SSF AMQP queues** | A broker publisher can send tenant-branded mail to any address (defeats SEC-055), webhook-secret-signed POSTs, and deployment-key-signed SETs. | Broker ACLs. |
| 8 | **mTLS device login ignores service-account status** | Disabling a service account does not stop `/auth/device` from minting new tokens. Both sibling paths check status. | Integration run. |
| 9 | **Stale OPAQUE record survives password reset** (`opaque_mode=optional`) | The old password keeps working on the OPAQUE login endpoint after a reset. | Integration run. |
| 10 | **SAML SP: no mandatory audience or recipient binding on the form ACS** | A cross-SP assertion relay is possible if the IdP omits `AudienceRestriction`. | IdP policy. |
| 11 | **Rust SDK guard accepts purpose JWTs** when `expect_audience` is unset | Server-side variant of lead 1, reaching SDK-protected applications. | SDK build. |
| 12 | **Java, Kotlin and PHP `require_role` checks OAuth scopes** | A scope named like a role grants the role. The server emits no `roles` claim. | Tenant scope and role name overlap. |
| 13 | **SSRF pin bypassed via env proxy** (`pinned_client` lacks `.no_proxy()`) | DNS-rebinding through a corporate proxy. | Proxy environment in production. |
| 14 | **Kotlin Ktor guard lacks §3a inbound CSRF** for cookie credentials | Same-site cross-origin form POST. | Deployment topology. |
| 15 | **Tenant `Suspended` status is never enforced** | Suspension is cosmetic. | Intended semantics. |
| 16 | **Erasure cancel re-activates suspended accounts** | Reverses an admin lock. | Process facts. |
| 17 | **`release-opaque.yml` mutable action refs and `npm@latest` in OIDC publish jobs** | Supply-chain compromise of the OPAQUE core that all SDKs load. | Org SHA-pinning policy. |
| 18 | **SurrealDB root password in argv** (prod and minimal compose, k8s) | A local host user can read the datastore root credential. | `hidepid` and local accounts. |
| 19 | **Dev compose pulls `ghcr.io/axiamhq/axiam/server:latest`** | That namespace is outside the release pipeline. | Namespace ownership. |
| 20 | **Shared unsigned `axiam.authz.response` queue** | Cross-tenant decision leakage or injection. | Consumers and ACLs. |
| 21 | **Group member count lacks a tenant predicate** | A cross-tenant count oracle, but it needs a foreign UUIDv7. | Integration run. |

## 5. Positive source patterns worth keeping

These were all checked and **held**:
- **CSRF and public paths:** suffix-exempt CSRF has no reachable bypass, and the public-path matcher fails closed.
- **SAML IdP:** single-signature placement, escaping and ACS from registration only.
- **Redirect validation:** `validate_return_to_at` was harness-tested against 20+ bypass forms.
- **OAuth2:** code, PKCE, DPoP, `redirect_uri`, refresh-reuse and token-exchange narrowing.
- **Data layer:** every SurrealQL `format!` site interpolates only UUIDs or static literals. LDAP RFC 4515 escaping was fuzzed with 200,000 inputs.
- **mTLS:** organisation-bound CA lookup and chain walk; CSR signing overrides SAN, KU and EKU.
- **SSRF guard:** resolves every address, pins it, and blocks IPv6-embedded IPv4 (harness-tested).
- **Frontend:** no DOM XSS sinks, and frame-ancestors are set everywhere.
- **CI:** no `pull_request_target`, and secrets are gated off PRs.
- **SDK primitives:** EdDSA pinned before key lookup in every SDK; constant-time webhook MACs; CSPRNG for PKCE, state and nonce; strict TLS.

## 6. Coverage summary (from `coverage-ledger.json`)

59 units in total:

| Status | Units | Notes |
|---|---|---|
| Covered | 17 | |
| Candidate | 27 | Carry the 42 raw hunter fingerprints, consolidated into 28 final records. |
| Blocked | 1 | Go SDK JWT unit. Decisive: jwx v3.4.0 behaviour on a JWS with no `kid`. The module source is not available offline. |
| Deferred | 14 | Listed below; they carry **no coverage claim**. |

The 14 deferred units:
- **Swift, C and C++ SDK token-verification and transport/secrets units (6):** the wave-1 hunter was stopped by the platform safety classifier. Recon leads remain open: a missing §3a CSRF check in C, C++ and Swift guards; `kid`-less single-key acceptance in C and C++; no refetch on unknown `kid` in Swift.
- **New units the critic accepted (6):**
  - OAuth2 client authentication and DPoP (`private_key_jwt` jti replay across all doors);
  - tombstoned-tenant non-session credentials (e.g. SCIM tokens);
  - client-minted tokens on `/api/v1` person-acting routes;
  - pre-auth CPU and outbound work balance;
  - the Java SDK AMQP consumer, which is the parallel of C2;
  - unreviewed admin configuration handlers (directory, saml_admin, scim_targets/tokens, ssf_admin, network, webauthn_policy, crl, authz_check).
- **Units the critic reopened (2):** SCIM token scope versus tenant lifecycle, and the role-assignment privilege ceiling.

The final-clean critic did not run, so a clean-coverage claim is **not** made.

## 7. Recommended next steps

1. Fix C1 now, before the next release: always require the setup token. Then fix the guard omissions behind leads 2–4. The pattern is to add the actions to `ORGANIZATION_LEVEL_ACTIONS` and call `require_organization_principal(_for_tenant)`.
2. Add a typed token discriminator, `typ: at+jwt` or a mandatory `aud`, and reject purpose tokens in `decode_access_token`. Default `allow_missing_aud_as_user` to `false`. This closes lead 1 and lead 11 together.
3. In an environment with the cargo registry, run the `validation_plan.local` tests in `findings.json`. Each is written as an integration test that should fail today and pass after the fix.
4. Run a follow-up audit pass on the 14 deferred units, then the final-clean critic and Phase 5.

---

## Confirmed findings — detail

### C1. Setting AXIAM_BOOTSTRAP_ADMIN_EMAIL replaces the unguessable setup token with a guessable email as the only first-admin credential

- **Fingerprint:** `axiam-api-rest/handlers/bootstrap/email-gate-replaces-setup-token`
- **Severity:** medium (likelihood low: Needs a not-yet-bootstrapped instance that the attacker can reach, the variable set, and the address known or guessed. The window is usually short and operator-controlled; impact high: The winner becomes the deployment's first super-admin with a password they chose, and the legitimate operator is then refused with 409)
- **Confidence:** high: The branch is short and fully source-visible, an upstream test asserts email-only success, and an independent sandboxed replica reproduces the decision. End-to-end HTTP was not run because the workspace cannot be built offline

POST /api/v1/admin/bootstrap is public (PUBLIC_PATHS) and creates the organization, its tenant and the first super-admin with a caller-chosen password. When AXIAM_BOOTSTRAP_ADMIN_EMAIL is set and non-empty, the handler's only check is req.email == expected. The server-minted one-time setup token is neither required nor consulted on that branch. The admin guide calls this variable 'optional and low-sensitivity' and keeps it out of the secrets table, and the shipped k8s ConfigMap and the e2e compose show it being set. Setting it strictly weakens the gate compared with leaving it unset: the 256-bit token that would otherwise be required is dropped, and the only remaining credential is an address that is not secret. On a deployment that is reachable before the operator bootstraps, anyone who knows or guesses the address (for example admin@<company domain>) becomes super-admin, and the operator's later attempt gets 409. Earlier reviews (SEC-049 in claude_dev/security-review.md) asked for a one-time secret to be required unconditionally. No accepted-risk entry covers the email-only branch.

**Root cause.** bootstrap() (bootstrap.rs:280-320) treats a non-secret configuration value as an authentication factor. The Ok(expected) branch returns after the email comparison and never requires or verifies setup_token.

**Intended behaviour.** First-admin creation should always require a secret only the operator holds (the logged setup token, or an operator-chosen secret supplied via a secret store). The configured email should be at most an additional restriction.

**Source trace.**

1. *entrypoint* `axiam/crates/axiam-api-rest/src/server.rs:2032` (`route /api/v1/admin/bootstrap`): Public POST route with no auth, listed in PUBLIC_PATHS (permissions.rs:692)
1. *propagation* `axiam/crates/axiam-api-rest/src/handlers/bootstrap.rs:280` (`bootstrap()`): Reads AXIAM_BOOTSTRAP_ADMIN_EMAIL; non-empty selects the Ok(expected) branch
1. *propagation* `axiam/crates/axiam-api-rest/src/handlers/bootstrap.rs:287` (`bootstrap()`): The only check is req.email != expected -> 403. setup_token is not read on this branch and consumed_token_hash stays None
1. *sink* `axiam/crates/axiam-api-rest/src/handlers/bootstrap.rs:322` (`bootstrap()`): Proceeds to validation and creation of the org, tenant and super-admin with the request's username and password

**Conditions.**

- *system_configuration*: AXIAM_BOOTSTRAP_ADMIN_EMAIL is set to a non-empty value (as the k8s ConfigMap comment and e2e compose show)
- *data_state*: The deployment has not been bootstrapped yet (no bootstrap lock / admin exists)
- *timing_dependency*: The attacker reaches the endpoint before the operator completes bootstrap
- *network_routing*: The REST listener is reachable by the attacker before bootstrap (compose and k8s bind 0.0.0.0 behind an edge proxy; the default bare bind is 127.0.0.1)
- *authentication_level*: None; the attacker only needs to know or guess the configured email address

**Bounded local reproduction** (attacker perspective: Unauthenticated network client that can reach a freshly deployed, not-yet-bootstrapped server and knows or guesses the configured admin address).

- Wrote an independent std-only Rust replica of the match at bootstrap.rs:280-320 that calls std::env::var("AXIAM_BOOTSTRAP_ADMIN_EMAIL") with the same .ok().filter(non-empty) chain and models setup_token_is_valid as an input (scratch bootstrap_gate2.rs)
- Compiled it with rustc and ran it twice in bin/sandbox.sh (no network, read-only root, empty env): once with the variable set to a dummy address, once unset
- Cross-checked against the upstream integration test bootstrap_creates_org_tenant_admin, which asserts 201 for an email-only request

*Observed:* Variable set: configured email with no token -> Proceed{token_consumed:false}; configured email with a garbage token -> Proceed{token_consumed:false}; other email -> Forbidden(email mismatch), even with a valid token. Variable unset: no token -> Forbidden; garbage token -> Forbidden; valid token -> Proceed{token_consumed:true}. The decision that leads to super-admin creation depends only on the non-secret email when the variable is set.

**Remediation.** Always require a valid, unconsumed setup token (or an operator-chosen secret held in a Secret, compared in constant time). Keep AXIAM_BOOTSTRAP_ADMIN_EMAIL only as an additional restriction. Update main.rs's log text and docs/admin/README.md accordingly, and add a regression test: with the email gate set, a request without a valid setup_token gets 403.

Sketch for `axiam/crates/axiam-api-rest/src/handlers/bootstrap.rs`:

```
if let Some(expected) = std::env::var("AXIAM_BOOTSTRAP_ADMIN_EMAIL").ok().filter(|s| !s.trim().is_empty()) {
    if req.email != expected {
        return Err(denied("email does not match AXIAM_BOOTSTRAP_ADMIN_EMAIL"));
    }
}
let token_hash = req.setup_token.as_deref().filter(|t| !t.is_empty())
    .map(hash_setup_token)
    .ok_or_else(|| denied("setup_token required"))?;
if !setup_token_is_valid(&state.db.current(), &token_hash).await? {
    return Err(denied("setup token is invalid, unknown, or already consumed"));
}
consumed_token_hash = Some(token_hash);
```

### C2. Go SDK AMQP Consume verifies HMAC over a case-folded struct but hands the handler a case-sensitive parse of the raw body

- **Fingerprint:** `axiam-go-sdk:amqp:hmac-canonical-vs-event-fields-casefold-differential`
- **Severity:** medium (likelihood low: Needs broker publish access, a fresh unseen signed message, and a handler that reads Event.Fields; impact medium: Defeats the per-message integrity guarantee the verified consumer exists to provide against exactly this broker-access threat. The handler acts on unsigned subject/action/tenant values)
- **Confidence:** high: Reproduced by the verifier in the sandbox on byte-identical SDK code, with a negative control. The behaviour follows from documented encoding/json struct-versus-map key semantics

verifyAndDispatch (amqp/consumer.go) authenticates a canonical form that canonicalCandidates rebuilds by json.Unmarshal into authzRequestCanonical/auditEventCanonical and re-marshalling. Go's encoding/json matches struct field names case-insensitively, with the last matching key winning, and it ignores unknown keys. After HMAC and replay checks pass, parseEvent builds the handler's Event.Fields from the same raw body, decoded into a case-sensitive map[string]json.RawMessage. A body can therefore carry forged lower-case keys (subject_id, action, tenant_id) followed by the originally signed values under case-variant keys (SUBJECT_ID, ACTION, TENANT_ID). The struct decode, and so the HMAC, sees only the signed values. Event.Fields["subject_id"/"action"/"tenant_id"] returns the forged ones. A publisher with broker access but no tenant HMAC subkey, holding one fresh signed message whose nonce this consumer has not seen, can make the handler act on values that were never signed. The official example (examples/amqp-consumer/main.go:69) makes its decision from event.Fields["action"]. Verified on the Go SDK only, which is the single variant in this group. Verifier note: outside the sandbox, a `go version` run from inside the SDK checkout made the Go command auto-fetch the go1.26.0 toolchain named in go.mod. That was unintended toolchain-download traffic, with no target or AXIAM endpoint contacted. Every harness execution then ran inside bin/sandbox.sh with GOTOOLCHAIN=local and GOPROXY=off.

**Root cause.** verifyHMAC/canonicalCandidates (amqp/hmac.go:157-189) authenticate bytes produced by a lossy, case-insensitive, last-key-wins struct decode and re-marshal. parseEvent (amqp/event.go:24-31) rebuilds the handler-visible view from the raw body with different, case-sensitive key semantics, so the verified bytes and the delivered fields can diverge.

**Intended behaviour.** Only HMAC-covered values reach the handler (CONTRACT section 8). A body that is not byte-equal to the signed canonical form plus hmac_signature is nacked, or the handler's Event is built only from the verified canonical bytes.

**Source trace.**

1. *entrypoint* `axiam-go-sdk/amqp/consumer.go:152` (`verifyAndDispatch`): The raw delivery body from the broker is passed to verifyHMAC
1. *propagation* `axiam-go-sdk/amqp/hmac.go:161` (`canonicalCandidates`): json.Unmarshal into authzRequestCanonical (case-insensitive field match, last key wins, unknown keys ignored), then json.Marshal; the HMAC is computed over these re-marshalled bytes
1. *propagation* `axiam-go-sdk/amqp/event.go:25` (`parseEvent`): After verification and the replay gate, the same raw body is decoded into a case-sensitive map[string]json.RawMessage
1. *sink* `axiam-go-sdk/amqp/consumer.go:178` (`verifyAndDispatch`): The handler is invoked with Event.Fields holding unsigned lower-case values; a nil return acks the delivery

**Conditions.**

- *authentication_level*: Broker publish access to the consumer's queue, without the tenant HMAC subkey
- *data_state*: Possession of a fresh (within skew) server-signed message whose nonce this consumer has not yet processed, for example by reading or intercepting it from the broker before delivery
- *system_configuration*: The application uses amqp.Consume and its handler reads Event.Fields, as the official example does. Handlers that re-unmarshal Event.Raw into a Go struct see the signed values instead

**Bounded local reproduction** (attacker perspective: Broker-access publisher without the HMAC subkey, re-publishing one fresh signed AuthzRequest).

- Copied the SDK's amqp/hmac.go, event.go, replay.go and errdrop.go verbatim (cmp-identical), plus consumer.go up to the end of verifyAndDispatch without the amqp091 adapter, into scratch alongside the hunter's retained forgery_test.go (fake delivery, dummy key)
- Ran go test inside bin/sandbox.sh with no network, GOTOOLCHAIN=local (go1.24.7) and GOPROXY=off
- Compared against the negative control in the same test: the same signature on a plainly tampered body

*Observed:* verifyHMAC=true (key_version 2, fresh nonce), acked=true, and the handler saw subject_id=99999999-..., action=documents:delete, tenant_id=88888888-..., while the signed values were 3333.../documents:read/2222.... The plain-tamper control gave acked=false, nacked=true. Test PASS.

**Remediation.** Bind the handler's view to the verified bytes. Either reconstruct the canonical bytes and require the received body, minus hmac_signature, to be byte-equal to them, or build Event.Fields and Event.Raw from the matched canonical bytes rather than the raw body. Also reject bodies with duplicate or case-variant keys. Regression test: a case-variant duplicate-key body is nacked and the handler is never invoked.

Sketch for `axiam-go-sdk/amqp/consumer.go`:

```
ok, meta, signed := verifyHMAC(signingKey, body) // return the matched canonical bytes
if !ok { delivery.Nack(false); return }
// ... replay gate ...
event, err := parseEvent(signed)
```

### C3. Timing-equalisation dummy Argon2 hash costs about 5x more than real password hashes, so login timing shows whether an account exists

- **Fingerprint:** `axiam-auth/dummy-hash-params-mismatch-timing-oracle`
- **Severity:** low (likelihood high: Unauthenticated, and needs only latency measurement of a gap of roughly 100 ms or more. Rate limits slow per-name probing but do not prevent it; impact low: Discloses account existence and lockout state (the enumeration SEC-026 is meant to prevent), not credentials)
- **Confidence:** medium: The parameter mismatch and the single-threaded verifier are certain from source and Cargo.lock, and the cost ratio was reproduced with reference libargon2. The RustCrypto crate AXIAM links and the end-to-end endpoint timing were not measured because the workspace cannot be built offline

SEC-026 makes the unknown-name, locked-account and gRPC ValidateCredentials refusal branches run one Argon2id verify against password::DUMMY_HASH, so that they cost the same as a wrong-password verify of a real account. DUMMY_HASH encodes m=65536,t=3,p=4. Every hash AXIAM writes uses Params::new(19456, 2, 1). verify_password takes its parameters from the PHC string (password.rs:22 comment, 101-104), so the dummy verify does about 5.05x the memory-pass work (65536*3 vs 19456*2). AXIAM links argon2 0.6.0, whose Cargo.lock entry has no rayon or parallel dependency, so p=4 lanes run sequentially and wall time follows work. An unauthenticated caller of POST /api/v1/auth/login can therefore tell unknown usernames or emails (and locked accounts) from existing active ones by latency, roughly 100 ms or more. The same holds for gRPC ValidateCredentials (user.rs:272-275). The password-reset unknown-address branch also uses this verify, but there the valid-account branch does no Argon2 work at all, so that oracle exists independently of this mismatch and is not claimed here.

**Root cause.** password.rs:22 DUMMY_HASH was generated with different Argon2 parameters from the ones hash_password uses (password.rs:53, Params::new(19456, 2, 1)), and no test ties the two together.

**Intended behaviour.** The equalising verify should cost the same as verifying a real stored hash. DUMMY_HASH should be derived with exactly hash_password's Params (for example generated once at startup), with a test asserting the parameters match.

**Source trace.**

1. *entrypoint* `axiam/crates/axiam-auth/src/service.rs:361` (`AuthService::login`): Unauthenticated login looks up the username, then the email; when neither exists it calls login_unknown_user (line 377)
1. *propagation* `axiam/crates/axiam-auth/src/service/directory.rs:733` (`authenticate_unknown_name_against_directory`): With no directory authenticator configured, it runs equalising_dummy_verify and returns None
1. *propagation* `axiam/crates/axiam-auth/src/password.rs:43` (`equalising_dummy_verify`): verify_password(probe, DUMMY_HASH), whose cost is set by the m=65536,t=3,p=4 parameters parsed from the PHC string
1. *sink* `axiam/crates/axiam-auth/src/password.rs:53` (`hash_password`): Real accounts' hashes use m=19456,t=2,p=1, so the existing-user wrong-password verify (service.rs:417-424) costs about one fifth as much as the dummy verify

**Conditions.**

- *authentication_level*: None: the REST login endpoint is public, subject to per-IP rate limits
- *system_configuration*: Stored hashes use AXIAM's hash_password parameters (true for every password AXIAM sets), and the tenant has no LDAP directory authenticator, which would add network latency to the unknown-name branch
- *network_routing*: The attacker can measure response latency over a few requests per candidate name; the gap of roughly 100 ms or more is well above typical jitter

**Bounded local reproduction** (attacker perspective: Anonymous client probing which usernames or emails exist in a tenant).

- Copied DUMMY_HASH and hash_password's parameters from axiam/crates/axiam-auth/src/password.rs into an independent PHP script (scratch argon2_ratio.php) that uses reference libargon2 via password_verify and measures getrusage CPU and hrtime wall time
- Ran it in bin/sandbox.sh (no network, empty env, rlimits): 1 warm-up and then 8 verifies of a wrong probe against each hash
- Compared the measured ratio with the analytic memory*passes ratio (65536*3)/(19456*2)

*Observed:* Real-params verify: cpu=23.9 ms, wall=23.9 ms. DUMMY_HASH verify: cpu=176.4 ms, wall=62.3 ms. CPU ratio 7.38x and wall ratio 2.61x with libargon2 threading; analytic work ratio 5.05x. AXIAM's single-threaded argon2 0.6.0 makes wall time follow the CPU or work ratio. End-to-end endpoint latency was not measured.

**Remediation.** Generate the equalisation hash with exactly the production Params, once per process (OnceLock), so the two cannot drift. Share one production_params() function between hash_password and the dummy. Add a unit test asserting that the dummy hash's m/t/p equal hash_password's.

Sketch for `axiam/crates/axiam-auth/src/password.rs`:

```
fn production_params() -> argon2::Params { argon2::Params::new(19456, 2, 1, None).expect("static params") }

fn dummy_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| hash_password(&Uuid::new_v4().simple().to_string(), None).expect("dummy hash"))
}

pub fn equalising_dummy_verify(pepper: Option<&str>) {
    let _ = verify_password(dummy_probe(), dummy_hash(), pepper);
}
// hash_password builds Argon2 from production_params(); test: PasswordHash::new(dummy_hash()) params == production_params()
```

### C4. C++ SDK: unauthenticated JWT header makes the 'non-throwing' TokenAuthenticator::try_authenticate throw an undocumented nlohmann exception

- **Fingerprint:** `axiam-cplusplus-sdk:jwks.cpp:JwksVerifier::verify_with_reason:nlohmann-value-type_error-escapes`
- **Severity:** low (likelihood medium: Needs no credentials, only a crafted token header, but the host application must use the C++ SDK guard or OIDC RP verification; impact low: Fails closed, with no authentication bypass. The established effect is an undocumented vendored exception escaping a documented no-throw API. That becomes a request-level error, or a process abort only in hosts without a catch-all (not observed here))
- **Confidence:** high: Source trace checked line by line, and the result reproduced deterministically by the verifier in the sandbox against the SDK's own sources and vendored nlohmann. The sink is reached before any network or crypto work

JwksVerifier::verify_with_reason parses the attacker-supplied JWS header with allow_exceptions=false. It rejects only unparseable JSON (is_discarded), then reads the header with nlohmann's json::value("alg", "") and value("kid", ""). In the vendored nlohmann 3.12.0, value() throws type_error.306 when the document is not an object and type_error.302 when the key holds a non-string. Both throws happen before any key lookup, network fetch or signature work. TokenAuthenticator::try_authenticate is documented as the 'Non-throwing twin, for wiring into AxiamGuard / framework adapters', but it catches only const AxiamError&. The guard_authenticator lambda calls it directly with the request's bearer token. So any unauthenticated caller who sends a token such as eyJhbGciOjF9.e30.c2ln (header {"alg":1}) makes a vendored nlohmann::json::type_error escape into the host. Client::verify_logout_token (oidc.cpp:1696) and ID-token validation in the token response (oidc.cpp:1047) call the same verify_with_reason and do not catch it, so the same exception replaces their documented OidcValidationError. Variant (verified): load_from_json still calls k.value("kty", "") on JWKS members (jwks.cpp:118), so a member such as {"kty":1} throws type_error.302 from refresh_keys(). That input comes from the configured issuer's JWKS endpoint, not from an anonymous caller. The comment at jwks.cpp:104-117 fixed only the non-object-member case. Authentication still fails closed. The result is a broken exception contract: the request becomes whatever the host does with an unknown std::exception (often a 500), or std::terminate in a host that has no catch-all around the guard.

**Root cause.** Typed access with nlohmann json::value(key, default), which throws on a type mismatch or a non-object receiver, applied to untrusted JSON without is_object()/is_string() guards (jwks.cpp:191-192, 118-123). The documented no-throw and OidcValidationError entry points filter only AxiamError.

**Intended behaviour.** Any malformed token header, whatever its JSON shape, yields kInvalidAlg: nullopt from try_authenticate and AuthError/OidcValidationError from the throwing entry points. A malformed JWKS member is skipped. No vendored exception type leaves the SDK from the verification path.

**Source trace.**

1. *entrypoint* `axiam-cplusplus-sdk/include/axiam/authenticator.hpp:186` (`TokenAuthenticator::guard_authenticator lambda`): The bearer token extracted from an incoming framework request is passed straight to try_authenticate
1. *propagation* `axiam-cplusplus-sdk/src/authenticator.cpp:246` (`TokenAuthenticator::try_authenticate`): Calls authenticate() inside a try block whose only handler is catch (const AxiamError&) at line 249
1. *propagation* `axiam-cplusplus-sdk/src/authenticator.cpp:133` (`TokenAuthenticator::authenticate_checked`): Calls jwks_->verify_signature_only_unchecked(token), which forwards to verify_with_reason (jwks.cpp:162)
1. *propagation* `axiam-cplusplus-sdk/src/jwks.cpp:184` (`JwksVerifier::verify_with_reason`): The header segment is base64url-decoded and parsed with allow_exceptions=false. Only is_discarded() is rejected (line 185), so a number, array, string or wrong-typed object passes
1. *sink* `axiam-cplusplus-sdk/src/jwks.cpp:191` (`JwksVerifier::verify_with_reason`): header.value("alg", "") throws nlohmann::json::type_error (306 for a non-object, 302 for a non-string alg). Line 192 does the same for a non-string kid

**Conditions.**

- *system_configuration*: An application uses the AXIAM C++ SDK TokenAuthenticator/AxiamGuard, or Client::verify_logout_token / ID-token validation, to verify tokens it receives
- *authentication_level*: None for the header path. The header is read before any key lookup or signature check, so any caller who can present a bearer token or logout_token reaches it. The JWKS variant needs control of the issuer's JWKS response
- *environmental_dependency*: Any effect beyond a wrong error class (for example a 500 instead of a 401) needs a host without a std::exception catch-all around the guard; std::terminate then aborts the process

**Bounded local reproduction** (attacker perspective: Unauthenticated HTTP client of a resource server that protects routes with the C++ SDK guard).

- Copied the hunter's retained harness (agents/h13-native-ffi/artifacts/cpp/harness.cpp, build.sh) unchanged into the verifier scratch. The harness is benign: a local stub Transport, a dummy tenant UUID, and a dummy Ed25519 JWK
- Inside bin/sandbox.sh (no network, read-only root), compiled the SDK's own src/jwks.cpp and src/authenticator.cpp against the vendored nlohmann 3.12.0 with g++ -std=c++17 -fsanitize=undefined
- Called try_authenticate for each hostile header inside catch (const std::exception&) to print the escaping type, and called refresh_keys() against a stub that returns {"keys":[{"kty":1}]}

*Observed:* build exit=0. For {"alg":1} and {"alg":"EdDSA","kid":7}, try_authenticate threw a non-AxiamError: [json.exception.type_error.302] type must be string, but is number. For [1] and "x" it threw type_error.306 (cannot use value() with array / with string). refresh_keys threw type_error.302 for {"kty":1}. Transport stub calls: 0. No authentication succeeded.

**Remediation.** Type-check untrusted JSON before typed access throughout the verification path, and make the documented no-throw entry point actually no-throw. In verify_with_reason, require header.is_object() and use find() plus is_string() for alg and kid. In load_from_json, skip members whose kty, crv, kid or x are not strings. As a backstop, catch nlohmann::json::exception in verify_with_reason and map it to kInvalidAlg, and catch std::exception in try_authenticate and map it to nullopt. Regression test: the four headers return nullopt from try_authenticate and kInvalidAlg from verify_with_reason, and {"keys":[{"kty":1}]} yields zero cached keys without throwing.

Sketch for `axiam-cplusplus-sdk/src/jwks.cpp`:

```
    if (header.is_discarded() || !header.is_object()) return fail(OidcValidationReason::kInvalidAlg);
    const auto alg_it = header.find("alg");
    if (alg_it == header.end() || !alg_it->is_string() || alg_it->get<std::string>() != "EdDSA")
        return fail(OidcValidationReason::kInvalidAlg);
    const auto kid_it = header.find("kid");
    if (kid_it != header.end() && !kid_it->is_string()) return fail(OidcValidationReason::kInvalidAlg);
    const std::string kid = kid_it != header.end() ? kid_it->get<std::string>() : std::string();
```

### C5. PHP and C# SDK JwksVerifier refetches the JWKS for every token with an unknown kid, with no cooldown

- **Fingerprint:** `axiam-sdks:jwks:unknown-kid-refetch-no-cooldown`
- **Severity:** low (likelihood high: It is unauthenticated, trivial to send and has no prerequisites.; impact low: Each forged request causes a bounded number of blocking outbound requests to the AXIAM server: 2 in PHP, and 1 in C# from source. That adds latency and load. There is no authentication bypass, and every forged token is rejected.)
- **Confidence:** high: The PHP result comes from executing the unmodified SDK class with only third-party libraries stubbed, and it follows directly from the source condition. The C# variant is the same predicate, read from source but not executed.

An unauthenticated client of an application guarded by the PHP SDK can trigger outbound fetches. The guard may be Laravel AxiamMiddleware, Symfony AxiamAuthSubscriber or verifyLocally. The client presents a syntactically valid token with an EdDSA header and a random kid. Before rejecting it, JwksVerifier makes two outbound requests: GET /.well-known/openid-configuration and GET jwks_uri. CONTRACT section 12.4 rule 2, which section 10 shares, allows at most one refetch per cooldown window and forbids 'always re-fetch'. PHP was confirmed by executing the unmodified class: 20 forged kids caused 40 outbound requests. The C# SDK (Axiam.Sdk/Auth/JwksVerifier.cs) has the same root cause, verified from source only. IsFresh is !expired && !unknown with no time term, so each unknown kid causes one GET of the JWKS, serialised by _fetchLock. The C# variant was not executed because dotnet is unavailable. Its count of one fetch per token comes from source reading. In the same SDK, SsfReceiver already implements the required 60 s ForcedRefetchInterval.

**Root cause.** In PHP, ensureFreshAsync treats 'kid not in cache' the same as 'cache expired'. inFlightFetch only collapses concurrent waiters and is cleared when the fetch settles. In C#, IsFresh has no cooldown term. Neither verifier records when the last refetch caused by an unknown kid happened.

**Intended behaviour.** An unknown kid triggers at most one JWKS refetch per 30-60 s window. Further unknown kids inside that window are rejected from the cached set without network I/O, as SsfReceiver does with ForcedRefetchInterval.

**Source trace.**

1. *entrypoint* `axiam-php-sdk/src/Laravel/AxiamMiddleware.php:170` (`AxiamMiddleware::handle`): The Bearer or cookie token from the request is passed to verifyLocally() for the configured tenant.
1. *propagation* `axiam-php-sdk/src/AxiamClient.php:2387` (`AxiamClient::verifyLocally`): Delegates to JwksVerifier::verify().
1. *propagation* `axiam-php-sdk/src/Auth/JwksVerifier.php:253` (`JwksVerifier::verifyWithProofs`): After the alg pin and the check for a non-empty kid, calls ensureFresh() with the attacker-chosen kid.
1. *propagation* `axiam-php-sdk/src/Auth/JwksVerifier.php:704` (`JwksVerifier::ensureFreshAsync`): The fast path requires !$unknown and has no cooldown term, so any unknown kid falls through to a fetch.
1. *propagation* `axiam-php-sdk/src/Auth/JwksVerifier.php:714` (`JwksVerifier::ensureFreshAsync`): resolveJwksUriAsync (GET discovery, line 750) and then GET jwks_uri (line 715) run for every forged token.
1. *sink* `axiam-csharp-sdk/Axiam.Sdk/Auth/JwksVerifier.cs:808` (`JwksVerifier.EnsureFreshAsync`): C# variant: GetFromJsonAsync(_jwksUri) runs for every unknown kid. It is reached from AxiamAuthMiddleware.cs:224 through VerifyCoreAsync:310.

**Conditions.**

- *authentication_level*: No authentication is needed. The token is rejected, but only after the outbound fetches.
- *system_configuration*: Amplification relative to normal traffic matters where the verifier is long-lived and its cache is warm: PHP under Octane, RoadRunner, Swoole or the AMQP worker, and C# where AxiamClient is a DI singleton (TryAddSingleton). Under classic PHP-FPM each request already starts cold.

**Bounded local reproduction** (attacker perspective: An unauthenticated HTTP client of an application that uses the PHP SDK guard.).

- Load the unmodified axiam-php-sdk/src/Auth/JwksVerifier.php, plus its Core and PresentedProofs dependencies, with local stubs. The stubs are guzzle ClientInterface with deferred promises drained on wait(), php-jwt JWK::parseKeySet and PSR ResponseInterface. The stub HTTP client counts requests and serves a discovery document and a one-key JWKS (kid real-key-1).
- Call verify() for tenant 'tenant-a' once with kid real-key-1 to warm the cache, once more with the same kid, then 20 times with fresh random kids.
- Run it under bin/sandbox.sh (no network, read-only root, env -i, rlimits) and compare the request counts.

*Observed:* Warm fill: 2 requests. Repeat with the known kid: 0 extra requests. 20 unknown-kid tokens: 40 extra requests, each a discovery GET followed by a JWKS GET, and all 20 tokens were rejected. A control run with synchronous (non-deferred) promise stubs showed 0 extra requests, because the inFlightFetch guard is then left set. The amplification therefore depends on guzzle's real deferred settlement, which the second stub models.

**Remediation.** In both SDKs, record when the last refetch caused by an unknown kid happened. While the cache is otherwise fresh, do not refetch for an unknown kid within a 60 s window; reject from the cache instead. In PHP, also cache the resolved jwks_uri rather than re-reading discovery on every refetch. Regression test: 50 random kids inside one window cause at most 1 fetch, and a rotated kid is accepted after the window.

Sketch for `axiam-php-sdk/src/Auth/JwksVerifier.php`:

```
private const UNKNOWN_KID_REFETCH_COOLDOWN_SECONDS = 60;
private int $lastUnknownKidRefetchAt = 0;

private function ensureFreshAsync(string $unknownKid): PromiseInterface
{
    $now = time();
    $expired = ($now - $this->fetchedAt) > $this->cacheTtlSeconds;
    $unknown = !isset($this->keysByKid[$unknownKid]);
    if ($this->keysByKid !== null && !$expired) {
        if (!$unknown) {
            return Create::promiseFor(null);
        }
        if (($now - $this->lastUnknownKidRefetchAt) < self::UNKNOWN_KID_REFETCH_COOLDOWN_SECONDS) {
            return Create::promiseFor(null);
        }
        $this->lastUnknownKidRefetchAt = $now;
    }
    // existing in-flight/fetch logic unchanged
}
```

Sketch for `axiam-csharp-sdk/Axiam.Sdk/Auth/JwksVerifier.cs`:

```
private static readonly TimeSpan UnknownKidRefetchCooldown = TimeSpan.FromSeconds(60);
private DateTimeOffset _lastUnknownKidRefetch = DateTimeOffset.MinValue;

// inside EnsureFreshAsync, under _fetchLock, after the second IsFresh check:
bool expired = DateTimeOffset.UtcNow - _fetchedAt > _cacheTtl;
if (!expired && _keysByKid.Count > 0)
{
    if (DateTimeOffset.UtcNow - _lastUnknownKidRefetch < UnknownKidRefetchCooldown)
        return; // unknown kid inside the window: reject from cache, no network
    _lastUnknownKidRefetch = DateTimeOffset.UtcNow;
}
```

### C6. Python, PHP and C# SDK login glue redirects to an unvalidated ?return_to= after login (open redirect)

- **Fingerprint:** `axiam-sdks:oidc-login-glue:return_to-unvalidated-redirect`
- **Severity:** low (likelihood medium: One crafted link to the real login route is enough; the attacker needs no account. It requires the glue to be enabled without a fixed success redirect, and PHP's shipped controllers never set one.; impact low: After a genuine sign-in the browser is sent to an attacker origin, which helps phishing. No token, code or cookie reaches the attacker origin.)
- **Confidence:** high: The SDK flow code ran unmodified for Django and PHP and redirected to the foreign URL. The C# and FastAPI paths are direct source reads of the same pattern.

The Django and FastAPI views, the PHP Laravel and Symfony OidcLoginController (via OidcLoginFlow), and the C# MapAxiamOidcLogin login endpoint all read return_to from the login request's query string and store it unchanged with the OIDC state. After a successful callback they redirect to successRedirect ?? return_to with no origin or path check, so absolute URLs on other origins are followed. A link such as <app>/login?return_to=https://other-origin sends the victim through a genuine AXIAM sign-in and then to the attacker's page, which can pose as the app.

Variants verified:
- Python Django: run unmodified, ending in a 302 to the absolute foreign URL. FastAPI checked from source (RedirectResponse at line 927).
- PHP: run unmodified, ending in a redirect to the foreign URL. The shipped Laravel and Symfony controllers pass return_to straight into begin() and never pass a successRedirect.
- C#: checked from source only, since dotnet is unavailable. Response.Redirect(destination) at line 189.

The C# and PHP docblocks call return_to the caller's open-redirect responsibility, but in both the SDK's own route reads the value from attacker-controlled input and offers no validation hook. That note does not mitigate the issue. TS, Kotlin and Java were not part of this candidate.

**Root cause.** The login handlers copy the untrusted return_to query parameter into the state entry, and the callback uses entry.return_to as the redirect target (when no success redirect is configured) without restricting it to a same-origin relative path or an allowlist.

**Intended behaviour.** Only a same-origin relative path should be honoured: it starts with a single '/', not '//' or '/\', and has no scheme, backslash or control characters. A value from an integrator-supplied allowlist may also be honoured. Anything else is dropped at login time, checked again before redirecting, and the flow falls back to the configured successRedirect or the JSON summary.

**Source trace.**

1. *entrypoint* `axiam-python-sdk/src/axiam_sdk/django/oidc.py:101` (`oidc_login_views.login_view`): Unauthenticated GET login view reads return_to from request.GET
1. *propagation* `axiam-python-sdk/src/axiam_sdk/django/oidc.py:118` (`login_view`): Saves the OidcStateEntry with return_to unchanged
1. *propagation* `axiam-python-sdk/src/axiam_sdk/django/oidc.py:196` (`callback_view`): destination = success_redirect or entry.return_to, with no validation
1. *sink* `axiam-python-sdk/src/axiam_sdk/django/oidc.py:198` (`callback_view`): HttpResponseRedirect(destination) sends a 302 to the attacker-chosen absolute URL

**Conditions.**

- *system_configuration*: The application uses the SDK login glue without a fixed success redirect: Python success_redirect unset, C# SuccessRedirect unset, or PHP's shipped controllers, which never set one
- *user_interaction*: The victim follows a crafted link to the application's login route and completes the AXIAM sign-in

**Bounded local reproduction** (attacker perspective: An unauthenticated attacker who can get a victim to open a link to the legitimate application's login route).

- Django: in the sandboxed harness described for the login-binding check, call login_view with return_to=https://other-origin.invalid/landing, then callback_view with that state and a code the stub IdP accepts.
- PHP: re-ran the s04 harness in the sandbox. It calls begin('https://evil.example.net/phish'), as the controller does for that query, then complete(state, code) with no successRedirect, as OidcCallbackController does.

*Observed:* Django: redirect_status 302, redirect_location "https://other-origin.invalid/landing". PHP: outcome=redirect redirectUrl='https://evil.example.net/phish'. The framework response classes (Django HttpResponseRedirect, Symfony RedirectResponse) were stubbed or not exercised. Their stock behaviour permits absolute http(s) targets, and ASP.NET Response.Redirect does likewise.

**Remediation.** Validate return_to when storing it and again before redirecting. Accept only a value that starts with a single '/', does not start with '//' or '/\', and contains no backslash or control characters. Optionally accept an integrator-supplied allowed_return_to predicate. Otherwise drop it and fall back to successRedirect or the JSON summary. In C#, use the LocalRedirect semantics (Url.IsLocalUrl). Regression tests: absolute, scheme-relative and backslash forms produce no redirect to that target.

Sketch for `axiam-python-sdk/src/axiam_sdk/django/oidc.py`:

```
def _safe_return_to(value):
    if value and value.startswith('/') and not value.startswith(('//', '/\\')) and '\\' not in value and not any(ord(c) < 0x20 for c in value):
        return value
    return None
# login_view: return_to = _safe_return_to(request.GET.get('return_to'))
# callback_view: destination = success_redirect or _safe_return_to(entry.return_to)
```

Sketch for `axiam-php-sdk/src/Oidc/OidcLoginFlow.php`:

```
private static function safeReturnTo(?string $v): ?string
{
    if ($v === null || $v === '' || $v[0] !== '/' || str_starts_with($v, '//') || preg_match('/[\\\\\x00-\x1f]/', $v)) {
        return null;
    }
    return $v;
}
// begin(): returnTo: self::safeReturnTo($returnTo)
// complete(): $destination = $successRedirect ?? self::safeReturnTo($entry->returnTo);
```

Sketch for `axiam-csharp-sdk/Axiam.Sdk.AspNetCore/OidcLoginEndpoints.cs`:

```
string? returnTo = context.Request.Query["return_to"];
if (returnTo is not null && !IsLocalPath(returnTo)) returnTo = null; // '/' but not '//' or '/\\', no control chars
// callback:
string? destination = options.SuccessRedirect ?? (entry.ReturnTo is { } r && IsLocalPath(r) ? r : null);
```

### C7. SDK 'Login with AXIAM' glue completes a callback in a browser other than the one that started it (login CSRF), in the TS, Python, Java, Kotlin, C# and PHP SDKs

- **Fingerprint:** `axiam-sdks:oidc-login-glue:state-not-bound-to-user-agent`
- **Severity:** low (likelihood medium: The attacker needs only their own account for the relying party's client and one victim navigation to a crafted callback link within 10 minutes; no secret is needed. Real-world harm also needs the application's onSuccess to create a session bound to the current request. The C# sample does this directly; the other SDKs need ambient request context, and PHP's shipped controllers pass no hook.; impact low: Login CSRF: the victim's browser is signed in to the relying-party app as the attacker, so data the victim enters lands in the attacker's account. The victim's own account is not taken over, and no victim credential or token is disclosed.)
- **Confidence:** high: The binding decision lives entirely in SDK code. The verifier ran it unmodified in three SDKs (TS, Python/Django, PHP) and read it from source in the other three; only the IdP/token endpoint was stubbed. The session effect in the host app is shown with a harness-modeled onSuccess and remains a condition.

Six SDKs ship login glue that keeps the in-flight OIDC tuple (state, nonce, code_verifier, redirect_uri, return_to) in an OidcStateStore keyed only by state. The glue sets no cookie and reads no session, so nothing ties that entry to the browser that called the login route. The callback checks only that a live state exists, then exchanges the code with the stored PKCE verifier and nonce and calls the application's onSuccess hook during whatever request carries the state. The SDKs document that hook as the place where the application creates its own session.

Attack: an attacker starts a login on the target app, signs in to AXIAM as themselves and stops before the callback. They then get a victim's browser to load callback?state=...&code=.... The victim's request then finishes the attacker's login. This is login CSRF: RFC 6749 §10.12 requires state to be bound to the user agent. The AXIAM server already fixed the same gap in its own federation flow with __Host-axiam_fed_bind (CONTRACT §12.1 rule 12b).

Variants verified:
- TypeScript (Express oidcLoginHandlers, Fastify oidcLoginPlugin): shared core run unmodified.
- Python (Django oidc_login_views): run unmodified. FastAPI oidc_login_router checked from source; it uses the same state-only consume.
- PHP (OidcLoginFlow + MemoryOidcStateStore): run unmodified.
- Java (Spring AxiamOidcLoginRoutes), Kotlin (Ktor axiamOidcLogin) and C# (MapAxiamOidcLogin): checked from source only. No Spring, Ktor or dotnet runtime is available here.

No variant was refuted.

How much harm this does depends on how the application wires its session:
- C# passes HttpContext to OnSuccessAsync, and the README's sample appends the app session cookie there, so the shipped pattern signs the victim's browser in as the attacker.
- TS, Python, Java and Kotlin pass no request object to onSuccess. The session lands on the victim's browser only if the app reaches the current request through ambient context: Spring RequestContextHolder or the servlet session, AsyncLocalStorage, contextvars, or a wrapping handler.
- PHP's shipped Laravel and Symfony callback controllers pass no onSuccess, so only an app that calls OidcLoginFlow::complete() with its own onSuccess is affected.

**Root cause.** The glue treats knowing a live state value as proof that the callback came from the browser that started the login. beginOidcLogin/login_view/beginLogin/MapAxiamOidcLogin/OidcLoginFlow::begin create no user-agent binding: no cookie, session id or digest. The callback consumes the entry by state alone (store.consume(state)), and every store implementation takes no caller input other than state.

**Intended behaviour.** The callback must complete only for the user agent that called the login route. The login handler should set a random binding value as an HttpOnly, Secure, SameSite=Lax __Host- cookie and record its digest on the state entry. The callback should consume the entry and then refuse with the uniform 401, without calling onSuccess, unless the request presents a matching cookie (compared in constant time). This mirrors the server's own __Host-axiam_fed_bind rule (CONTRACT §12.1 rule 12b).

**Source trace.**

1. *entrypoint* `axiam-typescript-sdk/src/middleware/express.ts:350` (`oidcLoginHandlers.login`): Unauthenticated GET login route, reached by the attacker's browser. It reads ?returnTo= and calls beginOidcLogin (line 352).
1. *propagation* `axiam-typescript-sdk/src/middleware/oidcLoginCore.ts:143` (`beginOidcLogin`): Saves {state, nonce, codeVerifier, redirectUri, returnTo} in the store and returns only a redirect. No cookie or user-agent binding is produced (the module header says it 'sets no cookie').
1. *propagation* `axiam-typescript-sdk/src/node/oidcState.ts:115` (`MemoryOidcStateStore.save`): Map keyed by entry.state only
1. *propagation* `axiam-typescript-sdk/src/middleware/express.ts:359` (`oidcLoginHandlers.callback`): The victim's browser loads the callback. Only the state, code and error query values are passed on; no cookie or session is consulted.
1. *propagation* `axiam-typescript-sdk/src/middleware/oidcLoginCore.ts:197` (`completeOidcLogin`): consume(query.state) is the only check before the exchange. Lines 209-214 exchange the attacker's code with the stored verifier and nonce, so PKCE and the nonce check both pass.
1. *sink* `axiam-typescript-sdk/src/middleware/oidcLoginCore.ts:227` (`completeOidcLogin`): onSuccess(tokens, entry) runs with the attacker's validated token set during the victim's request. This is the documented hook where the application creates its own session. Then comes the redirect to successRedirect ?? entry.returnTo (line 229).

**Conditions.**

- *system_configuration*: The application uses one of the SDK login glues (Express/Fastify, Django/FastAPI, Spring routes, Ktor axiamOidcLogin, ASP.NET MapAxiamOidcLogin, or PHP OidcLoginFlow::complete with an onSuccess). It creates its session in onSuccess and binds that session to the current request. C# hands over HttpContext directly. TS, Python, Java and Kotlin need ambient request context. PHP's shipped controllers pass no onSuccess.
- *authentication_level*: The attacker has an account that can complete the authorization-code flow for the relying party's AXIAM client
- *user_interaction*: The victim's browser loads an attacker-supplied callback URL (by link or auto-navigation) within the 10-minute state TTL, before the attacker's state is consumed

**Bounded local reproduction** (attacker perspective: A web attacker with their own AXIAM account at the relying party's tenant, targeting a different user of an application built on the SDK login glue).

- Copied TS src/middleware/oidcLoginCore.ts and src/node/oidcState.ts (commit ca0701e) unchanged into scratch. Added a three-class core shim (AuthError, NetworkError, Sensitive) and a stub OidcClient whose exchange returns the subject recorded for the presented code. Compiled with tsc and ran with node inside bin/sandbox.sh (empty network namespace, read-only root, env -i, rlimits, 300 s timeout).
- The harness calls beginOidcLogin as browser-A and records code 'code-dummy' as issued to dummy-user-A. It then calls completeOidcLogin as browser-B with A's state and code, then replays the same callback once.
- Copied Python src/axiam_sdk/django/oidc.py and _oidc_state.py (commit 484c824) unchanged. Stubbed django.http, httpx.HTTPError and the _client, _errors and _models imports. Ran with python3 -I in the same sandbox: login_view as browser-A, then callback_view as browser-B.
- Re-ran the s04 PHP harness, which loads the unmodified OidcLoginFlow and MemoryOidcStateStore (commit 11233f6), with php in the same sandbox.

*Observed:* TS: {"begin":"redirect","callback_in_B":{"kind":"redirect","url":"/dashboard"},"sessions":{"browser-B":"dummy-user-A"},"replay_status":401}. Django: callback in browser-B returned 200 {authenticated:true, sub:dummy-user-A} and sessions_after_csrf {browser-B: dummy-user-A}. PHP: 'A login-CSRF: outcome=json ... onSuccess(sub)='attacker-user-uuid''. In every case the SDK accepted a callback from a request with no tie to the login request and called onSuccess with the other account's tokens.

**Remediation.** In every SDK glue, bind the state entry to the user agent. At login, generate 32 random bytes and set them as a __Host-axiam_oidc_bind cookie (HttpOnly; Secure; SameSite=Lax; Path=/). Store their SHA-256 on the entry; the store interface gains an optional binding field. At the callback, consume the entry first so the state stays single-use. If the cookie is missing or its digest differs (constant-time compare), refuse with the uniform 401 and do not exchange the code or call onSuccess. Clear the cookie on both outcomes. Adapters that cannot reach the request, such as the TS core, take the cookie value as a parameter from the Express/Fastify adapter. Pass the request or call to onSuccess, so apps do not need ambient context to create sessions. Regression test in each SDK: a callback carrying a valid state but no or a different binding cookie returns 401 and onSuccess is not called.

Sketch for `axiam-typescript-sdk/src/middleware/oidcLoginCore.ts`:

```
// begin: const binding = randomBytes(32).toString('base64url');
// await options.store.save({ ...entry, bindingDigest: sha256(binding) });
// return { kind: 'redirect', url: request.url, setBindingCookie: binding };
// complete(options, query, bindingCookie?: string):
const entry = await options.store.consume(query.state);
if (!entry || !bindingCookie || !entry.bindingDigest ||
    !timingSafeEqual(Buffer.from(entry.bindingDigest), Buffer.from(sha256(bindingCookie)))) {
  return { kind: 'error', status: 401, body: authenticationFailedBody('unknown, expired, or already-used login state') };
}
```

Sketch for `axiam-python-sdk/src/axiam_sdk/django/oidc.py`:

```
binding = request.COOKIES.get('__Host-axiam_oidc_bind', '')
entry = state_store.consume(state)
if entry is None or not binding or not entry.binding_digest or not hmac.compare_digest(entry.binding_digest, hashlib.sha256(binding.encode()).hexdigest()):
    return JsonResponse({'error': 'authentication_failed', 'message': 'unknown, expired, or already-used login state'}, status=_AUTH_FAILED_STATUS)
```

Sketch for `axiam-csharp-sdk/Axiam.Sdk.AspNetCore/OidcLoginEndpoints.cs`:

```
// login: var binding = Base64Url(RandomNumberGenerator.GetBytes(32));
// context.Response.Cookies.Append("__Host-axiam_oidc_bind", binding, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax, Path = "/" });
// entry = entry with { BindingDigest = Sha256(binding) };
// callback, after ConsumeAsync:
string? presented = context.Request.Cookies["__Host-axiam_oidc_bind"];
if (entry is null || presented is null || entry.BindingDigest is null || !CryptographicOperations.FixedTimeEquals(entry.BindingDigest, Sha256(presented))) { await WriteOidcErrorAsync(context, 401, "authentication_failed", "unknown, expired, or already-used login state"); return; }
```

## Needs validation — detail

These are source-grounded leads whose decisive fact is outside source or could not be observed locally (mostly because the Rust workspace cannot be built offline). They carry no severity.

### N1. Any standard-tenant admin can read the deployment-wide system audit partition, which holds other tenants' request metadata

- **Fingerprint:** `audit-list-system-cross-tenant`

GET /api/v1/audit-logs/system (handlers/audit.rs:63-77) returns every audit_log row with tenant_id = nil, through list_system, which calls self.list(Uuid::nil()) at db audit.rs:422. The only gate is RequirePermission audit_logs:list_system. That permission is described as 'List system-wide audit logs (all tenants)' (permissions.rs:94), yet it is not in ORGANIZATION_LEVEL_ACTIONS and is seeded to every Standard tenant's super-admin and admin; this was re-checked in the sandbox. The handler has no organization-principal guard. The nil partition is not organization-scoped. The request audit middleware writes into it for every request with no verifiable JWT and no AuditAttribution (middleware.rs:625), recording action 'METHOD /path', the client IP and forwarded_for_claimed. Only the login and password-reset handlers set AuditAttribution; the SCIM handlers do not, and the middleware wraps the whole app, SCIM included. So other tenants' SCIM provisioning traffic, requests with refused or expired tokens, and unauthenticated OAuth/SAML traffic are written there. So are tenants.deleted control records (tenants.rs:824) and the unattributable rows described in security-analysis-2026-08-02 §23.2. A tenant-A admin therefore reads IP addresses and request paths produced by other tenants' users and integrations, including those of other organizations. The prior review SEC-034 records only that list_system requires the permission; it does not mark tenant-admin access as accepted.

**Claimed root cause.** list_system gates the global nil-tenant partition only on audit_logs:list_system. That permission is seeded to standard-tenant roles because it is absent from ORGANIZATION_LEVEL_ACTIONS, and there is no organization-principal check.

**Source trace.**

1. *entrypoint* `axiam/crates/axiam-api-rest/src/handlers/audit.rs:63` (`list_system`): GET /api/v1/audit-logs/system by an authenticated admin of standard tenant A.
1. *propagation* `axiam/crates/axiam-api-rest/src/handlers/audit.rs:70` (`list_system`): Only RequirePermission audit_logs:list_system in the caller's tenant; no organization-scope guard.
1. *propagation* `axiam/crates/axiam-audit/src/middleware.rs:625` (`AuditMiddlewareService::call`): A request with no verifiable JWT and no attribution (for example tenant B's SCIM call) is written with tenant_id = nil, the client IP, forwarded_for_claimed and action 'METHOD /path' (line 643).
1. *sink* `axiam/crates/axiam-db/src/repository/audit.rs:422` (`list_system`): self.list(Uuid::nil(), ...) returns the mixed, deployment-wide partition to tenant A's admin.

**Evidence.**

- `axiam/crates/axiam-api-rest/src/permissions.rs:94`: audit_logs:list_system is described as 'List system-wide audit logs (all tenants)'.
- `agents/v2-tenant-isolation/artifacts/seed_check_out.txt:3`: Sandbox re-check: audit_logs:list_system org_level=False super-admin=True admin=True for a Standard tenant.
- `axiam/crates/axiam-api-rest/src/handlers/tenants.rs:824`: tenants.deleted control records for any tenant are written with tenant_id nil.
- `axiam/crates/axiam-api-rest/src/handlers/auth.rs:562`: AuditAttribution is inserted only by the login and password-reset handlers; a repo-wide search finds none in axiam-scim.
- `axiam/crates/axiam-audit/src/middleware.rs:643`: The full request path is recorded as the action, so path-embedded identifiers are copied into the shared partition.

**Blockers.**

- Workspace crates cannot be built or tested offline (no cargo registry, no SurrealDB instance), so the handler could not be run against two dummy tenants. The source trace and the seeder grant predicate were the only things checked locally. It was therefore not observed which concrete rows another tenant's SCIM traffic produces in the nil partition through the full app.
- Operator intent is not settled in source: nothing marks tenant-admin access to the system partition as an accepted risk, but nothing states the opposite either beyond the 'all tenants' permission text.

**Validation plan.**

- *Local:* Build the test app with AuditMiddleware and two Standard tenants A and B. Send one dummy SCIM request with B's SCIM token from peer address 192.0.2.10. Then call GET /api/v1/audit-logs/system as A's seeded admin and check whether a row with ip 192.0.2.10 and path /scim/v2/... is returned. Vulnerable result: 200 including the row. Expected after the fix: 403. The fix is to guard with require_organization_principal (or restrict the read to the platform operator) and to add audit_logs:list_system to ORGANIZATION_LEVEL_ACTIONS.
- *Owner-observed:* An operator lists the roles in a standard tenant that hold audit_logs:list_system, and confirms whether the nil-tenant partition contains rows from other tenants' SCIM or unauthenticated traffic.

### N2. Async authz decisions for all tenants are published unsigned to one shared axiam.authz.response queue

- **Fingerprint:** `axiam-amqp:authz-response-shared-unsigned-queue`

Verified in source. After a request passes HMAC, nonce and freshness verification, process_authz_request evaluates it and builds an AuthzResponse carrying only correlation_id, allowed, reason and reason_code (messages.rs:202-215). The response has no tenant_id, nonce or signature. start_authz_consumer publishes it on the default exchange to the fixed queue axiam.authz.response (authz_consumer.rs:302-304; connection.rs:179). It ignores any reply_to: the crate has no reply_to handling on this path. CONTRACT.md documents this as unsigned in v1.0 (CONTRACT.md:1115). If more than one tenant's service consumes that queue, competing consumers would receive and ack each other's decisions. A principal with publish rights on it could inject allowed:true for a correlation_id it learns. In the SDK repositories, no non-test source subscribes to axiam.authz.response; only the TypeScript message type names it (axiam-typescript-sdk/src/amqp/messages.ts:59). Whether any shared consumer exists is therefore integration and deployment state, and exploitation also depends on broker ACLs.

**Claimed root cause.** Response routing is not namespaced per producer or tenant (no reply_to, no per-tenant queue; axiam/crates/axiam-amqp/src/authz_consumer.rs:304), and the response is not authenticated (AuthzResponse has no hmac_signature; axiam/crates/axiam-amqp/src/messages.rs:202).

**Source trace.**

1. *entrypoint* `axiam/crates/axiam-amqp/src/authz_consumer.rs:156` (`process_authz_request`): A verified request is evaluated; the response carries correlation_id only, with no tenant and no signature.
1. *sink* `axiam/crates/axiam-amqp/src/authz_consumer.rs:304` (`start_authz_consumer`): The response is published on the default exchange to the fixed queue queues::AUTHZ_RESPONSE for every tenant.

**Evidence.**

- `axiam/crates/axiam-amqp/src/connection.rs:179`: One AUTHZ_RESPONSE queue name, shared by all tenants.
- `axiam/crates/axiam-amqp/src/messages.rs:202`: AuthzResponse has no tenant_id, nonce or hmac_signature.
- `axiam/sdks/CONTRACT.md:1115`: The contract states that AuthzResponse does not carry hmac_signature in v1.0.
- `axiam/crates/axiam-amqp/src/reactor/transport.rs:644`: The reactor path in the same crate uses an exclusive, broker-named reply queue per process: the contrasting pattern.

**Blockers.**

- Whether more than one tenant's service consumes axiam.authz.response, and whether non-server principals may publish to it, are broker and deployment facts not in source. No SDK in the workspace subscribes to the queue in non-test code.
- Whether a requester can learn another request's correlation_id before the genuine response arrives, for example through read access on axiam.authz.request, depends on broker ACLs.

**Validation plan.**

- *Local:* With a broker-free harness, run process_authz_request for two dummy tenants and show that both serialized responses lack any tenant field and target the same queue name. Fix: honour a per-producer reply_to (or a per-tenant response queue) and sign AuthzResponse with the tenant subkey, bound to the request nonce.
- *Owner-observed:* Owner runs rabbitmqctl list_consumers -p <vhost> and checks which principals consume axiam.authz.response. The owner then lists configure, write and read permissions for SDK principals on axiam.authz.response and axiam.authz.request.

### N3. The mail and outbound (webhook/SSF) AMQP consumers accept unsigned messages and turn them into tenant-branded mail, webhook-secret-signed POSTs and deployment-key-signed SETs

- **Fingerprint:** `axiam-amqp:unsigned-internal-queues:mail_consumer+outbound_consumer`

Verified in source. start_mail_consumer deserializes the delivery straight into OutboundMailMessage, with no HMAC, nonce or freshness check (mail_consumer.rs:507-508). In send_with_retry_and_audit, the message's template_context is extended over the identity context (mail_consumer.rs:302-303), so action_url, username and tenant_name are publisher-controlled. The built-in activation and reset templates put {{action_url}} in the link (template.rs:161, 178). The recipient is msg.to_address for Notification (321-322) and also for every other type when the user_id lookup fails (329-335), which defeats SEC-055. Mail is sent through the tenant's configured provider (342). The outbound consumer decodes with plain serde (wire.rs:59-73, consumer.rs:293). The webhook deliverer passes the message's event_type and payload to deliver_once (webhook.rs:365-371). deliver_once fetches the webhook by (tenant_id, webhook_id), then signs and POSTs the payload with the stored secret (webhook.rs:266-301). It never checks the webhook's enabled flag or its events subscription (models/webhook.rs:40, 45). The SSF deliverer takes SsfPendingEvent from the payload (ssf_delivery.rs:329). Stream status and the event-type subscription are enforced (ssf_delivery.rs:362-375; ssf.rs:659-695), but sub_id and the event body are publisher-chosen, and sign_set signs them with the deployment key (ssf.rs:718-730). Target URLs come from stored records via the SSRF guard. Forging a webhook or SSF delivery needs the target webhook or stream UUID. Whether any lower-trust principal can publish to these queues is a broker-ACL fact.

**Claimed root cause.** OutboundMailMessage and OutboundMessage/WebhookMessage carry no signed envelope, and their consumers deserialize them with plain serde (axiam/crates/axiam-amqp/src/mail_consumer.rs:508, axiam/crates/axiam-amqp/src/outbound/wire.rs:59). Broker write access to these queues is therefore treated as control-plane authority, while the sibling authz and audit queues require the per-tenant HMAC/nonce/freshness envelope.

**Source trace.**

1. *entrypoint* `axiam/crates/axiam-amqp/src/mail_consumer.rs:508` (`start_mail_consumer`): Delivery bytes are deserialized as OutboundMailMessage, with no HMAC, nonce or freshness check.
1. *propagation* `axiam/crates/axiam-amqp/src/mail_consumer.rs:303` (`send_with_retry_and_audit`): The message's template_context overlays the identity keys, so action_url, username and tenant_name are publisher-controlled.
1. *propagation* `axiam/crates/axiam-amqp/src/mail_consumer.rs:334` (`send_with_retry_and_audit`): Recipient falls back to msg.to_address when the user_id lookup fails; Notification uses it directly at 322.
1. *propagation* `axiam/crates/axiam-amqp/src/outbound/wire.rs:59` (`decode`): Webhook, SSF, SCIM and CIBA outbound messages are decoded with plain serde, with no authentication (called from consumer.rs:293).
1. *propagation* `axiam/crates/axiam-api-rest/src/webhook.rs:284` (`deliver_once`): The message payload is signed with the stored webhook secret and POSTed to the registered URL. There is no enabled or events-subscription check.
1. *sink* `axiam/crates/axiam-oauth2/src/ssf.rs:730` (`sign_set`): The queued sub_id and event are signed with the deployment key and pushed to the stream receiver (ssf_delivery.rs:430).

**Evidence.**

- `axiam/crates/axiam-amqp/src/authz_consumer.rs:92`: The sibling authz consumer verifies the per-tenant HMAC before any processing.
- `axiam/crates/axiam-amqp/src/mail_consumer.rs:342`: Mail is sent through the tenant/org EmailService built from stored config.
- `axiam/crates/axiam-email/src/template.rs:161`: The built-in activation template places {{action_url}} in the call-to-action link; the reset template does the same at 178.
- `axiam/crates/axiam-oauth2/src/ssf_delivery.rs:329`: SsfPendingEvent (sub_id, event, event_uri, jti) is taken from the queued payload.
- `axiam/crates/axiam-core/src/models/webhook.rs:45`: Webhook has an enabled flag (and events at 40) that deliver_once never consults.
- `axiam/docs/deployment/README.md:1591`: The docs say AMQP HMAC gives authenticity. The mail, webhook and SSF queues are not covered by it.
- `axiam/docs/deployment/README.md:1586`: The docs say SDKs consume AMQP directly across service boundaries, so non-server principals hold broker credentials.

**Blockers.**

- Broker ACLs are not in source. Shipped compose creates a single full-permission default user (docker-compose.prod.yml:442-443), and the k8s NetworkPolicy admits only server pods. Whether SDK or device broker principals can write to axiam.mail.outbound, axiam.webhook(.retry) or the ssf_push queues depends on the operator's RabbitMQ permissions or HTTP auth backend.
- The workspace cannot be built offline, so send_with_retry_and_audit and the SSF deliverer could not be driven with a forged message locally.

**Validation plan.**

- *Local:* With dependencies available, add a test that calls send_with_retry_and_audit with an OutboundMailMessage of mail_type PasswordReset, a nil user_id, a dummy to_address and template_context {action_url: 'https://example.invalid/x'}, and asserts that a mock EmailService receives that recipient and URL. Add a test that calls SsfPushDeliverer::deliver_attempt with a hand-built SsfPendingEvent for an enabled dummy push stream (admitting_private_networks_for_tests) and asserts that a SET carrying the chosen sub_id reaches a loopback receiver. Fix: carry a signed envelope (a server-only or per-tenant subkey, plus nonce and issued_at) on mail and outbound messages and verify it in both consumers; drop the to_address fallback for non-Notification types; check webhook.enabled and its events in deliver_once.
- *Owner-observed:* Owner lists RabbitMQ permissions (rabbitmqctl list_permissions -p <vhost>, or the HTTP auth backend policy) for every non-server principal and checks whether any write regex matches axiam.mail.outbound, axiam.webhook, axiam.webhook.retry or the ssf_push queues, or the default exchange that routes to them.

### N4. gRPC UserService.GetUser and ValidateCredentials perform no permission check, so any same-tenant token reads any user's username, email and status

- **Fingerprint:** `axiam-api-grpc:user-service-no-rbac`

Verified from source. UserServiceServer is wrapped only with AuthInterceptor (server.rs:337-345), which authenticates any user- or m2m-audience access token and applies no per-method authorization. get_user (services/user.rs:120-158) checks only that the body tenant_id equals the claims tenant_id. It then returns id, tenant_id, username, email, status and timestamps of any user_id in that tenant, without comparing claims.sub to user_id and without calling an authorization engine. The REST twin GET /api/v1/users/{id} (handlers/users.rs:333-345) requires RequirePermission('users:get') unless the caller is reading itself. The in-repo test grpc_units.rs::get_user_success pins the current gRPC behaviour: a token for a random subject with only the 'profile' scope reads alice's record. validate_credentials (user.rs:161 onwards) likewise has no permission check. It answers valid/user_id for any username or email in the tenant (it accrues lockout, so it also allows lockout of victims); this adds little over the public login oracle. The sibling ReactorAdminService does call require_permission (reactor.rs), so per-method RBAC is the established pattern on this listener. The documentation (design-document.md:1038 'User lookups for inter-service use', docs/api/grpc.md:21) names the intended callers but no code restricts the service to service principals.

**Claimed root cause.** UserServiceImpl authorizes only on tenant equality between the request body and the verified claims (services/user.rs:138, 180). It never evaluates a permission, whereas the REST handler for the same data requires users:get.

**Source trace.**

1. *entrypoint* `axiam/crates/axiam-api-grpc/src/server.rs:337` (`serve`): UserServiceServer is registered with AuthInterceptor only.
1. *propagation* `axiam/crates/axiam-api-grpc/src/middleware/auth.rs:44` (`AuthInterceptor::call`): Any valid axiam:user or axiam:m2m access token is accepted, and its claims are placed in the request extensions.
1. *propagation* `axiam/crates/axiam-api-grpc/src/services/user.rs:138` (`get_user`): The sole check is body tenant_id == claims tenant_id. There is no sub/user_id comparison and no permission evaluation.
1. *sink* `axiam/crates/axiam-api-grpc/src/services/user.rs:150` (`get_user`): Returns another user's username, email and status to the caller.

**Evidence.**

- `axiam/crates/axiam-api-rest/src/handlers/users.rs:340`: REST equivalent: RequirePermission::new('users:get') unless is_own_resource.
- `axiam/crates/axiam-api-grpc/tests/grpc_units.rs:697`: get_user_success: token_for (line 45) issues an AUD_USER token for a random subject with only the 'profile' scope, and the test asserts it reads alice's record.
- `axiam/crates/axiam-api-grpc/src/services/user.rs:161`: validate_credentials has no permission check either.
- `axiam/crates/axiam-api-grpc/src/services/reactor.rs:290`: ReactorAdmin RPCs call require_permission, the established per-method pattern on this listener.

**Blockers.**

- No cargo registry offline: grpc_units.rs::get_user_success and a negative-permission variant could not be executed. The behaviour is established from source and from that existing test's assertion, not from an observed run.
- The intended access policy for UserService is not stated in code. The design document calls it 'for inter-service use', but whether end-user tokens are meant to reach it (and so whether this is a vulnerability or an undocumented design choice) needs owner confirmation.

**Validation plan.**

- *Local:* With dependencies available, add a test beside grpc_units.rs::get_user_success that calls get_user with an AUD_USER token whose sub has no role grants, targeting a different user_id in the same tenant. Expect PermissionDenied after the fix; today it returns the record. Repeat for validate_credentials. Fix: inject the AuthorizationEngine and require users:get for non-self reads and a dedicated permission for validate_credentials, or restrict both RPCs to m2m / service-account principals.
- *Owner-observed:* Owner-observed only: on staging, call axiam.v1.UserService/GetUser with an ordinary end-user access token for another dummy user's UUID in the same tenant, and record whether the response is OK with email or PERMISSION_DENIED.

### N5. mTLS device login mints fresh service-account tokens for a disabled (non-Active) service account

- **Fingerprint:** `axiam-api-rest/handlers/auth.rs:device_auth:service-account-status-unchecked`

POST /api/v1/auth/device issues an m2m access token for the service account bound to the presented client certificate. It never checks that the account's status is Active. Disabling a service account (PUT /api/v1/service-accounts/{id} with status Inactive or Locked) only updates the status column. The cert_bound_to edge and the certificate stay usable. So a device whose account was disabled can keep calling /api/v1/auth/device and getting new tokens (aud axiam:m2m, sub_kind service_account) for as long as its certificate stays Active and bound. Both sibling issuing paths refuse a non-Active account: client_credentials (axiam-oauth2 token.rs:2017) and the certificate-bound network_decide caller check (network_decide.rs:366). The machine-principal extractor skips a per-request status check on the stated assumption that 'the token-issuing paths check' it (extractors/auth.rs:1660-1662). I found no downstream status re-check in axiam-authz. The verifier confirmed every trace line from source. This is separate from the accepted lifetime of already-issued tokens, because new tokens keep being minted.

**Claimed root cause.** device_auth (axiam/crates/axiam-api-rest/src/handlers/auth.rs:934-976) trusts DeviceAuthService::authenticate_der. That function resolves only the cert_bound_to edge (mtls.rs:183-186 -> certificate.rs:1092-1112, `SELECT meta::id(out) ... FROM cert_bound_to`) and never loads the service_account row. The handler then calls issue_service_account_token with no ServiceAccountRepository lookup or status check. The service-account update handler (service_accounts.rs:205-220) and repository (service_account.rs:269-275) only set status. They neither unbind nor revoke the certificate.

**Source trace.**

1. *entrypoint* `axiam/crates/axiam-api-rest/src/server.rs:375` (`route /api/v1/auth/device`): Public device-auth route (rate-limited only), POST to handlers::auth::device_auth
1. *propagation* `axiam/crates/axiam-api-rest/src/handlers/auth.rs:938` (`device_auth`): CertificateAuthenticated::extract builds the device identity from the verified peer certificate (cert_auth.rs:250) or the trusted forwarded header (cert_auth.rs:288)
1. *propagation* `axiam/crates/axiam-pki/src/mtls.rs:183` (`DeviceAuthService::authenticate_der`): After the cert, CA and chain checks, it returns the SA id from get_bound_service_account(cert.id), which is edge-only. The service_account row and its status are never read
1. *propagation* `axiam/crates/axiam-api-rest/src/handlers/auth.rs:941` (`device_auth`): Only the tenant is loaded (tenant_repo.get_by_id); there is no service_account_repo lookup
1. *sink* `axiam/crates/axiam-api-rest/src/handlers/auth.rs:965` (`device_auth`): issue_service_account_token mints an access token whose sub is the (possibly disabled) service account

**Evidence.**

- `axiam/crates/axiam-oauth2/src/token.rs:2017`: client_credentials refuses `sa.status != UserStatus::Active`, which is the intended policy for SA token issuance
- `axiam/crates/axiam-api-rest/src/handlers/network_decide.rs:366`: The certificate-bound sibling runs authenticate_der and then separately requires account.status == Active. The PKI layer is not relied on for status
- `axiam/crates/axiam-api-rest/src/extractors/auth.rs:1662`: Machine-token extractor comment: revoking a machine is disabling the account, 'which the token-issuing paths check'. device_auth is a token-issuing path that does not
- `axiam/crates/axiam-db/src/repository/certificate.rs:1095`: get_bound_service_account selects only meta::id(out) from cert_bound_to, with no join or filter on service_account.status
- `axiam/crates/axiam-db/src/repository/service_account.rs:270`: The update sets status only. The binding and certificate are untouched
- `axiam/crates/axiam-core/src/models/service_account.rs:48`: UpdateServiceAccount.status is the field used to disable an account

**Blockers.**

- Workspace crates cannot be built or tested offline (no cargo registry, and no SurrealDB binary in the sandbox), so the 200 response for an Inactive service account at POST /api/v1/auth/device could not be observed. The missing check itself is fully source-visible.

**Validation plan.**

- *Local:* In axiam/crates/axiam-api-rest/tests/device_auth_test.rs, reuse the fixture that issues a Device certificate under an mtls_trust_anchor CA and binds it to a service account. Set that account to status Inactive via PUT /api/v1/service-accounts/{id} (or service_account_repo.update), then POST /api/v1/auth/device with the same peer certificate. Defect confirmed if the response is 200 with an access_token whose sub is the disabled SA. Control: client_credentials for the same SA returns invalid_client. Fix: in device_auth, load service_account_repo.get_by_id(cert_auth.tenant_id, cert_auth.service_account_id) and return 401 unless status == UserStatus::Active, mirroring network_decide.rs:362-368. The same test must return 401 after the fix.
- *Owner-observed:* The owner checks whether disabling a service account is the operational procedure for cutting off IoT devices without also revoking their certificates.

### N6. /oauth2/authorize accepts an access token AXIAM minted for one OAuth2 client as the user's authorization, letting its holder obtain a code, and with it tokens and a refresh token, for another public client without user interaction

- **Fingerprint:** `axiam-api-rest/oauth2-authorize-admits-client-minted-user-token`

Verified from source. The authorize handler (handlers/oauth2.rs:1663) takes MaybeAuthenticatedUser, which wraps AuthenticatedUser::from_request (extractors/auth.rs:420-429, Admit::AnyUserToken). That admits any axiam:user access token with a live session, from the axiam_access cookie or an Authorization Bearer/DPoP header. Code-grant and refresh-grant tokens carry client_id and sid=the authorizing session (axiam-oauth2/src/token.rs:2652-2660), so they pass the session check. resolve_authorize_principal Path 1 (handlers/oauth2.rs:653-664) returns only tenant_id, user_id and session_id. It never calls minted_for_client and never compares the token's client_id with the requested client. That check exists (extractors/auth.rs:414) and is applied on the device (ConsoleSignIn) and CIBA approval surfaces under T-447, whose scope note leaves 'other routes that act as the person' as a separate decision. AuthorizeService requires only a code_challenge from a public client (authorize.rs:371), which the token holder supplies, and asks for consent only for sensitive scopes or external (DCR/CIMD) clients. So a relying party X holding a user's X access token can call GET /oauth2/authorize for an admin-registered public client Y with Y's registered redirect_uri and its own PKCE challenge, read the code from the 302 Location header, and redeem it with its verifier. It receives Y's tokens and, if Y has the grant, a refresh token bound to the user's session. Calibration: X's token is already accepted as the user on /api/v1 (AnyUserToken), so the gain is client hopping (Y's scopes and audience) and persistence beyond X's 15-minute access token, up to session logout or the refresh lifetime. The gain is not new API reach as the user. A token X obtained for a non-AXIAM resource (aud != axiam:user) is refused by the audience check.

**Claimed root cause.** resolve_authorize_principal Path 1 (handlers/oauth2.rs:653-664) takes any AuthenticatedUser (Admit::AnyUserToken) and drops the token's client_id. It does not apply the minted_for_client refusal (extractors/auth.rs:414) that the approval surfaces device.rs (ConsoleSignIn) and ciba_approval.rs apply, although /oauth2/authorize likewise mints a grant in the person's name.

**Source trace.**

1. *entrypoint* `axiam/crates/axiam-api-rest/src/handlers/oauth2.rs:1663` (`authorize`): GET /oauth2/authorize (also under /t/{tenant}) takes MaybeAuthenticatedUser.
1. *propagation* `axiam/crates/axiam-api-rest/src/extractors/auth.rs:427` (`AuthenticatedUser::from_request`): extract_user plus handles.apply(.., Admit::AnyUserToken) admits a client-minted user token whose sid names a live session.
1. *propagation* `axiam/crates/axiam-api-rest/src/handlers/oauth2.rs:659` (`resolve_authorize_principal`): Path 1 returns tenant_id, user_id and session_id; client_id is never compared with q.client_id.
1. *propagation* `axiam/crates/axiam-oauth2/src/authorize.rs:371` (`AuthorizeService::authorize`): A public client needs only a code_challenge, which the token holder supplies. There is no consent gate for admin-registered clients without sensitive scopes.
1. *sink* `axiam/crates/axiam-oauth2/src/token.rs:2307` (`handle_authorization_code`): The code is redeemed for public client Y with the holder's verifier. This issues Y's access token and, if Y has the refresh_token grant, a refresh token bound to the victim's session.

**Evidence.**

- `axiam/crates/axiam-oauth2/src/token.rs:2652`: Code-grant access tokens carry client_id(Some(client_id)) and session(auth_code.session_id).
- `axiam/crates/axiam-api-rest/src/extractors/auth.rs:414`: minted_for_client() exists and is documented as the T-447 rule for approval surfaces.
- `axiam/crates/axiam-api-rest/src/handlers/device.rs:149`: Device decide uses ConsoleSignIn; /oauth2/authorize has no equivalent.
- `axiam/crates/axiam-api-rest/src/handlers/ciba_approval.rs:187`: CIBA approval refuses tokens that carry client_id.
- `axiam/crates/axiam-api-rest/src/handlers/oauth2.rs:605`: The doc comment confirms Path 1 accepts the axiam_access cookie or a Bearer/DPoP header.
- `axiam/claude_dev/threat-model-stride.md:1584`: The T-447 scope note limits the rule to approval surfaces; /oauth2/authorize is not decided there.

**Blockers.**

- No cargo registry offline: the end-to-end sequence (X's Bearer code-grant token, a 302 with a code for public client Y, then redemption) could not be executed locally.
- Exposure needs an admin-registered public client (token_endpoint_auth_method none) in the same tenant, without sensitive scopes, ideally holding the refresh_token grant. That is deployment configuration and is not visible in source.

**Validation plan.**

- *Local:* In the axiam-api-rest integration test harness, create a tenant, a dummy user, a confidential client X and a public client Y (auth method none, grants authorization_code+refresh_token, scope openid). Sign in and run the code flow for X to obtain X's access token. Call GET /oauth2/authorize?tenant_id=T&client_id=Y&redirect_uri=<Y's URI>&response_type=code&scope=openid&code_challenge=<S256(v)>&code_challenge_method=S256 with Authorization: Bearer <X token> and no cookies. Expected today: a 302 with a code. Then POST /oauth2/token with grant_type=authorization_code, client_id=Y, the code, code_verifier=v and redirect_uri; a refresh_token is expected. After the fix (apply minted_for_client in Path 1, or require that a token-borne principal's client_id is absent), authorize must answer 403 authorization_denied or treat the request as anonymous.
- *Owner-observed:* Owner check: per tenant, list admin-registered public clients (token_endpoint_auth_method none) that have the refresh_token grant and are not DCR/CIMD, to size exposure. No live requests are needed.

### N7. Password reset or change leaves the old OPAQUE record live under opaque_mode=optional, so the old password keeps signing in

- **Fingerprint:** `axiam-api-rest/opaque_enrollment/stale-opaque-record-survives-password-reset`

Under opaque_mode=optional, POST /api/v1/auth/reset/confirm (public, reset-token gated) and the authenticated password change both accept a request with no `opaque` field. validate_enrollment returns Ok(None) for (Optional, None). PasswordResetService::confirm_reset then rewrites only password_hash, revokes sessions and refresh tokens and resets lockout counters, and store_credential(None) returns Ok(()) without touching opaque_credential. No reset or change path deletes the existing record. OpaqueCredentialRepository::delete_for_user has no non-test caller; its documented uses (account deletion, admin reset) are not wired. The only OPAQUE-record DELETE outside it is the directory-link path in user.rs:1015. The schema has no DEFINE EVENT that would cascade. /auth/opaque/login/start loads the stored record by user (opaque.rs:172-175) with no freshness check against the password change, so a KE3 built from the pre-reset password should still complete a login through complete_authenticated_login (opaque.rs:332). A reset done because a password leaked therefore does not lock out a holder of the old password on the OPAQUE endpoint. MFA, where enrolled, still applies. The frontend omits the field when the browser has no OPAQUE/WASM support (opaque.ts:245), and SDK or API clients that do not build a record take the same path. The verifier confirmed every cited line.

**Claimed root cause.** store_credential (opaque_enrollment.rs:154-162) treats an absent enrollment as a no-op rather than deleting the now-stale record. confirm_reset (password_reset.rs:376) and change_password replace only the Argon2id hash. The invariant stated at auth.rs:1471-1475 (no window where the OPAQUE record still answers to the old password) holds only when a new record is supplied.

**Source trace.**

1. *entrypoint* `axiam/crates/axiam-api-rest/src/handlers/password_reset.rs:299` (`confirm_reset`): Public POST /api/v1/auth/reset/confirm with tenant_id, token, new_password and an optional opaque field
1. *propagation* `axiam/crates/axiam-api-rest/src/handlers/opaque_enrollment.rs:88` (`validate_enrollment`): (OpaqueMode::Optional, None) => Ok(None): a reset without a record is accepted
1. *propagation* `axiam/crates/axiam-auth/src/password_reset.rs:376` (`PasswordResetService::confirm_reset`): Writes only the new password_hash (after invalidating sessions and refresh tokens); opaque_credential is not touched
1. *propagation* `axiam/crates/axiam-api-rest/src/handlers/opaque_enrollment.rs:160` (`store_credential`): `let Some(enrolled) = enrolled else { return Ok(()) }` leaves the existing record in place
1. *sink* `axiam/crates/axiam-api-rest/src/handlers/opaque.rs:174` (`opaque_login_start`): get_by_user returns the still-stored pre-reset record and login_start runs against it. login_finish then reaches complete_authenticated_login (line 332)

**Evidence.**

- `axiam/crates/axiam-core/src/repository.rs:3984`: delete_for_user is documented for account deletion and admin reset. The only callers of any delete_for_user in non-test code are the SCIM-token, SAML session and logout-run repositories, never the OPAQUE one
- `axiam/crates/axiam-db/src/repository/opaque_credential.rs:257`: The deletion primitive exists but is not called on reset or change
- `axiam/crates/axiam-db/src/repository/user.rs:1015`: The only other DELETE FROM opaque_credential is in the directory-link transaction, which shows the pattern is known but not applied to reset or change
- `axiam/crates/axiam-api-rest/src/handlers/auth.rs:1471`: The change_password comment states the intended invariant, which the Ok(None)/early-return path does not uphold
- `axiam/frontend/src/services/opaque.ts:245`: buildEnrollment returns null (field omitted) when the browser cannot run OPAQUE

**Blockers.**

- The workspace cannot be built offline (no cargo registry, no SurrealDB binary), so the axiam-api-rest OPAQUE integration harness could not be run to observe the old password succeeding after a reset. The full exchange depends on the axiam-opaque crypto dependencies, so it cannot be reduced to a std-only harness.

**Validation plan.**

- *Local:* In axiam/crates/axiam-api-rest/tests/opaque_login_test.rs: set the tenant to opaque_mode=optional; enrol a record for the original password via the existing enroll_via_password_change helper; mint a reset token with initiate_reset; POST /api/v1/auth/reset/confirm with a new password and no `opaque` field (expect 200); then run the OPAQUE login exchange with the OLD password. Defect confirmed if login/finish returns 200 with session cookies. Control: the password login with the old password returns 401. Fix: when enrolled is None on reset or change and a record exists, call opaque_credential_repo.delete_for_user (or refuse the request); add a regression test.
- *Owner-observed:* The owner checks whether any organization or tenant runs opaque_mode=optional and whether users reset or change passwords from non-WASM browsers or SDKs that send no record.

### N8. Standard-tenant administrators can rewrite the organization security baseline inherited by sibling tenants

- **Fingerprint:** `axiam-api-rest/settings.set_org_settings/org-baseline-writable-by-ordinary-tenant-admin`

PUT /api/v1/organizations/{org_id}/settings writes the organization baseline that get_effective_settings merges into every tenant of the org. The handler's own comment (NEW-2, settings.rs:432) says a tenant admin must not be able to do this. The handler checks only RequirePermission organizations:update_settings in the acting tenant and org_id == user.org_id (settings.rs:436-450). It never calls require_organization_principal. organizations:update_settings is not in ORGANIZATION_LEVEL_ACTIONS, so seed_default_roles grants it to the super-admin and admin of every Standard tenant; this was re-checked in the sandbox. The existing test rbac_test.rs::org_settings_update_allows_org_settings_permission (line 647) asserts 200 for a user of a TenantKind::Standard tenant (rbac_test.rs:126), which pins the behaviour. A tenant-A admin can therefore weaken org-wide controls such as MFA enforcement, password policy, lockout and token lifetimes, and org-wide toggles such as SSF and OPAQUE mode. Every sibling tenant whose overrides are not stricter inherits the change. get_org_settings has the same gap for reads. A restricted organization principal also passes, because no reach check runs.

**Claimed root cause.** set_org_settings authorizes on a permission plus an org-equality check that every principal of the organization passes, and lacks the require_organization_principal guard (org_scope.rs:67) that other organization-level mutations use. organizations:update_settings is also absent from ORGANIZATION_LEVEL_ACTIONS (permission_scope.rs:64), so the seeder does not withhold it.

**Source trace.**

1. *entrypoint* `axiam/crates/axiam-api-rest/src/server.rs:981` (`route /organizations/{org_id}/settings`): PUT is routed to handlers::settings::set_org_settings; the caller is an authenticated admin of standard tenant A.
1. *propagation* `axiam/crates/axiam-api-rest/src/handlers/settings.rs:436` (`set_org_settings`): RequirePermission organizations:update_settings is evaluated in acting tenant A, where the seeded super-admin and admin hold it.
1. *propagation* `axiam/crates/axiam-api-rest/src/handlers/settings.rs:442` (`set_org_settings`): The only other gate is org_id == user.org_id. No require_organization_principal.
1. *sink* `axiam/crates/axiam-api-rest/src/handlers/settings.rs:507` (`set_org_settings`): settings_repo.set_org_settings(org_id, input) overwrites the org baseline, then reconcile_tenant_overrides runs across all tenants (line 521).

**Evidence.**

- `axiam/crates/axiam-api-rest/src/handlers/settings.rs:432`: The NEW-2 comment states the intended invariant: a tenant admin cannot rewrite the org baseline inherited by every sibling tenant.
- `axiam/crates/axiam-core/src/permission_scope.rs:64`: ORGANIZATION_LEVEL_ACTIONS omits organizations:update_settings.
- `axiam/crates/axiam-db/src/seeder.rs:527`: Only ORGANIZATION_LEVEL_ACTIONS are withheld from Standard-tenant super-admin and admin.
- `agents/v2-tenant-isolation/artifacts/seed_check_out.txt:2`: Sandbox re-check with lists extracted from source: organizations:update_settings in_registry=True org_level=False super-admin=True admin=True.
- `axiam/crates/axiam-api-rest/tests/rbac_test.rs:647`: org_settings_update_allows_org_settings_permission asserts 200 for a user of the Standard tenant created at line 126.
- `axiam/crates/axiam-api-rest/src/handlers/org_scope.rs:67`: require_organization_principal (B-04 scope guard) exists and is applied to the tenant, organization and CA mutations, but not here.
- `axiam/crates/axiam-db/src/repository/settings.rs:1133`: get_effective_settings starts from the org baseline and applies the tenant's sparse overrides.

**Blockers.**

- Workspace crates cannot be built or tested offline (no cargo registry, no SurrealDB instance), so the handler could not be run against two dummy tenants. The source trace and the seeder grant predicate were the only things checked locally. The rbac_test.rs case that asserts 200 could not be executed here.

**Validation plan.**

- *Local:* Next to rbac_test.rs::org_settings_update_allows_org_settings_permission, create an org with Standard tenants A and B, seeded through the tenant-create path, and give a dummy user of A A's seeded admin role. PUT /api/v1/organizations/{org}/settings with a weaker dummy body (for example mfa_enforced=false). Vulnerable result: 200, and get_effective_settings(org, B) reflects the weaker value. Expected after the fix: 403. The fix is to add require_organization_principal and to add organizations:update_settings to ORGANIZATION_LEVEL_ACTIONS. Then update the existing test to use an organization-scope tenant.
- *Owner-observed:* In staging, an owner checks whether the seeded admin role of a standard tenant holds organizations:update_settings, then sends a no-op PUT of the current org settings as that admin and observes 200 or 403.

### N9. A standard-tenant administrator can export the full audit trail of any sibling tenant in the same organization

- **Fingerprint:** `axiam-api-rest/tenants.export_audit/sibling-tenant-audit-export`

Merged from axiam-api-rest/tenants.export_audit/sibling-tenant-audit-export (h02) and tenants-export-audit-sibling-tenant (h12); both variants were verified and they describe the same root cause. POST /api/v1/organizations/{org_id}/tenants/{tenant_id}/audit-export streams every audit_log row of path.tenant_id as NDJSON, then appends a tenants.audit_exported receipt to that tenant's log. export_audit (tenants.rs:881-909) makes three checks: tenants:export_audit in the caller's acting tenant, path.org_id == user.org_id, and that the path tenant belongs to that org. It never calls require_organization_principal or require_organization_principal_for_tenant, and it never compares path.tenant_id with user.tenant_id. Its siblings update and delete do call the guard (tenants.rs:646, 714). tenants:export_audit is not in ORGANIZATION_LEVEL_ACTIONS, and every new Standard tenant is seeded from PERMISSION_REGISTRY (tenants.rs:304, 328), so that tenant's super-admin and admin hold it. This was re-checked in the sandbox with the predicates extracted from source. No extractor-level binding applies: enforce_tenant_path_binding acts only on the /t/{tenant} scope. An admin of tenant A can therefore read tenant B's whole trail: actor ids, resource ids, IP addresses, actions and metadata. The receipt it writes into B's log also satisfies the freshness precondition of tenant delete, but delete itself stays org-guarded. tenants::get (tenants.rs:585) has the same unbound path tenant, which exposes sibling tenant metadata. A restricted organization principal (tenant_scope limited to T1) also passes the checks for T2, because no reach check runs.

**Claimed root cause.** export_audit, and also tenants::get, authorize only on a permission plus an org-equality check that every principal of the organization passes. Neither binds path.tenant_id to the caller's tenant or to principal_tenant_reach (require_organization_principal_for_tenant, org_scope.rs:199). tenants:export_audit is also missing from ORGANIZATION_LEVEL_ACTIONS (permission_scope.rs:64), so the seeder does not withhold it from standard-tenant roles (seeder.rs:527).

**Source trace.**

1. *entrypoint* `axiam/crates/axiam-api-rest/src/server.rs:1024` (`route /organizations/{org_id}/tenants/{tenant_id}/audit-export`): POST is routed to handlers::tenants::export_audit; the caller is an authenticated admin of standard tenant A.
1. *propagation* `axiam/crates/axiam-api-rest/src/handlers/tenants.rs:887` (`export_audit`): RequirePermission tenants:export_audit is evaluated in acting tenant A, where the seeded super-admin and admin hold it.
1. *propagation* `axiam/crates/axiam-api-rest/src/handlers/tenants.rs:892` (`export_audit`): Only path.org_id == user.org_id is checked, and A and B share the org; then tenant B is loaded and its organization_id compared with org_id. No tenant binding and no org-principal guard.
1. *propagation* `axiam/crates/axiam-api-rest/src/handlers/tenants.rs:909` (`export_audit`): audit_export_response is called with the caller-chosen path.tenant_id (B).
1. *sink* `axiam/crates/axiam-api-rest/src/handlers/tenants.rs:955` (`audit_export_response`): audit_repo.list(tenant_id = B, ...) pages every B row into the response body, and a receipt is appended to B's log.

**Evidence.**

- `axiam/crates/axiam-api-rest/src/handlers/tenants.rs:714`: delete calls require_organization_principal (update does too, at line 646); export_audit, at lines 881-909, does not.
- `axiam/crates/axiam-api-rest/src/handlers/org_scope.rs:199`: require_organization_principal_for_tenant exists to check that the caller's reach covers a named tenant, and is not used by export_audit.
- `axiam/crates/axiam-core/src/permission_scope.rs:64`: ORGANIZATION_LEVEL_ACTIONS lists tenants:create, update and delete, but not tenants:export_audit.
- `axiam/crates/axiam-db/src/seeder.rs:527`: withheld() holds back only ORGANIZATION_LEVEL_ACTIONS; admin_may_hold (line 603) allows everything except admin:bootstrap and network:*.
- `agents/v2-tenant-isolation/artifacts/seed_check_out.txt:1`: Re-run in the sandbox, with the action lists extracted from source: tenants:export_audit in_registry=True org_level=False super-admin=True admin=True, against the control tenants:delete super-admin=False admin=False.
- `axiam/crates/axiam-api-rest/src/handlers/tenants.rs:443`: The tenants::list rationale states that a tenant administrator's reach is one tenant, and that disclosing even sibling slugs is something the isolation boundary must prevent.
- `axiam/crates/axiam-api-rest/src/handlers/email_config.rs:298`: Comparable per-tenant handlers bind tenant_id != user.tenant_id to a 403.
- `axiam/crates/axiam-api-rest/src/extractors/auth.rs:1112`: enforce_tenant_path_binding returns Ok when there is no /t/{tenant} binding, so it gives no protection on /api/v1/organizations/... routes.
- `axiam/crates/axiam-api-rest/tests/tenant_test.rs:811`: The negative export test covers only a cross-org path; no test covers a same-org sibling tenant.

**Blockers.**

- Workspace crates cannot be built or tested offline (no cargo registry, no SurrealDB instance), so the handler could not be run against two dummy tenants. The source trace and the seeder grant predicate were the only things checked locally.

**Validation plan.**

- *Local:* In axiam-api-rest/tests/tenant_test.rs (in-memory SurrealDB), create one org with Standard tenants A and B through the tenant-create path, so both are seeded from PERMISSION_REGISTRY. Write one dummy audit row in B. Mint a token for a dummy user of A holding A's seeded admin role (no X-Axiam-Tenant). POST /api/v1/organizations/{org}/tenants/{B}/audit-export. Vulnerable result: 200, the NDJSON contains B's row, and B now has a tenants.audit_exported receipt. Expected after the fix: 403. The fix is to call require_organization_principal_for_tenant(&user, &state, path.tenant_id) and to add tenants:export_audit to ORGANIZATION_LEVEL_ACTIONS. Repeat with GET /api/v1/organizations/{org}/tenants/{B} for the metadata variant.
- *Owner-observed:* In staging, an owner checks whether the seeded admin role of a standard tenant holds tenants:export_audit, then runs the export as that admin against a dummy sibling tenant and observes 200 or 403. Do not use production tenants.

### N10. WebAuthn ceremony state JWTs pass validate_access_token and are admitted as user tokens by verifiers with no session check (default gRPC interceptor, gRPC ValidateToken, token exchange, UMA claim_token)

- **Fingerprint:** `axiam-auth/webauthn-state-token-accepted-as-access-token`

Verified from source (merged from the h11-crypto, h01-rest-authn and h16-obvious-wildcard variants; all three describe the same root cause and none was refuted). WebauthnService::encode_state_token_json signs ceremony state tokens with the access-token Ed25519 key (jwt_private_key_pem) under a plain EdDSA header. Their claims are sub, tenant_id, org_id, purpose, state, jti (random v4), iss=config.jwt_issuer, iat and exp=now+mfa_challenge_lifetime_secs (default 300 s). There is no aud and no typ. AccessTokenClaims requires exactly sub, tenant_id, org_id, iss, iat, exp and jti; every other field is an Option or #[serde(default)] (sub_kind defaults to User), and there is no deny_unknown_fields. decode_access_token requires only sub/exp/iat/iss, and the code comment plus the in-repo tests (extractors/auth.rs accepts_missing_aud_when_flag_true, and the gRPC interceptor's explicit aud=None branch) treat an absent aud as passing set_audience. The iss check pins root_issuer(), which is oauth2_issuer_url if set and otherwise jwt_issuer. So a state token validates whenever jwt_issuer equals the effective root issuer: both unset (default 'axiam'), or both set to the same URL as the commented k8s/server/configmap.yml example shows. The compose files set only OAUTH2_ISSUER_URL, so there the state token's iss='axiam' does not match and it is refused. There are two ways to obtain one. (a) POST /api/v1/auth/webauthn/authenticate/discoverable/start is in PUBLIC_PATHS and needs only an org/tenant slug or id; it returns a token with sub=nil UUID for that tenant (the WebAuthn encryption key must be configured). (b) POST /api/v1/auth/webauthn/authenticate/start returns a token with sub=<user> to anyone holding that user's MFA challenge token, i.e. after the password factor only. On REST, AuthenticatedUser refuses it only through is_session_active (extractors/auth.rs:619), because the random jti names no session. Verifiers with no session check: the gRPC AuthInterceptor (aud=None admitted while allow_missing_aud_as_user=true, the default; GrpcConfig.strict_revocation defaults to false), gRPC TokenService.ValidateToken (returns valid=true, subject_id=sub), the RFC 8693 subject_token (token_exchange.rs:643, decode_access_token only; this needs a client allowed to exchange) and the UMA claim_token (handlers/oauth2.rs:4830). IntrospectToken additionally runs subject_may_act, which refuses the nil-sub token but would accept a token naming a real active victim. The hunters' claim of an anonymous principal in 'any tenant' is narrowed here: the caller must know or guess the org/tenant slug or id.

**Claimed root cause.** There is no token-type separation between AXIAM access tokens and other JWTs signed with the same key and issuer. WebauthnStateClaims carries a superset of AccessTokenClaims' required fields, decode_access_token checks no typ/aud/purpose discriminator, and aud-less tokens are admitted for D-20 back-compat (token.rs:1714-1718, config.rs:739 allow_missing_aud_as_user=true). State tokens are minted with jwt_private_key_pem and iss=jwt_issuer (webauthn.rs:653, 658). The REST surface is protected only incidentally, by the session-row lookup.

**Source trace.**

1. *entrypoint* `axiam/crates/axiam-api-rest/src/handlers/webauthn.rs:900` (`start_discoverable_authentication`): Public route (PUBLIC_PATHS permissions.rs:536, server.rs:464). It resolves (tenant_id, org_id) from caller-supplied slugs or ids and returns state_token with no credential.
1. *propagation* `axiam/crates/axiam-auth/src/webauthn.rs:410` (`WebauthnService::start_discoverable_authentication`): encode_state_token(Uuid::nil(), tenant_id, org_id, PURPOSE_AUTHENTICATE_DISCOVERABLE, ..). The MFA variant at line 367 passes sub=user_id after the password factor only.
1. *propagation* `axiam/crates/axiam-auth/src/webauthn.rs:653` (`encode_state_token_json`): iss=config.jwt_issuer, random jti, no aud. Line 658 signs with EncodingKey::from_ed_pem(jwt_private_key_pem), the access-token key, under Header::new(EdDSA).
1. *propagation* `axiam/crates/axiam-auth/src/token.rs:1714` (`decode_access_token`): Required spec claims are sub/exp/iat/iss only. set_audience (line 1718) is not enforced for an absent aud. The claims deserialize into AccessTokenClaims (line 46), whose required fields the state token all carries.
1. *propagation* `axiam/crates/axiam-api-grpc/src/middleware/auth.rs:61` (`AuthInterceptor::call`): aud=None is admitted with a warning while allow_missing_aud_as_user is true. ValidatedClaims are inserted with no session check; strict_revocation defaults to false (axiam-api-grpc/src/config.rs:118).
1. *sink* `axiam/crates/axiam-api-grpc/src/services/token.rs:99` (`TokenService::validate_token`): validate_access_token on the presented state token returns valid=true with subject_id=claims.sub. UserService.get_user (services/user.rs:120) also runs for the nil-sub principal in the chosen tenant.

**Evidence.**

- `axiam/crates/axiam-auth/src/webauthn.rs:131`: WebauthnStateClaims: sub, tenant_id, org_id, purpose, state, jti, iss, iat, exp. No aud and no typ.
- `axiam/crates/axiam-auth/src/token.rs:67`: AccessTokenClaims.jti is a required String. The remaining fields are Option or serde(default), and the struct has no deny_unknown_fields.
- `axiam/crates/axiam-auth/src/token.rs:1713`: 'Do NOT require aud'. No typ or purpose check exists.
- `axiam/crates/axiam-auth/src/config.rs:492`: root_issuer() returns oauth2_issuer_url when it is set, otherwise jwt_issuer. Defaults: jwt_issuer 'axiam' (line 714), oauth2_issuer_url empty (line 715), allow_missing_aud_as_user true (line 739), mfa_challenge_lifetime_secs 300 (line 741).
- `axiam/crates/axiam-api-rest/src/extractors/auth.rs:619`: The only REST barrier is is_session_active(principal_tenant_id, session_id); session_id falls back to the state token's random jti.
- `axiam/crates/axiam-api-rest/src/extractors/auth.rs:1825`: The unit test accepts_missing_aud_when_flag_true shows that an aud-less token signed with the access key passes the decoder under jsonwebtoken 11.1.0 (Cargo.lock), the workspace version.
- `axiam/crates/axiam-oauth2/src/token_exchange.rs:643`: subject_token is verified with decode_access_token only, with no session or aud requirement.
- `axiam/crates/axiam-api-rest/src/handlers/oauth2.rs:4830`: The UMA claim_token is verified with validate_access_token only, and its sub becomes the requesting party.
- `axiam/k8s/server/configmap.yml:200`: The commented guidance sets JWT_ISSUER and OAUTH2_ISSUER_URL to the same URL (line 206), which meets the issuer-equality condition. docker-compose.minimal.yml:167 sets only OAUTH2_ISSUER_URL, which does not meet it.

**Blockers.**

- No cargo registry offline: jsonwebtoken 11.1.0, serde and the workspace crates cannot be built, so validate_access_token was not executed on a real WebauthnService state token. The aud-absent behaviour rests on the in-repo code comment, the interceptor's explicit aud=None branch and the accepts_missing_aud_when_flag_true test, not on an observed run.
- Exposure depends on deployment: jwt_issuer must equal root_issuer() (OAUTH2_ISSUER_URL unset, or equal to JWT_ISSUER); gRPC strict revocation and allow_missing_aud_as_user must be at their defaults; the gRPC listener must be reachable by the attacker; and the WebAuthn encryption key must be configured for discoverable start.

**Validation plan.**

- *Local:* In an environment with the cargo registry, add an axiam-auth unit test. Build an AuthConfig with jwt_issuer='axiam-test', empty oauth2_issuer_url and the test Ed25519 keypair plus an MFA encryption key, and a WebauthnService over a mock credential repository. Call start_discoverable_authentication(T, O) and assert that axiam_auth::token::validate_access_token(&state_token, &config) is Err. The expected result today is Ok, with aud None, sub 00000000-0000-0000-0000-000000000000 and tenant_id T. Repeat for start_authentication (sub=user). Then, in axiam-api-grpc/tests, pass the token as 'Bearer' through AuthInterceptor::call and TokenServiceImpl::validate_token with the default AuthConfig: Ok and valid=true are expected today. Regression after the fix: all of these refuse. Suggested fix: give state, MFA and setup tokens a distinct typ or aud, require typ at+jwt or an AXIAM aud in decode_access_token, and default allow_missing_aud_as_user to false.
- *Owner-observed:* An owner, on a non-production instance whose JWT_ISSUER equals its effective root issuer (or where neither is set), POSTs to /api/v1/auth/webauthn/authenticate/discoverable/start for a dummy tenant. They then call gRPC axiam.v1.TokenService/ValidateToken with that state_token as both the bearer and access_token, and record whether valid=true is returned. No real user is involved.

### N11. Cancelling an erasure request sets the account Active regardless of its prior status, undoing an administrator's suspension

- **Fingerprint:** `axiam-db/account_deletion/cancel-restores-active-over-prior-status`

POST /api/v1/account/delete lets the subject, or an administrator with users:erase acting on any user_id, mark an account deletion-pending. create_with_pending_flag sets status='Inactive' in the same transaction and does not record the previous status; the request handler applies no status precondition. The cancel link (raw 256-bit token) is mailed to the target user's own address (gdpr.rs:599-606). The public GET /api/v1/auth/account/delete/cancel looks the token up globally and runs cancel_tx, which sets status='Active' unconditionally. An account that was Inactive, Locked or PendingVerification before an admin-filed erasure (for example a suspended user whose data-subject request an admin files for them, which gdpr.rs describes as the purpose of the user_id parameter) is therefore re-activated by the subject following the link. It keeps its existing password and factors. A PendingVerification account would also skip email verification. The verifier confirmed both SurrealQL statements and the public-path entry from source.

**Claimed root cause.** cancel_tx (account_deletion.rs:370-372) restores a hard-coded 'Active' instead of the status the account had before the request, and create_with_pending_flag (account_deletion.rs:211-215) overwrites status without persisting the prior value on the account_deletion row.

**Source trace.**

1. *entrypoint* `axiam/crates/axiam-api-rest/src/handlers/gdpr.rs:514` (`request_account_delete`): A caller with users:erase may target another user_id; there is no check of the target's current status
1. *propagation* `axiam/crates/axiam-db/src/repository/account_deletion.rs:214` (`create_with_pending_flag`): Overwrites status with 'Inactive'; the prior status is not stored
1. *propagation* `axiam/crates/axiam-api-rest/src/handlers/gdpr.rs:606` (`request_account_delete`): The cancel link is mailed to target_user.email, the subject's own address
1. *propagation* `axiam/crates/axiam-api-rest/src/handlers/gdpr.rs:680` (`cancel_account_delete`): The public endpoint (token-only) calls cancel_pending for the globally looked-up deletion row
1. *sink* `axiam/crates/axiam-db/src/repository/account_deletion.rs:371` (`cancel_tx`): Sets deletion_pending=false, scheduled_purge_at=NONE and status='Active' unconditionally

**Evidence.**

- `axiam/crates/axiam-api-rest/src/permissions.rs:696`: /api/v1/auth/account/delete/cancel is a public path; possession of the mailed token is the only credential
- `axiam/crates/axiam-db/src/repository/account_deletion.rs:371`: Hard-coded `status = 'Active'` in the cancel transaction
- `axiam/crates/axiam-core/src/models/user.rs:8`: UserStatus includes Inactive, Locked and PendingVerification, the distinct prior states that cancel collapses to Active

**Blockers.**

- The workspace cannot be built offline and there is no SurrealDB binary locally, so the account_deletion repository transaction could not be executed to observe status flipping to Active.
- Whether operators file erasure requests for already-suspended or unverified accounts, and whether those subjects still receive mail, is a process fact outside source.

**Validation plan.**

- *Local:* In axiam-db account_deletion repository tests (in-memory SurrealDB): create a user, update status to Locked (and separately Inactive, PendingVerification), call create_with_pending_flag, then cancel_pending. Defect confirmed if the user's status reads Active afterwards. Fix: store the pre-request status on the account_deletion row (or a user field) inside the same transaction and restore it in cancel_tx; add a regression test per prior status.
- *Owner-observed:* The owner checks whether admin-initiated erasure is used on suspended or unverified accounts and whether the cancel mail reaches those subjects.

### N12. Kotlin Ktor guard accepts the axiam_access cookie on state-changing requests without the section 3a double-submit CSRF check

- **Fingerprint:** `axiam-kotlin-sdk:ktor/cookie-credential-missing-inbound-csrf`

Source confirms this. extractToken falls back to the axiam_access cookie without recording where the credential came from. The AxiamAuthentication onCall verifies the token and injects the AxiamUser for every HTTP method. requireAuth, requireRole, requireAccess and enforce never compare X-CSRF-Token with axiam_csrf. The comment in enforce says state-changing methods are handled identically. Nothing in the Kotlin SDK's main sources implements an inbound CSRF check (grep). CONTRACT section 3a makes the check mandatory for cookie-sourced credentials on non-safe methods and tells SDKs not to rely on host-framework CSRF protection. The sibling Java Spring filter implements it. Because axiam_access is SameSite=Strict with Path=/, the browser still sends it on same-site, cross-origin requests. So a page on an attacker-controlled same-site origin could submit a form POST that the Ktor app executes as the victim, wherever that cookie reaches the app.

**Claimed root cause.** AxiamAuthentication.onCall and the section 11 helpers do not distinguish a cookie-sourced credential from a header-sourced one. They never apply the section 3a check (X-CSRF-Token must equal axiam_csrf, compared in constant time) on POST, PUT, PATCH or DELETE.

**Source trace.**

1. *entrypoint* `axiam-kotlin-sdk/src/main/kotlin/io/axiam/sdk/ktor/AxiamAuthentication.kt:177` (`extractToken`): With no Bearer header, the axiam_access cookie is returned as the credential and its source is not recorded.
1. *propagation* `axiam-kotlin-sdk/src/main/kotlin/io/axiam/sdk/ktor/AxiamAuthentication.kt:107` (`AxiamAuthentication onCall`): The cookie token is verified and AxiamUser is injected regardless of HTTP method. There is no CSRF branch.
1. *propagation* `axiam-kotlin-sdk/src/main/kotlin/io/axiam/sdk/ktor/AxiamAuthentication.kt:270` (`ApplicationCall.enforce`): requireAuth succeeds on the injected user. The comment at line 280 says state-changing calls are handled identically.
1. *sink* `axiam-kotlin-sdk/src/main/kotlin/io/axiam/sdk/ktor/AxiamAuthentication.kt:205` (`ApplicationCall.requireRole / requireAccess`): The guarded handler runs as the cookie's user with no CSRF proof.

**Evidence.**

- `axiam-kotlin-sdk/CONTRACT.md:382`: Section 3a: every SDK's resource-server middleware MUST enforce the cookie double-submit check for cookie-sourced credentials on state-changing methods and reject with 403.
- `axiam-java-sdk/src/main/java/io/axiam/sdk/spring/AxiamAuthenticationFilter.java:200`: The Java guard implements exactly this check: fromCookie, a non-safe method and isCsrfValid, otherwise 403.
- `axiam/crates/axiam-api-rest/src/middleware/csrf.rs:397`: axiam_access is SameSite=Strict; Path=/, so the browser sends it on same-site, cross-origin requests.
- `axiam-kotlin-sdk/src/main/kotlin/io/axiam/sdk/ktor/AxiamAuthentication.kt:50`: The KDoc states that Ktor has no equivalent authorization layer behind this plugin, so an omission here is not caught anywhere else.

**Blockers.**

- Exploitability depends on deployment topology that source does not show. The axiam_access cookie must reach the Ktor application, for example because it runs on the same host as AXIAM, and the attacker must control a same-site origin. The application must also not install its own CSRF plugin.
- kotlinc and the Ktor and nimbus dependencies are absent locally, so the plugin could not be run.

**Validation plan.**

- *Local:* With dependencies available, build a Ktor testApplication with AxiamAuthentication (test JWKS) and a POST route guarded by requireAuth(). Send a POST with Cookie: axiam_access=<valid test token>; axiam_csrf=x and no X-CSRF-Token header. Section 3a expects 403; source predicts 200. As a control, sending the same request with X-CSRF-Token: x should also return 200.
- *Owner-observed:* Owner check, read-only: confirm whether any Ktor application using AxiamAuthentication is served on a host or same-site origin that receives the axiam_access cookie, and whether it installs Ktor's CSRF plugin.

### N13. SSRF guard's IP pin can be bypassed when the server runs with HTTP(S)_PROXY/ALL_PROXY set, because the guarded reqwest client keeps env-proxy discovery on

- **Fingerprint:** `axiam-pki/ssrf/pinned_client-honours-env-proxy`

pinned_client (ssrf.rs:251-257) builds each guarded-fetch client with ClientBuilder::resolve(host, validated_ip), redirect Policy::none and a 10 s timeout, and never calls .no_proxy(). Both guarded_fetch (ssrf.rs:314-318) and guarded_fetch_no_redirect (ssrf.rs:378-381) use it. Every outbound fetch to a URL a tenant admin or IdP supplies goes through these functions: webhook delivery (webhook.rs:301), SSF push (ssf_delivery.rs:458), JWKS (jwks_cache.rs:255) and CIMD (cimd.rs:842). If reqwest 0.12.28 (Cargo.lock:6874-6875) reads proxy env vars by default, as upstream documents, then in a deployment where the axiam-server process has a proxy variable set, the TCP connection goes to the proxy. The target is then named by hostname (CONNECT host:443), so the proxy resolves it again and the validated-IP pin does not decide the destination. resolve_and_pick still checks AXIAM's own lookup (ssrf.rs:195-245), so an attacker needs a name that answers AXIAM with a public address and the proxy with an internal one, i.e. DNS rebinding or split-horizon. This breaks the module's stated invariant (ssrf.rs:24-27). The repository's own test client calls .no_proxy() (provider_id_token_test.rs:304). No compose, k8s or doc file sets or warns about proxy variables. This is not confirmed: the reqwest source is not available offline, and whether production sets a proxy, and what that proxy can reach, is deployment state.

**Claimed root cause.** axiam/crates/axiam-pki/src/ssrf.rs pinned_client (lines 251-257) relies on reqwest's resolve() override for IP pinning but leaves reqwest's default automatic env/system proxy enabled. In a proxied deployment the final destination is chosen by the proxy's own DNS resolution, not by the validated IP.

**Source trace.**

1. *entrypoint* `axiam/crates/axiam-api-rest/src/webhook.rs:301` (`WebhookDeliveryService::deliver_once`): The stored webhook.url, chosen by a tenant admin, is passed to guarded_fetch_no_redirect. Other entry points: jwks_cache.rs:255, cimd.rs:842, ssf_delivery.rs:458.
1. *propagation* `axiam/crates/axiam-pki/src/ssrf.rs:378` (`guarded_fetch_no_redirect`): resolve_and_pick resolves the host with tokio lookup_host and refuses any non-global address.
1. *propagation* `axiam/crates/axiam-pki/src/ssrf.rs:253` (`pinned_client`): The validated IP is passed to ClientBuilder::resolve(host, ip). There is no .no_proxy() call, so reqwest's default env-proxy discovery stays active.
1. *sink* `axiam/crates/axiam-pki/src/ssrf.rs:380` (`guarded_fetch_no_redirect`): build_request(&client, url).send(): with a proxy configured, the connection goes to the proxy and the target is named by hostname, so the proxy re-resolves it and the pin does not apply.

**Evidence.**

- `axiam/crates/axiam-pki/src/ssrf.rs:251`: pinned_client builder: resolve(), redirect(Policy::none()), timeout(10s), build(). No no_proxy().
- `axiam/crates/axiam-pki/src/ssrf.rs:24`: Module contract step 3: the socket actually opened is the one that was validated, not an independently resolved address.
- `axiam/Cargo.toml:137`: reqwest 0.12 with default-features=false and features json and rustls-tls; Cargo.lock:6875 pins 0.12.28. Env-var proxy reading is not gated behind any feature listed here.
- `axiam/crates/axiam-api-rest/tests/provider_id_token_test.rs:304`: The repository's own test HTTP client calls .no_proxy(); the production guard client does not.

**Blockers.**

- The reqwest 0.12.28 / hyper-util source is not present offline (no cargo registry), so default env-proxy behaviour and how resolve() interacts with a proxied connection cannot be observed locally.
- Whether a production axiam-server process has HTTP_PROXY/HTTPS_PROXY/ALL_PROXY set, and whether that proxy will CONNECT to link-local, RFC 1918 or loopback destinations after its own DNS resolution, is deployment configuration that is not in source.

**Validation plan.**

- *Local:* In an environment with the cargo registry, add a test in axiam-pki that starts a loopback CONNECT proxy fixture which only logs the requested authority and closes. Set HTTPS_PROXY=http://127.0.0.1:<port> for that test process. Call guarded_fetch_no_redirect("https://<test-name>/", false, |c,u| c.get(u)) where <test-name> resolves to a public documentation-range address via a stub resolver. Today the expected observation is that the proxy logs CONNECT <test-name>:443 (hostname, not the pinned IP). After adding .no_proxy() to pinned_client, the proxy should see no connection.
- *Owner-observed:* Owner checks the axiam-server process environment (k8s Deployment env, systemd unit, container env) for HTTP_PROXY, HTTPS_PROXY or ALL_PROXY, in either case. If one is present, the owner checks that the proxy refuses CONNECT to link-local (169.254.0.0/16, fd00:ec2::254), RFC 1918 and loopback destinations after its own resolution.

### N14. Rust SDK guard with default configuration would accept AXIAM MFA-challenge and WebAuthn-state JWTs as access tokens

- **Fingerprint:** `axiam-rust-sdk:jwks:aud-optional-kidless-fallback-accepts-purpose-jwts`

Source confirms each link in the chain. The server signs its purpose JWTs with the same Ed25519 key as access tokens (config.jwt_private_key_pem) under Header::new(EdDSA). That header has no kid, and the tokens carry no aud. They are the MFA challenge (sub=user, tenant_id, iss, exp, purpose), returned after the password step when MFA is enabled, and the mfa_setup token. They also include the WebAuthn state token, which the public discoverable-start endpoint returns to anonymous callers with sub set to the nil UUID. The Rust SDK's JwksVerifier has expected_audience None by default and then sets validate_aud=false. Its only required claim is exp. For a token with no kid, find_jwk falls back to the single JWKS key, and the server's JWKS always has exactly one key. Claims deserialization needs only sub, tenant_id, iss and exp, which these tokens carry, and the extra purpose claim is ignored. assert_tenant passes for the same tenant. Revocation is skipped without a sid, and rule 9 passes without a cnf. So the actix AxiamUser extractor would admit an MFA challenge, letting a password-only attacker in as the victim user before the second factor, and the anonymous discoverable state token as the nil-UUID user of the tenant. Lifetime is mfa_challenge_lifetime_secs, 300 s by default.

**Claimed root cause.** The Rust SDK verifier skips aud when no expectation is configured, which is the default, and find_jwk falls back to the single key when kid is absent. The server mints purpose tokens with the access-token key without aud, kid or typ separation. The SDK also does not reject a purpose claim.

**Source trace.**

1. *entrypoint* `axiam/crates/axiam-api-rest/src/handlers/webauthn.rs:900` (`start_discoverable_authentication`): A public endpoint returns a state token signed with the access-token key and with sub set to the nil UUID (axiam-auth/src/webauthn.rs:409, header at :660).
1. *propagation* `axiam/crates/axiam-auth/src/service.rs:754` (`AuthService login (MFA branch)`): After a correct password for an MFA user, issue_mfa_challenge returns a token with sub, tenant_id, iss and exp, a header with no kid, and no aud (service.rs:1889-1912).
1. *propagation* `axiam-rust-sdk/src/middleware/actix.rs:451` (`AxiamUser::from_request`): The presented token is passed to verify_with_proofs.
1. *propagation* `axiam-rust-sdk/src/token/jwks.rs:1158` (`JwksVerifier::decoding_key_for`): find_jwk is called with kid None, and the single-key fallback at line 1391 selects the server key.
1. *sink* `axiam-rust-sdk/src/token/jwks.rs:1126` (`JwksVerifier::verify_claims`): With no expected audience, validate_aud=false. Only exp is required, so a purpose token decodes into Claims.

**Evidence.**

- `axiam-rust-sdk/src/token/jwks.rs:1391`: Single-key fallback for a token with no kid.
- `axiam-rust-sdk/src/token/jwks.rs:552`: The default builder sets expected_audience: None.
- `axiam/crates/axiam-auth/src/service.rs:1910`: The MFA challenge header is Header::new(EdDSA): no kid. The claims struct (service.rs:197) has no aud.
- `axiam/crates/axiam-auth/src/token.rs:495`: Access tokens carry a kid derived from the same public key, so both kinds of token verify under the one JWKS key.

**Blockers.**

- The Rust SDK cannot be built offline: no cargo registry, and jsonwebtoken 11 is not vendored. The exact decode and Claims deserialization of a purpose-shaped token could not be executed.
- Impact applies only where the application does not call expect_audience(...), which is the default. The WebAuthn variant also requires WebAuthn to be enabled. Whether real applications set expect_audience cannot be seen from source.

**Validation plan.**

- *Local:* With a cargo registry available, add a test to axiam-rust-sdk. Generate a dummy Ed25519 key, serve a one-key JWKS whose entry has a kid, and mint a token with no kid in the header whose claims are {sub:<uuid>, tenant_id:<tenant>, org_id, purpose:'mfa_challenge', iss, iat, exp:now+300}, with no aud. Call JwksVerifier::verify with only expect_tenant_id. The vulnerable result is Ok(claims). Repeat with sub set to the nil UUID and purpose 'webauthn_authenticate_discoverable'. A control with expect_audience("axiam:user") should return Err.
- *Owner-observed:* Owner check, read-only: review applications built on axiam-rust-sdk and confirm whether each JwksVerifier is built with expect_audience(...). Any guard without it accepts purpose tokens.

### N15. Java, Kotlin and PHP require_role guards authorize on client-requested OAuth2 scopes instead of the caller's tenant roles

- **Fingerprint:** `axiam-sdks:require-role-derived-from-scope`

I checked all three variants against source: Java (Spring), Kotlin (Ktor) and PHP (Laravel and Symfony). All three are confirmed and none was refuted. Java: AxiamAuthenticationFilter turns each value of the verified token's scope claim into a SimpleGrantedAuthority with no prefix (scopeToAuthorities). AxiamAuthorizationInterceptor.hasAnyRole then grants @AxiamRequireRole(x) when an authority equals x or ROLE_x. Kotlin: verifySession builds AxiamUser.roles by splitting the scope claim, although Models.kt documents roles as 'the user's roles within tenantId'. requireRole and enforce(@AxiamRequireRole) test membership in that list. PHP: AxiamMiddleware and AxiamAuthSubscriber both use rolesFromClaims, which reads roles ?? scope. The server never emits a roles claim (AccessTokenClaims has scope and no roles field), so AccessEnforcer::enforceRole always compares against scopes. On the server, the scope is bounded only by the client's registered scopes and the DCR ceiling (authorize.rs), never by the user's role assignments. So any tenant user who can complete a flow with a client whose registered scope has the same name as an application role passes that role guard. A real role holder whose token lacks that scope is refused. The hunter's sandboxed Java harness reproduced the decision logic: a roleless user with scope 'openid admin' was allowed, and an admin with scope 'openid profile' was denied (agents/s03-java-kotlin/artifacts/rolescope/output.txt). I did not re-run the frameworks end to end because the Spring, Ktor and Symfony dependencies are absent.

**Claimed root cause.** The three SDKs map the per-client, user-agnostic OAuth2 scope claim onto the identity's roles. CONTRACT section 11 require_role is defined over the verified token's roles, and the server issues no roles claim. So require_role silently becomes require_scope.

**Source trace.**

1. *entrypoint* `axiam-java-sdk/src/main/java/io/axiam/sdk/spring/AxiamAuthenticationFilter.java:224` (`AxiamAuthenticationFilter.doFilterInternal`): The Bearer or cookie token is verified for the configured tenant (signature, exp, tenant_id, cnf) and its claims are returned.
1. *propagation* `axiam-java-sdk/src/main/java/io/axiam/sdk/spring/AxiamAuthenticationFilter.java:267` (`scopeToAuthorities`): Each space-separated scope value becomes a GrantedAuthority verbatim. These are the only authorities set on the SecurityContext (line 227).
1. *propagation* `axiam-java-sdk/src/main/java/io/axiam/sdk/spring/AxiamAuthorizationInterceptor.java:358` (`hasAnyRole`): @AxiamRequireRole (line 198) grants when a scope string equals the role or ROLE_ plus the role.
1. *propagation* `axiam-kotlin-sdk/src/main/kotlin/io/axiam/sdk/AxiamClient.kt:1511` (`AxiamClient.verifySession`): AxiamUser.roles is set to the scope claim split on whitespace. The Ktor plugin calls this at AxiamAuthentication.kt:107.
1. *propagation* `axiam-kotlin-sdk/src/main/kotlin/io/axiam/sdk/ktor/AxiamAuthentication.kt:206` (`ApplicationCall.requireRole`): Access is granted when any required role is in user.roles, which holds scope values. enforce() delegates @AxiamRequireRole here at line 273.
1. *propagation* `axiam-php-sdk/src/Laravel/AxiamMiddleware.php:252` (`AxiamMiddleware::rolesFromClaims`): The identity's roles are set to roles ?? scope. The scope string is split on spaces. Symfony does the same at AxiamAuthSubscriber.php:272.
1. *sink* `axiam-php-sdk/src/AccessEnforcer.php:166` (`AccessEnforcer::enforceRole`): array_intersect of the required roles with the identity's scope-derived roles decides access.

**Evidence.**

- `axiam/crates/axiam-auth/src/token.rs:123`: AccessTokenClaims carries scope (OAuth2 scopes) and has no roles field. No roles claim is emitted anywhere in axiam-auth or axiam-oauth2 (grep).
- `axiam/crates/axiam-oauth2/src/authorize.rs:434`: Requested scopes are refused only if absent from client.scopes or the DCR ceiling. The user's roles are never consulted.
- `axiam-java-sdk/CONTRACT.md:1892`: require_role is defined as a local check that the verified token's roles contain one of the given roles.
- `axiam-java-sdk/src/main/java/io/axiam/sdk/annotations/AxiamRequireRole.java:13`: The javadoc promises a check against 'the verified token's roles/authorities'.
- `axiam-kotlin-sdk/src/main/kotlin/io/axiam/sdk/Models.kt:11`: roles is documented as the user's roles within the tenant but is derived from scope.
- `axiam-php-sdk/src/Symfony/AxiamAuthSubscriber.php:272`: The Symfony subscriber has the same roles ?? scope fallback.

**Blockers.**

- Exploitability requires tenant configuration that source does not show. Some client the attacker can use must have a registered scope, or a DCR-allowed scope, whose name equals a role name that an application gates with require_role, @AxiamRequireRole or #[RequireRole]. Without that overlap, the defect only denies real role holders (it fails closed).
- The Spring, Ktor, nimbus, Symfony and Laravel dependencies are absent locally, and kotlinc is not installed, so the framework paths could not be run end to end. Only the hunter's copied Java decision logic was executed.

**Validation plan.**

- *Local:* With dependencies available, run one test per SDK. Use a test JWKS and a token for the configured tenant whose subject holds no AXIAM roles and whose scope is 'openid admin'. Put it against a route guarded by @AxiamRequireRole("admin") (Spring MockMvc), requireRole("admin") (Ktor testApplication) and #[RequireRole('admin')] (Laravel or Symfony kernel test). The expected result is 403; source predicts 200. A second token for a subject holding the admin role with scope 'openid' should get 200 and is predicted to get 403.
- *Owner-observed:* Owner check, read-only: list each tenant's OAuth2 clients' registered scopes and dcr_allowed_scopes. Compare them against the role names used by require_role, @AxiamRequireRole, #[RequireRole] and Spring hasRole/hasAuthority rules in applications built on these SDKs. Any name in both lists is a bypass for users of that client.

### N16. Suspending a tenant (status=Suspended) has no effect on sign-in or request authorization

- **Fingerprint:** `axiam-tenant-status-suspended-unenforced`

TenantStatus::Suspended is documented as 'treated as administratively disabled' (models/tenant.rs:20-28), and UpdateTenant.status as 'suspend/reactivate' (tenant.rs:165). An org principal can set it through PUT /api/v1/organizations/{org_id}/tenants/{tenant_id}, and the admin UI's Active toggle sends status 'Suspended' (TenantsPage.tsx:351). The repository persists it (db tenant.rs:1042-1043). A repository-wide search of crates/ and frontend/src, in both enum and string forms, found no read of the status outside parse and serialize in db tenant.rs:62-76. TenantRepository::get_by_id filters only deleted_at = NONE (tenant.rs:967). Login loads the tenant and rejects only on an organization mismatch (auth.rs:541-552). Nothing in docs/ describes a runtime effect of suspension. From source, then, a suspended tenant's users, service accounts, SCIM tokens and existing sessions keep working, against the operator's explicit disable. This is a lifecycle-control failure inside the suspended tenant, not a cross-tenant disclosure.

**Claimed root cause.** The tenant lifecycle predicate is implemented for deletion only. get_by_id selects WHERE deleted_at = NONE, and no login, token, refresh, extractor, gRPC or SCIM path compares tenant.status. Suspension is stored but never enforced, and unlike delete it revokes no sessions.

**Source trace.**

1. *entrypoint* `axiam/crates/axiam-api-rest/src/handlers/tenants.rs:634` (`update`): An org principal sends {"status":"Suspended"} (the admin UI toggle at TenantsPage.tsx:351) to disable the tenant.
1. *propagation* `axiam/crates/axiam-db/src/repository/tenant.rs:1043` (`SurrealTenantRepository::update`): status = $status is persisted.
1. *propagation* `axiam/crates/axiam-db/src/repository/tenant.rs:967` (`SurrealTenantRepository::get_by_id`): Tenant resolution filters only deleted_at = NONE, so a suspended tenant resolves as live.
1. *sink* `axiam/crates/axiam-api-rest/src/handlers/auth.rs:541` (`login`): Login checks only that the tenant resolves and that its org matches (line 546), then proceeds to credential verification and token issuance.

**Evidence.**

- `axiam/crates/axiam-core/src/models/tenant.rs:20`: The model documents Suspended as 'treated as administratively disabled'.
- `axiam/crates/axiam-core/src/models/tenant.rs:165`: UpdateTenant.status is documented as 'suspend/reactivate'.
- `axiam/crates/axiam-db/src/repository/tenant.rs:65`: The only non-test references to Suspended are parse and serialize here; the search also covered the string form 'Suspended' in SurrealQL.
- `axiam/crates/axiam-db/src/repository/tenant.rs:967`: get_by_id has no status predicate.
- `axiam/crates/axiam-api-rest/src/handlers/auth.rs:546`: Login rejects only on org mismatch, not on tenant status.
- `axiam/frontend/src/pages/tenants/TenantsPage.tsx:351`: The admin UI offers the Active/Suspended toggle as an operator control.

**Blockers.**

- Workspace crates cannot be built or run offline (no cargo registry), so a suspended-tenant login could not be executed end to end.
- No document in docs/ states whether suspension is meant to block sign-in or is only a label. That decides whether this is a broken control or an unimplemented feature that is misrepresented in the UI and model docs.

**Validation plan.**

- *Local:* In an axiam-api-rest integration test, create an org, a Standard tenant T and an active dummy user U in T, and mint a token for U. PUT the tenant with {"status":"Suspended"} as an org principal. Then POST /api/v1/auth/login for U with the correct dummy password, and call GET /api/v1/settings with the pre-suspension token. Vulnerable result: 200 on both. Expected after the fix: both refused. The fix is to check status during tenant resolution for login, token, refresh and the extractors, and to revoke sessions on suspend as delete does.
- *Owner-observed:* In staging, an owner toggles a dummy tenant inactive in the admin UI, then confirms whether its test user can still sign in and whether a token issued before the toggle still passes on an authenticated route.

### N17. release-opaque.yml runs tag/branch-pinned third-party actions and npm@latest inside OIDC Trusted Publishing and contents:write jobs

- **Fingerprint:** `axiam/.github/workflows/release-opaque.yml:mutable-action-refs-in-oidc-publish`

Verified from source: all 22 `uses:` lines in .github/workflows/release-opaque.yml use mutable refs (0 are 40-hex SHAs), including dtolnay/rust-toolchain@stable (a branch), Swatinem/rust-cache@v2, rust-lang/crates-io-auth-action@v1 inside publish-crate (environment: production, id-token: write), actions/setup-node@v7.1.0 and `npm install -g npm@latest` inside publish-wasm (id-token: write), taiki-e/install-action@v2 in the wasm job whose artifact publish-wasm publishes verbatim, and softprops/action-gh-release@v3 in the contents: write release job. By contrast every `uses:` in release.yml is SHA-pinned with a version comment, and ci.yml:1104 explicitly calls out 'the floating @v2 release-opaque.yml still carries'. A retagged or compromised upstream action (or a malicious npm 'latest') would execute in a job that can mint crates.io/npm Trusted Publishing tokens for axiam-opaque / @axiam/opaque-wasm. Controls that hold: tag-only trigger with verify-tag-on-main ancestor check, environment: production, per-job permission overrides, and the NPM_TOKEN-absent assertion; none of these constrain the code the referenced actions run. Exploitation requires an upstream compromise; no ref is known to be compromised.

**Claimed root cause.** Actions and the npm CLI in the release-opaque publishing jobs are referenced by mutable tag/branch/dist-tag rather than immutable commit SHA/exact version, diverging from the SHA-pinning convention used in release.yml.

**Source trace.**

1. *entrypoint* `axiam/.github/workflows/release-opaque.yml:61` (`on.push.tags`): push of an axiam-opaque-v* tag starts the publishing workflow
1. *propagation* `axiam/.github/workflows/release-opaque.yml:229` (`jobs.wasm`): taiki-e/install-action@v2 (mutable) installs wasm-pack that builds the package artifact later published unchanged
1. *propagation* `axiam/.github/workflows/release-opaque.yml:188` (`jobs.publish-crate`): dtolnay/rust-toolchain@stable (branch ref) runs in the environment: production, id-token: write job
1. *propagation* `axiam/.github/workflows/release-opaque.yml:202` (`jobs.publish-crate`): rust-lang/crates-io-auth-action@v1 (mutable tag) exchanges the job OIDC token for a crates.io publish token
1. *sink* `axiam/.github/workflows/release-opaque.yml:306` (`jobs.publish-wasm`): npm install -g npm@latest runs an unpinned npm CLI in the id-token: write job immediately before npm publish via Trusted Publishing

**Evidence.**

- `axiam/.github/workflows/release-opaque.yml:185`: publish-crate grants id-token: write (crates.io Trusted Publishing OIDC)
- `axiam/.github/workflows/release-opaque.yml:290`: publish-wasm grants id-token: write (npm Trusted Publishing OIDC)
- `axiam/.github/workflows/release-opaque.yml:306`: npm install -g npm@latest before npm publish
- `axiam/.github/workflows/release-opaque.yml:449`: softprops/action-gh-release@v3 (mutable) in the contents: write release job
- `axiam/.github/workflows/release.yml:435`: release.yml pins the same dtolnay/rust-toolchain action by full commit SHA, showing the intended convention
- `axiam/.github/workflows/ci.yml:1104`: Comment acknowledges 'the floating @v2 release-opaque.yml still carries'

**Blockers.**

- Whether the org/repo Actions policy 'require actions to be pinned to a full-length commit SHA' is enabled (which would make these jobs fail rather than run mutable code) is a hosted setting not visible in source
- Production environment protection rules (required reviewers, deployment branch/tag rules) are hosted settings not visible in source
- Exploitation depends on an upstream action tag/branch or npm 'latest' being moved to malicious code; no such compromise is known and it cannot be observed offline

**Validation plan.**

- *Local:* Run `grep -nE 'uses: [^ ]+@' .github/workflows/release-opaque.yml | grep -vE '@[0-9a-f]{40}'` and confirm 22 mutable refs, and that publish-crate/publish-wasm declare id-token: write; no execution of workflows or registry contact needed.
- *Owner-observed:* Owner checks Settings > Actions > General for the SHA-pinning requirement and allowed-actions list, and Settings > Environments > production for required reviewers and tag rules. Remediate by SHA-pinning every uses: line (as release.yml does) and pinning npm to an exact version >= 11.5.1 (e.g. npm@11.x.y) instead of npm@latest.

### N18. Dev compose full-stack profile pulls a mutable image from ghcr.io/axiamhq, a namespace the release workflow does not publish to

- **Fingerprint:** `axiam/docker/docker-compose.dev.yml:ghcr-axiamhq-server-latest`

Verified from source: docker/docker-compose.dev.yml line 111 sets the full-stack axiam-server image to ghcr.io/axiamhq/axiam/server:latest, while release.yml publishes to ${REGISTRY}/${github.repository} (repo origin is github.com/ilpanich/axiam, so ghcr.io/ilpanich/axiam/server), and prod/minimal compose use ghcr.io/ilpanich/axiam/server with an explicit tag. The image is a mutable :latest tag with no digest. A developer running `docker compose --profile full-stack up -d` (line 68) would run whatever that namespace serves, and the container receives the local dev Vault root token (line 143), SurrealDB root/root (line 123) and a published port 8090. Scope is local development only (opt-in profile; prod/k8s unaffected), and the credentials are dev defaults. Whether a lower-trust party can publish to ghcr.io/axiamhq is decisive and not observable offline; if the owner controls axiamhq the impact reduces to a stale/unsigned image.

**Claimed root cause.** Hard-coded, mutable image reference in a namespace outside the signed release pipeline (ghcr.io/axiamhq instead of ghcr.io/ilpanich, :latest instead of a version/digest).

**Source trace.**

1. *entrypoint* `axiam/docker/docker-compose.dev.yml:68` (`full-stack profile comment`): developers are told to run `docker compose --profile full-stack up -d`
1. *propagation* `axiam/docker/docker-compose.dev.yml:111` (`services.axiam-server.image`): pulls ghcr.io/axiamhq/axiam/server:latest (mutable tag, foreign namespace)
1. *sink* `axiam/docker/docker-compose.dev.yml:143` (`services.axiam-server.environment`): container receives the dev Vault root token (and DB root/root at line 123)

**Evidence.**

- `axiam/docker/docker-compose.dev.yml:143`: AXIAM__AUTH__VAULT_TOKEN set to the dev Vault root token
- `axiam/.github/workflows/release.yml:328`: release images are tagged ${REGISTRY}/${github.repository}/<image>, i.e. ghcr.io/ilpanich/axiam/...
- `axiam/docker/docker-compose.prod.yml:133`: prod compose uses ghcr.io/ilpanich/axiam/server with a required explicit tag

**Blockers.**

- Ownership/control of the github.com/axiamhq organization and the ghcr.io/axiamhq/axiam/server package cannot be observed offline; if the owner controls it, there is no lower-trust publisher

**Validation plan.**

- *Local:* `docker compose -f docker/docker-compose.dev.yml --profile full-stack config` (no pull) shows image ghcr.io/axiamhq/axiam/server:latest; compare with release.yml's `${{ env.REGISTRY }}/${{ github.repository }}` naming.
- *Owner-observed:* Owner verifies whether the axiamhq GitHub org/ghcr namespace is registered and controlled by them; regardless, change the reference to ghcr.io/ilpanich/axiam/server pinned by version and digest (or build from source as docker-compose.e2e.yml does).

### N19. SurrealDB root password passed on the process command line in prod/minimal compose and the k8s StatefulSet

- **Fingerprint:** `axiam/surrealdb-root-pass-in-process-args`

Verified from source: docker/docker-compose.prod.yml:419 and docker/docker-compose.minimal.yml:72 start SurrealDB with `start --user ${AXIAM__DB__USERNAME} --pass ${AXIAM__DB__PASSWORD}`, and k8s/surrealdb/statefulset.yml:40-43 passes `--pass $(SURREALDB_PASS)`, which the kubelet expands from the surrealdb-credentials Secret into argv. The same credential is the server's DB login (prod compose line 178), i.e. root access to every tenant's data. /proc/<pid>/cmdline is world-readable by default, so any unprivileged account on the Docker host or k8s node (host PID namespace) can read it with ps, whereas environment variables in /proc/<pid>/environ are owner-only. In k8s the stored pod spec holds only the literal `$(SURREALDB_PASS)`, so API-level pod readers do not see it; exposure is node-local. Severity depends on host facts (hidepid mount option, presence of unprivileged local users, process-capturing agents) and on whether surrealdb v4.0.0 accepts SURREAL_USER/SURREAL_PASS env vars as the alternative; neither is visible offline. Not documented as an accepted risk in the repo.

**Claimed root cause.** Datastore root credentials supplied via --user/--pass command-line flags instead of environment variables or a file.

**Source trace.**

1. *entrypoint* `axiam/docker/docker-compose.prod.yml:419` (`services.surrealdb.command`): start --user ${AXIAM__DB__USERNAME} --pass ${AXIAM__DB__PASSWORD} places the password in argv
1. *propagation* `axiam/k8s/surrealdb/statefulset.yml:43` (`containers.surrealdb.args`): $(SURREALDB_PASS) from the surrealdb-credentials Secret is expanded into the container argv
1. *sink* `axiam/docker/docker-compose.prod.yml:178` (`services.axiam-server.environment`): the same root credential is the server's DB login, granting all tenants' data

**Evidence.**

- `axiam/docker/docker-compose.minimal.yml:72`: minimal compose also passes --pass on the command line
- `axiam/k8s/surrealdb/statefulset.yml:42`: --pass flag in StatefulSet args
- `axiam/docker/docker-compose.prod.yml:178`: AXIAM__DB__PASSWORD is the same value used by axiam-server

**Blockers.**

- Host /proc hidepid mount option and the inventory of unprivileged local accounts or command-line-capturing agents on Docker hosts/k8s nodes are deployment facts
- Whether surrealdb/surrealdb:v4.0.0 honours SURREAL_USER/SURREAL_PASS environment variables (the remediation) cannot be verified offline: no surreal binary or source is available locally

**Validation plan.**

- *Local:* On a disposable host, start surrealdb/surrealdb:v4.0.0 with the prod command and a dummy password, run `ps -eo args | grep surreal` as an unprivileged host user and observe the dummy password; repeat with SURREAL_USER/SURREAL_PASS set via env and no flags to confirm startup works and argv no longer contains it.
- *Owner-observed:* Owner checks whether /proc is mounted with hidepid=2 on Docker hosts and k8s nodes, whether unprivileged users or monitoring agents that record process command lines exist there, and switches to env/file-based credentials.

### N20. Group member listings report another tenant's group member count because the count query lacks a tenant predicate

- **Fingerprint:** `db-group-members-count-missing-tenant-predicate`

SurrealGroupRepository::get_members and get_service_account_members filter the returned rows by tenant_id (group.rs:639, 923). The total, however, counts member_of edges into type::record('group', $group_id) with only group_id bound (group.rs:624-628, 909-913), and paginate() reports that count (group.rs:660, 943). GET /api/v1/groups/{group_id}/members and the service-account variant call these with principal.tenant_id and a caller-supplied group id. They do not first check that the group belongs to the tenant, and they copy total into the response (groups.rs:276-281, 439-447). A tenant-A principal with groups:list_members who supplies a tenant-B group UUID therefore receives items=[] and total equal to B's member count. Practical likelihood is low: group ids are UUIDv7 with about 74 random bits, and no channel that exposes B's group ids to A was established. For an unknown id the endpoint returns total=0 rather than 404.

**Claimed root cause.** The count queries in get_members and get_service_account_members bind only $group_id and have no tenant predicate on the group or the members, while the data query beside them filters on tenant_id = $tenant_id.

**Source trace.**

1. *entrypoint* `axiam/crates/axiam-api-rest/src/handlers/groups.rs:264` (`list_members`): An authenticated tenant-A principal with groups:list_members supplies an arbitrary group UUID.
1. *propagation* `axiam/crates/axiam-api-rest/src/handlers/groups.rs:276` (`list_members`): get_members(principal.tenant_id, group_id, ...) is called without a prior check that the group is in tenant A.
1. *sink* `axiam/crates/axiam-db/src/repository/group.rs:624` (`SurrealGroupRepository::get_members`): SELECT count() FROM member_of WHERE out = type::record('group', $group_id) AND record::tb(in) = 'user' runs with no tenant filter, and the result becomes PaginatedResult.total (line 660), returned at groups.rs:281.

**Evidence.**

- `axiam/crates/axiam-db/src/repository/group.rs:624`: The user-member count query binds only group_id.
- `axiam/crates/axiam-db/src/repository/group.rs:909`: The service-account-member count query binds only group_id.
- `axiam/crates/axiam-db/src/repository/group.rs:639`: The data query beside it filters tenant_id = $tenant_id.
- `axiam/crates/axiam-api-rest/src/handlers/groups.rs:281`: The handler copies result.total into the response.
- `axiam/crates/axiam-api-rest/src/handlers/groups.rs:447`: The service-account member listing copies page.total in the same way.

**Blockers.**

- No SurrealDB instance and no buildable workspace (no cargo registry) are available, so the two-tenant count could not be observed.
- Whether a tenant-B group UUID (UUIDv7, not guessable) can reach a tenant-A principal through any channel is not established; this bounds likelihood but does not change the source defect.

**Validation plan.**

- *Local:* In the axiam-db integration-test harness (in-memory SurrealDB), create tenants A and B, a group G in B, and 3 dummy users in G. Call get_members(A, G.id, Pagination::default()). Vulnerable result: items=[] and total=3. Expected after the fix: total=0. Repeat with get_service_account_members and 2 dummy service accounts. The fix is to add AND out.tenant_id = $tenant_id AND in.tenant_id = $tenant_id to both count queries and bind tenant_id, or to return 404 when the group is not in the tenant.

### N21. The IdP-facing SAML form ACS never compares the signed SubjectConfirmationData@Recipient, and the audience check is skipped when AudienceRestriction is absent, so nothing mandatory binds the assertion to this SP

- **Fingerprint:** `saml-sp-assertion-not-bound-to-this-sp`

Verified in source. handle_saml_response_for requires Conditions (saml.rs:607-611). The audience check runs only 'if let Some(audience_restrictions)' (saml.rs:636), so an assertion whose Conditions has no AudienceRestriction passes. check_bearer_confirmation_data requires a non-empty Recipient but compares its value only when expected_recipient is Some (saml.rs:1483-1490). The public form ACS, /api/v1/auth/federation/saml/acs/form, which is where IdPs post, passes expected_destination=None (federation_login.rs:1331). Its comment says no ACS URL is stored, but saml_login_public now stores idp_redirect_uri: Some(acs_url) (federation.rs:2760), and acs_url is the form ACS URL (saml_acs_url -> SAML_FORM_ACS_PATH, federation_login.rs:1535-1538). The JSON sibling ACS does compare it (federation.rs:2859). The signed InResponseTo must equal the stored request ID, but that ID is not secret: saml_login_public returns saml_request_b64 to the unauthenticated caller (federation.rs:2771). Relay scenario that is plausible but not demonstrated: the operator of another SP registered at the same IdP starts an AXIAM sign-in in their own browser and reads the AuthnRequest ID. They reuse that ID in their own AuthnRequest to the IdP. When a victim signs in to their SP, they post the IdP-signed assertion to AXIAM's form ACS with their own RelayState and redeem the handoff code bound to their browser (federation_login.rs:1349-1359). This works only if the IdP omits AudienceRestriction (most mainstream IdPs include it) and issues the same NameID/attributes for both SPs (not pairwise). The authenticated /api/v1/federation/saml/acs compares Recipient against the caller-supplied acs_url and binds InResponseTo to no stored request (federation.rs:1904-1924). It issues no session; it returns or provisions a link.

**Claimed root cause.** Binding the assertion to this SP is optional twice: a missing AudienceRestriction is treated as a pass (axiam/crates/axiam-federation/src/saml.rs:636), and @Recipient is compared only when the caller supplies an expected value (saml.rs:1483). The form ACS supplies None (axiam/crates/axiam-api-rest/src/handlers/federation_login.rs:1331) even though login_state.idp_redirect_uri holds the expected form ACS URL.

**Source trace.**

1. *entrypoint* `axiam/crates/axiam-api-rest/src/handlers/federation_login.rs:1293` (`saml_acs_form_public`): Unauthenticated form POST of SAMLResponse plus RelayState. The RelayState may be the attacker's own login-state value; it is consumed at 1308.
1. *propagation* `axiam/crates/axiam-api-rest/src/handlers/federation_login.rs:1331` (`saml_acs_form_public`): Calls handle_saml_response_for with the stored request_id but expected_destination=None, so neither Response@Destination nor the signed SubjectConfirmationData@Recipient value is compared.
1. *propagation* `axiam/crates/axiam-federation/src/saml.rs:636` (`handle_saml_response_for`): The audience check runs only when Conditions carries AudienceRestriction; an absent restriction passes.
1. *propagation* `axiam/crates/axiam-federation/src/saml.rs:1483` (`check_bearer_confirmation_data`): Recipient must be present, but its value is compared only if expected_recipient is Some.
1. *sink* `axiam/crates/axiam-api-rest/src/handlers/federation_login.rs:1349` (`saml_acs_form_public`): mint_handoff_and_redirect issues a single-use handoff code for the resolved user, bound to the browser that started the sign-in.

**Evidence.**

- `axiam/crates/axiam-api-rest/src/handlers/federation.rs:2760`: saml_login_public stores idp_redirect_uri: Some(acs_url) on the login-state row; acs_url comes from saml_acs_url (federation.rs:2715), which is the form ACS path.
- `axiam/crates/axiam-api-rest/src/handlers/federation.rs:2859`: The JSON sibling saml_acs_public passes login_state.idp_redirect_uri as expected_destination; the form ACS does not.
- `axiam/crates/axiam-api-rest/src/handlers/federation.rs:2771`: saml_login_public returns saml_request_b64, which carries the AuthnRequest ID, to the unauthenticated caller.
- `axiam/crates/axiam-api-rest/src/handlers/federation.rs:1916`: The authenticated ACS uses the caller-supplied req.acs_url as the expected Recipient and passes no stored request ID.
- `axiam/crates/axiam-federation/src/saml.rs:1471`: Its comment says the public path's login-state row 'has no column for' the ACS URL. That is stale: the column now exists and is populated.

**Blockers.**

- Whether the deployment's SAML IdP ever issues assertions without <AudienceRestriction>, and whether it gives two SPs the same NameID/attributes (not pairwise), is IdP policy that is not in source. Mainstream IdPs normally include AudienceRestriction, in which case saml.rs:636-646 blocks the relay.
- The workspace cannot be built offline (no cargo registry; samael/xmlsec unavailable), so a signed fixture cannot be driven through handle_saml_response_for locally.

**Validation plan.**

- *Local:* In axiam-federation's test module, sign a dummy fixture whose Assertion has Conditions without AudienceRestriction, a bearer SubjectConfirmationData with Recipient=https://other-sp.example/acs and InResponseTo set to a known request ID. Call handle_saml_response_for(config, tenant, b64, Some(state), Some(request_id), None, false), which is the form-ACS argument shape. Expect Ok today. Expect Err once expected_destination=Some(<form ACS URL>) is passed (the fix: pass login_state.idp_redirect_uri.as_deref() at federation_login.rs:1331), or once AudienceRestriction is required.
- *Owner-observed:* Owner checks, on the deployment's configured SAML IdP, whether assertions for AXIAM can omit AudienceRestriction, per SP or by default, and whether the NameID format is shared across SPs rather than pairwise. If audience can be absent, the relay is reachable.

## Hardening notes (non-findings, from hunters)

These are concrete observations with no demonstrated boundary crossing; listed verbatim per hunter for triage.

- *(h01-rest-authn)* AuthzMiddleware's credential-presence check is satisfied by any Authorization header value, including a non-Bearer scheme or garbage. It is not a security control, and every protected handler must keep its own extractor. The ROUTE_PERMISSION_MAP parity test is what guards that.
- *(h01-rest-authn)* normalize_for_public_check rejects literal '..' but not percent-encoded '%2e%2e'. '/api/docs/%2e%2e/v1/users' is classified public. Harmless today because actix does not resolve dot segments and routes that path to the SwaggerUi tail outside the authz scopes. Recommend rejecting any segment that percent-decodes to '.' or '..'.
- *(h01-rest-authn)* is_csrf_exempt uses path.ends_with(suffix) on the raw path rather than exact matching on the scope-relative path. No current route makes it exploitable (no multi-segment tail routes under /api/v1), but a future '{tail:.*}' or nested resource could silently become CSRF-exempt. Recommend exact equality, matching PUBLIC_PATHS semantics.
- *(h01-rest-authn)* tenant_path's duplicate-selector check compares raw query keys ('tenant_id' / 'tenant_id='), so 'tenant%5Fid=<other>' evades it. It currently fails closed only because serde struct deserialization rejects the resulting duplicate tenant_id field. Recommend comparing percent-decoded keys with url::form_urlencoded::parse.
- *(h01-rest-authn)* AuthenticatedServiceAccount (used by network_decide) performs no enforce_tenant_path_binding and no DPoP replay recording, unlike AuthenticatedPrincipal's machine branch. It is not mounted under /t/{tenant} today.
- *(h02-rest-rbac)* roles.rs assign paths and role.rs relate_subject_to_role do not validate that resource_id exists in the caller's tenant (role.rs:911-922). There is no cross-tenant effect, because the engine resolves ancestors and scopes in request.tenant_id, but a dangling or foreign resource_id produces an inert, confusing grant. Validate it with resource_repo.get_by_id(tenant_id, rid) before RELATE.
- *(h02-rest-rbac)* get_org_settings (settings.rs:380) and get_org_email_config (email_config.rs:146) are readable by ordinary-tenant admins, for the same reason as the set_org_settings candidate (org-level permissions seeded to tenant roles, no org-principal guard). The disclosure is the non-secret org baseline only. Include them when adding organizations:get_settings/update_settings to the B-04 guard.
- *(h02-rest-rbac)* organization_scope_consistency_test.rs only pins actions whose handlers are already scope-guarded. It cannot detect an organization-level handler that lacks the guard altogether (set_org_settings, export_audit). Add an explicit list of /organizations/{org_id}/** mutations that must call require_organization_principal or bind tenant_id to the caller's reach.
- *(h02-rest-rbac)* roles:assign, groups:add_member and permissions:grant have no privilege ceiling outside the network: namespace. This is documented as accepted (threat-model-stride.md:429, :4777), but a tenant 'admin' holding roles:assign can make itself 'super-admin' (gaining admin:bootstrap and the network meta permissions). Consider a 'delegate only what you hold' rule like the network gate's §5.3.
- *(h03-db-isolation)* has_role.resource_id is never checked to belong to the assigning tenant (role.rs:910-922; roles.rs validate_tenant_scope validates only tenant_scope). A foreign resource UUID cannot match any in-tenant resource evaluation, so no cross-tenant effect was found, but the RELATE could verify `$resource_id` against resource WHERE tenant_id = $tid the way grants does for scope_ids.
- *(h03-db-isolation)* idx_ssf_stream_audience is UNIQUE across all tenants by design (D-47, schema.rs:4759-4811). A tenant admin can pre-register another tenant's intended audience string, which blocks that tenant with 409 and reveals that the audience is in use elsewhere. A tenant-qualified audience or per-tenant issuer would remove the squat.
- *(h03-db-isolation)* get_bound_service_account and bound_service_accounts (certificate.rs:1045-1100) take no tenant. Every current caller passes ids already read tenant-scoped, but the trait could take tenant_id to keep that invariant from being lost.
- *(h04-oauth2-as)* Token endpoint: when the authorization code has no stored code_challenge, a presented code_verifier is silently ignored (token.rs:2488). RFC 9700 §2.1.1 recommends rejecting it to prevent a PKCE downgrade. Only confidential clients are affected, since public clients require a stored challenge.
- *(h04-oauth2-as)* PAR consume spends a request_uri before checking that it was issued to the presenting client (par.rs:328-345). A party holding another client's handle can burn it. This is DoS-only and needs the 256-bit handle.
- *(h04-oauth2-as)* JWT introspection (token.rs:3655-3715, and gRPC IntrospectToken) re-reads the account but does not check that the token's sid session is still live. A token from a logged-out session reports active:true until exp, and resource servers that rely on introspection for logout must also poll the revocation feed.
- *(h04-oauth2-as)* Token exchange does not check the subject token's session liveness. The exchanged token has no sid, but its lifetime is capped at the subject's remaining exp, so nothing is extended.
- *(h04-oauth2-as)* Refresh grant does not check session liveness, only revocation at logout, so refresh tokens outlive session expiry. This is a documented residual (F4-R12-01 residual / #844).
- *(h05-ssrf-dcr)* The CIMD cimd.allow_http flag is passed as guarded_fetch allow_private (axiam/crates/axiam-oauth2/src/cimd.rs:841-842). resolve_and_pick returns addrs[0] with no is_never_allowed check when allow_private is true (axiam/crates/axiam-pki/src/ssrf.rs:210-211). So once an org admin enables allow_http in the org baseline, a tenant admin can name a domain they control in trusted_client_id_domains and point a blind first-hop GET at 169.254.169.254. Meanwhile the operator's own AXIAM__PKI__SSRF_ALLOWED_HOSTS exception can never reach the metadata service. This is documented as an accepted development-only risk. Smallest fix: apply is_never_allowed to every resolved address even when allow_private is true, and decouple the CIMD scheme rule from the address rule.
- *(h05-ssrf-dcr)* host_glob_matches (axiam/crates/axiam-oauth2/src/dcr.rs:349) byte-slices host at host.len()-suffix.len(), and a local harness showed it panics on a non-ASCII host. Callers only pass url::Url::host_str() (ASCII) today. Use host.get(..)/as_bytes() comparison or eq_ignore_ascii_case on byte slices for defence in depth.
- *(h05-ssrf-dcr)* ip_class::classify_v6 (axiam/crates/axiam-core/src/ip_class.rs) classifies the RFC 2765 IPv4-translated prefix ::ffff:0:0/96 (e.g. ::ffff:0:a9fe:a9fe) as Global, which a local harness confirmed. It is unreachable without a SIIT translator on the path. Consider classifying ::ffff:0:0/96 as SpecialPurpose, and judging NAT64 network-specific prefixes by their embedded IPv4 where the operator configures one.
- *(h06-federation-sp)* Require <AudienceRestriction> containing config.client_id (reject when absent, as the Web-SSO profile requires) at axiam/crates/axiam-federation/src/saml.rs:636, and pass login_state.idp_redirect_uri.as_deref() instead of None at axiam/crates/axiam-api-rest/src/handlers/federation_login.rs:1331. Add a regression fixture with no audience and a foreign Recipient.
- *(h06-federation-sp)* The authenticated /api/v1/federation/saml/acs (axiam/crates/axiam-api-rest/src/handlers/federation.rs:1886-1931) and /api/v1/federation/oidc/callback (federation.rs:1621-1694) are labelled account-linking but link nothing to the caller. They let any authenticated tenant user JIT-provision accounts from IdP assertions or codes, using a caller-chosen acs_url and no stored InResponseTo. The OIDC callback consumes a state row by value globally without checking login_state.tenant_id or federation_config_id against user.tenant_id or req.config_id. No session is minted, so there is no identity gain, but these should either bind to the caller and to a stored request or be removed.
- *(h06-federation-sp)* OIDC browser federation ignores email_verified (axiam/crates/axiam-federation/src/oidc.rs:1028-1042 uses the mapped email as both username and email), while the plain-OAuth2 path refuses an unverified email (oauth2.rs:301). Apple's unsigned form 'user' email can also fill an absent email claim (oidc.rs:612). Linking is by sub only, so this allows tenant username/email squatting (later sign-ups or SSO for that address hit ProvisioningConflict) but no takeover.
- *(h06-federation-sp)* Add a SAML unit test asserting that a NameID containing an interior XML comment parses to its full concatenated text through samael/quick-xml (comments are admitted by refuse_markup_declarations and ignored by exc-c14n).
- *(h07-saml-idp-render)* signature_placement checks Reference URI == #<root ID> but does not refuse a second element elsewhere in the document carrying the same ID value. Whether an XSW-style copy could work then depends on how samael/xmlsec resolves duplicate IDs (ID registration order or a duplicate-ID error), which I could not inspect offline (the samael source is not present locally). Impact is bounded anyway: the root ID is replay-guarded, and ACS and LogoutRequest NameID/SessionIndex are re-bound to the SP's own registration and participant rows. Refusing any non-root element whose ID/Id attribute equals the root ID in signature_placement would close the question.
- *(h07-saml-idp-render)* Password-reset and verification action_url values are relative paths (/auth/reset-password?..., password_reset.rs:231, email_verification.rs:71). Mail clients cannot resolve them, so the links are functionally broken. This is not a security issue, but an absolute URL from the configured issuer would be the usual form.
- *(h07-saml-idp-render)* The AdminNotification plain-text body interpolates the actor username and email unescaped (by design for text/plain). If usernames can contain newlines, a crafted name could spoof lines in administrators' plain-text alerts. Username character validation was not traced here (owned by user-management peers).
- *(h08-authn-recovery)* AuthService::enroll_mfa (axiam/crates/axiam-auth/src/service.rs:1051) overwrites mfa_secret even when mfa_enabled is already true. Re-starting TOTP enrollment therefore immediately invalidates a confirmed authenticator, and on a passkey-only account it creates a live TOTP factor before confirm_mfa. Write the pending secret to a separate field and swap it in at confirm.
- *(h08-authn-recovery)* enroll_mfa_with_setup_token guards only on `mfa_enabled && mfa_secret.is_some()`, while the WebAuthn setup twin uses available_method_types. Use the same guard on both, and consider making setup tokens single-use (a jti in a replay store), because they stay valid for 5 minutes after the forced enrollment completes.
- *(h08-authn-recovery)* finish_authentication (username-bound WebAuthn, axiam/crates/axiam-api-rest/src/handlers/webauthn.rs:1125) issues a session without ensure_can_sign_in, unlike verify_mfa and the discoverable path, so an account disabled between the password step and the assertion (at most 5 minutes) still gets a session.
- *(h08-authn-recovery)* verify_mfa has no per-account failure counter (only the per-IP mfa_per_min governor), so TOTP guessing for one account is bounded only by how many source IPs the attacker uses and how XFF trust is configured.
- *(h08-authn-recovery)* Bootstrap email gate (AXIAM_BOOTSTRAP_ADMIN_EMAIL) is a non-secret value: whoever first reaches /api/v1/admin/bootstrap with that email becomes super-admin. Documented as D-10/D-03; recommend pairing it with the setup token.
- *(h08-authn-recovery)* Deletion cancel is a state-changing GET reached from an emailed link; mail-security link scanners can cancel an Art. 17 erasure without the subject acting. Use a confirmation page and a POST.
- *(h09-grpc-amqp)* gRPC skips session revocation unless AXIAM__GRPC__STRICT_REVOCATION=true (server.rs:319-330). A logged-out or revoked session keeps gRPC access until access-token expiry (about 15 min). This is documented in threat-model-stride.md:408/4230 and the runbook, so it is recorded as an accepted posture, not a finding. Consider enabling it by default when the listener is not loopback.
- *(h09-grpc-amqp)* gRPC ValidateCredentials writes no audit row for success or failure, unlike REST login. Add an auth.credentials_validated audit event per call.
- *(h09-grpc-amqp)* AMQP AuthzRequest lets any holder of a tenant's HKDF subkey ask about any subject_id and resource in that tenant. That is by design for async service checks, but it means the subkey is a tenant-wide decision-query credential, and the deployment docs should say so.
- *(h09-grpc-amqp)* Reactor topic routing keys are <tenant_id>.<event> on a shared exchange (reactor/transport.rs:584). Subscriber isolation between tenants' reactor runtimes depends entirely on broker topic-permission ACLs. Document the required per-tenant topic permission.
- *(h10-pki-scim)* SCIM provisioning tokens are not revoked by the tenant tombstone transaction (axiam-db tenant.rs:1132-1167 revokes sessions, refresh tokens and certificates but not scim_token), and SurrealScimTokenResolver::resolve (extractors/scim_token.rs) never checks tenant liveness. user rows survive until the purge sweep (default cleanup_interval_secs=300, axiam-server boot.rs:83), so a SCIM token keeps reading and writing a deleted tenant's users until the purge's Grants stage, or indefinitely if the purge keeps failing before that stage. Fix: add `UPDATE scim_token SET revoked_at = time::now() WHERE tenant_id = $id AND revoked_at = NONE` to the tombstone transaction, and/or a tenant_repo.get_by_id liveness check in resolve().
- *(h10-pki-scim)* cert_bound_to has no uniqueness on the certificate side: bind can attach one certificate to several service accounts of the same tenant, and get_bound_service_account (axiam-db certificate.rs:1092-1112) returns whichever edge SurrealDB yields first, so which identity a device gets is nondeterministic. This is a same-tenant admin action, not a boundary crossing. Consider a unique index on cert_bound_to.in, or refusing to rebind without an unbind.
- *(h10-pki-scim)* TenantStatus::Suspended is defined and stored (axiam-core tenant.rs:28, schema.rs:1689) but no authentication path reads it (no non-model references in axiam-auth, axiam-oauth2 or axiam-api-rest), including device_auth and SCIM token resolution. Suspending a tenant therefore has no access effect.
- *(h11-crypto)* AES-256-GCM in axiam-auth/src/crypto.rs, used for TOTP secrets, webhook secrets, passkey/ceremony state and DB-custody CA keys (axiam-pki/src/ca_key_store.rs:63), binds no AAD (record id, tenant id, organization id). A database writer could move one tenant's encrypted CA key or TOTP secret onto another row and it would decrypt. Bind (table, tenant/org id, record id) as AAD.
- *(h11-crypto)* The bootstrap setup token is logged at INFO once at first boot (axiam/crates/axiam-server/src/main.rs:530). It is a documented exception, valid only while no user exists, and hash-stored. Operators should treat first-boot logs as secret until bootstrap completes.
- *(h11-crypto)* AMQP derive_tenant_key puts key_version into the HKDF info but derives every version from the same master key, so 'rotation' by version bump does not retire a leaked master key.
- *(h11-crypto)* Webhook secrets are operator-supplied with no minimum length visible in handlers/webhook.rs. Consider enforcing at least 32 bytes or generating them server-side.
- *(h12-directory-audit-gdpr)* The request audit middleware records req.path() verbatim as the action (axiam/crates/axiam-audit/src/middleware.rs:543). GET /api/v1/account/export/{token} therefore copies the raw single-use export download token into the subject tenant's audit log, which is readable with audit_logs:list (seeded to viewer). When the session is expired it goes into the nil partition instead. Downloading still requires the subject or gdpr:export in the owning tenant, so this is not a boundary crossing today. Redact token path segments, or move the token out of the path.
- *(h12-directory-audit-gdpr)* Audit append-only is enforced only at the application layer: schema PERMISSIONS do not bind the root connection the server uses (axiam/crates/axiam-db/src/repository/audit.rs:443-445). An off-host signed export (pgp sign_audit_batch) is the real integrity control.
- *(h13-native-ffi)* axiam-c-sdk/src/client.c:921 and similar sites cast cJSON valuedouble straight to unsigned/long/long long (e.g. (unsigned)item->valuedouble for KSF costs, (long long) timeout_ms in reactor.c:245). An out-of-range double is C undefined behaviour (GCC -fsanitize=undefined does not include float-cast-overflow, so the harness would not flag it). The effect is limited to a wrong integer that is then range-checked or MAC-covered, so it is not a memory-safety finding. Clamp or reject non-finite and out-of-range values before casting.
- *(h13-native-ffi)* axiam/crates/axiam-opaque/src/lib.rs:174 lets a server name Argon2id memory_kib up to 1 GiB with 10 iterations, and the C/C++ bindings accept the same band, so a hostile or misconfigured server can make each client login allocate about 1 GiB. This is resource exhaustion in the client, owned by another class. Consider a lower client-side ceiling.
- *(h13-native-ffi)* axiam-c-sdk/src/transport_curl.c:25-35 write_cb grows the response body without a size cap, so a hostile server can drive unbounded client memory. This is resource exhaustion, not out-of-bounds.
- *(h13-native-ffi)* axiam-cplusplus-sdk/src/opaque.cpp passes password.c_str() to the FFI, so a std::string password with an embedded NUL is silently truncated (consistently at registration and login). Reject embedded NUL rather than truncating.
- *(h13-native-ffi)* axiam/crates/axiam-opaque-ffi/src/lib.rs:261-264 and 346-352: if a later to_c_string fails after an out-parameter string was already written, the function returns NULL with *out_export_key/*out_session_key allocated. A caller that frees out-params only on success leaks it. This is unreachable today because the output is hex, but documenting or zeroing out-params on failure would make the contract total.
- *(h13-native-ffi)* axiam-cplusplus-sdk/src/client.cpp (e.g. lines 387-478, 1112-1114) uses json::value(key, default) on server response bodies, which throws nlohmann::json::type_error on a wrong-typed field from a hostile server. This is the same root shape as the candidate, but a server-trusted input owned by the SDK-correctness hunter s05; see uncovered.
- *(h14-frontend)* docker/nginx.conf.template:95 CSP form-action 'self' will block SAML SP-initiated HTTP-POST sign-in (services/ssoLogin.ts:357-380) to an external IdP; functional issue — fix by adding IdP origins or using Redirect binding, not by widening form-action to '*'.
- *(h14-frontend)* ConsentPage.tsx shows only the client_id parsed from return_to; also displaying the registered (escaped) client_name would help users recognise socially-engineered consent links.
- *(h15-supply-deploy)* k8s configmap sets TRUSTED_HOPS=0 without TRUSTED_PROXIES; set it to ingress pod CIDR.
- *(h15-supply-deploy)* allow-ingress-to-server admits whole ingress-nginx namespace; add controller podSelector.
- *(h15-supply-deploy)* No automountServiceAccountToken: false on pods.
- *(h15-supply-deploy)* Mutable base-image tags (rabbitmq, vault, busybox, surrealdb) in k8s/prod compose; pin digests.
- *(h15-supply-deploy)* Dev/e2e compose publish SurrealDB/RabbitMQ/Vault dev creds on 0.0.0.0; bind 127.0.0.1.
- *(h15-supply-deploy)* Prod/minimal compose bind to 127.0.0.1 with empty TRUSTED_PROXIES; local processes can forge XFF.
- *(h15-supply-deploy)* rpi5-k3s ServiceLB without externalTrafficPolicy: Local collapses client IPs into one bucket (lockout DoS).
- *(h16-obvious-wildcard)* /health/jobs is unauthenticated and returns last_error from AxiamError Display; it relies on edge non-routing (T-213). Consider returning only a category, or requiring an internal listener.
- *(h16-obvious-wildcard)* axiam-api-grpc/src/server.rs:373-377 comment wrongly says tonic 0.14 lacks max_decoding_message_size; the default 4 MiB applies. Set it explicitly and fix the comment.
- *(h16-obvious-wildcard)* UMA list_resource_sets reads only the first default page of tenant resources before filtering by client, so a resource server can miss its own sets (functional; use a repository query on uma_registered_by).
- *(h16-obvious-wildcard)* Add a typ or token_use claim (for example at+jwt) to access tokens and require it in decode_access_token, and retire allow_missing_aud_as_user, so other JWTs signed with the same key can never be admitted.
- *(h16-obvious-wildcard)* Verifiable credentials are design-only (claude_dev/verifiable-credentials-design.md); there is no runtime surface.
- *(s01-rust-go)* Rust/Go: default to requiring aud in {axiam:user, axiam:m2m} when no audience configured; server: give purpose tokens distinct aud/typ or key.
- *(s01-rust-go)* Rust find_jwk single-key fallback: require kid on access-token path.
- *(s01-rust-go)* Rust/Go require_role matches OAuth scope tokens, not roles; document or redesign.
- *(s01-rust-go)* Rust dpop.rs:417 unchecked (now-iat).abs(); use checked arithmetic.
- *(s01-rust-go)* Rust/Go oidc_exchange returns tokens without ID-token validation when id_token is absent; refuse.
- *(s01-rust-go)* Go NewClient accepts http:// base URL for any host.
- *(s01-rust-go)* Reactor replies use unsigned reply_to property (info leak only).
- *(s02-ts-python)* axiam-typescript-sdk/src/middleware/express.ts:351 and fastify.ts:357 redirect to an unvalidated returnTo after login (same open-redirect shape as the Python candidate). The TS docs tell integrators to validate it, but the handler exposes no validation hook. Accept only same-origin relative paths by default.
- *(s02-ts-python)* axiam-typescript-sdk/src/node/jwks.ts verifyAccessToken does not require a kid header: jose selects the only matching key when the JWKS has one. ID-token and logout paths do require kid. This is a contract deviation (§12.4/§10 kid discipline) with no forgery effect.
- *(s02-ts-python)* axiam-typescript-sdk/src/node/oidcIdToken.ts resolveClockSkewSec passes NaN through (Math.min/Math.max), and jose clockTolerance NaN then disables the exp/nbf comparisons. Operator configuration only. Reject non-finite values.
- *(s02-ts-python)* axiam-typescript-sdk/src/amqp/consumer.ts verifyAndDispatch creates a fresh InMemoryNonceStore per call when nonceStore is omitted, so nonce replay dedup is a no-op for integrators who drive it from their own channel. This is documented. Prefer failing when it is absent.
- *(s02-ts-python)* axiam-typescript-sdk/src/rest/session.ts:276 isForeignHost compares host only. An http:// URL on the same host as an https baseUrl would still get X-CSRF-Token/X-Tenant-ID/device bearer attached. Compare the origin (scheme+host+port).
- *(s02-ts-python)* axiam-typescript-sdk/src/grpc/client.ts:468-488 allowInsecure:true opens a plaintext channel for any http host, not only loopback. It is an explicit, logged opt-in. Consider restricting it to loopback in line with §6's spirit.
- *(s02-ts-python)* Both SDKs: require_role/requireRole derive roles from the token's scope claim (axiam-typescript-sdk/src/middleware/verifyCore.ts:195, axiam-python-sdk/src/axiam_sdk/fastapi/__init__.py:299). CONTRACT §11.1 says 'roles'. Scope names are admin-controlled (dcr_allowed_scopes), so this is not a lower-trust bypass, but a scope that shares a role's name is treated as that role for every user of the client.
- *(s02-ts-python)* axiam-python-sdk/src/axiam_sdk/webhook/_verify.py:125,218 re-serializes t via int() (accepts '+', leading zeros, '_' and Unicode digits) instead of MACing the header bytes. No forgery or freshness effect. Align with CONTRACT §13.
- *(s02-ts-python)* axiam-python-sdk/src/axiam_sdk/fastapi/__init__.py:225 and django/middleware.py:136 call hmac.compare_digest on str values, which raises TypeError for a non-ASCII X-CSRF-Token (a 500, fail closed). Compare encoded bytes.
- *(s02-ts-python)* Both SDKs: MemoryOidcStateStore lets anonymous login-route hits add one entry each for up to 10 minutes with no size cap (memory growth). Cap the size.
- *(s02-ts-python)* Both SDKs accept a plain http:// base URL for REST (axiam-python-sdk/src/axiam_sdk/_session.py, axiam-typescript-sdk/src/core/config.ts). This is caller configuration and §6 does not forbid it, but bearer/cookie credentials would travel in cleartext.
- *(s03-java-kotlin)* Java JwksVerifier.selectKey (axiam-java-sdk/src/main/java/io/axiam/sdk/internal/JwksVerifier.java:965-1000) builds JWKMatcher.keyID(header.getKeyID()). For an access token with no kid this matches any OKP key, so kid-less tokens are accepted (the signature must still verify; no forgery). The OIDC path and Kotlin both require kid.
- *(s03-java-kotlin)* Java and Kotlin JWKS: the javadoc claims a 'forced-refetch cooldown 60s' through DefaultJWKSetCache(300,60). In nimbus RemoteJWKSet the second value is only a refresh-ahead time, and an unknown kid triggers updateJWKSetFromURL on every miss (serialized by refreshLock). Each unauthenticated token with a random kid costs one JWKS fetch. Nimbus 10.10 source is not present locally to confirm; add an explicit per-verifier unknown-kid cooldown.
- *(s03-java-kotlin)* Java AxiamClient accepts a plaintext http:// base URL for non-loopback hosts (no ensureSecureBaseUrl equivalent). Kotlin refuses it (AxiamClient.kt 3311-3322).
- *(s03-java-kotlin)* Spring auto-configuration defaults axiam.expected-audience to blank (AxiamAutoConfiguration.java:84-88), so any tenant token is accepted by the default filter. That includes tokens issued to other clients, axiam:m2m tokens and exchanged tokens. Recommend defaulting to RECOMMENDED_RESOURCE_SERVER_AUDIENCE.
- *(s03-java-kotlin)* Spring filter authorities are raw scope strings without Spring's SCOPE_ prefix (AxiamAuthenticationFilter.java:267-271). A scope named ROLE_X therefore satisfies the application's own hasRole("X") rules, a variant of the require-role finding.
- *(s03-java-kotlin)* Kotlin AxiamWebhooks re-serializes t through toLongOrNull before computing the MAC (AxiamWebhooks.kt:91,122-123), so non-canonical t encodings are accepted. No forgery results; use the raw t substring as Java does.
- *(s03-java-kotlin)* Kotlin axiamOidcLogin redirects to an unvalidated return_to query parameter after login (AxiamOidcLogin.kt:81,215,224). It is documented as the caller's responsibility, but the glue gives the caller no validation hook short of a fixed successRedirect.
- *(s04-csharp-php)* Both SDKs leave aud unchecked unless ExpectedAudience/expectedAudience is configured (contract-conditional), so any AXIAM access token of the configured tenant minted for another client or audience is accepted by the guards; consider defaulting to axiam:user and documenting it prominently.
- *(s04-csharp-php)* PHP AxiamClient::verifyLocallyOrFallback() remains public; it returns the application's own claims when the caller's token fails (documented SEC-085 footgun). Consider renaming/internalising it.
- *(s04-csharp-php)* PHP AxiamAccessMiddleware attribute mode returns 'allow' when the route action cannot be reflected (closure routes, missing class/method), silently skipping #[RequireAuth]/#[RequireRole]/#[RequireAccess].
- *(s04-csharp-php)* C# IdTokenValidator accepts an empty caller nonce when the token's nonce is also empty; reject an empty expected nonce in OidcExchangeAsync.
- *(s04-csharp-php)* PHP mTLS private key is written to a tempnam() file for the AxiamClient lifetime and is left on disk if the process dies before __destruct.
- *(s04-csharp-php)* Neither SDK refuses an http:// base URL (not a contract requirement); bearer tokens and the double-submit CSRF cookie then travel in cleartext.
- *(s04-csharp-php)* C# AMQP Hmac.Verify re-serialises with System.Text.Json default escaping, which differs from the server serializer for non-ASCII and HTML-sensitive characters, causing false rejections (availability only, no forgery).
- *(s04-csharp-php)* C# JwksVerifier JwksCacheTtl is unbounded, so a key removed from the JWKS (e.g. after compromise) stays trusted until the TTL expires; SsfReceiver already clamps its cache to 10 minutes.

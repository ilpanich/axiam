import type { DocPage } from "./types";
import { DOCS_VERIFIED_RELEASE } from "../version";

const GH_BLOB = "https://github.com/ilpanich/axiam/blob/main";

/**
 * "Authentication" — every way a principal can prove who it is, one page per
 * mechanism. The ordering runs from the most common (a password) to the most
 * specialised (a machine identity), so a reader integrating a login form is not
 * asked to read about certificate binding first.
 */
export const AUTHENTICATION_PAGES: DocPage[] = [
  {
    slug: "auth",
    section: "Authentication",
    navLabel: "Passwords & sessions",
    title: "Passwords, sessions & tokens",
    intro:
      "How AXIAM verifies a credential, what it hands back, and how that session is kept alive — or ended.",
    verifiedRelease: DOCS_VERIFIED_RELEASE,
    blocks: [
      { type: "h", id: "passwords", text: "Password storage" },
      {
        type: "p",
        text: "Passwords are hashed with **Argon2id** using OWASP-recommended parameters, with a server-side pepper mixed in before hashing. AXIAM never stores or logs a plaintext credential, and every SDK wraps secrets in a redacting type so they cannot leak into a log line, a debug print or an error message.",
      },
      {
        type: "p",
        text: "Each in-flight Argon2id operation allocates roughly a 19 MiB arena, which makes unbounded concurrency a memory-exhaustion vector rather than a throughput problem. A process-wide semaphore caps the number of concurrent arenas and sheds excess load with a `503` instead of queueing without limit. The cost parameters themselves are never weakened to buy throughput — see `AXIAM__AUTH__MAX_CONCURRENT_HASHES` in [Configuration](#/docs/configuration).",
      },
      {
        type: "note",
        text: "If the password should never reach the server at all, AXIAM speaks OPAQUE (RFC 9807). It is off by default and enabled per organization or tenant — see [OPAQUE](#/docs/opaque).",
      },
      { type: "h", id: "policy", text: "Password policy" },
      {
        type: "p",
        text: "Complexity, history and breach-checking are policy, set as an organization baseline and tightened per tenant. The fields are `min_length`, `require_uppercase`, `require_lowercase`, `require_digits`, `require_symbols`, `password_history_count` (how many previous hashes a new password is checked against) and `hibp_check_enabled` (reject passwords appearing in known-breach corpora). See [Settings & policies](#/docs/settings).",
      },
      { type: "h", id: "lockout", text: "Lockout" },
      {
        type: "p",
        text: "Repeated failures lock an account with exponential backoff rather than a flat window: `max_failed_login_attempts` triggers a lock of `lockout_duration_secs`, multiplied by `lockout_backoff_multiplier` on each subsequent lock and clamped at `max_lockout_duration_secs`. An administrator holding `users:admin` can clear a lock early.",
      },
      {
        type: "p",
        text: "Those numbers come from the **organization's effective settings** — the organization baseline as tightened by the tenant — and not from the deployment's process-wide defaults. Every credential-checking path resolves the same policy before accruing a failure: the REST login handler, OPAQUE's login-finish, and the gRPC `ValidateCredentials` service. An account therefore cannot lock after a different number of failures depending on which transport an attacker chose. If the settings cannot be resolved at all, the deployment default applies as a fail-safe floor — a settings outage must not become an open brute-force window.",
      },
      {
        type: "note",
        text: "This is worth knowing if you administer a deployment that predates it: lowering `max_failed_login_attempts` in the admin console used to change nothing at all. The value was stored, merged organization → tenant, and returned by the settings API, but the code that locks accounts never read it.",
      },
      {
        type: "api",
        endpoints: [
          { method: "POST", path: "/api/v1/users/{user_id}/unlock", summary: "Clear an active lockout on an account." },
        ],
      },
      { type: "h", id: "tenant-at-login", text: "Naming the tenant — or not" },
      {
        type: "p",
        text: "`POST /api/v1/auth/login` takes `org_slug` and, optionally, a tenant. Omitting the tenant signs you in at **organization level**, in the organization's reserved scope, which is where estate-wide administrators live. A tenant user who omits the tenant is simply not found there and receives the same enumeration-safe `401` as a wrong password — so a tenant user must name their tenant, and learns nothing by failing to.",
      },
      {
        type: "p",
        text: "Password, OPAQUE and discoverable-passkey sign-in all resolve the blank tenant the same way; nothing on those paths knows or cares which kind of tenant it is authenticating against. The login response carries `organization_level: true` for an organization principal, and such a principal then acts on a member tenant with the `X-Axiam-Tenant` header rather than by signing in again — see [Organization-level principals](#/docs/organization-scope).",
      },
      { type: "h", id: "tokens", text: "Tokens" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Token", "Form", "Lifetime & rules"],
        rows: [
          [
            "Access token",
            "JWT signed with EdDSA (Ed25519)",
            "Short-lived — 15 minutes by default, set per tenant with `access_token_lifetime_secs`. Verifiable offline against the tenant's JWKS.",
          ],
          [
            "Refresh token",
            "Opaque, server-stored",
            "**Single-use**: every refresh rotates it and invalidates the previous one. Reuse of a spent token is detectable and treated as compromise.",
          ],
          [
            "ID token",
            "JWT (OpenID Connect)",
            "Carries `sid`, the session identifier, which is stable across refresh so a relying party can still match a logout token to its own session.",
          ],
        ],
      },
      {
        type: "p",
        text: "In a browser, none of these are handed to JavaScript. They live in `httpOnly` cookies, and the SDKs handle CSRF token forwarding and single-flight refresh — concurrent 401s collapse into one refresh request rather than a thundering herd of them.",
      },
      { type: "h", id: "flow", text: "The login flow" },
      {
        type: "api",
        endpoints: [
          { method: "POST", path: "/api/v1/auth/login", summary: "Authenticate with username/email and password.", public: true },
          { method: "POST", path: "/api/v1/auth/refresh", summary: "Exchange a refresh token for a new pair. Rotates.", public: true },
          { method: "POST", path: "/api/v1/auth/logout", summary: "End the session." },
        ],
      },
      {
        type: "p",
        text: "`login` has **three** outcomes, not two: authenticated, MFA required, and MFA *setup* required — the last on a tenant that enforces MFA for an account that has none. It comes back as a `403` carrying a setup token, and it is recoverable: see [Multi-factor auth](#/docs/mfa) for the branch and what to do with it.",
      },
      {
        type: "codegroup",
        caption: "sign in, then handle a step-up",
        tabs: [
          {
            label: "Rust",
            code: "let result = client.login(\"user@acme.dev\", &password).await?;\n\nif result.mfa_required {\n    client.verify_mfa(\"123456\").await?;\n}",
          },
          {
            label: "TypeScript",
            code: "const result = await client.login(email, password);\n\nswitch (result.status) {\n  case 'mfa_required': {\n    const code = await promptForMfaCode(result.availableMethods);\n    await client.verifyMfa(result.mfaToken, code);\n    break;\n  }\n  case 'authenticated':\n    console.log(`Authenticated as ${result.user.username}`);\n    break;\n}",
          },
          {
            label: "Python",
            code: "result = client.login(email, password)\n\nif result.mfa_required:\n    result = client.verify_mfa(result.mfa_token, totp_code)\n\nprint(result.session_id, result.expires_in)",
          },
          {
            label: "Go",
            code: "result, err := client.Login(ctx, email, password)\nif err != nil {\n    return err\n}\n\nif result.MFARequired {\n    // complete the challenge before the session is established\n}",
          },
          {
            label: "Java",
            code: "LoginResult result = client.login(\"user@acme.dev\", password);\n\nif (result.mfaRequired()) {\n    result = client.verifyMfa(result.challengeToken(), \"123456\");\n}",
          },
        ],
      },
      { type: "h", id: "lifecycle", text: "Account lifecycle" },
      {
        type: "p",
        text: "Everything above assumes an account that already exists and is already verified. These five endpoints are what gets it there and back — and six of the nine account-lifecycle operations are unauthenticated on purpose, because a user who cannot log in is the entire audience for a password reset, and a user whose address is unverified may have no session at all.",
      },
      {
        type: "api",
        endpoints: [
          { method: "POST", path: "/api/v1/auth/verify-email", summary: "Confirm an address from a mailed token. `tenant_id` is a body field.", public: true },
          { method: "POST", path: "/api/v1/auth/resend-verification", summary: "Re-send the verification mail.", public: true },
          { method: "POST", path: "/api/v1/auth/reset", summary: "Begin a password reset. Accepts the workspace in slug form, like login.", public: true },
          { method: "GET", path: "/api/v1/auth/reset/context", summary: "The effective OPAQUE policy for the account a reset token belongs to.", public: true },
          { method: "POST", path: "/api/v1/auth/reset/confirm", summary: "Set the new password with the mailed token.", public: true },
          { method: "POST", path: "/api/v1/users/me/resend-verification", summary: "Re-send the verification mail to the signed-in caller, reporting the real outcome." },
        ],
      },
      {
        type: "p",
        text: "The last of those is the signed-in counterpart to `POST /auth/resend-verification`, and the pair exists because the two answer to different constraints. The anonymous endpoint takes an address it cannot vouch for, so it answers a constant `200 {\"sent\": true}` whether or not the account exists — it has to, or it becomes an address oracle. The authenticated one already knows who is asking, so it can tell them the truth: that the address is already verified, that no address is on file, or that the mail could not be queued. Reporting a real outcome to a caller who is entitled to it is not a leak.",
      },
      {
        type: "warn",
        text: "**These endpoints are enumeration-safe, and your UI must not undo that.** `POST /auth/reset` answers `200` whether or not the address exists. `GET /auth/reset/context` answers `404` for a token that is unknown, expired *or* already consumed, without distinguishing the three, and discloses no identity — an unauthenticated endpoint that confirmed which account a token belongs to would be an oracle worth not having. A screen that says “no such user”, or that shows the account beside the form, hands back exactly what the uniform response was protecting.",
      },
      {
        type: "p",
        text: "The reset context exists because of OPAQUE. A tenant with OPAQUE enabled needs the client to build a registration record before it can send a new password, and building one needs the server's parameters — which the client cannot know before it has a token to ask with. So on any tenant that might have OPAQUE enabled, read the context first and populate the `opaque` field when it says the tenant requires it; sending a plaintext `new_password` to a tenant in `opaque_mode: required` is refused, and refused late.",
      },
      {
        type: "codegroup",
        caption: "completing a reset, OPAQUE or not",
        tabs: [
          {
            label: "Rust",
            code: `let context = client.password_reset_context(&token).await?;

client.confirm_password_reset(&PasswordResetConfirmation {
    token,
    new_password,
    tenant_id,
    opaque: /* build a §23 record when context.opaque is Some */ None,
})
.await?;`,
          },
          {
            label: "TypeScript",
            code: `const context = await client.passwordResetContext(token);

await client.confirmPasswordReset({
  token,
  newPassword,
  tenantId,
  ...(context.opaque ? { opaque: await client.opaqueEnrollment(newPassword) } : {}),
});`,
          },
        ],
      },
      {
        type: "note",
        text: "The tokens in these mails are single-use and short-lived, which is what bounds the risk of the final mail hop being unencrypted — an inherent property of email that no server-side control closes. See [OPAQUE](#/docs/opaque) for when the password never reaches the server at all.",
      },
      { type: "h", id: "sessions", text: "Sessions end, not users" },
      {
        type: "p",
        text: "Logout operates on a session, not on an identity. A user signed in on a phone and a laptop who logs out on the laptop expects the phone to stay signed in, and that is what happens. When relying parties are registered for back-channel logout, ending a session also notifies them — see [Logout & session management](#/docs/logout).",
      },
      {
        type: "p",
        text: "The removal cookies logout sends back are built from the same setters they clear, so their protective attributes — `Secure`, `HttpOnly`, `SameSite`, path and domain — are mirrored by construction rather than restated in a second place. A browser only replaces a cookie when the attributes match; a hand-written removal that drifted from the setter would leave the session cookie sitting in the jar while the response claimed to have cleared it.",
      },
      { type: "h", id: "rate", text: "Rate limiting" },
      {
        type: "p",
        text: "`/auth/login` is always keyed per source IP regardless of the deployment's rate-limit key mode, and stays strict under every posture preset. Register, password-reset, MFA and WebAuthn endpoints are likewise per-IP. The reasoning — and why `client_id` keying is a fairness control rather than an abuse control — is in [Configuration](#/docs/configuration).",
      },
    ],
  },

  {
    slug: "opaque",
    section: "Authentication",
    navLabel: "OPAQUE (RFC 9807)",
    title: "OPAQUE — the password never reaches the server",
    intro:
      "An augmented PAKE in which AXIAM authenticates you without ever receiving your password, and in which a stolen credential database is not offline-crackable on its own.",
    verifiedRelease: DOCS_VERIFIED_RELEASE,
    blocks: [
      { type: "h", id: "what", text: "What it changes" },
      {
        type: "p",
        text: "In an ordinary password login the plaintext travels to the server inside the TLS session, and the server hashes it. TLS protects it in transit, but the server *has* it — which means a TLS-terminating proxy, an accidentally verbose request log, a heap dump or a memory-scraping exploit can capture it.",
      },
      {
        type: "p",
        text: "With **OPAQUE** ([RFC 9807](https://datatracker.ietf.org/doc/rfc9807/)), the CFRG's augmented PAKE, the client blinds the password and the server evaluates an oblivious PRF over it without learning either the input or the output. The client uses the result to open a sealed envelope containing its long-term key material, and the two sides complete an authenticated key exchange. The server never holds a plaintext password at any point in the exchange.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Exposure", "Password + Argon2id", "OPAQUE"],
        rows: [
          ["TLS-terminating proxy sees the password", "Yes", "No — it sees a blinded element"],
          ["Verbose request log captures it", "Yes", "No"],
          ["Server heap dump contains it", "Yes", "No"],
          [
            "Stolen credential database is offline-crackable",
            "Yes, at the cost of the KDF",
            "**No** — an attacker additionally needs the tenant's OPRF seed, encrypted at rest under a key that is not in the database",
          ],
          ["Compromised AXIAM server can steal it", "Yes", "Yes — see the limits below"],
        ],
      },
      { type: "h", id: "limits", text: "What it does not do" },
      {
        type: "warn",
        text: "OPAQUE does not protect against a compromised AXIAM server. A server that wants your password can serve a login page that collects it. For **browser** clients the benefit is bounded for exactly this reason — AXIAM serves the code that performs the computation. The strong case is native SDK clients, IoT devices, and deployments sitting behind infrastructure the tenant does not control.",
      },
      { type: "h", id: "modes", text: "Enabling it" },
      {
        type: "p",
        text: "OPAQUE is **off by default** and configured as a policy: an organization sets the baseline and a tenant may only tighten it. The relevant fields are `opaque_mode`, `opaque_suite` (default `ristretto255_sha512`) and `opaque_ksf` (default `argon2id`, with `scrypt` as the alternative rung).",
      },
      {
        type: "table",
        headers: ["Mode", "Meaning"],
        rows: [
          ["disabled", "The default. Only password login is offered."],
          [
            "optional",
            "Both paths work. Users enrol an OPAQUE record as they next set a password — creation, change, or reset completion; those who have not yet keep using the password path.",
          ],
          [
            "required",
            "Only OPAQUE login is accepted, tenant-wide.",
          ],
        ],
      },
      {
        type: "warn",
        text: "`required` cannot be turned on safely until every user in the tenant has enrolled. A registration record must be built from the plaintext password, and a stored Argon2id hash is not invertible — so **nobody can be enrolled retroactively**. Switching to `required` early locks out every user who has no record. Run `optional` until enrolment is complete, then flip.",
      },
      {
        type: "p",
        text: "Turning OPAQUE on provisions the tenant's server-side key material at the settings write, so `opaque_server_setup` is populated immediately rather than waiting for somebody's first sign-in. Registration records are a different matter: `opaque_credential` fills up only as users set passwords, which is what `optional` is for. A tenant that has just switched to `optional` has key material and no records at all, and that is the expected state, not a failure.",
      },
      {
        type: "warn",
        text: "**Under `optional`, a failed OPAQUE exchange means \"try the password path\", not \"wrong password\".** An account with no registration record is the *ordinary* case during a migration, and the server deliberately makes that indistinguishable from a wrong password — it must, or the exchange becomes an enrolment oracle. So `login/start` returns a `mode` field carrying the tenant's `opaque_mode`, and a client that sees a failed `KE2` under `optional` is required to retry over `POST /api/v1/auth/login` rather than treating the exchange as final. Without that retry, enabling `optional` is indistinguishable from enabling `required` with nobody enrolled — which is to say it locks out every user of the tenant.",
      },
      {
        type: "note",
        text: "`mode` is a property of the tenant, identical for a real and a decoy exchange, so it discloses nothing about whether an identity is enrolled. It is `\"optional\"` or `\"required\"` and never `\"disabled\"` — a disabled tenant answers `404`. An absent `mode` reads as `required`, so a client written before contract 1.29 stays correct against a `required` tenant and only a tenant mid-migration is affected.",
      },
      {
        type: "note",
        text: "Bootstrap is the exception, and the only moment a deployment can start with OPAQUE already working: `POST /api/v1/admin/bootstrap` receives the plaintext password — it must, to compute the Argon2id hash — so it runs both halves of the registration itself and the first administrator is enrolled with no client involvement. The admin UI's initialization page exposes the three policy fields for exactly this reason.",
      },
      { type: "h", id: "flow", text: "The exchange" },
      {
        type: "api",
        endpoints: [
          { method: "POST", path: "/api/v1/auth/opaque/register/start", summary: "Begin enrolment: server evaluates the OPRF over the blinded password.", public: true },
          { method: "POST", path: "/api/v1/auth/opaque/login/start", summary: "Send KE1; receive KE2 plus the KSF parameters to use.", public: true },
          { method: "POST", path: "/api/v1/auth/opaque/login/finish", summary: "Send KE3; the session is established.", public: true },
        ],
      },
      {
        type: "p",
        text: "Login is two round trips rather than one, because the OPRF needs the server. Two rules matter to anyone integrating it directly:",
      },
      {
        type: "list",
        items: [
          "**Build the key-stretching function from what the server named**, never from a local default. `login/start` returns the KSF and its parameters; using anything else produces an envelope that cannot be opened.",
          "**A failure at `finish` is indistinguishable by design.** Wrong password, unknown account, and an account with no registration record all fail identically. What to do next comes from `mode` in the `login/start` response, and nothing else: under `required`, the attempt is over and no plaintext may be sent. Under `optional`, retry over `POST /api/v1/auth/login` — an account with no record is the ordinary case there, and a client that treats the failure as final locks out every user of a tenant mid-migration.",
        ],
      },
      {
        type: "code",
        caption: "login · TypeScript, via the shared WASM core",
        code: "import init, { OpaqueLogin, OpaqueKsf } from '@axiam/opaque-wasm';\n\nawait init();\n\n// 1. Blind the password and start the exchange.\nconst login = new OpaqueLogin(password);\nconst started = await postJson('/api/v1/auth/opaque/login/start', {\n  org_slug, tenant_slug, username_or_email, ke1: login.ke1,\n});\n\n// 2. Build the KSF from what the SERVER named.\nconst ksf = started.ksf === 'argon2id'\n  ? OpaqueKsf.argon2id(started.memory_kib, started.iterations, started.parallelism)\n  : OpaqueKsf.scrypt(started.log_n, started.r, started.p);\n\n// 3. Open the envelope, then finish.\nconst finished = login.finish(password, started.ke2, ksf);\n\nawait postJson('/api/v1/auth/opaque/login/finish', {\n  opaque_session: started.opaque_session,\n  ke3: finished.ke3,\n});",
      },
      {
        type: "note",
        text: "`login` is **consumed** by `finish`. Calling it twice throws rather than reusing one OPRF blind across two exchanges.",
      },
      { type: "h", id: "sdk-usage", text: "Through an SDK" },
      {
        type: "p",
        text: "Integrating directly is only necessary in a browser or on an unsupported platform. Every SDK wraps the exchange in one call that returns the same result type as an ordinary login, MFA challenge included.",
      },
      {
        type: "codegroup",
        caption: "sign in without sending the password",
        tabs: [
          {
            label: "Rust",
            code: 'use axiam_sdk::AxiamClient;\n\nlet client = AxiamClient::builder()\n    .base_url("https://axiam.example")?\n    .org_slug("acme")\n    .tenant_slug("default")\n    .build()?;\n\n// Same LoginResult as login(), including the MFA-challenge case.\nlet result = client.login_opaque("alice", "correct horse battery staple").await?;\nif result.mfa_required {\n    client.verify_mfa("123456").await?;\n}',
          },
          {
            label: "Python",
            code: '# Same LoginResult as login(), including the mfa_required case.\nresult = client.login_opaque("alice", "correct horse battery staple")',
          },
          {
            label: "Go",
            code: 'result, err := client.LoginOpaque(ctx, "alice", password)',
          },
        ],
      },
      {
        type: "p",
        text: "Enrolment is a separate call, and it exists because the server cannot build a record on its own — it never sees the plaintext. Send the result with any request that sets a password.",
      },
      {
        type: "codegroup",
        caption: "enrol a record when setting a password",
        tabs: [
          {
            label: "Rust",
            code: 'let enrollment = client.opaque_enrollment("new password").await?;\n// send `enrollment` as the request\'s `opaque` field',
          },
          {
            label: "Python",
            code: 'enrollment = client.opaque_enrollment("new password")\n# send enrollment["registration_record"] and enrollment["opaque_session"]\n# as the request\'s `opaque` object',
          },
          {
            label: "Go",
            code: 'enrollment, err := client.OpaqueEnrollment(ctx, newPassword)\n// send `enrollment` as the request body\'s `opaque` field',
          },
        ],
      },
      {
        type: "note",
        text: "Enrolment takes one argument where the SRP verifier it replaced took four. There is no identity, group or KDF to pass: the server names the ciphersuite and the costs in its `register/start` response, and the record binds to a credential identifier the server chooses — so enrolling against an email can no longer produce a record no login can satisfy, and a later rename no longer invalidates a credential.",
      },
      {
        type: "warn",
        text: "**Fall back to ordinary login on exactly one error.** A tenant that does not offer OPAQUE reports it as a network-class error naming OPAQUE — deliberately not an authentication error, so it cannot be mistaken for a bad password. Fall back on that one and nothing else: a failed exchange *is* a failed login, and retrying it over the password path hands the plaintext to a server that just failed to prove it holds the record.",
      },
      {
        type: "note",
        text: "The call blocks for as long as the tenant's key-stretching function takes — Argon2id at 19 MiB by default, so tens to hundreds of milliseconds. That cost is the point, since it is what makes a stolen record expensive to attack even for someone holding the OPRF seed, but on an async runtime treat it as blocking work rather than as a quick round trip.",
      },
      { type: "h", id: "availability", text: "How each SDK binds it" },
      {
        type: "p",
        text: "Every SDK ships OPAQUE. There is no conditional row in the sense that mattered before — the SRP implementation this replaced had four SDKs that could not compute Argon2id and one that needed a specific bignum extension. What differs now is only *how* each binds the single implementation.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["SDK", "Binding", "What that means for you"],
        rows: [
          ["Rust", "Native crate", "Also compiles to `wasm32-unknown-unknown` for the WASM package."],
          ["TypeScript", "WebAssembly", "Adds a WASM module to the package; check its README for the size."],
          ["Go", "Native", "No cgo, so a `CGO_ENABLED=0` build still works."],
          ["Python", "C ABI via wheels", "Platform wheels. A source install needs a Rust toolchain."],
          ["Java", "C ABI via JNI/FFM", "Native artifacts ship inside the jar."],
          ["Kotlin", "As Java", "Same JVM target, same artifacts."],
          ["C#", "C ABI via P/Invoke", "Native assets ship in the NuGet package."],
          [
            "PHP",
            "C ABI via `ext-ffi`",
            "**The one build-time conditional.** Without `ext-ffi` and the shared library present, the availability probe answers false.",
          ],
          ["Swift", "C interop", "Replaces the bundled modular exponentiation SRP required."],
          ["C", "Header and library", "Direct."],
          ["C++", "Wraps the C binding", "Direct."],
        ],
      },
      { type: "h", id: "one-impl", text: "One implementation, twelve callers" },
      {
        type: "p",
        text: "AXIAM speaks OPAQUE from twelve places — the server, the admin console and eleven SDKs — and every one of them must agree on every byte. OPAQUE is not a protocol it is reasonable to hand-write once per language: it needs an OPRF, `hash_to_curve`, `expand_message_xmd`, an envelope construction and a three-message AKE.",
      },
      {
        type: "p",
        text: "So there is exactly one implementation, the `axiam-opaque` crate, and every client binds it: compiled directly (Rust, the server), through WebAssembly as `@axiam/opaque-wasm` (TypeScript, the admin console), or behind a C ABI (everything else). The cross-language contract is `sdks/CONTRACT.md` §23, and `sdks/opaque-test-vectors.json` is the shared fixture every SDK is tested against.",
      },
      {
        type: "note",
        text: "This replaced an SRP-6a implementation that had been written eleven times, because SRP is modular arithmetic and every language has a bignum. That produced a bundled Montgomery modular exponentiation in one SDK and another that reported itself unavailable without a specific extension. OPAQUE removes the offline attack rather than repricing it, and one audited implementation removes the drift.",
      },
      { type: "h", id: "keys", text: "The two keys it needs" },
      {
        type: "table",
        headers: ["Variable", "What it protects", "Cost of losing it"],
        rows: [
          [
            "AXIAM__AUTH__OPAQUE_SETUP_KEY",
            "Encrypts each tenant's OPRF seed and AKE keypair at rest.",
            "**A password reset for every user in every tenant.** Back this up.",
          ],
          [
            "AXIAM__AUTH__OPAQUE_SESSION_KEY",
            "Seals in-flight exchange state (a 120-second window).",
            "In-flight logins fail and are retried. Deliberately separate from the setup key so it is cheap to rotate.",
          ],
        ],
      },
      {
        type: "p",
        text: "Both are required whenever any organization or tenant has `opaque_mode` other than `disabled`. Where they come from is pluggable — environment, a mounted file, or HashiCorp Vault. See [Secrets & Vault](#/docs/secrets).",
      },
    ],
  },

  {
    slug: "mfa",
    section: "Authentication",
    navLabel: "Multi-factor auth",
    title: "Multi-factor authentication",
    intro:
      "TOTP as the baseline second factor, enrolled voluntarily by a signed-in user or forced during a login that cannot complete without it.",
    verifiedRelease: DOCS_VERIFIED_RELEASE,
    blocks: [
      { type: "h", id: "totp", text: "TOTP" },
      {
        type: "p",
        text: "AXIAM's baseline second factor is TOTP (RFC 6238) — the six-digit rolling code produced by an authenticator app. Enrolment returns a secret and a provisioning URI for a QR code; the user confirms with one generated code, which proves their clock and the secret agree before the factor is armed.",
      },
      {
        type: "p",
        text: "Stored TOTP secrets are encrypted at rest with AES-256-GCM under `AXIAM__AUTH__MFA_ENCRYPTION_KEY`. Losing that key makes every enrolled secret undecryptable and forces every user to re-enrol.",
      },
      {
        type: "warn",
        text: "**Treat the provisioning URI as the secret, because it is one.** `otpauth://totp/…?secret=…` contains the shared secret verbatim, and it is the field that actually reaches a log — it is the one you hand to a QR renderer. Every SDK wraps both in its redacting type; a receiver that unwraps the URI to render it has unwrapped the secret.",
      },
      { type: "h", id: "what-counts", text: "What counts as a second factor" },
      {
        type: "p",
        text: "The account's second-factor requirement is about *factors*, not about TOTP specifically. It turns on when the first method is enrolled — a confirmed TOTP secret, or a passkey, or a security key — and off when the last one is removed. So enrolling a passkey makes the next sign-in ask for a second factor just as confirming a TOTP code does, and an account holding only passkeys is a properly two-factor account.",
      },
      {
        type: "note",
        text: "One interaction is worth knowing if you enrol both: a TOTP enrolment that was started and never confirmed is **dropped** when a passkey turns the requirement on, rather than being promoted alongside it. There is no separate \"confirmed\" bit — every reader tests the pair of flag-and-secret — so adopting the pending secret would arm a factor the user never proved they could produce a code for.",
      },
      { type: "h", id: "paths", text: "Two enrolment paths, and they are not interchangeable" },
      {
        type: "p",
        text: "Confusing these two is the failure mode worth spelling out: they use different endpoints, different credentials and different starting states, and reaching for the wrong pair locks a user out of an account they are entitled to.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["", "Voluntary", "Forced during login"],
        rows: [
          ["Who starts it", "A signed-in user adding a factor", "Anyone whose tenant requires MFA on an account that has none"],
          ["Credential", "The existing session", "A `setup_token` the failed login handed back — there is no session yet"],
          ["Endpoints", "`/auth/mfa/enroll` then `/auth/mfa/confirm`", "`/auth/mfa/setup/enroll` then `/auth/mfa/setup/confirm`"],
          ["What confirming does", "Arms the factor; the current session is untouched", "**Completes the interrupted login** — the response is a normal login success"],
        ],
      },
      { type: "h", id: "voluntary", text: "Voluntary enrolment" },
      {
        type: "steps",
        steps: [
          {
            title: "Enrol",
            body: "`POST /api/v1/auth/mfa/enroll` with the user's session and no body. The response carries `secret_base32` and `totp_uri`.",
          },
          {
            title: "Show it once",
            body: "Render the URI as a QR code, and offer the base32 secret for manual entry. This is the only time the secret is available.",
          },
          {
            title: "Confirm",
            body: "`POST /api/v1/auth/mfa/confirm` with a code generated from it. **The factor is not active until this succeeds** — a client that reports MFA as enabled after the first call is reporting a factor nobody can use.",
          },
        ],
      },
      { type: "h", id: "forced", text: "Forced enrolment during login" },
      {
        type: "steps",
        steps: [
          {
            title: "The login is refused, with the means to recover",
            body: "`POST /api/v1/auth/login` answers `403` with `mfa_setup_required: true` and a `setup_token`. This is an outcome, not a permission failure: the caller can act on it, and an SDK that reports it as an authorization error has told them they may not log in when the server said “finish setting up, here is the token”.",
          },
          {
            title: "Enrol with the setup token",
            body: "`POST /api/v1/auth/mfa/setup/enroll`. The setup token *is* the credential — there is no session to authenticate with yet.",
          },
          {
            title: "Confirm, and the login completes",
            body: "`POST /api/v1/auth/mfa/setup/confirm` returns the normal login success, cookies and all. Nothing needs re-submitting a password.",
          },
        ],
      },
      {
        type: "codegroup",
        caption: "handling all three login outcomes",
        tabs: [
          {
            label: "Rust",
            code: `let result = client.login(email, password).await?;

if result.mfa_required {
    client.verify_mfa(code).await?;
} else if result.mfa_setup_required {
    let setup_token = result.setup_token.as_ref().expect("populated by §25.2 rule 1");
    let enrolment = client.mfa_setup_enroll(setup_token).await?;
    render_qr(enrolment.totp_uri.expose());
    client.mfa_setup_confirm(setup_token, code).await?;   // completes the login
}`,
          },
          {
            label: "TypeScript",
            code: `switch (result.status) {
  case 'authenticated':
    break;
  case 'mfa_required':
    await client.verifyMfa(result.mfaToken, code);
    break;
  case 'mfa_setup_required': {
    const enrolment = await client.mfaSetupEnroll(result.setupToken);
    renderQr(enrolment.totpUri.expose());
    await client.mfaSetupConfirm(result.setupToken, codeTypedByUser);
    break;                                  // this completes the login
  }
}`,
          },
          {
            label: "Python",
            code: `result = client.login(email, password)

if result.mfa_required:
    result = client.verify_mfa(result.mfa_token, totp_code)
elif result.mfa_setup_required:
    enrolment = client.mfa_setup_enroll(setup_token=result.setup_token)
    render_qr(enrolment.totp_uri.get_secret_value())
    client.mfa_setup_confirm(setup_token=result.setup_token, totp_code=code)`,
          },
        ],
      },
      {
        type: "note",
        text: "Contract 1.28 made the setup branch a first-class login outcome across all eleven SDKs. If you match a login result exhaustively, that is the edit: a genuine authorization refusal is still an authorization error, because the SDK matches on the body's own discriminant rather than on the `403` alone.",
      },
      { type: "h", id: "endpoints", text: "Endpoints" },
      {
        type: "api",
        endpoints: [
          { method: "POST", path: "/api/v1/auth/mfa/enroll", summary: "Begin voluntary enrolment. **Requires a session**; no body." },
          { method: "POST", path: "/api/v1/auth/mfa/confirm", summary: "Arm the factor with a generated code. **Requires a session.**" },
          { method: "POST", path: "/api/v1/auth/mfa/setup/enroll", summary: "Begin forced enrolment, authenticated by the login's setup token.", public: true },
          { method: "POST", path: "/api/v1/auth/mfa/setup/confirm", summary: "Arm it and complete the interrupted login.", public: true },
          { method: "POST", path: "/api/v1/auth/mfa/verify", summary: "Answer an MFA challenge during login.", public: true },
          { method: "GET", path: "/api/v1/users/{user_id}/mfa-methods", summary: "List a user's enrolled factors." },
          { method: "DELETE", path: "/api/v1/users/{user_id}/mfa-methods/{method_id}", summary: "Remove one factor." },
          { method: "POST", path: "/api/v1/users/{user_id}/reset-mfa", summary: "Administratively clear every factor on an account." },
        ],
      },
      { type: "h", id: "stepup", text: "The step-up in a login" },
      {
        type: "p",
        text: "When a factor is required, `POST /auth/login` does not establish a session. It returns an MFA challenge, and the SDK surfaces it as an outcome rather than an exception — the session is established only once `/auth/mfa/verify` succeeds. The challenge has its own lifetime, `mfa_challenge_lifetime_secs`, set per tenant.",
      },
      { type: "h", id: "policy", text: "Enforcing it" },
      {
        type: "p",
        text: "`mfa_enforced` is a policy field on the settings baseline: set it at the organization and every tenant inherits it, or tighten it on one tenant. As with every setting, a tenant may make the posture stricter than the organization's baseline but never looser. Turning it on is what produces the forced-enrolment branch above for accounts that have no factor yet.",
      },
      {
        type: "warn",
        text: "Enforce MFA on administrative accounts before anything else. A super-admin holds every permission in the tenant, including the ones that would let an attacker remove the audit evidence of what they did with it.",
      },
      {
        type: "note",
        text: "TOTP is the baseline, not the ceiling. **Passkeys and security keys are phishing-resistant in a way a typed code is not** — a code can be entered into a lookalike page and forwarded to the real one inside its window. A registered passkey appears as `webauthn` among a challenge's available methods. See [Passkeys & WebAuthn](#/docs/passkeys).",
      },
    ],
  },

  {
    slug: "passkeys",
    section: "Authentication",
    navLabel: "Passkeys & WebAuthn",
    title: "Passkeys & WebAuthn",
    intro:
      "Phishing-resistant authentication bound to your origin — as a second factor, or as the only factor — with an attestation policy for deployments that need to say which authenticators are acceptable.",
    verifiedRelease: DOCS_VERIFIED_RELEASE,
    blocks: [
      { type: "h", id: "why", text: "Why they are different" },
      {
        type: "p",
        text: "A **passkey** is a credential held by a device the user already has — a laptop's fingerprint sensor, a phone's face unlock, a platform PIN. A **security key** is the same construction on a removable device. Both are WebAuthn credentials, and both are phishing-resistant for a structural reason: the credential is cryptographically bound to the exact origin that created it, so a lookalike page cannot use it *even if the user is completely fooled*.",
      },
      {
        type: "p",
        text: "A one-time code cannot make that promise. It can be typed into a fake page and forwarded to the real one inside its thirty-second window, which is precisely how modern credential-phishing kits work.",
      },
      { type: "h", id: "endpoints", text: "Six endpoints, three ceremonies" },
      {
        type: "api",
        endpoints: [
          { method: "POST", path: "/api/v1/auth/webauthn/register/start", summary: "Creation options for a new credential. **Requires a session.**" },
          { method: "POST", path: "/api/v1/auth/webauthn/register/finish", summary: "Submit the attestation; the credential is stored. **Requires a session.**" },
          { method: "POST", path: "/api/v1/auth/webauthn/authenticate/start", summary: "Request options for a second-factor ceremony, from a login's challenge token.", public: true },
          { method: "POST", path: "/api/v1/auth/webauthn/authenticate/finish", summary: "Submit the assertion; the session is established.", public: true },
          { method: "POST", path: "/api/v1/auth/webauthn/authenticate/discoverable/start", summary: "Request options for a usernameless sign-in — no prior step.", public: true },
          { method: "POST", path: "/api/v1/auth/webauthn/authenticate/discoverable/finish", summary: "Submit the assertion; the assertion itself identifies the user.", public: true },
        ],
      },
      {
        type: "warn",
        text: "**The two authentication ceremonies are different flows, not one with a flag.** `authenticate/*` is a *second* factor: it continues a login that answered with an MFA challenge, and the challenge token names the user so the server can send an `allowCredentials` list. `discoverable/*` is a *primary* factor: nothing precedes it, `allowCredentials` is empty, and the authenticator offers whichever credential it holds for your origin. Modelling them as one call with an optional token reproduces a bug the server already fixed — `authenticate/start` decodes the token to learn who is signing in, so an empty one is rejected as malformed before anything else happens.",
      },
      { type: "h", id: "register", text: "Enrolling a passkey" },
      {
        type: "steps",
        steps: [
          {
            title: "Ask the server for creation options",
            body: "`POST /api/v1/auth/webauthn/register/start`, with the user's existing session. The response carries the challenge and a state token. The server chooses `residentKey`, `userVerification`, the attestation conveyance, the exclusion list and the timeout — every one of them is a security parameter. `userVerification` it chooses **from policy**, not from a library constant: see [User verification is a setting](#uv-policy) below.",
          },
          {
            title: "Run the ceremony",
            body: "Hand the options to the platform: `navigator.credentials.create()` in a browser, `CreatePublicKeyCredentialRequest` on Android, `AuthenticationServices` on Apple platforms. Pass them **unchanged** — see the note below.",
          },
          {
            title: "Post the attestation back",
            body: "`POST /api/v1/auth/webauthn/register/finish` with the state token and the authenticator's response verbatim. A `201` returns the stored credential. A `403` is the tenant's attestation policy refusing *this authenticator* rather than a permission problem — surface its message, because it is how the person holding the key learns that this one will never work and a different one might.",
          },
          {
            title: "Have the user name it, and enrol a second",
            body: "A passkey lives on the device that created it. If that device is the only factor and it is lost, the account is locked out — and “Passkey 2” is not a name anyone can act on when deciding which to revoke.",
          },
        ],
      },
      {
        type: "note",
        text: "**Enrolling a passkey is enrolling a factor.** From the moment a WebAuthn credential exists on the account, the next sign-in demands a second factor — exactly as confirming a TOTP secret does. Removing the last credential turns the requirement back off. This used to be true only of TOTP: a passkey was listed on the profile and accepted at `/auth/webauthn/authenticate`, while a password on its own still let the account straight in. An abandoned, unconfirmed TOTP enrolment sitting on the same account is **dropped** rather than silently promoted alongside the passkey — the two are not the same factor, and turning the requirement on must not arm a secret the user never confirmed.",
      },
      {
        type: "warn",
        text: "**Pass the options through untouched, in both directions.** Do not supply a `timeout` the server omitted, do not expand an absent `authenticatorSelection` into an empty object, do not reorder or prune `pubKeyCredParams` or `excludeCredentials`, and do not re-encode the response's base64url fields. Relaxing `userVerification` to `preferred` because a CI authenticator kept prompting weakens a ceremony the server believes it configured, and the server cannot detect it: an assertion produced under weaker options is a perfectly valid assertion.",
      },
      { type: "h", id: "uv-policy", text: "User verification is a setting" },
      {
        type: "p",
        text: "`webauthn_user_verification` is a security setting: an **organization** baseline every tenant inherits and may only make stricter, ordered `required` > `preferred` > `discouraged`. Raising the organization baseline past a tenant's override clears that override, so the tenant tracks the new baseline.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Value", "At enrolment", "Use it when"],
        rows: [
          ["`discouraged`", "No verification requested", "The key is unambiguously a second factor behind a password"],
          ["`preferred` **(default)**", "Requested, accepted either way, and what happened is recorded", "Supporting security keys generally, PIN-protected or not"],
          ["`required`", "A key that cannot verify is refused", "A WebAuthn credential may stand alone as a login factor"],
        ],
      },
      {
        type: "p",
        text: "The default is `preferred` rather than `required` because nobody chose `required` — it was a library constant. So a security key with no PIN now **enrols and works as a second factor**, and the server records whether verification actually happened.",
      },
      {
        type: "note",
        text: "**Two ceremonies ignore the setting.** Usernameless sign-in keeps `required` whatever it is set to — there the credential is the only factor, so without verification mere possession of the token would be a complete login; the practical consequence is that a PIN-less key works as a second factor and cannot be used for passwordless sign-in. Attested registration keeps `required` too, because the library imposes it on the attested ceremony and AXIAM does not override it.",
      },
      {
        type: "p",
        text: "**Relaxing the setting weakens nothing already enrolled.** The policy a credential was registered under is recorded and honoured for the rest of that credential's life, so every credential enrolled before this existed keeps demanding verification. The setting governs new enrolments. It is also a required field on the settings write, so a client cannot relax it by omission.",
      },
      {
        type: "links",
        links: [
          {
            label: "Authenticator policies (administrator guide)",
            href: `${GH_BLOB}/docs/admin/authenticator-policies.md`,
            note: "The setting, the two ceremonies that ignore it, and the attestation policy it sits beside",
          },
        ],
      },
      { type: "h", id: "signin", text: "Signing in" },
      {
        type: "steps",
        steps: [
          {
            title: "As a second factor",
            body: "`POST /api/v1/auth/login` answers with an MFA challenge listing `webauthn` among its methods. Call `authenticate/start` with that challenge token, run the ceremony, and post the assertion to `authenticate/finish`.",
          },
          {
            title: "Usernameless, as the only factor",
            body: "Call `discoverable/start` with your workspace — it accepts `org_id`/`org_slug` and `tenant_id`/`tenant_slug`, and unlike the OAuth2 endpoints it accepts slugs, so a slug-only client can run it. Then run the ceremony and post to `discoverable/finish`.",
          },
          {
            title: "Either way, you are signed in",
            body: "Both `finish` calls answer `200` with `access_token`, `refresh_token`, `session_id` and `expires_in`, **and** set the `axiam_access` / `axiam_refresh` / `axiam_csrf` cookie triple with an `X-CSRF-Token` response header — the same triple `POST /api/v1/auth/login` sets. Browser clients are authenticated by the cookies; non-browser clients adopt the body tokens.",
          },
        ],
      },
      {
        type: "note",
        text: "The cookies arrived in **1.0.0-alpha38**. Before it these two endpoints answered with the body alone, which made a browser passkey sign-in impossible to complete: `POST /api/v1/auth/refresh` reads the refresh token from `axiam_refresh` and never from a body, so the session could not be kept alive. If you built against an older server, the body is unchanged — the cookies are additive.",
      },
      {
        type: "note",
        text: "Only the usernameless path fires the `login.post_auth` reactor hook. The username-bound ceremony continues a login that was already gated at its first step; the discoverable one has no first step to have been gated at. See [Reactors](#/docs/reactors).",
      },
      { type: "h", id: "sdks", text: "From an SDK" },
      {
        type: "p",
        text: "A WebAuthn ceremony is two exchanges stacked: one with an *authenticator*, which needs a platform API, and one with *AXIAM*, which is four ordinary JSON round trips. Only the first needs a browser — which is why all eleven SDKs carry the AXIAM half. They expose the challenge in its wire JSON form and accept the platform's response JSON back, because that is exactly what the platform APIs take and return: `parseCreationOptionsFromJSON()` and `credential.toJSON()` in browsers, `requestJson` in and `registrationResponseJson` out on Android.",
      },
      {
        type: "codegroup",
        caption: "the JSON bridge — any runtime",
        tabs: [
          {
            label: "Rust",
            code: `let challenge = client.webauthn_discoverable_start(None).await?;

// The JSON form every platform authenticator API takes (§24.6a) — the exact
// string Android's CreatePublicKeyCredentialRequest and a browser's
// parseRequestOptionsFromJSON() both want.
let response_json = your_device_channel(&challenge.request_json())?;

let session = client
    .webauthn_discoverable_finish(
        &challenge.state_token,
        webauthn_response_from_json(&response_json)?,
    )
    .await?;`,
          },
          {
            label: "TypeScript",
            code: `import { webauthnRequestJson } from 'axiam-sdk/rest';

const { challenge, stateToken } = await client.webauthnDiscoverableStart();
const requestJson = webauthnRequestJson(challenge);   // → give this to the platform

// …the platform runs the ceremony and hands back a JSON string…
await client.webauthnDiscoverableFinish(stateToken, responseJson);`,
          },
          {
            label: "Browser",
            code: `// The half that needs a browser, and only this half.
const options = PublicKeyCredential.parseRequestOptionsFromJSON(requestJson);
const assertion = await navigator.credentials.get({ publicKey: options });
const responseJson = assertion.toJSON();   // → back to the SDK, unchanged`,
          },
        ],
      },
      {
        type: "p",
        text: "TypeScript (browser build), the Rust WebAssembly build and Swift additionally compose the whole thing into one call, because their build can reach an authenticator API. The other SDKs deliberately do not: a server or CLI runtime has no authenticator, and emulating one in software would make the SDK the weakest link in a mechanism chosen for being the strongest.",
      },
      { type: "h", id: "attestation", text: "Attestation policy" },
      {
        type: "p",
        text: "Most deployments should accept any authenticator the user has. Some — regulated environments, or a fleet standardised on issued hardware — need to say which models are acceptable, and prove afterwards that the rule held. That is what the per-tenant attestation policy is for. A tenant with no policy row behaves exactly as one with the defaults below.",
      },
      {
        type: "table",
        headers: ["Field", "Default", "Meaning"],
        rows: [
          [
            "mode",
            "`none`",
            "`none`, `indirect` or `direct_required` — whether attestation is requested at all. `none` short-circuits every other field and performs no metadata lookup.",
          ],
          [
            "require_fido_certified",
            "`false`",
            "Deny unless the authenticator has any FIDO certification in its metadata history. Only enforceable when `mode` is not `none`.",
          ],
          [
            "min_certification",
            "`null`",
            "`L1` … `L3Plus` — deny unless the authenticator's highest ever certified level meets the bar.",
          ],
          [
            "allowed_aaguids",
            "`null`",
            "`null` allows every model except the blocked list. An explicitly empty array means *nothing* may register — a deliberate lockout rather than an unset field.",
          ],
          ["blocked_aaguids", "`[]`", "Never registrable, regardless of the allow-list. Blocking wins."],
          [
            "block_revoked_status",
            "`true`",
            "Deny an authenticator whose metadata history ever reported a revocation or key compromise.",
          ],
          [
            "unknown_aaguid",
            "`null`",
            "What to do about a model with no metadata entry. Unset resolves to `allow` under `none` and `indirect`, and to **`deny`** under `direct_required`, so the strictest mode fails closed. A read returns `effective_unknown_aaguid` alongside your stored intent.",
          ],
        ],
      },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/tenants/{tenant_id}/webauthn/attestation-policy", summary: "Read the tenant's policy, with the resolved `unknown_aaguid`." },
          { method: "PUT", path: "/api/v1/tenants/{tenant_id}/webauthn/attestation-policy", summary: "Set it. Certification fields are refused while `mode` is `none`." },
          { method: "GET", path: "/api/v1/tenants/{tenant_id}/webauthn/compliance-report", summary: "Which already-registered credentials satisfy the current policy." },
          { method: "GET", path: "/api/v1/mds/status", summary: "The ingested FIDO metadata snapshot: serial, `next_update`, entry count, `stale`." },
          { method: "POST", path: "/api/v1/mds/refresh", summary: "Ingest a new snapshot now. Refuses to run when metadata is disabled." },
        ],
      },
      {
        type: "warn",
        text: "**Passkeys frequently carry no meaningful attestation.** Platform authenticators commonly attest as `none` by design, for user-privacy reasons. A strict attestation policy therefore tends to exclude exactly the credentials most users have, and turns into a security-key-only policy in practice. Decide which of those two things you actually want before setting it.",
      },
      { type: "h", id: "mds", text: "FIDO metadata, refresh and air gaps" },
      {
        type: "p",
        text: "Authenticator models are identified against the FIDO Metadata Service (MDS3), and ingestion is **off by default** — with it disabled there are no outbound calls at all. Ingestion verifies the snapshot's signature and refuses a lower serial number than the one already stored, so an older validly-signed blob cannot be replayed to quietly reintroduce a model that has since been revoked.",
      },
      {
        type: "table",
        headers: ["Setting", "Default", "Meaning"],
        rows: [
          ["AXIAM__PKI__MDS_ENABLED", "`false`", "Master switch. `false` means no background job and a refresh endpoint that refuses to run."],
          ["AXIAM__PKI__MDS_BLOB_URL", "the FIDO Alliance endpoint", "Fetch source for the network path."],
          [
            "AXIAM__PKI__MDS_BLOB_PATH",
            "unset",
            "A local file for air-gapped deployments. When set it wins over the URL and **no network fetch happens at all** — you re-supply the file yourself.",
          ],
          ["AXIAM__PKI__MDS_REFRESH_INTERVAL_SECS", "`604800`", "Background refresh interval — weekly. `0` disables the job; the admin endpoint still works."],
          ["AXIAM__PKI__MDS_LEAF_DNS", "`mds.fidoalliance.org`", "Expected DNS name on the snapshot's signing certificate, so a legitimate hostname change is an ops action rather than a release."],
          [
            "AXIAM__PKI__MDS_MAX_STALE_DAYS",
            "`0`",
            "How far past its `next_update` the snapshot may drift before **attested** registration is refused. `0` keeps the fail-open behaviour.",
          ],
        ],
      },
      {
        type: "p",
        text: "Staleness never blocks ingestion or the use of already-ingested entries: a transient outage at the FIDO Alliance must not brick registration everywhere. The cost of that choice is that a model revoked since your last refresh keeps passing policy, which is what the staleness bound is for — it is opt-in rather than defaulted because the right bound is a property of the deployment. A high-assurance tenant may want days; an air-gapped one with no automatic refresh path would be taken offline by anything short of months. It applies to attested ceremonies only, since an unattested one consults no metadata and stale metadata cannot have misled it.",
      },
      {
        type: "note",
        text: "`register/start` answering `503` is this state, not a transient failure: the policy requires attestation and there is no usable metadata snapshot. It is a documented exception to the SDK retry policy — retrying changes nothing and only delays a message an operator needs to see. The full decision order, the known `USER_VERIFICATION_BYPASS` limitation and the air-gap procedure are in [docs/admin/authenticator-policies.md](https://github.com/ilpanich/axiam/blob/main/docs/admin/authenticator-policies.md).",
      },
      { type: "h", id: "limits", text: "Rate limiting" },
      {
        type: "p",
        text: "All six ceremony routes are throttled per source IP by `AXIAM__RATE_LIMIT__WEBAUTHN_PER_MIN`, which defaults to **10** and is deliberately the same allowance `/auth/login` gives passwords. Each route carries that budget independently, so a ceremony — one `start`, one `finish` — spends one request from each rather than two from one bucket, and the number is the ceremonies-per-minute figure rather than half of it. It is not sized from throughput: an assertion is a single signature check, cheap next to Argon2id. What needed bounding is that every `start` allocates challenge state, and that the username-bound `authenticate/start` would otherwise be a credential-enumeration oracle.",
      },
      { type: "h", id: "users", text: "How users experience it" },
      {
        type: "list",
        items: [
          "**Autofill** — tapping the username field offers a saved passkey alongside saved passwords. A conditional ceremony may never settle, because the user simply may not pick one; abandon it on navigation rather than reporting an authentication failure.",
          "**An explicit button** — “Sign in with a passkey” below the password field, for users whose browser did not offer autofill. This is the usernameless path.",
          "**As a second factor** — after a password, where policy requires a step-up rather than a replacement.",
          "End-user guidance, including what to do when a device is lost, is in [docs/user/passkeys.md](https://github.com/ilpanich/axiam/blob/main/docs/user/passkeys.md).",
        ],
      },
    ],
  },

  {
    slug: "federation",
    section: "Authentication",
    navLabel: "Federation & SSO",
    title: "Federation — SAML & OIDC",
    intro:
      "Delegate authentication to an external identity provider, and map what it asserts onto tenant identities, groups and roles.",
    verifiedRelease: DOCS_VERIFIED_RELEASE,
    blocks: [
      { type: "h", id: "why", text: "Why federate" },
      {
        type: "p",
        text: "Federation lets a user from an external identity provider sign in to an AXIAM tenant without a separate local credential. AXIAM acts as a **SAML service provider** and as an **OIDC relying party**, so it slots into existing enterprise SSO rather than asking an organization to move its directory.",
      },
      {
        type: "p",
        text: "A federated identity is an ordinary user inside the tenant. Roles, permissions, audit and MFA policy apply to it exactly as they do to a locally-credentialed one — the difference is only where the authentication happened.",
      },
      { type: "h", id: "saml", text: "SAML" },
      {
        type: "p",
        text: "As a service provider, AXIAM consumes assertions from an external IdP, validates the signature against the configured certificate, and maps assertion attributes onto tenant identities, group membership and roles. Attribute mapping is per federation configuration.",
      },
      {
        type: "note",
        text: "SAML support is behind a default-on `saml` build feature that links `libxml`. A build made with `--no-default-features` — which is what CI's *Build (SAML off)* job produces — has every other capability and no SAML service provider.",
      },
      { type: "h", id: "oidc", text: "OIDC federation" },
      {
        type: "p",
        text: "As a relying party, AXIAM delegates authentication upstream and then issues its own tenant-scoped session. Claim mapping is configured per tenant, and the upstream client secret is encrypted at rest with AES-256-GCM under `AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY`.",
      },
      {
        type: "api",
        endpoints: [
          { method: "POST", path: "/api/v1/auth/federation/oidc/start", summary: "Begin an upstream authentication.", public: true },
          { method: "POST", path: "/api/v1/auth/federation/oidc/callback", summary: "Complete it and establish the local session.", public: true },
          { method: "GET", path: "/api/v1/federation-configs", summary: "List configured identity providers." },
          { method: "POST", path: "/api/v1/federation-configs", summary: "Register one." },
          { method: "PUT", path: "/api/v1/federation-configs/{id}", summary: "Update it." },
          { method: "DELETE", path: "/api/v1/federation-configs/{id}", summary: "Remove it." },
          { method: "GET", path: "/api/v1/federation-links/user/{user_id}", summary: "Which upstream identities are linked to a user." },
          { method: "DELETE", path: "/api/v1/federation-links/{id}", summary: "Unlink one." },
        ],
      },
      { type: "h", id: "setup", text: "Registering a provider" },
      {
        type: "p",
        text: "Both protocols are configured through the same endpoint and the same record — what differs is which fields matter.",
      },
      {
        type: "steps",
        steps: [
          {
            title: "Register the configuration",
            body: "`provider` is the display name. `metadata_url` is the OIDC discovery URL or the SAML metadata URL. The client secret is stored as AES-256-GCM ciphertext, never in plaintext.",
            code: 'POST /api/v1/federation-configs\n{\n  "provider": "Okta",\n  "protocol": "OidcConnect",\n  "metadata_url": "https://acme.okta.com/.well-known/openid-configuration",\n  "client_id": "<upstream-client-id>",\n  "client_secret": "<upstream-client-secret>",\n  "attribute_map": { "email": "email", "name": "name" },\n  "enabled": true\n}',
          },
          {
            title: "Pin the signature algorithms you accept",
            body: "`allowed_algorithms` defaults to `RS256` for OIDC and is empty for SAML, where the certificate does the work instead. Narrow it to what the provider actually signs with rather than leaving it open.",
            code: '"allowed_algorithms": ["RS256"]',
          },
          {
            title: "For SAML, supply the IdP signing certificate",
            body: "`idp_signing_cert_pem` is the X.509 certificate assertions are verified against. Without it there is nothing to check a signature with.",
            code: '"idp_signing_cert_pem": "-----BEGIN CERTIFICATE-----\\n..."',
          },
          {
            title: "Map the attributes onto AXIAM fields",
            body: "`attribute_map` maps AXIAM field names to the provider's attribute names — not the other way round, which is the direction people write first.",
            code: '{ "email": "mail", "name": "displayName" }',
          },
        ],
      },
      {
        type: "note",
        text: "The mapping resolves two fields: `email`, and a display name taken from `name` with `displayName` as a fallback. A provider that calls its address attribute `mail` needs `{\"email\": \"mail\"}` — with the AXIAM name as the key.",
      },
      { type: "h", id: "buttons", text: "Sign-in buttons and the public login surface" },
      {
        type: "p",
        text: "A login page renders its \"Sign in with …\" buttons from an **unauthenticated** listing, so that surface is designed for the fact that it is public. It returns only what a button needs — no client id, no endpoint URLs, no `attribute_map`, no secret column — from a dedicated response type rather than a narrowed admin one, so a field added to the admin response cannot leak here by inheritance.",
      },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/auth/federation/providers", summary: "Which buttons to render for a workspace.", public: true },
          { method: "POST", path: "/api/v1/auth/federation/oauth2/start", summary: "Begin a login through a plain-OAuth2 provider.", public: true },
          { method: "POST", path: "/api/v1/auth/federation/oauth2/callback", summary: "Complete one, same-origin from the SPA.", public: true },
          { method: "POST", path: "/api/v1/auth/federation/handoff", summary: "Exchange a handoff code for session cookies.", public: true },
        ],
      },
      {
        type: "note",
        text: "An unknown organization and a known one with nothing configured both answer `200` with an empty list. That is deliberate: a list-shaped endpoint answering `401` for one and `200 []` for the other would be a two-valued oracle and a perfect organization-slug enumerator. The listing is rate-limited on the same per-IP login budget as the sign-in endpoints, which is what bounds the guessing rate.",
      },
      { type: "h", id: "oauth2-variant", text: "The plain-OAuth2 variant, and the trust it does not have" },
      {
        type: "p",
        text: "Some providers issue no ID token — GitHub and Facebook among them. For those, the `oauth2` protocol authenticates by calling a configured userinfo endpoint with the access token just received. That is a **downgrade**, and AXIAM states it rather than hiding it: on the OIDC path a JWS signature, `iss`, `aud`, `exp`, `iat` and `nonce` are all cryptographic statements bound to this login attempt, and on this path none of them exist. The trust is transport and configuration trust instead.",
      },
      {
        type: "list",
        items: [
          "**It cannot be selected by accident.** The protocol is refused at create and update time for every kind that supports OIDC properly (`google`, `microsoft`, `apple`); it is offered only for `facebook`, `github` and `generic_oauth2`.",
          "**PKCE is mandatory here**, not optional — it is the only replay protection left once `nonce` is gone. `S256` is always sent and the verifier is always stored server-side.",
          "**The three endpoints come only from configuration.** They are validated as absolute HTTPS on write, never derived from anything the provider says at runtime, and fetched through the same SSRF guard as every other outbound call. A substituted userinfo endpoint would be an authentication bypass with no signature to catch it.",
          "**Only an affirmatively verified email is adopted.** For `github` a second mandatory call takes the primary *and* verified address, and a login with none is refused rather than provisioned under a synthesized or unverified one. Where a provider offers no verification signal at all, an operator who wants to accept its assertion writes that decision down as a literal in `attribute_map` rather than having AXIAM make it silently.",
        ],
      },
      { type: "h", id: "handoff", text: "Cross-site returns and the handoff code" },
      {
        type: "p",
        text: "The session cookies are `SameSite=Strict`, and that is not being weakened. SAML and Apple both have the provider perform a cross-site form POST straight to an AXIAM endpoint, and the browser will not send `Strict` cookies on the navigation that follows — the user would land back in the SPA holding a session it cannot use. So those two endpoints mint a **handoff code** instead and answer `303` to the SPA, which posts the code back same-origin and gets the cookies on a same-site response.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Property", "Value"],
        rows: [
          ["Entropy", "256 bits, `base64url`"],
          ["Storage", "SHA-256 hash only — a database read must not yield a usable credential"],
          ["TTL", "60 seconds; it exists to survive one redirect"],
          ["Uses", "Exactly one, consumed atomically"],
          ["Carries", "No token material — the tokens are created at redemption, not at mint"],
        ],
      },
      {
        type: "warn",
        text: "**Where the code may be delivered is not the caller's choice.** On these two flows the provider never sees the SPA URL, so nothing else would have checked it, and an unchecked `redirect_uri` here is an authentication bypass rather than an open redirect. The target is confined to the deployment's own issuer origin plus anything an operator names in `AXIAM__AUTH__SSO_SPA_ORIGINS`. Comparison is by origin, not by prefix — a different port, a different scheme, a path suffix and a `https://host@attacker.example/` userinfo trick are all different origins — and the check runs at login start, again at the mint, and on the error redirect.",
      },
      { type: "h", id: "inheritance", text: "Organization providers a tenant inherits" },
      {
        type: "p",
        text: "A config in the organization's own scope carrying `allow_tenant_inheritance` is offered to the organization's tenants, so one Google registration serves the whole estate. The user it signs in is provisioned in the **requesting** tenant, not in the organization scope.",
      },
      {
        type: "p",
        text: "A tenant's own config of the same kind shadows the inherited one — **including a disabled one**. A tenant administrator who creates a Google config and disables it has said something about Google in this tenant, and the something is *no*; falling back to the inherited config there would make \"disable\" mean \"re-enable the other one\". The key match is what shadows, not the enabled bit.",
      },
      {
        type: "note",
        text: "Two more rules worth knowing before you configure a provider. A **templated issuer** — Entra's `common` authority publishes a literal `{tenantid}` placeholder — requires an explicit `allowed_issuer_tenants` list, refused at write time and again at sign-in without one: Microsoft signs every tenant's tokens at `common` with the same keys, so \"accept anything\" there means every Microsoft account on earth. And a custom **button icon** is accepted only for the `generic_*` kinds (the branded marks are not replaceable), stored as a raster `data:` URL bounded at 16 KiB — no SVG, because this is served to everyone who loads a login page.",
      },
      {
        type: "links",
        links: [
          {
            label: "Federated login providers, end to end",
            href: `${GH_BLOB}/claude_dev/federation-sso-login-design.md`,
            note: "The protocol matrix, the inheritance precedence table, the handoff-code mechanism and the alternatives rejected.",
          },
          {
            label: "SDK contract §12.1",
            href: `${GH_BLOB}/sdks/CONTRACT.md`,
            note: "The canonical operation set and endpoint map these four operations belong to.",
          },
        ],
      },
      { type: "h", id: "links", text: "Linking and unlinking" },
      {
        type: "p",
        text: "A **federation link** records that a given upstream subject corresponds to a given local user. Links are visible and removable per user, which is what makes offboarding an IdP tractable: unlink, and the local account remains with whatever other credential it holds — rather than becoming an orphan nobody can sign in to.",
      },
      { type: "h", id: "provisioning", text: "Federation is not provisioning" },
      {
        type: "p",
        text: "Federation answers *who is this person* at sign-in time. It does not create, update or deactivate accounts ahead of time, and it does not remove one when someone leaves. For that, use **SCIM 2.0** — Okta, Entra ID and any other SCIM-compliant IdP can drive user and group lifecycle directly. See [SCIM provisioning](#/docs/scim).",
      },
      {
        type: "p",
        text: "There is one adjacent place where an external identity *can* create a local user, and it is worth knowing it is a different mechanism: cross-domain token exchange, where a partner's IdP presents a subject token. That trust configuration carries a subject-mapping setting with two values.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Subject mapping", "Behaviour"],
        rows: [
          [
            "`linked_only`",
            "**The default.** Refuse an external subject with no existing link. The user must already have signed in through that provider, or been linked by an administrator, before a partner token buys anything.",
          ],
          [
            "`jit_provision`",
            "Provision an AXIAM user on first sight. Audited as such — that record is the only place a partner IdP's creation of a local user is visible.",
          ],
        ],
      },
      {
        type: "note",
        text: "An unrecognised value is refused rather than defaulted. That matters more than it looks: the default is the stricter of the two, so a silently-tolerated typo would fail closed today and open on any future revision that flips which value is the default.",
      },
    ],
  },

  {
    slug: "service-accounts",
    section: "Authentication",
    navLabel: "Service accounts",
    title: "Service accounts & machine identity",
    intro:
      "Non-human principals for service-to-service access — authenticated by a client secret or by a bound X.509 certificate, and subject to exactly the same authorization engine as a user.",
    verifiedRelease: DOCS_VERIFIED_RELEASE,
    blocks: [
      { type: "h", id: "what", text: "What a service account is" },
      {
        type: "p",
        text: "A service account is a tenant-scoped identity for an automated caller. It holds roles and permissions like a user, appears in the audit log like a user, and is denied by a deny grant like a user. What it does not have is a password, an email address or an interactive login.",
      },
      {
        type: "p",
        text: "One created in the organization's reserved scope is an **organization-level** service account: its global grants reach every tenant of the organization, including tenants created after it, which is what a deployment-wide automation actually needs. `POST /api/v1/roles/{role_id}/service-accounts` takes the same `tenant_scope` list as the user and group assignment endpoints, so such an account can be confined to named tenants instead — see [Organization-level principals](#/docs/organization-scope).",
      },
      {
        type: "p",
        text: "Use one wherever a human account would otherwise be shared between people or embedded in a deployment — a CI pipeline, a batch job, a backend service calling AXIAM on its own behalf. The audit trail then names the *system* that acted rather than whichever employee's credentials it was using.",
      },
      { type: "h", id: "endpoints", text: "Managing them" },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/service-accounts", summary: "List the tenant's service accounts." },
          { method: "POST", path: "/api/v1/service-accounts", summary: "Create one. The secret is returned exactly once." },
          { method: "GET", path: "/api/v1/service-accounts/{sa_id}", summary: "Read one." },
          { method: "PUT", path: "/api/v1/service-accounts/{sa_id}", summary: "Update it." },
          { method: "DELETE", path: "/api/v1/service-accounts/{sa_id}", summary: "Delete it." },
          { method: "POST", path: "/api/v1/service-accounts/{sa_id}/rotate-secret", summary: "Issue a new secret. Returned once." },
          { method: "POST", path: "/api/v1/service-accounts/{sa_id}/bind-certificate", summary: "Bind an X.509 certificate for mTLS authentication." },
        ],
      },
      {
        type: "warn",
        text: "A service-account secret is shown once, at creation or rotation, and is never retrievable afterwards. If it is lost, rotate — there is no recovery path, by design.",
      },
      { type: "h", id: "auth", text: "Authenticating as one" },
      {
        type: "p",
        text: "The ordinary path is the OAuth2 **client credentials** grant: the service account exchanges its identifier and secret for a short-lived access token, then uses that token like any other caller.",
      },
      {
        type: "code",
        caption: "client credentials",
        code: "curl -X POST 'https://iam.acme.dev/oauth2/token?tenant_id=<uuid>' \\\n  -d grant_type=client_credentials \\\n  -d client_id=\"$SA_CLIENT_ID\" \\\n  -d client_secret=\"$SA_CLIENT_SECRET\" \\\n  -d scope='read:orders'",
      },
      { type: "h", id: "mtls", text: "Certificates instead of secrets" },
      {
        type: "p",
        text: "A shared secret has to be distributed, stored and rotated, and it is bearer material — whoever holds it is the service. Binding an X.509 certificate to the service account replaces that with a private key that never leaves the machine holding it, authenticated through mutual TLS terminated inside `axiam-server` rather than asserted by a proxy header.",
      },
      {
        type: "p",
        text: "This is the recommended shape for IoT fleets and for anything in a service mesh that already has a certificate. Combined with **certificate-bound access tokens**, it also means a stolen token is useless without the corresponding private key — see [FAPI 2.0 & mTLS clients](#/docs/fapi2) and [PKI & certificates](#/docs/pki).",
      },
      {
        type: "note",
        text: "Client-certificate verification is native: `AXIAM__SERVER__TLS__CLIENT_AUTH` (`off` | `optional` | `required`) with a trust bundle at `AXIAM__SERVER__TLS__CLIENT_CA_PATH`. No proxy-asserted identity header is in the trusted path, and a misconfigured mTLS server fails fast at startup rather than serving without verification.",
      },
      { type: "h", id: "auth-methods", text: "How a client proves who it is" },
      {
        type: "p",
        text: "Four client-authentication methods are registrable, and the choice is recorded on the client rather than negotiated per request.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Method", "The credential", "Register with"],
        rows: [
          [
            "`client_secret_post`",
            "A shared secret in the request body. The default, and bearer material.",
            "The secret returned once at creation.",
          ],
          [
            "`tls_client_auth`",
            "A certificate issued by a CA the mTLS listener trusts. AXIAM matches the registered expected subject DN or SAN against the certificate rustls already verified during the handshake.",
            "`tls_client_auth_subject_dn`, or the expected SAN.",
          ],
          [
            "`self_signed_tls_client_auth`",
            "A certificate that chains to nothing, so the certificate itself is the credential — matched by SHA-256 thumbprint.",
            "The thumbprint.",
          ],
          [
            "`private_key_jwt`",
            "A short-lived JWT the client signs with a private key whose public half AXIAM holds. Needs no transport-level cooperation at all.",
            "A `jwks` inline, or a `jwks_uri` to publish at.",
          ],
        ],
      },
      {
        type: "code",
        caption: "registering a private_key_jwt client",
        code: 'POST /api/v1/oauth2-clients\n{\n  "client_name": "orders-batch",\n  "token_endpoint_auth_method": "private_key_jwt",\n  "jwks_uri": "https://orders.acme.dev/.well-known/jwks.json",\n  "grant_types": ["client_credentials"]\n}',
      },
      {
        type: "note",
        text: "`private_key_jwt` is the method to reach for behind a TLS-terminating load balancer you do not control — which is exactly why FAPI 2.0 permits it alongside the mTLS methods. There is deliberately **no** `none` method: every AXIAM client is confidential, and a public-client value would let an operator register a client whose authentication is silently skipped.",
      },
      { type: "h", id: "audience", text: "Machine tokens are a different audience" },
      {
        type: "warn",
        text: "A service-account token carries `aud` of **`axiam:m2m`**, where a user token carries `axiam:user`. A route guard configured to expect the user audience will reject a perfectly valid machine token with a bare `401`, and nothing in that response says why — this is the single most confusing failure on this page. If a service account authenticates cleanly and is then refused by your own middleware, check the audience your verifier expects before checking anything else.",
      },
      {
        type: "p",
        text: "The split is deliberate rather than incidental: it lets a resource server decide that an endpoint is for humans, or for machines, without inspecting roles. Pin whichever audience the endpoint is actually for, and pin it explicitly — a verifier that checks no audience accepts both.",
      },
    ],
  },
];

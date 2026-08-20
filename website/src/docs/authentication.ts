import type { DocPage } from "./types";

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
        type: "api",
        endpoints: [
          { method: "POST", path: "/api/v1/users/{user_id}/unlock", summary: "Clear an active lockout on an account." },
        ],
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
          { method: "POST", path: "/api/v1/auth/verify-email", summary: "Confirm an email address from a mailed token.", public: true },
          { method: "POST", path: "/api/v1/auth/resend-verification", summary: "Re-send the verification mail.", public: true },
          { method: "POST", path: "/api/v1/auth/reset", summary: "Begin a password reset.", public: true },
          { method: "POST", path: "/api/v1/auth/reset/confirm", summary: "Complete a reset with the mailed token.", public: true },
          { method: "GET", path: "/api/v1/auth/reset/context", summary: "Policy context a reset page needs to render.", public: true },
        ],
      },
      {
        type: "codegroup",
        caption: "sign in, then handle a step-up",
        tabs: [
          {
            label: "TypeScript",
            code: "const result = await client.login(email, password);\n\nswitch (result.status) {\n  case 'mfa_required': {\n    const code = await promptForMfaCode(result.availableMethods);\n    await client.verifyMfa(result.mfaToken, code);\n    break;\n  }\n  case 'authenticated':\n    console.log(`Authenticated as ${result.user.username}`);\n    break;\n}",
          },
          {
            label: "Python",
            code: "result = client.login(email, password)\n\nif result.mfa_required:\n    result = client.verify_mfa(result.mfa_token, totp_code)\n\nprint(result.session_id, result.expires_in)",
          },
          {
            label: "Rust",
            code: "let result = client.login(\"user@acme.dev\", &password).await?;\n\nif result.mfa_required {\n    client.verify_mfa(\"123456\").await?;\n}",
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
      { type: "h", id: "sessions", text: "Sessions end, not users" },
      {
        type: "p",
        text: "Logout operates on a session, not on an identity. A user signed in on a phone and a laptop who logs out on the laptop expects the phone to stay signed in, and that is what happens. When relying parties are registered for back-channel logout, ending a session also notifies them — see [Logout & session management](#/docs/logout).",
      },
      { type: "h", id: "rate", text: "Rate limiting" },
      {
        type: "p",
        text: "`/auth/login` is always keyed per source IP regardless of the deployment's rate-limit key mode, and stays strict under every posture preset. Register, password-reset and MFA endpoints are likewise per-IP. The reasoning — and why `client_id` keying is a fairness control rather than an abuse control — is in [Configuration](#/docs/configuration).",
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
            "Both paths work. Users enrol an OPAQUE record as they sign in or change password; those who have not yet keep using the password path.",
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
          "**A failure at `finish` is indistinguishable by design.** Wrong password, unknown account, and a server holding no record all fail identically — and nothing further may be posted after one.",
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
      "TOTP as the baseline second factor, enrolled by the user or enforced by policy, with secrets encrypted at rest.",
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
      { type: "h", id: "endpoints", text: "Endpoints" },
      {
        type: "api",
        endpoints: [
          { method: "POST", path: "/api/v1/auth/mfa/setup/enroll", summary: "Begin enrolment during initial account setup.", public: true },
          { method: "POST", path: "/api/v1/auth/mfa/setup/confirm", summary: "Confirm setup-time enrolment with a generated code.", public: true },
          { method: "POST", path: "/api/v1/auth/mfa/enroll", summary: "Enrol an additional factor on an authenticated account." },
          { method: "POST", path: "/api/v1/auth/mfa/confirm", summary: "Confirm that enrolment." },
          { method: "POST", path: "/api/v1/auth/mfa/verify", summary: "Answer an MFA challenge during login.", public: true },
          { method: "GET", path: "/api/v1/users/{user_id}/mfa-methods", summary: "List a user's enrolled factors." },
          { method: "DELETE", path: "/api/v1/users/{user_id}/mfa-methods/{method_id}", summary: "Remove one factor." },
          { method: "POST", path: "/api/v1/users/{user_id}/reset-mfa", summary: "Administratively clear every factor on an account." },
        ],
      },
      { type: "h", id: "stepup", text: "The step-up in a login" },
      {
        type: "p",
        text: "When a factor is required, `POST /auth/login` does not establish a session. It returns an MFA challenge, and the SDK surfaces it as a flag rather than an exception — the session is established only once `/auth/mfa/verify` succeeds. The challenge has its own lifetime, `mfa_challenge_lifetime_secs`, set per tenant.",
      },
      { type: "h", id: "policy", text: "Enforcing it" },
      {
        type: "p",
        text: "`mfa_enforced` is a policy field on the settings baseline: set it at the organization and every tenant inherits it, or tighten it on one tenant. As with every setting, a tenant may make the posture stricter than the organization's baseline but never looser.",
      },
      {
        type: "warn",
        text: "Enforce MFA on administrative accounts before anything else. A super-admin holds every permission in the tenant, including the ones that would let an attacker remove the audit evidence of what they did with it.",
      },
      {
        type: "note",
        text: "TOTP is the baseline, not the ceiling. **Passkeys and security keys are phishing-resistant in a way a typed code is not** — a code can be entered into a lookalike page and forwarded to the real one inside its window. See [Passkeys & WebAuthn](#/docs/passkeys).",
      },
    ],
  },

  {
    slug: "passkeys",
    section: "Authentication",
    navLabel: "Passkeys & WebAuthn",
    title: "Passkeys & WebAuthn",
    intro:
      "Phishing-resistant authentication bound to your origin, with an attestation policy for deployments that need to say which authenticators are acceptable.",
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
      { type: "h", id: "flows", text: "Registration and authentication" },
      {
        type: "api",
        endpoints: [
          { method: "POST", path: "/api/v1/auth/webauthn/register/start", summary: "Get creation options for a new credential." },
          { method: "POST", path: "/api/v1/auth/webauthn/register/finish", summary: "Submit the attestation; the credential is stored." },
          { method: "POST", path: "/api/v1/auth/webauthn/authenticate/start", summary: "Get request options for a sign-in ceremony.", public: true },
          { method: "POST", path: "/api/v1/auth/webauthn/authenticate/finish", summary: "Submit the assertion; the session is established.", public: true },
        ],
      },
      {
        type: "p",
        text: "Both ceremonies are the standard WebAuthn two-step. The browser does the work — your code passes the options through to `navigator.credentials` and posts the result back.",
      },
      {
        type: "code",
        caption: "registration · browser",
        code: "// 1. Ask the server for creation options.\nconst options = await postJson('/api/v1/auth/webauthn/register/start', {});\n\n// 2. Let the browser and authenticator do the ceremony.\nconst credential = await navigator.credentials.create({ publicKey: options });\n\n// 3. Hand the attestation back.\nawait postJson('/api/v1/auth/webauthn/register/finish', credential);",
      },
      {
        type: "note",
        text: "Tell users to register **at least two**, on different devices. A passkey lives on the device that created it; if that device is the only factor and it is lost, the account is locked out. Naming them at registration matters too — \"Passkey 2\" is not a name anybody can act on when deciding which one to revoke.",
      },
      { type: "h", id: "attestation", text: "Attestation policy" },
      {
        type: "p",
        text: "Most deployments should accept any authenticator the user has. Some — regulated environments, or a fleet standardised on issued hardware — need to say which models are acceptable, and prove afterwards that the rule held. That is what the per-tenant attestation policy is for.",
      },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/tenants/{tenant_id}/webauthn/attestation-policy", summary: "Read the tenant's policy." },
          { method: "PUT", path: "/api/v1/tenants/{tenant_id}/webauthn/attestation-policy", summary: "Set it." },
          { method: "GET", path: "/api/v1/tenants/{tenant_id}/webauthn/compliance-report", summary: "Which registered credentials satisfy the current policy." },
          { method: "GET", path: "/api/v1/mds/status", summary: "FIDO Metadata Service snapshot status." },
          { method: "POST", path: "/api/v1/mds/refresh", summary: "Refresh the MDS trust anchors." },
        ],
      },
      {
        type: "p",
        text: "Authenticator models are identified against the FIDO Metadata Service (MDS3). The snapshot is refreshable on demand, which is also the air-gap story: an operator with no outbound access refreshes from a fetched blob rather than from the network.",
      },
      {
        type: "warn",
        text: "**Passkeys frequently carry no meaningful attestation.** Platform authenticators commonly attest as `none` by design, for user-privacy reasons. A strict attestation policy therefore tends to exclude exactly the credentials most users have, and turns into a security-key-only policy in practice. Decide which of those two things you actually want before setting it.",
      },
      { type: "h", id: "signin", text: "How users sign in" },
      {
        type: "list",
        items: [
          "**Autofill** — tapping the username field offers a saved passkey alongside saved passwords.",
          "**An explicit button** — \"Sign in with a passkey\" below the password field, for users whose browser did not offer autofill.",
          "**As a second factor** — after a password, where policy requires a step-up rather than a replacement.",
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
    ],
  },

  {
    slug: "service-accounts",
    section: "Authentication",
    navLabel: "Service accounts",
    title: "Service accounts & machine identity",
    intro:
      "Non-human principals for service-to-service access — authenticated by a client secret or by a bound X.509 certificate, and subject to exactly the same authorization engine as a user.",
    blocks: [
      { type: "h", id: "what", text: "What a service account is" },
      {
        type: "p",
        text: "A service account is a tenant-scoped identity for an automated caller. It holds roles and permissions like a user, appears in the audit log like a user, and is denied by a deny grant like a user. What it does not have is a password, an email address or an interactive login.",
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
    ],
  },
];

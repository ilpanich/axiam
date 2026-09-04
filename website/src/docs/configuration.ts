import type { DocPage } from "./types";
import { DOCS_VERIFIED_RELEASE } from "../version";

/**
 * The configuration reference.
 *
 * Kept as its own module because it is the longest single page in the docs and
 * the one most likely to be edited in isolation: it is a reference table, not
 * prose, and every row corresponds to a key the server actually reads.
 */
export const CONFIGURATION_PAGES: DocPage[] = [
  {
    slug: "configuration",
    section: "Operate",
    navLabel: "Configuration",
    title: "Configuration & environment variables",
    intro:
      "Every setting on the AXIAM server image is an environment variable. This is the reference: what each variable means, its default, and an example value.",
    verifiedRelease: DOCS_VERIFIED_RELEASE,
    blocks: [
      { type: "h", id: "naming", text: "The naming convention" },
      {
        type: "p",
        text: "All configuration keys use a double underscore (`__`) after the `AXIAM` prefix — for example `AXIAM__DB__USERNAME`. The `__` separates both the prefix and the nested key levels (this is how the config layer distinguishes them). A single underscore (`AXIAM_DB__USERNAME`) is silently ignored and the in-code default wins, so double-check the doubling when a value doesn't take effect.",
      },
      {
        type: "warn",
        text: "Secrets (database password, JWT keys, the AES-256-GCM encryption keys, the peppers) must come from a secret manager or mounted secret — never bake real key material into an image, a compose file or git. Use a placeholder like `<set-in-secret-manager>` in any template, and never reuse a value across environments.",
      },
      { type: "h", id: "scope", text: "What this page covers" },
      {
        type: "p",
        text: "This is a **curated reference, not an exhaustive one.** It documents the settings a deployment normally has to make a decision about — connectivity, secrets, token and hashing policy, rate limits, caches and TLS. The keys it leaves out are transport and pool tuning, debug-build fallbacks, and switches for features that are not shipped yet: things with working defaults and no deployment-specific right answer.",
      },
      {
        type: "note",
        text: "The complete list is the configuration structs themselves, and it is worth knowing that they are the authority in two ways. Many keys never appear as a literal string in the source: the config layer derives `AXIAM__SERVER__HOST` from the `host` field of the server config struct, so grepping for the variable name finds nothing while the variable works perfectly. If a setting you need is not on this page, look for the field rather than for the key.",
      },
      {
        type: "note",
        text: "That scope is enforced rather than asserted. `scripts/check-config-key-coverage.py` compares every key literally present in the server against this page, and fails on one that is neither documented here nor carrying a written exemption saying why a deployment never needs to set it — so the gap between the two can be argued with, but it cannot quietly grow.",
      },
      { type: "h", id: "connectivity", text: "Connectivity & bind addresses" },
      {
        type: "table",
        headers: ["Variable", "Meaning", "Example"],
        rows: [
          [
            "AXIAM__DB__URL",
            "SurrealDB address as a bare host:port — not a URL scheme (the Ws engine resolves a scheme as a hostname and fails).",
            "surrealdb:8000",
          ],
          ["AXIAM__DB__NAMESPACE", "SurrealDB namespace.", "axiam"],
          ["AXIAM__DB__DATABASE", "SurrealDB database.", "axiam"],
          [
            "AXIAM__AMQP__URL",
            "RabbitMQ connection string, assembled from the broker credentials at the deployment layer. Must be amqps:// — AMQP is TLS-only and every other scheme is refused at startup.",
            "amqps://user:pass@rabbitmq:5671",
          ],
          [
            "AXIAM__AMQP__TLS__CA_CERT_PATH",
            "CA bundle for the broker's certificate. rustls compiles its roots in, so an in-cluster broker issued by a private CA is unverifiable without this — and that is the common case rather than the exception.",
            "/etc/axiam/amqp/ca.pem",
          ],
          [
            "AXIAM__AMQP__TLS__CLIENT_CERT_PATH",
            "Client certificate chain for mutual TLS toward the broker. Optional.",
            "/etc/axiam/amqp/client.pem",
          ],
          [
            "AXIAM__AMQP__TLS__CLIENT_KEY_PATH",
            "Its private key. Required together with the certificate — setting one without the other is refused at startup rather than connecting without the mutual half.",
            "/etc/axiam/amqp/client.key",
          ],
          [
            "AXIAM__SERVER__HOST",
            "REST bind address (default 127.0.0.1). Set 0.0.0.0 in a container.",
            "0.0.0.0",
          ],
          ["AXIAM__SERVER__PORT", "REST bind port (default 8090).", "8090"],
          [
            "AXIAM__GRPC__HOST",
            "gRPC bind address (default 127.0.0.1, loopback-only). Set 0.0.0.0 to serve in-cluster.",
            "0.0.0.0",
          ],
          ["AXIAM__GRPC__PORT", "gRPC bind port (default 50051).", "50051"],
          [
            "AXIAM__GRPC_TLS_CERT_PATH",
            "PEM certificate for the gRPC listener. **Both this and the key must be set or gRPC serves plaintext** — acceptable in a mesh that provides its own transport security, and not otherwise. Note the single underscore after the prefix: these two are read directly rather than through the layered config.",
            "/etc/axiam/grpc/server.pem",
          ],
          [
            "AXIAM__GRPC_TLS_KEY_PATH",
            "Its private key. Set together with the certificate; the server logs a warning at startup whenever TLS is off.",
            "/etc/axiam/grpc/server.key",
          ],
          [
            "AXIAM__GRPC__GRPC_AUTHZ_PER_SEC",
            "Max gRPC authz requests per second per IP (default 100).",
            "100",
          ],
          [
            "AXIAM__AUTH__SSO_SPA_ORIGINS",
            "Extra browser origins a federated sign-in may return the browser to. Empty (the default) means the issuer's own origin only, which is right whenever the admin UI is served from the same origin as the API. Set it when the SPA is on a different host: every federated sign-in — SAML, Apple, OIDC and plain OAuth2 — is refused with a 400 for any other origin. On SAML and Apple this is the only check there is, because the identity provider never sees the SPA redirect URI; on OIDC and OAuth2 the provider's own registered-redirect comparison sits behind it as a second layer. Compared as scheme + host + port, so a different port needs its own entry.",
            "https://app.acme.dev",
          ],
          [
            "AXIAM__SERVER__CORS_ALLOWED_ORIGINS",
            "Allowed CORS origins; empty disables cross-origin requests (restrictive default). The supported topologies serve the admin UI and the API from one origin, so this stays empty in both.",
            "https://admin.acme.dev",
          ],
          [
            "AXIAM__AUTH__TRUST_FORWARDED_CLIENT_CERT",
            "Accept an `X-Client-Certificate` header as device identity when the connection has no TLS-verified client certificate. **Off by default, and it should stay off unless a proxy you operate terminates mTLS and overwrites that header on every request.** A certificate is public data and the header path cannot prove possession of the private key, so wherever anything but that proxy can reach the listener, anyone holding a copy of an enrolled device's certificate authenticates as that device. Native mTLS is unaffected — a certificate rustls verified on the connection is always preferred and this setting is not consulted.",
            "false",
          ],
          [
            "RUST_LOG",
            "Log verbosity / filter. Keep it narrow in production — no internal module exposure.",
            "info",
          ],
        ],
      },
      { type: "h", id: "secrets", text: "Secrets & encryption keys" },
      {
        type: "p",
        text: "These are required for a real deployment. Generate the 32-byte hex keys with `openssl rand -hex 32` and the Ed25519 JWT keypair with `openssl genpkey -algorithm ed25519`.",
      },
      {
        type: "table",
        headers: ["Variable", "Meaning", "Example"],
        rows: [
          ["AXIAM__DB__USERNAME", "SurrealDB username.", "axiam"],
          ["AXIAM__DB__PASSWORD", "SurrealDB password.", "<set-in-secret-manager>"],
          [
            "AXIAM__AUTH__JWT_PRIVATE_KEY_PEM",
            "Ed25519 JWT signing private key (PEM).",
            "-----BEGIN PRIVATE KEY----- …",
          ],
          [
            "AXIAM__AUTH__JWT_PUBLIC_KEY_PEM",
            "Ed25519 JWT verification public key (PEM), paired with the private key.",
            "-----BEGIN PUBLIC KEY----- …",
          ],
          [
            "AXIAM__AUTH__MFA_ENCRYPTION_KEY",
            "AES-256-GCM key (32-byte hex) encrypting TOTP MFA secrets at rest.",
            "<64 hex chars>",
          ],
          [
            "AXIAM__PKI__ENCRYPTION_KEY",
            "AES-256-GCM key (hex) encrypting CA signing keys (and webhook secrets) at rest.",
            "<64 hex chars>",
          ],
          [
            "AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY",
            "AES-256-GCM key (hex) encrypting SAML/OIDC federation client secrets at rest.",
            "<64 hex chars>",
          ],
          [
            "AXIAM__EMAIL_ENCRYPTION_KEY",
            "AES-256-GCM key (hex) encrypting email/SMTP secrets; also gates the email-config admin endpoints.",
            "<64 hex chars>",
          ],
          [
            "AXIAM__GDPR_PSEUDONYM_PEPPER",
            "HMAC-SHA256 pepper (hex) pseudonymizing audit-log actor identities on GDPR erasure.",
            "<64 hex chars>",
          ],
          [
            "AXIAM__AUTH__PEPPER",
            "Password pepper (string) prepended before Argon2id hashing.",
            "<random string>",
          ],
        ],
      },
      { type: "h", id: "provider", text: "Where secrets come from" },
      {
        type: "p",
        text: "The keys above do not have to be environment variables. `AXIAM__AUTH__SECRET_PROVIDER` selects where the server fetches them at startup, and the field names it looks for are the lowercase forms — `jwt_private_key_pem`, `opaque_setup_key`, `pki_encryption_key`, `auth_pepper` and the rest. See [Secrets & HashiCorp Vault](#/docs/secrets) for the full story.",
      },
      {
        type: "table",
        headers: ["Variable", "Meaning", "Example"],
        rows: [
          [
            "AXIAM__AUTH__SECRET_PROVIDER",
            "`env` (default), `file`, or `vault`. An unknown value is **refused at startup** rather than falling back — a typo that silently reverted to `env` presents as an unexplained outage.",
            "vault",
          ],
          [
            "AXIAM__AUTH__SECRET_DIR",
            "Required with `file`. Directory of one file per secret, named after the field — the shape a Kubernetes or Docker secret volume already has.",
            "/etc/axiam/secrets",
          ],
          [
            "AXIAM__AUTH__VAULT_ADDR",
            "Required with `vault`. Base address of the Vault server. Must be TLS in production — the token is a bearer credential for the setup key.",
            "https://vault.internal:8200",
          ],
          [
            "AXIAM__AUTH__VAULT_TOKEN",
            "Required with `vault`. A token with read access to the mount and path below, and nothing else.",
            "<set-in-secret-manager>",
          ],
          [
            "AXIAM__AUTH__VAULT_MOUNT",
            "KV v2 mount point (default `secret`).",
            "secret",
          ],
          [
            "AXIAM__AUTH__VAULT_PATH",
            "Path within the mount holding AXIAM's keys as fields (default `axiam`).",
            "axiam",
          ],
          [
            "AXIAM__AUTH__VAULT_CA_CERT_PATH",
            "Trust anchor for a Vault fronted by a private CA. rustls compiles its roots in, so a Vault certificate issued by an internal PKI — cert-manager, or the repository's own dev certificates — is otherwise unverifiable and the server fails at startup with a bare transport error.",
            "/etc/axiam/vault/ca.pem",
          ],
        ],
      },
      { type: "h", id: "opaque-keys", text: "OPAQUE" },
      {
        type: "p",
        text: "Both are required whenever any organization or tenant has `opaque_mode` other than `disabled`. They are split by what rotating them costs — see [OPAQUE](#/docs/opaque).",
      },
      {
        type: "table",
        headers: ["Variable", "Meaning", "Example"],
        rows: [
          [
            "AXIAM__AUTH__OPAQUE_SETUP_KEY",
            "AES-256-GCM key (32-byte hex) encrypting each tenant's OPRF seed and AKE keypair at rest. **Back this up** — losing it means a password reset for every user in every tenant.",
            "<64 hex chars>",
          ],
          [
            "AXIAM__AUTH__OPAQUE_SESSION_KEY",
            "AES-256-GCM key (32-byte hex) sealing in-flight exchange state (a 120-second window). Cheap to rotate; deliberately separate from the setup key.",
            "<64 hex chars>",
          ],
        ],
      },
      { type: "h", id: "oauth2", text: "OAuth2 & OIDC" },
      {
        type: "table",
        headers: ["Variable", "Meaning", "Example"],
        rows: [
          [
            "AXIAM__AUTH__OAUTH2_ISSUER_URL",
            "Public issuer URL for OIDC discovery. Must be an origin, not a path (path-based issuers are rejected).",
            "https://iam.acme.dev",
          ],
          [
            "AXIAM__OAUTH2__JWKS_CACHE_MAX_AGE_SECS",
            "Cache-Control max-age on the JWKS endpoint, in seconds.",
            "300",
          ],
          [
            "AXIAM__AUTH__ALLOW_MISSING_AUD_AS_USER",
            "Compatibility switch — treat a token with no audience claim as a user token. Leave off unless you need it.",
            "false",
          ],
        ],
      },
      { type: "h", id: "hashing", text: "Argon2id hash concurrency" },
      {
        type: "p",
        text: "Each in-flight Argon2id operation allocates a ~19 MiB arena, so unbounded concurrency is a memory-DoS vector. A process-wide semaphore caps peak concurrent arenas and sheds excess load with a 503 rather than queueing unboundedly. The cost parameters themselves are never weakened for throughput.",
      },
      {
        type: "table",
        headers: ["Variable", "Meaning", "Example"],
        rows: [
          [
            "AXIAM__AUTH__MAX_CONCURRENT_HASHES",
            "Max concurrent Argon2id hash/verify ops. 0 (default) = auto → min(CPU cores, 4). Peak crypto RSS ≈ this × 19 MiB.",
            "0",
          ],
          [
            "AXIAM__AUTH__HASH_ACQUIRE_TIMEOUT_SECS",
            "Seconds a request waits for a hash permit before returning a 503 backpressure error (default 5).",
            "5",
          ],
        ],
      },
      { type: "h", id: "authz-cache", text: "Authorization decision cache (optional)" },
      {
        type: "p",
        text: "An optional per-tenant cache that skips the SurrealDB round-trips per check. Off by default; enabling it changes performance only, never the decision returned. Every access-narrowing mutation invalidates the affected entries immediately, so no revocation can leave a stale allow — the TTL is only a bounded-staleness backstop.",
      },
      {
        type: "table",
        headers: ["Variable", "Meaning", "Example"],
        rows: [
          [
            "AXIAM__AUTHZ__DECISION_CACHE_ENABLED",
            "Master switch (default false).",
            "false",
          ],
          [
            "AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS",
            "Cached-decision TTL, and the upper bound on revocation latency if an invalidation is ever missed (default 5).",
            "5",
          ],
          [
            "AXIAM__AUTHZ__DECISION_CACHE_MAX_ENTRIES",
            "Max cached decisions per tenant before FIFO eviction (default 10000).",
            "10000",
          ],
        ],
      },
      { type: "h", id: "rate-limit", text: "Rate limiting" },
      {
        type: "p",
        text: "Every auth/OAuth2 endpoint is rate-limited per-key, per-minute. Defaults are shown; `/auth/login` always keys per-IP regardless of the key mode.",
      },
      {
        type: "table",
        headers: ["Variable", "Meaning", "Example"],
        rows: [
          [
            "AXIAM__RATE_LIMIT__PROFILE",
            "Posture preset moving the machine-traffic family coherently: internet (default) | gateway | mesh. The human endpoints — login, register, password-reset, MFA — stay strict per-IP under every preset.",
            "internet",
          ],
          ["AXIAM__RATE_LIMIT__LOGIN_PER_MIN", "Max /auth/login per minute per key.", "10"],
          ["AXIAM__RATE_LIMIT__REGISTER_PER_MIN", "Max register requests per minute.", "5"],
          ["AXIAM__RATE_LIMIT__TOKEN_PER_MIN", "Max /oauth2/token per minute.", "120"],
          [
            "AXIAM__RATE_LIMIT__PASSWORD_RESET_PER_MIN",
            "Max password-reset requests per minute.",
            "3",
          ],
          ["AXIAM__RATE_LIMIT__MFA_PER_MIN", "Max MFA enroll/confirm/verify per minute.", "5"],
          [
            "AXIAM__RATE_LIMIT__WEBAUTHN_PER_MIN",
            "Max WebAuthn ceremony requests per minute, applied to each of the six `/auth/webauthn/*` routes independently.",
            "10",
          ],
          [
            "AXIAM__RATE_LIMIT__INTROSPECT_PER_MIN",
            "Max /oauth2/introspect per minute.",
            "600",
          ],
          ["AXIAM__RATE_LIMIT__REVOKE_PER_MIN", "Max /oauth2/revoke per minute.", "60"],
          [
            "AXIAM__RATE_LIMIT__TOKEN_EXCHANGE_PER_MIN",
            "Max RFC 8693 token exchanges per minute.",
            "120",
          ],
          ["AXIAM__RATE_LIMIT__PAR_PER_MIN", "Max /oauth2/par per minute.", "120"],
          [
            "AXIAM__RATE_LIMIT__END_SESSION_PER_MIN",
            "Max /oauth2/end_session per minute. Never moved by a profile preset.",
            "30",
          ],
          [
            "AXIAM__RATE_LIMIT__DEVICE_AUTHORIZATION_PER_MIN",
            "Max device-grant starts per minute. Sized as a state-allocation guard rather than from capacity — each call reserves a user code — and never moved by a preset.",
            "12",
          ],
          [
            "AXIAM__RATE_LIMIT__DEVICE_VERIFY_PER_MIN",
            "Max device-code verifications per minute. Human-driven, so sized for a person at a keyboard; never moved by a preset.",
            "10",
          ],
          [
            "AXIAM__RATE_LIMIT__UMA_PERM_PER_MIN",
            "Max UMA permission-ticket requests per minute.",
            "120",
          ],
          [
            "AXIAM__RATE_LIMIT__UMA_TICKET_PER_MIN",
            "Max UMA ticket redemptions per minute.",
            "120",
          ],
          [
            "AXIAM__RATE_LIMIT__AUTHZ_CHECK_PER_MIN",
            "Max authz-check requests per minute.",
            "1800",
          ],
          [
            "AXIAM__RATE_LIMIT__TRUSTED_HOPS",
            "Trusted reverse-proxy entries to skip from the right of X-Forwarded-For. Set it to **the number of proxies in front of the server minus one** — a proxy appends the address it received *from*, so the nearest proxy is the socket peer and never appears in the header. One proxy (the shipped Compose and Kubernetes topologies both have exactly one) therefore wants `0`, two want `1`, three want `2`. Setting it to the proxy count instead makes the header unusable and keys every client in the world to the proxy's own address — one global bucket, `/auth/login` included.",
            "0",
          ],
          [
            "AXIAM__RATE_LIMIT__KEY",
            "Bucket-key mode for token/introspect/revoke: ip | client_id | ip_client_id.",
            "ip",
          ],
          [
            "AXIAM__RATE_LIMIT__SHARED",
            "Enables (on) or disables (off) the cross-replica write-behind shared counter. off is a single-replica escape hatch — the per-replica in-memory governor becomes the sole limiter.",
            "on",
          ],
          [
            "AXIAM__RATE_LIMIT__SHARED_SYNC_MS",
            "Write-behind flush interval (ms) for the shared counter, clamped 50-60000. Scales the cross-replica overshoot bound.",
            "1000",
          ],
        ],
      },
      {
        type: "note",
        text: "The shared counter behind AXIAM__RATE_LIMIT__SHARED no longer performs a synchronous datastore write on the request path (write-behind design): it decides in-memory and flushes one coalesced write per bucket per AXIAM__RATE_LIMIT__SHARED_SYNC_MS. Cross-replica enforcement is therefore eventual, not synchronous — worst-case overshoot beyond the configured limit is bounded by roughly (replicas - 1) x arrival_rate_per_replica x sync_interval, and is zero on a single replica. The per-replica in-memory governor is unchanged and still caps overshoot independently. See the Deployment Guide's rate-limiting section for the full bound, the store-outage semantics (a store outage is now detected by the background flusher rather than the request, so limit=0 plus an unreachable store denies rather than allows), and the observability log lines.",
      },
      { type: "h", id: "sizing", text: "Suggested settings by deployment (benchmark-derived)" },
      {
        type: "p",
        text: "The shipped defaults are tuned for one thing: blunting single-source abuse on a small internet-facing deployment. The benchmark's production-posture run showed exactly that — and also that those defaults are far too strict for machine-to-machine topologies, where many clients share one source IP behind a NAT or gateway. The recommendations below derive directly from the run-4 measurements (median-of-3, 2-CPU-per-container envelope) in `benchmarks/PUBLIC_BENCH_ANALYSIS.md` §7.",
      },
      {
        type: "warn",
        text: "These recommendations come from the current (still temporary) benchmark results on laptop-class hardware. They are good starting points, not guarantees — validate against your own traffic, and re-check this section as the benchmark improves.",
      },
      { type: "h", id: "sizing-throughput", text: "What a given envelope sustains" },
      {
        type: "p",
        text: "Measured per-path ceilings, useful for sizing both hardware and limits. Post rate-limit fix, database CPU is the main ceiling: authorization checks, introspection, token issuance and userinfo all gain 42–90% from a second pair of DB cores. Logins scale with server CPU at fixed Argon2id cost, and JWKS is limited by the load generator rather than by the server.",
      },
      {
        type: "table",
        headers: ["Envelope (server / DB)", "Token issuance", "Introspection", "Authz checks REST / gRPC", "Userinfo REST / gRPC", "Logins"],
        rows: [
          ["2 cores / 2 cores", "~2,700/s", "~4,400/s", "~750 / ~890/s", "~4,500 / ~12,700/s", "~69/s"],
          ["2 cores / 4 cores", "~4,500/s", "~6,200/s", "~1,430 / ~1,680/s", "~7,200/s (server-bound) / ~12,700/s", "~69/s"],
        ],
      },
      {
        type: "p",
        text: "The optional decision cache sits on top of these: at a ~100% hit rate it lifts gRPC checks to ~11,600/s, but REST checks gain only ~5% because their per-request session-cookie validation is a database read the cache does not cover. Size for the cache-off numbers and treat the cache as headroom.",
      },
      { type: "h", id: "sizing-knobs", text: "Recommended values per scenario" },
      {
        type: "table",
        headers: ["Variable", "Default", "Small internet-facing", "M2M / microservices / IoT", "Large multi-tenant"],
        rows: [
          [
            "AXIAM__RATE_LIMIT__PROFILE",
            "internet",
            "internet",
            "gateway — one variable moves the whole machine-traffic family coherently (key mode + token/introspect/revoke/authz), leaving the human endpoints untouched",
            "mesh",
          ],
          [
            "AXIAM__RATE_LIMIT__KEY",
            "ip",
            "ip",
            "client_id (or ip_client_id) — per-IP buckets collide behind NAT/gateways — see the security caveat below",
            "ip_client_id",
          ],
          [
            "AXIAM__RATE_LIMIT__TOKEN_PER_MIN",
            "120",
            "keep 120",
            "per-client peak RPS × 60 × 2 (a 2-core server sustains ~163k issuances/min total)",
            "budget per tenant SLA",
          ],
          [
            "AXIAM__RATE_LIMIT__INTROSPECT_PER_MIN",
            "600",
            "keep 600",
            "10–20× your token limit (resource servers introspect per request)",
            "same rule",
          ],
          [
            "AXIAM__RATE_LIMIT__AUTHZ_CHECK_PER_MIN",
            "1800",
            "keep 1800",
            "6,000–60,000 per client — checks are cheap reads; the pre-revision 300/min starved any real service",
            "size to the cache-ON ceiling",
          ],
          [
            "AXIAM__RATE_LIMIT__LOGIN_PER_MIN",
            "10 (always per-IP)",
            "keep 10",
            "60+ if users arrive through a shared NAT/proxy",
            "60+, front with a WAF",
          ],
          [
            "AXIAM__AUTHZ__DECISION_CACHE_ENABLED",
            "false",
            "true",
            "true if your checks go over gRPC — measured 13× there at a favourable keyspace, ~+32% at a realistic one; REST checks gain only ~5%",
            "true",
          ],
          [
            "AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS",
            "5",
            "5",
            "5 (raise only if a ≤TTL revocation delay is acceptable)",
            "5",
          ],
          [
            "AXIAM__AUTHZ__BATCH_STRATEGY",
            "coalesced",
            "default",
            "default — `coalesced` measured 744 batch ops/s ≈ 3,721 checks/s, about 5× single checks; a full-matrix re-measurement is queued",
            "default",
          ],
          [
            "AXIAM__DB__POOL_SIZE",
            "1",
            "1",
            "1 — no measured benefit; leave it alone",
            "1",
          ],
          [
            "AXIAM__AUTH__MAX_CONCURRENT_HASHES",
            "0 = auto (min(cores, 4))",
            "auto",
            "auto",
            "≈ physical cores reserved for auth; each concurrent hash holds a ~19 MiB arena",
          ],
          [
            "Database CPU allocation",
            "—",
            "DB ≥ server cores",
            "DB ≥ server cores if authz/userinfo-heavy (those paths scale with DB CPU; tokens don't)",
            "2× server cores for read-heavy workloads",
          ],
        ],
      },
      {
        type: "note",
        text: "`AXIAM__DB__POOL_SIZE` is a connection-pool sizing knob only; do not raise it expecting a throughput win. A pre-1.0 benchmark pass reported a one-off +7% on token issuance at `pool_size=4`, but that comparison was never confirmed on a settled measurement, and follow-up testing (`claude_dev/db-pool-design.md` §11) found no throughput difference between `pool_size=1` and `pool_size=8` under load. Leave it at the default `1` unless you have your own measured evidence for your deployment; `pool_size>1` still gives you independent per-connection session renewal, which is a robustness property worth having on its own, just not a speed one.",
      },
      {
        type: "warn",
        text: "Security caveat on `client_id` keying — read before changing the key mode. The `client_id` a request is bucketed by is read from the request body before the client credential is verified (that is what the OAuth2 spec puts there), so an attacker who simply varies the `client_id` string gets a fresh bucket each time and is effectively unlimited on the token, revoke and introspect endpoints. `client_id` keying is a fairness control between well-behaved clients, not an abuse control. `ip` is the only mode whose key an attacker cannot mint at will, which is why it stays the shipped default. Use `client_id`/`ip_client_id` only where something else already authenticates callers at the edge — mTLS, an API gateway, a WAF, or an IP allow-list — which is exactly the topology the M2M column assumes.",
      },
      {
        type: "note",
        text: "Two rules of thumb the data supports: if your traffic is authorization-check-heavy, spend hardware on the database first (those paths gained ~90% from a second pair of DB cores), then try the decision cache and measure its logged hit rate — it is transformative on gRPC checks and marginal on REST ones; if it's token-heavy, the limits — not the hardware — are what you'll hit first, so raise TOKEN_PER_MIN from your real per-client peak and — if and only if you have edge authentication per the caveat above — switch the key mode. The genuinely internet-exposed endpoints (login, register, password-reset, MFA) stay strict per-IP in every configuration, including under the gateway and mesh profiles.",
      },
      { type: "h", id: "mds", text: "WebAuthn attestation metadata (FIDO MDS3)" },
      {
        type: "p",
        text: "Attestation policy checks an authenticator model against the FIDO Alliance's metadata service. Ingestion is **off by default** — `false` means zero outbound calls, no background job, and an admin-triggered refresh that refuses to run — so a deployment that does not verify attestation carries no dependency on the FIDO Alliance at all.",
      },
      {
        type: "table",
        headers: ["Variable", "Meaning", "Example"],
        rows: [
          ["AXIAM__PKI__MDS_ENABLED", "Master switch. Default `false`.", "true"],
          [
            "AXIAM__PKI__MDS_BLOB_URL",
            "Fetch source (default `https://mds3.fidoalliance.org/`).",
            "https://mds3.fidoalliance.org/",
          ],
          [
            "AXIAM__PKI__MDS_BLOB_PATH",
            "Local BLOB file for an air-gapped deployment. When set it wins over the URL and no network fetch happens at all.",
            "/etc/axiam/mds/blob.jwt",
          ],
          [
            "AXIAM__PKI__MDS_REFRESH_INTERVAL_SECS",
            "Background refresh interval; default 604800 (weekly). `0` disables the background job while leaving the admin-triggered refresh working.",
            "604800",
          ],
          [
            "AXIAM__PKI__MDS_LEAF_DNS",
            "Expected DNS SAN on the BLOB's leaf signing certificate (default `mds.fidoalliance.org`). Configurable so a legitimate FIDO hostname change is an operations action rather than a code release.",
            "mds.fidoalliance.org",
          ],
          [
            "AXIAM__PKI__MDS_MAX_STALE_DAYS",
            "Refuse **attested** registration once the ingested BLOB is this many days past its own `nextUpdate`. Default `0`, which disables the check.",
            "30",
          ],
        ],
      },
      {
        type: "note",
        text: "The staleness bound is opt-in rather than defaulted, and that is a deliberate trade rather than an oversight. Ingestion never hard-fails on staleness — a transient outage at the FIDO Alliance must not brick WebAuthn registration for everyone — and the cost of that choice is a window in which an authenticator model revoked since the last successful refresh still passes policy, because the revocation is in a BLOB this deployment has not seen. The right bound is a property of the deployment: a high-assurance tenant may want days, while an air-gapped one with no automatic refresh path would be taken offline by anything short of months. Silently inventing a number would pick for you.",
      },
      {
        type: "p",
        text: "The bound applies to attestation only. A ceremony that requests no attestation consults no metadata, so stale metadata cannot have misled it.",
      },
      { type: "h", id: "ca-key-custody", text: "CA signing key custody" },
      {
        type: "p",
        text: "An organization's CA signing key is the one private key AXIAM persists. By default it is AES-256-GCM ciphertext in the CA record, sealed under `AXIAM__PKI__ENCRYPTION_KEY` — a real control with a bound worth stating: the key and the thing that opens it are in the same blast radius, and nothing anywhere records a read. Pointing the variables below at a HashiCorp Vault moves it somewhere access is a policy that can be scoped and revoked, every read is audited by something that is not AXIAM, and a database dump on its own is inert.",
      },
      {
        type: "table",
        headers: ["Variable", "Meaning", "Example"],
        rows: [
          [
            "AXIAM__PKI__VAULT_ADDR",
            "Vault base address. Setting this and the token turns Vault custody on.",
            "https://vault.internal:8200",
          ],
          [
            "AXIAM__PKI__VAULT_TOKEN",
            "A token with `create`/`read`/`update` on `<mount>/data/<prefix>/*` and `delete` on `<mount>/metadata/<prefix>/*`.",
            "hvs.…",
          ],
          [
            "AXIAM__PKI__VAULT_MOUNT",
            "KV v2 mount point. Default `secret`, Vault's own default.",
            "secret",
          ],
          [
            "AXIAM__PKI__VAULT_PREFIX",
            "Path prefix under the mount. One secret per CA is written beneath it, at `<prefix>/<org_id>/<ca_id>`. Default `axiam/ca-keys`.",
            "axiam/ca-keys",
          ],
          [
            "AXIAM__PKI__VAULT_CA_CERT_PATH",
            "Trust anchor for Vault's listener certificate. Required whenever that certificate comes from an internal PKI: the HTTP client is built with rustls, whose roots are compiled in, so there is no `SSL_CERT_FILE` to fall back on. An unreadable file is a startup failure, never a silent fallback to the built-in roots.",
            "/etc/ssl/certs/vault-ca.pem",
          ],
          [
            "AXIAM__PKI__VAULT_PKI_ROOT_MOUNT",
            "`vault_pki` custody only: the PKI mount holding the roots AXIAM generates. Default `pki`, Vault's own convention. The operator enables and tunes the mount; AXIAM never calls `sys/mounts`.",
            "pki",
          ],
          [
            "AXIAM__PKI__VAULT_PKI_INT_MOUNT",
            "`vault_pki` custody only: the PKI mount holding the signing intermediates, and the issuer every leaf is signed by. Default `pki_int`.",
            "pki_int",
          ],
          [
            "AXIAM__PKI__CA_KEY_STORE",
            "Which custodian **new** CAs are created with: `database`, `vault` or `vault_pki`. An address and a token together already imply `vault`; `vault_pki` must be named explicitly. Naming a custodian that is not configured is a startup failure rather than a fallback.",
            "vault_pki",
          ],
        ],
      },
      {
        type: "note",
        text: "**No `AXIAM__PKI__VAULT_*` pair means \"the Vault you already configured\".** A deployment that has set up Vault as its secret provider inherits it for CA custody rather than silently falling back to sealed database rows — the PKI-specific pair is an override, not the switch that turns Vault custody on. The startup line reports `vault_inherited` so an operator who never set `AXIAM__PKI__VAULT_ADDR` can see *why* their CA keys are in Vault, and so the reverse — a deployment expecting Vault and getting the database — is a line in the log rather than a discovery months later. Naming `database` explicitly beside a reachable Vault is legal and is warned about at startup: the two differ by whether one database dump is enough.",
      },
      {
        type: "note",
        text: "Custody is recorded per CA, not read from this configuration, and that is the point: a deployment that adopts Vault does not thereby move the CAs it already has. Those records still say `database`, their keys are still sealed into them, and the signing path asks the record rather than the environment — so `AXIAM__PKI__ENCRYPTION_KEY` stays required for as long as any such CA exists. What this configuration decides is the custodian for CAs created from now on; moving an existing one is `POST /api/v1/organizations/{org_id}/ca-certificates/{id}/migrate-custody`, which copies the key to the new custodian and only then releases it from the old, so the CA is never left without it.",
      },
      {
        type: "p",
        text: "One secret per CA rather than one secret with a field per CA, because Vault policy paths are the unit of access control: “read this organization's CAs and not that one's” is a path glob, and would be unwritable if every key shared one secret. Revocation deletes the *metadata* path — a KV v2 delete on the data path soft-deletes the latest version and leaves it readable by version number, which for a signing key is not deletion.",
      },
      {
        type: "warn",
        text: "`vault` is custody, not a key that never leaves the custodian. Vault holds the key and audits access to it; the key still reaches AXIAM's memory to sign with. For the stronger property, set `AXIAM__PKI__CA_KEY_STORE=vault_pki`.",
      },
      { type: "h", id: "ca-key-custody-pki", text: "Keys Vault generates and never releases (`vault_pki`)" },
      {
        type: "p",
        text: "Under `vault_pki` custody the key is generated inside Vault's PKI secrets engine, which exposes no API that exports it, and Vault performs the signature. The private key of such a CA has never existed in the AXIAM process: a memory dump, a malicious build or an operator with a shell yields certificates that Vault's audit log records, and no key. The arrangement follows HashiCorp's own PKI walkthrough — a root at one mount generates a key and certificate, an intermediate at a second mount generates a key and a CSR, the root signs it with `max_path_length=0`, and every leaf thereafter goes to the intermediate's `sign-verbatim`.",
      },
      {
        type: "p",
        text: "Both ways in are supported. Generating a CA has Vault create the root and the intermediate, and the response carries **no** `private_key_pem` because there is none — keep the `chain_pem` it returns instead, since Vault hands over a generated root's certificate exactly once and nothing outside Vault can validate a chain without it. Importing a CA with a `private_key_pem` sends the key and certificate to Vault as one bundle; the key passes through AXIAM's memory on the way, because AXIAM is what received the request, but it is never stored here.",
      },
      {
        type: "note",
        text: "Tune the mounts. A PKI mount's `max_lease_ttl` defaults to 30 days and Vault silently caps a longer request to it rather than failing, so an untuned mount turns a ten-year root into a month-long one. AXIAM records the certificate that came back rather than the one it asked for, and logs Vault's warning — neither is a substitute for `vault secrets tune -max-lease-ttl=87600h pki`.",
      },
      { type: "h", id: "audit-retention", text: "Audit retention" },
      {
        type: "table",
        headers: ["Variable", "Meaning", "Example"],
        rows: [
          [
            "AXIAM__AUDIT_RETENTION_DAYS",
            "How long audit entries are kept. A background sweep prunes anything older, through the audit table's only deletion path — deployment-wide, reachable from no HTTP handler. `0` disables pruning and restores unbounded growth, which is an explicit opt-out for deployments that archive out of band rather than something you fall into. Default `730`, chosen longer than most regimes ask because discarding evidence early is irreversible where keeping it is a storage cost.",
            "365",
          ],
        ],
      },
      { type: "h", id: "tls", text: "Direct TLS termination (opt-in)" },
      {
        type: "p",
        text: "By default the server binds plaintext and a proxy/ingress terminates TLS 1.3 in front of it. To terminate TLS inside the server process instead, set the following — the listener then binds with rustls restricted to TLS 1.3 only. When enabled, both paths are mandatory and the server fails fast at startup on a missing, unreadable or mismatched cert/key (it never falls back to plaintext).",
      },
      {
        type: "table",
        headers: ["Variable", "Meaning", "Example"],
        rows: [
          [
            "AXIAM__SERVER__TLS__ENABLED",
            "Enable in-process TLS 1.3 (default false).",
            "true",
          ],
          [
            "AXIAM__SERVER__TLS__CERT_PATH",
            "Path to the PEM certificate chain (leaf first).",
            "/etc/axiam/tls/tls.crt",
          ],
          [
            "AXIAM__SERVER__TLS__KEY_PATH",
            "Path to the PEM private key (PKCS#8, PKCS#1 or SEC1).",
            "/etc/axiam/tls/tls.key",
          ],
          [
            "AXIAM__SERVER__TLS__RELOAD_INTERVAL_SECS",
            "How often to re-read the certificate and key and pick up a renewal, in seconds. `0` disables polling; `SIGHUP` reloads immediately either way and is what an ACME deploy hook should send. The poll exists because the signal is the part that silently does not happen — a hook nobody wired up, or a runtime that does not forward signals — and a Let's Encrypt certificate renewed at day 60 stops being accepted on day 90. A reload that finds an unreadable or mismatched pair leaves the previous certificate serving and retries.",
            "3600",
          ],
          [
            "AXIAM__SERVER__TLS__CLIENT_AUTH",
            "Native client-certificate policy: `off` (default), `optional` or `required`. `optional` is what a listener serving both browser traffic and mTLS devices wants.",
            "optional",
          ],
          [
            "AXIAM__SERVER__TLS__CLIENT_CA_PATH",
            "PEM bundle used to verify client certificates. Required when `client_auth` is `optional` or `required`; ignored when `off`.",
            "/etc/axiam/tls/client-ca.pem",
          ],
          [
            "AXIAM__SERVER__TLS__CLIENT_CA_BUNDLE_PATH",
            "Where the server writes the client-CA bundle assembled from the organization CAs an operator flagged as mTLS trust anchors. Defaults to `client-ca-bundle.pem` beside the other TLS material.",
            "/etc/axiam/tls/client-ca-bundle.pem",
          ],
        ],
      },
      {
        type: "note",
        text: "The certificate is resolved per TLS handshake from a slot the server can replace while it is listening, so a renewal takes effect on the next connection with no restart and no dropped request. Certificate renewal is the reason the reload exists: rustls otherwise binds the certificate for the process's life.",
      },
      {
        type: "note",
        text: "The AMQP URL is assembled from the broker's own `RABBITMQ_DEFAULT_USER` / `RABBITMQ_DEFAULT_PASS` into `AXIAM__AMQP__URL` at the deployment layer. See Docker & Kubernetes for how the shipped compose file and manifests wire these together.",
      },
    ],
  },

];

import type { DocPage } from "./types";

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
            "AXIAM__GRPC__GRPC_AUTHZ_PER_SEC",
            "Max gRPC authz requests per second per IP (default 100).",
            "100",
          ],
          [
            "AXIAM__SERVER__CORS_ALLOWED_ORIGINS",
            "Allowed CORS origins; empty disables cross-origin requests (restrictive default).",
            "https://admin.acme.dev",
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
            "AXIAM__RATE_LIMIT__INTROSPECT_PER_MIN",
            "Max /oauth2/introspect per minute.",
            "600",
          ],
          ["AXIAM__RATE_LIMIT__REVOKE_PER_MIN", "Max /oauth2/revoke per minute.", "60"],
          [
            "AXIAM__RATE_LIMIT__AUTHZ_CHECK_PER_MIN",
            "Max authz-check requests per minute.",
            "1800",
          ],
          [
            "AXIAM__RATE_LIMIT__TRUSTED_HOPS",
            "Trusted reverse-proxy hops to skip from the right of X-Forwarded-For (set 1 behind a single ingress).",
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
        ],
      },
      {
        type: "note",
        text: "The AMQP URL is assembled from the broker's own `RABBITMQ_DEFAULT_USER` / `RABBITMQ_DEFAULT_PASS` into `AXIAM__AMQP__URL` at the deployment layer. See Docker & Kubernetes for how the shipped compose file and manifests wire these together.",
      },
    ],
  },

];

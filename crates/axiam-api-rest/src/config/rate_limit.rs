//! Rate limiting configuration loaded from environment variables.

use serde::Deserialize;

/// Rate-limit bucket-key derivation mode (D8).
///
/// Environment variable: `AXIAM__RATE_LIMIT__KEY` = `ip` | `client_id` |
/// `ip_client_id` (default `ip`).
///
/// **Why this exists (NAT'd-fleet lesson):** the bucket key was
/// unconditionally `"{endpoint}:{ip}"` (see
/// `middleware::rate_limit_shared::RateLimitShared` and
/// `extractors::rate_limit::XForwardedForKeyExtractor`). Behind a NAT/proxy
/// fleet (many distinct OAuth2 clients — e.g. IoT devices or microservices —
/// egressing through one shared IP), every client sharing that IP collided
/// into a SINGLE bucket, so one noisy/misbehaving client could exhaust the
/// `/oauth2/token`, `/oauth2/revoke`, or `/oauth2/introspect` quota for every
/// other client behind the same NAT gateway. `client_id` and `ip_client_id`
/// give each OAuth2 client its own bucket (optionally still scoped per-IP)
/// on the endpoints where a client identity is actually known.
///
/// **Scope — where this setting applies:** ONLY the three endpoints where an
/// OAuth2 client authenticates itself via a form-encoded `client_id`
/// (`client_secret_post`, RFC 6749 §2.3.1): `/oauth2/token`,
/// `/oauth2/revoke`, `/oauth2/introspect` (see `handlers::oauth2` and
/// `server.rs`'s wiring of `RateLimitShared::new_client_identity_aware` /
/// the client-aware governor for exactly those three resources).
///
/// **`/auth/login` (and every other rate-limited endpoint) ALWAYS keys
/// per-IP, regardless of this setting.** Login authenticates a *user* via
/// username/password — there is no OAuth2 client identity anywhere in that
/// request, so there is nothing meaningful to key on besides the source IP.
/// This is intentional and NOT a bug: switching this config value never
/// changes login's (or MFA's, or password-reset's, etc.) rate-limit
/// behavior. See `server.rs` — those resources are wired with the plain
/// `build_governor`/`RateLimitShared::new` constructors, which never read
/// this field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKeyMode {
    /// Key on source IP only (current/default behavior, unchanged).
    #[default]
    Ip,
    /// Key on the OAuth2 `client_id` alone — independent buckets per client,
    /// regardless of which IP(s) it connects from.
    ClientId,
    /// Key on the `(ip, client_id)` pair — independent buckets per client
    /// AND per IP, so a compromised/leaked client credential rate-limited
    /// from one IP doesn't automatically throttle the same client_id
    /// operating legitimately from a different IP.
    IpClientId,
}

impl RateLimitKeyMode {
    /// Stable, log-safe name — identical to the `AXIAM__RATE_LIMIT__KEY`
    /// value that selects this mode.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::ClientId => "client_id",
            Self::IpClientId => "ip_client_id",
        }
    }

    /// How much of this mode's bucket key an **unauthenticated** caller
    /// chooses (security-analysis-2026-08-02 §4 item 1).
    pub const fn mintability(self) -> KeyMintability {
        match self {
            // Source IP, after `trusted_hops` normalisation. Not caller-chosen.
            Self::Ip => KeyMintability::None,
            // The whole key is the `client_id` read from the raw form body
            // before any credential is verified.
            Self::ClientId => KeyMintability::Full,
            // Half the key (`client_id`) is caller-chosen; the IP half is not.
            Self::IpClientId => KeyMintability::Partial,
        }
    }
}

/// How much of a rate-limit bucket key an unauthenticated caller controls.
///
/// The bucket key for `/oauth2/{token,introspect,revoke}` is derived
/// **before** the credential check (`middleware/rate_limit_shared.rs`,
/// `extractors/rate_limit.rs`) — RFC 6749 §2.3.1 puts `client_id` in the
/// request body, so it cannot be authenticated before it is read. Whatever
/// part of the key comes from that body is therefore attacker-chosen, and a
/// caller rotating it mints a fresh bucket per value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMintability {
    /// No part of the key is caller-chosen (the shipped default, `ip`).
    None,
    /// Part of the key is caller-chosen, part is not (`ip_client_id`).
    Partial,
    /// The entire key is caller-chosen (`client_id`).
    Full,
}

/// Deployment rate-limit **posture preset** (G7).
///
/// Environment variable: `AXIAM__RATE_LIMIT__PROFILE` = `internet` |
/// `gateway` | `mesh` (default `internet`).
///
/// **Why a preset instead of new defaults.** Benchmark run 3 measured that
/// the then-shipped defaults (`token 20/min`, `introspect 10/min`,
/// `revoke 10/min`, `authz_check 300/min`, all keyed per-IP) flatten a
/// 50-VU single-source-IP load to ~0–14 req/s at ~100% `429`, while the
/// same 2-core server sustains ~1 800 token issuances/s and ~740–2 300
/// authz checks/s. A *strict per-IP* posture is still correct for a small
/// internet-facing deployment and still wrong for an M2M/NAT'd fleet where
/// many OAuth2 clients share one egress IP — which is why the M2M sizing
/// stays an **opt-in preset**: one env var moves the whole machine-traffic
/// family coherently (key mode + token/introspect/revoke/authz + the gRPC
/// authz ceiling).
///
/// Run 4 separately revised the shipped `internet` machine-endpoint numbers
/// themselves (I3 — token 20→120, introspect 10→600, authz 300→1 800,
/// revoke 10→60; see [`RateLimitConfig::default`]). That changed the
/// starting point, not the argument above: the `internet` posture is still
/// per-IP and still 2–3 orders of magnitude below measured capacity, and it
/// still collapses a NAT'd fleet into one bucket. The presets remain the
/// answer for machine fleets.
///
/// **Human endpoints are never touched by any preset.** `login_per_min`,
/// `register_per_min`, `password_reset_per_min` and `mfa_per_min` stay at
/// their strict per-IP defaults in every profile — they gate
/// password/OTP guessing and account-enumeration, which are human-scale
/// attacks whose economics do not change because the deployment is a
/// service mesh. Raise them deliberately, one env var at a time.
///
/// **Security caveat an operator MUST read before selecting a preset**
/// (also in `docs/deployment/rate-limit-sizing.md`): both non-default
/// presets set the key mode to `client_id`, and the `client_id` is parsed
/// from the *unauthenticated* request body (`client_secret_post`,
/// RFC 6749 §2.3.1) before any credential is verified. An attacker can
/// therefore rotate `client_id` values to mint fresh buckets. Under those
/// modes the token/introspect/revoke limits are a **fairness / noisy-
/// neighbour control between cooperating clients**, not an anti-abuse
/// control against a determined attacker; the anti-abuse job moves to the
/// edge (WAF / API gateway / mTLS). This is a property of the D8 key
/// modes themselves, not of the presets — the presets just make it the
/// active posture, which is exactly why they are opt-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitProfile {
    /// Shipped default: small internet-facing deployment, strict per-IP
    /// limits on every endpoint. No field is preset — the defaults in
    /// [`RateLimitConfig::default`] apply verbatim.
    #[default]
    Internet,
    /// M2M fleet reaching an internet-facing AXIAM through a shared
    /// NAT/egress gateway (the topology run 3 showed the defaults break).
    /// Per-client buckets and machine-scale ceilings on the machine
    /// endpoints; human endpoints unchanged.
    Gateway,
    /// AXIAM reachable only on a private network / service mesh (no
    /// internet exposure on the machine endpoints). Ceilings sized as
    /// runaway-loop guards rather than abuse controls; human endpoints
    /// still unchanged, because "private network" is not "no humans".
    Mesh,
}

/// The machine-traffic limits a non-default [`RateLimitProfile`] presets.
///
/// Human endpoints are deliberately absent from this struct — a preset
/// cannot express them, so it cannot weaken them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachineLimitPreset {
    /// Bucket-key mode for `/oauth2/token`, `/oauth2/revoke`,
    /// `/oauth2/introspect` (the only endpoints that honor it).
    pub key: RateLimitKeyMode,
    /// `/oauth2/token` per minute per bucket.
    pub token_per_min: u32,
    /// `/oauth2/introspect` per minute per bucket.
    pub introspect_per_min: u32,
    /// `/oauth2/revoke` per minute per bucket.
    pub revoke_per_min: u32,
    /// REST authz-check endpoints per minute per IP.
    pub authz_check_per_min: u32,
    /// gRPC `AuthorizationService` per second per IP — applied to
    /// `axiam_api_grpc::GrpcConfig::grpc_authz_per_sec` by the composition
    /// root (`axiam-server::main`). Kept here so the whole family has one
    /// source of truth.
    pub grpc_authz_per_sec: u32,
}

/// `AXIAM__RATE_LIMIT__KEY` — presence pins [`RateLimitConfig::key`].
pub const ENV_KEY: &str = "AXIAM__RATE_LIMIT__KEY";
/// `AXIAM__RATE_LIMIT__TOKEN_PER_MIN`.
pub const ENV_TOKEN_PER_MIN: &str = "AXIAM__RATE_LIMIT__TOKEN_PER_MIN";
/// `AXIAM__RATE_LIMIT__INTROSPECT_PER_MIN`.
pub const ENV_INTROSPECT_PER_MIN: &str = "AXIAM__RATE_LIMIT__INTROSPECT_PER_MIN";
/// `AXIAM__RATE_LIMIT__REVOKE_PER_MIN`.
pub const ENV_REVOKE_PER_MIN: &str = "AXIAM__RATE_LIMIT__REVOKE_PER_MIN";
/// `AXIAM__RATE_LIMIT__AUTHZ_CHECK_PER_MIN`.
pub const ENV_AUTHZ_CHECK_PER_MIN: &str = "AXIAM__RATE_LIMIT__AUTHZ_CHECK_PER_MIN";
/// `AXIAM__RATE_LIMIT__TOKEN_EXCHANGE_PER_MIN` — B3.
pub const ENV_TOKEN_EXCHANGE_PER_MIN: &str = "AXIAM__RATE_LIMIT__TOKEN_EXCHANGE_PER_MIN";
/// `AXIAM__RATE_LIMIT__END_SESSION_PER_MIN` — B5, never preset.
pub const ENV_END_SESSION_PER_MIN: &str = "AXIAM__RATE_LIMIT__END_SESSION_PER_MIN";
/// `AXIAM__RATE_LIMIT__PAR_PER_MIN` — B5.
pub const ENV_PAR_PER_MIN: &str = "AXIAM__RATE_LIMIT__PAR_PER_MIN";
/// `AXIAM__RATE_LIMIT__DEVICE_AUTHORIZATION_PER_MIN` — B2, never preset.
pub const ENV_DEVICE_AUTHORIZATION_PER_MIN: &str =
    "AXIAM__RATE_LIMIT__DEVICE_AUTHORIZATION_PER_MIN";
/// `AXIAM__RATE_LIMIT__DEVICE_VERIFY_PER_MIN` — B2, never preset.
pub const ENV_DEVICE_VERIFY_PER_MIN: &str = "AXIAM__RATE_LIMIT__DEVICE_VERIFY_PER_MIN";
/// `AXIAM__RATE_LIMIT__LOGIN_PER_MIN` — human endpoint, never preset.
pub const ENV_LOGIN_PER_MIN: &str = "AXIAM__RATE_LIMIT__LOGIN_PER_MIN";
/// `AXIAM__RATE_LIMIT__REGISTER_PER_MIN` — human endpoint, never preset.
pub const ENV_REGISTER_PER_MIN: &str = "AXIAM__RATE_LIMIT__REGISTER_PER_MIN";
/// `AXIAM__RATE_LIMIT__PASSWORD_RESET_PER_MIN` — human endpoint, never preset.
pub const ENV_PASSWORD_RESET_PER_MIN: &str = "AXIAM__RATE_LIMIT__PASSWORD_RESET_PER_MIN";
/// `AXIAM__RATE_LIMIT__MFA_PER_MIN` — human endpoint, never preset.
pub const ENV_MFA_PER_MIN: &str = "AXIAM__RATE_LIMIT__MFA_PER_MIN";

impl RateLimitProfile {
    /// Stable, log-safe name — identical to the
    /// `AXIAM__RATE_LIMIT__PROFILE` value that selects this profile.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Internet => "internet",
            Self::Gateway => "gateway",
            Self::Mesh => "mesh",
        }
    }

    /// The machine-traffic limits this profile presets, or `None` for
    /// [`RateLimitProfile::Internet`] (which presets nothing at all).
    ///
    /// Every number below is anchored to the run-3 measured envelope on
    /// 2-core server / 2-core DB containers (`benchmarks/PUBLIC_BENCH_ANALYSIS.md`
    /// §6, laptop-class and explicitly temporary): token issuance
    /// ~1 800/s (~108 000/min), introspection ~2 200/s (~132 000/min),
    /// authz checks ~740/s cache-off and ~2 300/s cache-on
    /// (~44 400 / ~138 000 per minute), gRPC single authz check ~603/s.
    /// The presets are *per bucket*, so they are deliberately a small
    /// fraction of the whole-server ceiling.
    pub const fn preset(self) -> Option<MachineLimitPreset> {
        match self {
            Self::Internet => None,
            // 600/min = 10/s per client ≈ 0.55% of the measured 1 800/s
            // server ceiling: ~180 distinct clients running flat out are
            // needed to saturate, so one compromised credential cannot
            // become the DoS engine. Introspect is 10× token per the
            // public §6 rule (resource servers introspect per request).
            // Authz 6 000/min = 100/s per client, the low end of §6's
            // 6 000–60 000 band.
            Self::Gateway => Some(MachineLimitPreset {
                key: RateLimitKeyMode::ClientId,
                token_per_min: 600,
                introspect_per_min: 6_000,
                revoke_per_min: 600,
                authz_check_per_min: 6_000,
                grpc_authz_per_sec: 1_000,
            }),
            // Private-network sizing: 6 000/min token = 100/s per client
            // (~5.6% of the measured ceiling) and 60 000/min authz =
            // 1 000/s per client, ABOVE the measured 740/s cache-off
            // ceiling — i.e. on this hardware the authz limit stops a
            // runaway retry loop, not an attacker. Documented as such.
            Self::Mesh => Some(MachineLimitPreset {
                key: RateLimitKeyMode::ClientId,
                token_per_min: 6_000,
                introspect_per_min: 60_000,
                revoke_per_min: 6_000,
                authz_check_per_min: 60_000,
                grpc_authz_per_sec: 5_000,
            }),
        }
    }
}

/// What the composition root actually resolved — the input to the startup
/// posture log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitPosture {
    /// The selected profile.
    pub profile: RateLimitProfile,
    /// `true` when a non-default preset was applied to at least the fields
    /// the operator did not pin explicitly.
    pub preset_applied: bool,
    /// Env vars the operator set explicitly, which therefore beat the
    /// preset. Names only — never values (some are not secret, but the
    /// log line stays uniformly value-free for this list).
    pub operator_overrides: Vec<&'static str>,
    /// gRPC authz ceiling the preset wants, for the composition root to
    /// hand to `axiam_api_grpc::GrpcConfig`. `None` under `internet`.
    pub grpc_authz_per_sec_preset: Option<u32>,
}

impl RateLimitPosture {
    /// Comma-joined override list for the startup log (`"none"` when empty).
    pub fn overrides_display(&self) -> String {
        if self.operator_overrides.is_empty() {
            "none".to_owned()
        } else {
            self.operator_overrides.join(",")
        }
    }
}

/// Rate limit configuration.
/// Environment variables: AXIAM__RATE_LIMIT__LOGIN_PER_MIN, etc.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Max login requests per minute per IP (default: 10).
    pub login_per_min: u32,
    /// Max register requests per minute per IP (default: 5).
    pub register_per_min: u32,
    /// Max oauth2/token requests per minute per client (default: 120 — I3).
    pub token_per_min: u32,
    /// Max password-reset requests per minute per IP (default: 3).
    pub password_reset_per_min: u32,
    /// Max MFA requests per minute per IP (default: 5).
    /// Covers /auth/mfa/enroll, /confirm, /verify, /setup/enroll, /setup/confirm (SEC-020).
    pub mfa_per_min: u32,
    /// Max oauth2/introspect requests per minute per IP (default: 600 — I3).
    /// SEC-020: introspect endpoint rate-limited to prevent token probing.
    pub introspect_per_min: u32,
    /// Max oauth2/revoke requests per minute per IP (default: 60 — I3).
    /// SEC-020: revoke endpoint rate-limited to prevent DoS via token flooding.
    pub revoke_per_min: u32,
    /// Max authz-check requests per minute per IP (default: 1800 — I3).
    /// Authz checks are read-only and high-frequency — used by UI permission gating.
    /// Kept in a dedicated bucket so heavy UI use does not consume the login/token limit (D-07).
    pub authz_check_per_min: u32,
    /// Max `/oauth2/device_authorization` requests per minute per IP
    /// (default: 12 — B2). Deliberately NOT part of [`MachineLimitPreset`]:
    /// like the human endpoints above, this one is not sized from capacity.
    /// It is unauthenticated (RFC 8628 targets public clients that cannot
    /// hold a secret) and every accepted request ALLOCATES STATE — a pending
    /// grant plus a user code drawn from a small space. The thing being
    /// limited is therefore exhaustion of that space, not throughput, and
    /// raising it to match a benchmark would be sizing the wrong quantity.
    pub device_authorization_per_min: u32,
    /// Max `/api/v1/device/verify` + `/api/v1/device/decide` requests per
    /// minute per IP (default: 10 — B2). This is the brute-force surface for
    /// user codes, which are 8 characters from a 20-letter alphabet because a
    /// human has to read them off a screen and type them.
    ///
    /// `axiam_oauth2::device::brute_force_attempts_required` is the arithmetic
    /// this number answers to: at the shipped 10-minute grant lifetime the
    /// OWASP bar (`charset^len / (rate × lifetime) > 10^6`) permits roughly
    /// 2 500 attempts per minute, so 10 leaves better than two orders of
    /// magnitude of margin — and the endpoint is one a human drives by hand,
    /// so a tight limit costs legitimate users nothing.
    pub device_verify_per_min: u32,
    /// Max token-exchange requests per minute per bucket (default: 120 — B3).
    ///
    /// Sized alongside `token_per_min` because an exchange IS a token
    /// request, but kept separate because it is strictly more expensive —
    /// it verifies an inbound JWT, consults the client registration and
    /// writes an audit record — and because it is the endpoint an attacker
    /// holding one stolen token would hammer looking for a widening path.
    /// A shared bucket would let ordinary token traffic hide that.
    pub token_exchange_per_min: u32,
    /// Max `/oauth2/par` requests per minute per authenticated client
    /// (default: 120 — B5).
    ///
    /// Sized like `token_per_min` because the traffic shape is the same: one
    /// PAR precedes one authorize, which precedes one token request, so a
    /// deployment that can serve N logins per minute pushes about N. Kept in
    /// its own bucket because the endpoint ALLOCATES STATE — a stored request
    /// per call — and sharing the token bucket would let ordinary token
    /// traffic mask an attempt to fill that store.
    ///
    /// Keyed by the authenticated client rather than per-IP: PAR always
    /// carries client credentials (that is the point of the endpoint), so
    /// there is a real identity to key on, and per-IP would collapse a whole
    /// deployment behind one NAT into a single bucket.
    pub par_per_min: u32,
    /// Max `/oauth2/end_session` requests per minute per IP (default: 30 —
    /// B5). Deliberately NOT part of [`MachineLimitPreset`]: like the other
    /// human-driven endpoints this is not sized from capacity.
    ///
    /// The endpoint is unauthenticated (a user whose session already expired
    /// must still be able to complete a logout) and it TERMINATES state. The
    /// thing being limited is therefore forced-logout abuse, not throughput.
    /// 30/min is generous for a human clicking "sign out" and low enough that
    /// scripting mass logouts against guessed sessions is not free — though
    /// the real defence there is that an unverifiable `id_token_hint` ends
    /// nothing at all.
    pub end_session_per_min: u32,
    /// Rate-limit bucket-key derivation mode (D8, default: `Ip` — current
    /// behavior, unchanged). See [`RateLimitKeyMode`] for the full
    /// rationale and scope (only `/oauth2/token`, `/oauth2/revoke`,
    /// `/oauth2/introspect` honor this; `/auth/login` and every other
    /// endpoint always stay per-IP).
    pub key: RateLimitKeyMode,
    /// Deployment posture preset (G7, default:
    /// [`RateLimitProfile::Internet`] — presets nothing, so the shipped
    /// defaults above apply verbatim). Configure via
    /// `AXIAM__RATE_LIMIT__PROFILE`. Applied by
    /// [`RateLimitConfig::apply_profile_from_env`] at startup; see
    /// [`RateLimitProfile`] for the values and the security caveat.
    pub profile: RateLimitProfile,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            // --- Human endpoints: NEVER sized from capacity (I3) ----------
            // These gate password/OTP guessing and account enumeration.
            // Benchmark capacity is irrelevant to their sizing and they are
            // deliberately untouched by the I3 revision below.
            login_per_min: 10,
            register_per_min: 5,
            password_reset_per_min: 3,
            mfa_per_min: 5,
            // --- Machine endpoints: I3 revision (run-4 sizing) ------------
            // Run 4 measured the `internet` machine-endpoint defaults against
            // the actual capacity behind them on a 2-core envelope
            // (`benchmarks/PUBLIC_BENCH_ANALYSIS.md` §7): token 20/min vs
            // ~163 000/min of capacity, introspect 10/min vs ~263 000/min,
            // authz 300/min vs ~45 000/min. Those numbers did not protect
            // anything the raised ones fail to protect — they broke the first
            // healthy integration behind a NAT while sitting 4–5 orders of
            // magnitude below the machine's ceiling. Each revised value still
            // stays well below measured capacity — 25x at the tightest
            // (authz_check, deliberately so: it is the endpoint a real service
            // calls per request), 400-2 700x on the rest — so the abuse
            // posture is intact. See `revised_defaults_keep_capacity_margin`
            // for the pinned arithmetic. (Do NOT restate this as ">=500x":
            // the run-4 planning docs made that claim and it is false for
            // authz_check and introspect.)
            //
            // Previous shipped values, for the record: token 20,
            // introspect 10, revoke 10, authz_check 300.
            token_per_min: 120,
            introspect_per_min: 600,
            revoke_per_min: 60,
            authz_check_per_min: 1_800,
            // --- B2 device flow: state-allocating and human-driven --------
            // Neither is sized from capacity, for the reasons on each field.
            device_authorization_per_min: 12,
            device_verify_per_min: 10,
            token_exchange_per_min: 120,
            par_per_min: 120,
            end_session_per_min: 30,
            key: RateLimitKeyMode::Ip,
            profile: RateLimitProfile::Internet,
        }
    }
}

impl RateLimitConfig {
    /// Applies [`RateLimitConfig::profile`]'s preset to every machine-traffic
    /// limit the operator did **not** pin with an explicit
    /// `AXIAM__RATE_LIMIT__*` env var, reading the process environment.
    ///
    /// Call once at startup, before [`RateLimitConfig::validate`] and before
    /// the config is cloned into the App factory.
    ///
    /// **Precedence:** explicit env var > profile preset > shipped default.
    /// **Known limitation:** "explicit" means *an env var is present*. A
    /// value coming from `config/default.toml` (the optional, non-shipped
    /// file source in `axiam-server::load_config`) is indistinguishable from
    /// "unset" here and will be overwritten by a non-default profile. Set the
    /// env var to pin it. This is documented in
    /// `docs/deployment/rate-limit-sizing.md`.
    pub fn apply_profile_from_env(&mut self) -> RateLimitPosture {
        self.apply_profile(|name| std::env::var_os(name).is_some())
    }

    /// [`RateLimitConfig::apply_profile_from_env`] with the environment
    /// lookup injected — `is_set(name)` answers "did the operator pin this
    /// env var?". Pure and unit-testable; the env-reading wrapper is the
    /// only impure part.
    pub fn apply_profile<F>(&mut self, is_set: F) -> RateLimitPosture
    where
        F: Fn(&str) -> bool,
    {
        let Some(preset) = self.profile.preset() else {
            // `internet`: nothing is preset — this is a no-op by
            // construction, so the shipped posture cannot drift.
            return RateLimitPosture {
                profile: self.profile,
                preset_applied: false,
                operator_overrides: Vec::new(),
                grpc_authz_per_sec_preset: None,
            };
        };

        let mut overrides: Vec<&'static str> = Vec::new();
        if is_set(ENV_KEY) {
            overrides.push(ENV_KEY);
        } else {
            self.key = preset.key;
        }
        for (env, field, value) in [
            (
                ENV_TOKEN_PER_MIN,
                &mut self.token_per_min,
                preset.token_per_min,
            ),
            (
                ENV_INTROSPECT_PER_MIN,
                &mut self.introspect_per_min,
                preset.introspect_per_min,
            ),
            (
                ENV_REVOKE_PER_MIN,
                &mut self.revoke_per_min,
                preset.revoke_per_min,
            ),
            (
                ENV_AUTHZ_CHECK_PER_MIN,
                &mut self.authz_check_per_min,
                preset.authz_check_per_min,
            ),
        ] {
            if is_set(env) {
                overrides.push(env);
            } else {
                *field = value;
            }
        }

        // NOTE: login/register/password_reset/mfa are intentionally absent.
        // No preset may touch a human endpoint — see `RateLimitProfile`.

        RateLimitPosture {
            profile: self.profile,
            preset_applied: true,
            operator_overrides: overrides,
            grpc_authz_per_sec_preset: Some(preset.grpc_authz_per_sec),
        }
    }

    /// Startup advisory for an **attacker-mintable** bucket-key mode
    /// (security-analysis-2026-08-02 §4 item 1).
    ///
    /// Call once, at composition time, right after the "Rate-limit posture
    /// active" line. Mirrors the two existing startup advisories: the I3
    /// machine-traffic advisory (armed only when the shipped defaults are what
    /// this process actually enforces) and the session-validation cache's
    /// `warn!` (fires only for the opt-in, bounded-staleness mode). Like both,
    /// this stays silent for the shipped default and speaks only when an
    /// operator has selected the mode with the caveat.
    ///
    /// - **`client_id` → `warn!`.** The entire bucket key is read from the
    ///   unauthenticated form body before the credential check, so rotating
    ///   `client_id` values mints fresh buckets on
    ///   `/oauth2/{token,introspect,revoke}`. The mode is intended only behind
    ///   an edge (mTLS / API gateway / WAF) that already authenticates
    ///   callers.
    /// - **`ip_client_id` → `info!`, deliberately softer.** It is *partially*
    ///   mintable: the same single-source evasion works, so this is not a
    ///   "safe" mode. But the key still carries a component the caller cannot
    ///   forge, which removes the one thing `client_id` mode uniquely allows —
    ///   `client_id`s are not secret, so under `client_id` an attacker can
    ///   exhaust a *known legitimate client's* bucket from anywhere and deny
    ///   it service, while under `ip_client_id` that collateral is confined to
    ///   the attacker's own source IP. Warning at the same level as
    ///   `client_id` would flatten a real difference and train operators to
    ///   ignore both; staying silent would hide a genuine caveat. `info!` is
    ///   the honest middle.
    /// - **`ip` (default) → silent.** Nothing about the key is caller-chosen.
    pub fn warn_on_mintable_key(&self) {
        match self.key.mintability() {
            KeyMintability::None => {}
            KeyMintability::Full => tracing::warn!(
                key_mode = self.key.as_str(),
                "rate-limit key mode `client_id` ACTIVE — the whole bucket key is the \
                 client_id read from the unauthenticated OAuth2 form body BEFORE any \
                 credential check, so a caller rotating client_id values mints fresh \
                 buckets on /oauth2/{{token,introspect,revoke}}. Under this mode those \
                 limits are a fairness control between cooperating clients, NOT an \
                 anti-abuse control; the mode assumes an edge (mTLS / API gateway / WAF) \
                 that already authenticates callers. See \
                 docs/deployment/rate-limit-sizing.md section 5"
            ),
            KeyMintability::Partial => tracing::info!(
                key_mode = self.key.as_str(),
                "rate-limit key mode `ip_client_id` active — the client_id half of the \
                 bucket key is caller-chosen before authentication, so a single source \
                 can still mint fresh buckets; the source-IP half only bounds the blast \
                 radius (a third party cannot exhaust a known client_id's bucket from \
                 elsewhere). See docs/deployment/rate-limit-sizing.md section 5"
            ),
        }
    }

    /// Validates all rate limits are >= 1 (governor panics on zero).
    pub fn validate(&self) {
        assert!(self.login_per_min >= 1, "login_per_min must be >= 1");
        assert!(self.register_per_min >= 1, "register_per_min must be >= 1");
        assert!(self.token_per_min >= 1, "token_per_min must be >= 1");
        assert!(
            self.password_reset_per_min >= 1,
            "password_reset_per_min must be >= 1"
        );
        assert!(self.mfa_per_min >= 1, "mfa_per_min must be >= 1");
        assert!(
            self.introspect_per_min >= 1,
            "introspect_per_min must be >= 1"
        );
        assert!(self.revoke_per_min >= 1, "revoke_per_min must be >= 1");
        assert!(
            self.authz_check_per_min >= 1,
            "authz_check_per_min must be >= 1"
        );
        assert!(
            self.device_authorization_per_min >= 1,
            "device_authorization_per_min must be >= 1"
        );
        assert!(
            self.device_verify_per_min >= 1,
            "device_verify_per_min must be >= 1"
        );
        assert!(
            self.token_exchange_per_min >= 1,
            "token_exchange_per_min must be >= 1"
        );
        assert!(self.par_per_min >= 1, "par_per_min must be >= 1");
        assert!(
            self.end_session_per_min >= 1,
            "end_session_per_min must be >= 1"
        );
        // B2: the user-code brute-force bound is arithmetic, not judgement, so
        // it is asserted rather than commented. `device_verify_per_min` gates
        // guessing against a code space of 20^8 over the grant's 10-minute
        // lifetime; OWASP wants better than 10^6 expected attempts. An
        // operator who raises this knob past that point has silently turned a
        // typed 8-character code into a guessable one, which is exactly the
        // kind of change that should fail at startup rather than in an
        // incident review.
        let expected_attempts = axiam_oauth2::device::brute_force_attempts_required(
            self.device_verify_per_min as u64,
            axiam_oauth2::device::DEFAULT_EXPIRES_IN_SECS,
        );
        assert!(
            expected_attempts > 1e6,
            "device_verify_per_min={} leaves only {expected_attempts:.0} expected guesses \
             against a live user code over its {}s lifetime — below the 10^6 bar. \
             Lower the limit (shipped default: 10).",
            self.device_verify_per_min,
            axiam_oauth2::device::DEFAULT_EXPIRES_IN_SECS,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    /// `docs/deployment/rate-limit-sizing.md` — the operator-facing sizing
    /// page. Its posture table is the ONLY place the shipped values are
    /// written down for humans, and these tests are what keep it honest.
    const POSTURE_DOC: &str = "docs/deployment/rate-limit-sizing.md";
    /// The published benchmark analysis carries the same "shipped default"
    /// column in its §7 production-rate-limit tables. Checked
    /// opportunistically (the file is owned by the benchmark harness, not
    /// this crate).
    const PUBLIC_BENCH_DOC: &str = "benchmarks/PUBLIC_BENCH_ANALYSIS.md";

    const TABLE_BEGIN: &str = "<!-- rate-limit-posture-table:begin -->";
    const TABLE_END: &str = "<!-- rate-limit-posture-table:end -->";

    /// `crates/axiam-api-rest` → repository root.
    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
    }

    fn cells(line: &str) -> Vec<String> {
        line.trim()
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().trim_matches('`').trim().to_owned())
            .collect()
    }

    /// Parses the marker-delimited posture table into
    /// `env var -> [internet, gateway, mesh]`.
    fn posture_table() -> HashMap<String, Vec<String>> {
        let path = repo_root().join(POSTURE_DOC);
        let md = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} must be readable: {e}", path.display()));
        let body = md
            .split(TABLE_BEGIN)
            .nth(1)
            .unwrap_or_else(|| panic!("{POSTURE_DOC} must contain {TABLE_BEGIN}"))
            .split(TABLE_END)
            .next()
            .unwrap_or_else(|| panic!("{POSTURE_DOC} must contain {TABLE_END}"));

        let mut table = HashMap::new();
        for line in body.lines() {
            let line = line.trim();
            if !line.starts_with("| `AXIAM__") {
                continue;
            }
            let cells = cells(line);
            assert_eq!(
                cells.len(),
                4,
                "{POSTURE_DOC}: posture row must have env + 3 profile columns: {line}"
            );
            table.insert(cells[0].clone(), cells[1..].to_vec());
        }
        assert!(
            !table.is_empty(),
            "{POSTURE_DOC}: posture table parsed to zero rows — did the format change?"
        );
        table
    }

    /// Column index: 0 = `internet`, 1 = `gateway`, 2 = `mesh`.
    fn documented(table: &HashMap<String, Vec<String>>, env: &str, column: usize) -> String {
        table
            .get(env)
            .unwrap_or_else(|| panic!("{POSTURE_DOC} must document {env}"))[column]
            .clone()
    }

    fn documented_u32(table: &HashMap<String, Vec<String>>, env: &str, column: usize) -> u32 {
        let raw = documented(table, env, column);
        raw.parse()
            .unwrap_or_else(|e| panic!("{POSTURE_DOC}: {env} column {column} ({raw:?}): {e}"))
    }

    /// **Single source of truth guard (G7).** Every shipped default written
    /// down in `docs/deployment/rate-limit-sizing.md` must equal
    /// `RateLimitConfig::default()`. Change one, this test makes you change
    /// the other.
    #[test]
    fn documented_defaults_match_shipped_config() {
        let table = posture_table();
        let d = RateLimitConfig::default();

        assert_eq!(documented(&table, ENV_KEY, 0), d.key.as_str());
        for (env, actual) in [
            (ENV_LOGIN_PER_MIN, d.login_per_min),
            (ENV_REGISTER_PER_MIN, d.register_per_min),
            (ENV_PASSWORD_RESET_PER_MIN, d.password_reset_per_min),
            (ENV_MFA_PER_MIN, d.mfa_per_min),
            (ENV_TOKEN_PER_MIN, d.token_per_min),
            (ENV_INTROSPECT_PER_MIN, d.introspect_per_min),
            (ENV_REVOKE_PER_MIN, d.revoke_per_min),
            (ENV_AUTHZ_CHECK_PER_MIN, d.authz_check_per_min),
        ] {
            assert_eq!(
                documented_u32(&table, env, 0),
                actual,
                "{POSTURE_DOC} documents a different shipped default for {env}"
            );
        }
    }

    /// The documented `gateway`/`mesh` columns must equal what
    /// [`RateLimitConfig::apply_profile`] actually produces — including the
    /// gRPC ceiling handed to `axiam-api-grpc` by the composition root.
    #[test]
    fn documented_presets_match_applied_profiles() {
        let table = posture_table();
        let shipped = RateLimitConfig::default();

        for (column, profile) in [(1, RateLimitProfile::Gateway), (2, RateLimitProfile::Mesh)] {
            let mut cfg = RateLimitConfig {
                profile,
                ..RateLimitConfig::default()
            };
            // Nothing pinned by the operator: the preset applies in full.
            let posture = cfg.apply_profile(|_| false);
            assert!(posture.preset_applied, "{profile:?}");
            assert!(posture.operator_overrides.is_empty(), "{profile:?}");

            assert_eq!(
                documented(&table, ENV_KEY, column),
                cfg.key.as_str(),
                "{profile:?} key mode"
            );
            for (env, actual) in [
                (ENV_TOKEN_PER_MIN, cfg.token_per_min),
                (ENV_INTROSPECT_PER_MIN, cfg.introspect_per_min),
                (ENV_REVOKE_PER_MIN, cfg.revoke_per_min),
                (ENV_AUTHZ_CHECK_PER_MIN, cfg.authz_check_per_min),
            ] {
                assert_eq!(
                    documented_u32(&table, env, column),
                    actual,
                    "{POSTURE_DOC} documents a different {profile:?} value for {env}"
                );
            }
            assert_eq!(
                documented_u32(&table, "AXIAM__GRPC__GRPC_AUTHZ_PER_SEC", column),
                posture
                    .grpc_authz_per_sec_preset
                    .expect("non-default profile presets a gRPC ceiling"),
                "{profile:?} gRPC ceiling"
            );

            // Human endpoints: identical to shipped, in the doc AND in code.
            assert_eq!(cfg.login_per_min, shipped.login_per_min);
            assert_eq!(cfg.register_per_min, shipped.register_per_min);
            assert_eq!(cfg.password_reset_per_min, shipped.password_reset_per_min);
            assert_eq!(cfg.mfa_per_min, shipped.mfa_per_min);
            for env in [
                ENV_LOGIN_PER_MIN,
                ENV_REGISTER_PER_MIN,
                ENV_PASSWORD_RESET_PER_MIN,
                ENV_MFA_PER_MIN,
            ] {
                assert_eq!(
                    documented_u32(&table, env, column),
                    documented_u32(&table, env, 0),
                    "{POSTURE_DOC}: {profile:?} must not change the human endpoint {env}"
                );
            }
        }
    }

    /// Canonical env-var name for a rate-limit row label found in the public
    /// benchmark doc, or `None` when the row is not one of the knobs this
    /// crate owns.
    ///
    /// §7 of the public doc keys its rows by **HTTP endpoint**
    /// (`` `POST /oauth2/token` ``) while §7.2 keys them by **short knob
    /// name** (`` `TOKEN_PER_MIN` ``); earlier drafts used the full
    /// `AXIAM__RATE_LIMIT__…` env-var name. All three spellings are accepted
    /// and normalized here so the check survives an editorial rewrite of the
    /// tables without silently degrading to "matched nothing".
    fn public_doc_row_knob(label: &str) -> Option<&'static str> {
        let label = label.trim().trim_matches('`').trim();
        let short = label
            .strip_prefix("AXIAM__RATE_LIMIT__")
            .unwrap_or(label)
            .to_ascii_uppercase();
        let by_knob = match short.as_str() {
            "TOKEN_PER_MIN" => Some(ENV_TOKEN_PER_MIN),
            "INTROSPECT_PER_MIN" => Some(ENV_INTROSPECT_PER_MIN),
            "REVOKE_PER_MIN" => Some(ENV_REVOKE_PER_MIN),
            "AUTHZ_CHECK_PER_MIN" => Some(ENV_AUTHZ_CHECK_PER_MIN),
            "LOGIN_PER_MIN" => Some(ENV_LOGIN_PER_MIN),
            _ => None,
        };
        by_knob.or_else(|| {
            // §7's endpoint-keyed spelling.
            match label.split_whitespace().next_back().unwrap_or(label) {
                "/oauth2/token" => Some(ENV_TOKEN_PER_MIN),
                "/oauth2/introspect" => Some(ENV_INTROSPECT_PER_MIN),
                "/oauth2/revoke" => Some(ENV_REVOKE_PER_MIN),
                "/api/v1/authz/check" => Some(ENV_AUTHZ_CHECK_PER_MIN),
                "/api/v1/auth/login" => Some(ENV_LOGIN_PER_MIN),
                _ => None,
            }
        })
    }

    /// `true` for a markdown table delimiter row (`|---|---:|`).
    fn is_delimiter_row(line: &str) -> bool {
        line.starts_with('|')
            && line
                .trim_matches('|')
                .split('|')
                .all(|c| !c.trim().is_empty() && c.trim().chars().all(|ch| matches!(ch, '-' | ':')))
    }

    /// Leading integer of a documented value cell, tolerating markdown
    /// emphasis (`**120**`), a unit suffix (`120/min`, `100/s`), trailing
    /// prose (`10 (per IP)`) and digit-group separators (`1 800`, `1 800`).
    /// `None` when the cell does not start with a number at all.
    fn documented_leading_number(cell: &str) -> Option<u32> {
        let mut chars = cell.chars().peekable();
        while matches!(chars.peek(), Some('*' | '`' | ' ')) {
            chars.next();
        }
        let mut digits = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_ascii_digit() {
                digits.push(c);
                chars.next();
            } else if !digits.is_empty()
                // A separator only counts as one when a digit follows it,
                // so "10 / 5 / 3" stops at 10 instead of becoming 1053.
                && matches!(c, ' ' | '\u{a0}' | '\u{202f}' | '_' | ',')
                && chars.clone().nth(1).is_some_and(|n| n.is_ascii_digit())
            {
                chars.next();
            } else {
                break;
            }
        }
        digits.parse().ok()
    }

    /// The published benchmark analysis (§7 "Production rate limits" and
    /// §7.2 "the shipped defaults") repeats the shipped defaults in its own
    /// tables; the publishing guidance requires those to stay in sync with
    /// code. The file belongs to the benchmark harness, so a **missing file
    /// is tolerated — a wrong value is not.**
    ///
    /// The scraper walks every markdown table in the doc, uses the table's
    /// own header row to locate the "shipped default" column (§7 and §7.2
    /// put it at different indices), and normalizes both the row label (§7
    /// keys by endpoint, §7.2 by short knob name) and the value cell (which
    /// is prose-decorated: `**120**`, `20/min`, `1 800`). Every knob in
    /// `expected` must be found at least once, so an editorial rewrite that
    /// drops or renames a row fails loudly instead of quietly checking
    /// nothing — which is exactly how this test previously went blind.
    #[test]
    fn public_benchmark_doc_shipped_defaults_match_code() {
        let path = repo_root().join(PUBLIC_BENCH_DOC);
        let Ok(md) = std::fs::read_to_string(&path) else {
            eprintln!("{PUBLIC_BENCH_DOC} not present — skipping cross-doc drift check");
            return;
        };
        let d = RateLimitConfig::default();
        let expected: HashMap<&str, u32> = HashMap::from([
            (ENV_TOKEN_PER_MIN, d.token_per_min),
            (ENV_INTROSPECT_PER_MIN, d.introspect_per_min),
            (ENV_REVOKE_PER_MIN, d.revoke_per_min),
            (ENV_AUTHZ_CHECK_PER_MIN, d.authz_check_per_min),
            (ENV_LOGIN_PER_MIN, d.login_per_min),
        ]);

        let lines: Vec<&str> = md.lines().map(str::trim).collect();
        // Index of the "shipped default" column in the table currently being
        // walked; `None` outside a table, or in a table that has no such
        // column (§7.1's posture table, §8's result matrix, …).
        let mut shipped_default_col: Option<usize> = None;
        let mut checked = 0usize;
        let mut seen: HashMap<&str, u32> = HashMap::new();

        for (i, line) in lines.iter().enumerate() {
            if !line.starts_with('|') {
                shipped_default_col = None;
                continue;
            }
            if is_delimiter_row(line) {
                continue;
            }
            // A row immediately followed by a delimiter row is this table's
            // header — that is where the column index comes from.
            if lines.get(i + 1).is_some_and(|next| is_delimiter_row(next)) {
                shipped_default_col = cells(line)
                    .iter()
                    .position(|h| h.to_ascii_lowercase().contains("shipped default"));
                continue;
            }
            let Some(column) = shipped_default_col else {
                continue;
            };
            let cells = cells(line);
            let Some(env) = cells.first().and_then(|l| public_doc_row_knob(l)) else {
                continue;
            };
            let Some(want) = expected.get(env) else {
                continue;
            };
            let got = cells
                .get(column)
                .and_then(|c| documented_leading_number(c))
                .unwrap_or_else(|| {
                    panic!(
                        "{PUBLIC_BENCH_DOC}: row {:?} has no parseable number in the \
                         'shipped default' column {column}",
                        cells[0]
                    )
                });
            assert_eq!(
                got, *want,
                "{PUBLIC_BENCH_DOC} §7 shipped default for {env} (row {:?}) disagrees \
                 with RateLimitConfig::default()",
                cells[0]
            );
            seen.insert(env, got);
            checked += 1;
        }

        // Floor 1 — every knob must actually appear somewhere in §7/§7.2.
        let mut missing: Vec<&str> = expected
            .keys()
            .filter(|env| !seen.contains_key(*env))
            .copied()
            .collect();
        missing.sort_unstable();
        assert!(
            missing.is_empty(),
            "{PUBLIC_BENCH_DOC}: no 'shipped default' row found for {missing:?} — \
             the §7/§7.2 table shape changed and this drift check went blind. Fix the \
             doc or teach `public_doc_row_knob`/`documented_leading_number` the new shape; \
             do NOT relax this assertion."
        );
        // Floor 2 — the doc states these numbers in more than one table, so a
        // silent collapse to a single surviving row is also a shape change.
        assert!(
            checked >= expected.len(),
            "{PUBLIC_BENCH_DOC}: only matched {checked} rate-limit rows for {} knobs — \
             §7/§7.2 table format changed?",
            expected.len()
        );
    }

    /// I3: the shipped `internet` numbers, pinned in code so a change is
    /// always a deliberate edit to this test as well as to
    /// [`RateLimitConfig::default`] (and therefore to every doc the two
    /// cross-doc tests above check).
    #[test]
    fn shipped_internet_defaults_are_pinned() {
        let d = RateLimitConfig::default();
        // Machine endpoints — revised by I3 from 20 / 10 / 10 / 300.
        assert_eq!(d.token_per_min, 120);
        assert_eq!(d.introspect_per_min, 600);
        assert_eq!(d.revoke_per_min, 60);
        assert_eq!(d.authz_check_per_min, 1_800);
        // Human endpoints — deliberately untouched by I3.
        assert_eq!(d.login_per_min, 10);
        assert_eq!(d.register_per_min, 5);
        assert_eq!(d.password_reset_per_min, 3);
        assert_eq!(d.mfa_per_min, 5);
    }

    /// I3 sizing rule: every revised machine default stays at least 25x
    /// below the run-4 measured per-minute capacity of its endpoint, which is
    /// what keeps the abuse posture intact after raising the numbers. The
    /// actual margins are token ~1 358x, introspect ~438x, revoke ~2 716x
    /// and authz_check ~25x — authz is deliberately the tightest (it is the
    /// endpoint a real service calls per request), so 25x is the bar the
    /// whole family has to clear.
    #[test]
    fn revised_machine_defaults_stay_far_below_measured_capacity() {
        // benchmarks/PUBLIC_BENCH_ANALYSIS.md §7 (2-core server / 2-core DB).
        const TOKEN_CAPACITY_PER_MIN: u32 = 163_000;
        const INTROSPECT_CAPACITY_PER_MIN: u32 = 263_000;
        const AUTHZ_CAPACITY_PER_MIN: u32 = 45_000;
        let d = RateLimitConfig::default();
        for (name, limit, capacity) in [
            ("token", d.token_per_min, TOKEN_CAPACITY_PER_MIN),
            (
                "introspect",
                d.introspect_per_min,
                INTROSPECT_CAPACITY_PER_MIN,
            ),
            ("revoke", d.revoke_per_min, TOKEN_CAPACITY_PER_MIN),
            ("authz_check", d.authz_check_per_min, AUTHZ_CAPACITY_PER_MIN),
        ] {
            assert!(
                limit * 25 <= capacity,
                "{name}: shipped default {limit}/min is not comfortably below the \
                 measured {capacity}/min capacity"
            );
        }
    }

    /// G7: the default profile presets NOTHING. This is what guarantees the
    /// shipped internet-facing posture cannot drift as presets evolve.
    #[test]
    fn internet_profile_is_a_no_op() {
        let mut cfg = RateLimitConfig::default();
        let before = cfg.clone();
        let posture = cfg.apply_profile(|_| panic!("internet must not consult the environment"));

        assert_eq!(posture.profile, RateLimitProfile::Internet);
        assert!(!posture.preset_applied);
        assert!(posture.operator_overrides.is_empty());
        assert_eq!(posture.grpc_authz_per_sec_preset, None);
        assert_eq!(posture.overrides_display(), "none");

        assert_eq!(cfg.key, before.key);
        assert_eq!(cfg.token_per_min, before.token_per_min);
        assert_eq!(cfg.introspect_per_min, before.introspect_per_min);
        assert_eq!(cfg.revoke_per_min, before.revoke_per_min);
        assert_eq!(cfg.authz_check_per_min, before.authz_check_per_min);
    }

    /// Precedence: an explicitly-set env var beats the preset, and is named
    /// in the posture (so the startup log tells the operator why a value
    /// isn't what the profile advertises).
    #[test]
    fn explicit_env_vars_win_over_the_preset() {
        let mut cfg = RateLimitConfig {
            profile: RateLimitProfile::Gateway,
            token_per_min: 2_000,
            key: RateLimitKeyMode::IpClientId,
            ..RateLimitConfig::default()
        };
        let posture = cfg.apply_profile(|name| name == ENV_TOKEN_PER_MIN || name == ENV_KEY);

        // Pinned by the operator — untouched.
        assert_eq!(cfg.token_per_min, 2_000);
        assert_eq!(cfg.key, RateLimitKeyMode::IpClientId);
        // Not pinned — preset applies.
        assert_eq!(cfg.introspect_per_min, 6_000);
        assert_eq!(cfg.revoke_per_min, 600);
        assert_eq!(cfg.authz_check_per_min, 6_000);

        assert!(posture.preset_applied);
        assert_eq!(posture.operator_overrides, vec![ENV_KEY, ENV_TOKEN_PER_MIN]);
        assert_eq!(
            posture.overrides_display(),
            format!("{ENV_KEY},{ENV_TOKEN_PER_MIN}")
        );
    }

    /// Non-negotiable invariant: **no profile may raise a human endpoint.**
    /// If someone adds `login_per_min` to a preset, this fails.
    #[test]
    fn no_profile_touches_human_endpoints() {
        let shipped = RateLimitConfig::default();
        for profile in [
            RateLimitProfile::Internet,
            RateLimitProfile::Gateway,
            RateLimitProfile::Mesh,
        ] {
            let mut cfg = RateLimitConfig {
                profile,
                ..RateLimitConfig::default()
            };
            cfg.apply_profile(|_| false);
            assert_eq!(cfg.login_per_min, shipped.login_per_min, "{profile:?}");
            assert_eq!(
                cfg.register_per_min, shipped.register_per_min,
                "{profile:?}"
            );
            assert_eq!(
                cfg.password_reset_per_min, shipped.password_reset_per_min,
                "{profile:?}"
            );
            assert_eq!(cfg.mfa_per_min, shipped.mfa_per_min, "{profile:?}");
        }
    }

    /// Presets must stay well inside the measured envelope: a per-bucket
    /// limit is a fraction of the whole-server ceiling, never a multiple of
    /// it. (Measured run 3, 2 cores: ~1 800 issuances/s = 108 000/min.)
    #[test]
    fn presets_stay_below_the_measured_server_ceiling() {
        const MEASURED_TOKEN_PER_MIN_CEILING: u32 = 108_000;
        for profile in [RateLimitProfile::Gateway, RateLimitProfile::Mesh] {
            let preset = profile.preset().expect("non-default profile has a preset");
            assert!(
                preset.token_per_min < MEASURED_TOKEN_PER_MIN_CEILING / 10,
                "{profile:?}: a single bucket must not be able to claim >10% of the \
                 measured server ceiling"
            );
        }
    }

    #[test]
    fn profile_deserializes_from_documented_env_values() {
        for (raw, expected) in [
            ("\"internet\"", RateLimitProfile::Internet),
            ("\"gateway\"", RateLimitProfile::Gateway),
            ("\"mesh\"", RateLimitProfile::Mesh),
        ] {
            assert_eq!(
                serde_json::from_str::<RateLimitProfile>(raw).unwrap(),
                expected
            );
        }
        assert_eq!(RateLimitProfile::default(), RateLimitProfile::Internet);
        assert_eq!(
            RateLimitConfig::default().profile,
            RateLimitProfile::Internet
        );
        assert!(serde_json::from_str::<RateLimitProfile>("\"m2m\"").is_err());
    }

    /// D8 acceptance: default behavior (`ip`) is unchanged — a
    /// freshly-defaulted config must key exactly the way it did before this
    /// field existed.
    #[test]
    fn default_key_mode_is_ip() {
        assert_eq!(RateLimitConfig::default().key, RateLimitKeyMode::Ip);
        assert_eq!(RateLimitKeyMode::default(), RateLimitKeyMode::Ip);
    }

    /// `AXIAM__RATE_LIMIT__KEY` values must map onto exactly `ip`,
    /// `client_id`, `ip_client_id` via serde `snake_case` — this is what the
    /// `config` crate's `Environment` source (see `axiam-server::main`)
    /// deserializes the raw env var string against.
    #[test]
    fn key_mode_deserializes_from_documented_env_values() {
        assert_eq!(
            serde_json::from_str::<RateLimitKeyMode>("\"ip\"").unwrap(),
            RateLimitKeyMode::Ip
        );
        assert_eq!(
            serde_json::from_str::<RateLimitKeyMode>("\"client_id\"").unwrap(),
            RateLimitKeyMode::ClientId
        );
        assert_eq!(
            serde_json::from_str::<RateLimitKeyMode>("\"ip_client_id\"").unwrap(),
            RateLimitKeyMode::IpClientId
        );
    }

    // ------------------------------------------------------------------
    // §4 item 1 — startup advisory for the attacker-mintable key mode
    // ------------------------------------------------------------------

    /// In-memory `MakeWriter` so the tests below assert on what a real
    /// subscriber would print, not on a return value. Mirrors the capture
    /// helper in `tests/gdpr_audit_dlq_test.rs`.
    #[derive(Clone)]
    struct BufWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for BufWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufWriter {
        type Writer = BufWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Runs `warn_on_mintable_key` under a capturing subscriber at TRACE and
    /// returns everything it emitted.
    fn captured_advisory(key: RateLimitKeyMode) -> String {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(BufWriter(buf.clone()))
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish();

        let cfg = RateLimitConfig {
            key,
            ..Default::default()
        };
        tracing::subscriber::with_default(subscriber, || cfg.warn_on_mintable_key());

        let out = buf.lock().unwrap().clone();
        String::from_utf8(out).expect("tracing output is utf-8")
    }

    /// The advisory must fire at WARN for `client_id`, must name the
    /// pre-authentication mintability and the authenticating-edge assumption,
    /// and must point at the configuration-guide caveat.
    #[test]
    fn mintable_key_advisory_warns_for_client_id() {
        let out = captured_advisory(RateLimitKeyMode::ClientId);
        assert!(out.contains("WARN"), "must be emitted at WARN, got: {out}");
        assert!(
            out.contains("client_id"),
            "must name the key mode, got: {out}"
        );
        assert!(
            out.contains("BEFORE any credential check"),
            "must state that the key is read pre-authentication, got: {out}"
        );
        assert!(
            out.contains("mTLS / API gateway / WAF"),
            "must state the authenticating-edge assumption, got: {out}"
        );
        assert!(
            out.contains("docs/deployment/rate-limit-sizing.md"),
            "must point at the configuration-guide caveat, got: {out}"
        );
    }

    /// The shipped default is not attacker-mintable, so it must stay silent —
    /// an advisory that fires for everyone teaches operators to ignore it.
    #[test]
    fn mintable_key_advisory_is_silent_for_the_default_ip_mode() {
        assert_eq!(RateLimitConfig::default().key, RateLimitKeyMode::Ip);
        let out = captured_advisory(RateLimitKeyMode::Ip);
        assert!(
            out.trim().is_empty(),
            "default `ip` mode must emit nothing, got: {out}"
        );
    }

    /// `ip_client_id` is partially mintable: it gets a note, deliberately at
    /// INFO rather than WARN (see `warn_on_mintable_key`'s rationale).
    #[test]
    fn mintable_key_advisory_notes_ip_client_id_at_info() {
        let out = captured_advisory(RateLimitKeyMode::IpClientId);
        assert!(
            out.contains("INFO"),
            "ip_client_id note must be INFO, got: {out}"
        );
        assert!(
            !out.contains("WARN"),
            "ip_client_id must not be raised to WARN — it would flatten a real \
             difference against `client_id` mode, got: {out}"
        );
        assert!(
            out.contains("ip_client_id") && out.contains("docs/deployment/rate-limit-sizing.md"),
            "must name the mode and point at the caveat, got: {out}"
        );
    }

    /// The classifier the advisory branches on, pinned independently of the
    /// emitter so a future key mode cannot be added without a decision.
    #[test]
    fn key_mode_mintability_is_pinned() {
        assert_eq!(RateLimitKeyMode::Ip.mintability(), KeyMintability::None);
        assert_eq!(
            RateLimitKeyMode::ClientId.mintability(),
            KeyMintability::Full
        );
        assert_eq!(
            RateLimitKeyMode::IpClientId.mintability(),
            KeyMintability::Partial
        );
    }
}

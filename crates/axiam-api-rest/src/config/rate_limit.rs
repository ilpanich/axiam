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
}

/// Deployment rate-limit **posture preset** (G7).
///
/// Environment variable: `AXIAM__RATE_LIMIT__PROFILE` = `internet` |
/// `gateway` | `mesh` (default `internet`).
///
/// **Why a preset instead of new defaults.** Benchmark run 3 measured that
/// the shipped defaults (`token 20/min`, `introspect 10/min`,
/// `revoke 10/min`, `authz_check 300/min`, all keyed per-IP) flatten a
/// 50-VU single-source-IP load to ~0–14 req/s at ~100% `429`, while the
/// same 2-core server sustains ~1 800 token issuances/s and ~740–2 300
/// authz checks/s. Those defaults are *correct* for a small
/// internet-facing deployment and *wrong* for an M2M/NAT'd fleet where
/// many OAuth2 clients share one egress IP. Rather than silently weaken
/// the internet-facing abuse posture for everyone, the M2M sizing is an
/// **opt-in preset**: one env var moves the whole machine-traffic family
/// coherently (key mode + token/introspect/revoke/authz + the gRPC authz
/// ceiling), and the shipped defaults are byte-for-byte unchanged.
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
    /// Max oauth2/token requests per minute per client (default: 20).
    pub token_per_min: u32,
    /// Max password-reset requests per minute per IP (default: 3).
    pub password_reset_per_min: u32,
    /// Max MFA requests per minute per IP (default: 5).
    /// Covers /auth/mfa/enroll, /confirm, /verify, /setup/enroll, /setup/confirm (SEC-020).
    pub mfa_per_min: u32,
    /// Max oauth2/introspect requests per minute per IP (default: 10).
    /// SEC-020: introspect endpoint rate-limited to prevent token probing.
    pub introspect_per_min: u32,
    /// Max oauth2/revoke requests per minute per IP (default: 10).
    /// SEC-020: revoke endpoint rate-limited to prevent DoS via token flooding.
    pub revoke_per_min: u32,
    /// Max authz-check requests per minute per IP (default: 300).
    /// Authz checks are read-only and high-frequency — used by UI permission gating.
    /// Kept in a dedicated bucket so heavy UI use does not consume the login/token limit (D-07).
    pub authz_check_per_min: u32,
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
            login_per_min: 10,
            register_per_min: 5,
            token_per_min: 20,
            password_reset_per_min: 3,
            mfa_per_min: 5,
            introspect_per_min: 10,
            revoke_per_min: 10,
            authz_check_per_min: 300,
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
    /// column in its §6 recommended-settings table. Checked opportunistically
    /// (the file is owned by the benchmark harness, not this crate).
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
            ("AXIAM__RATE_LIMIT__LOGIN_PER_MIN", d.login_per_min),
            ("AXIAM__RATE_LIMIT__REGISTER_PER_MIN", d.register_per_min),
            (
                "AXIAM__RATE_LIMIT__PASSWORD_RESET_PER_MIN",
                d.password_reset_per_min,
            ),
            ("AXIAM__RATE_LIMIT__MFA_PER_MIN", d.mfa_per_min),
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
                "AXIAM__RATE_LIMIT__LOGIN_PER_MIN",
                "AXIAM__RATE_LIMIT__REGISTER_PER_MIN",
                "AXIAM__RATE_LIMIT__PASSWORD_RESET_PER_MIN",
                "AXIAM__RATE_LIMIT__MFA_PER_MIN",
            ] {
                assert_eq!(
                    documented_u32(&table, env, column),
                    documented_u32(&table, env, 0),
                    "{POSTURE_DOC}: {profile:?} must not change the human endpoint {env}"
                );
            }
        }
    }

    /// The published benchmark analysis (§6 "Recommended settings by
    /// deployment") repeats the shipped defaults in its own table; run 3's
    /// publishing guidance requires those to stay in sync with code. The file
    /// belongs to the benchmark harness, so a missing file is tolerated — a
    /// *wrong* value is not.
    #[test]
    fn public_benchmark_doc_shipped_defaults_match_code() {
        let path = repo_root().join(PUBLIC_BENCH_DOC);
        let Ok(md) = std::fs::read_to_string(&path) else {
            eprintln!("{PUBLIC_BENCH_DOC} not present — skipping cross-doc drift check");
            return;
        };
        let d = RateLimitConfig::default();
        let expected: HashMap<&str, String> = HashMap::from([
            (ENV_KEY, d.key.as_str().to_owned()),
            (ENV_TOKEN_PER_MIN, d.token_per_min.to_string()),
            (ENV_INTROSPECT_PER_MIN, d.introspect_per_min.to_string()),
            (ENV_AUTHZ_CHECK_PER_MIN, d.authz_check_per_min.to_string()),
            (
                "AXIAM__RATE_LIMIT__LOGIN_PER_MIN",
                d.login_per_min.to_string(),
            ),
        ]);

        let mut checked = 0usize;
        for line in md.lines() {
            let line = line.trim();
            if !line.starts_with("| `AXIAM__RATE_LIMIT__") {
                continue;
            }
            let cells = cells(line);
            let Some(want) = expected.get(cells[0].as_str()) else {
                continue;
            };
            // The §6 "Shipped default" column is prose-decorated
            // (e.g. "10 (per IP)"); compare on the leading token only.
            let got = cells
                .get(1)
                .map(|c| {
                    c.split_whitespace()
                        .next()
                        .unwrap_or("")
                        .trim_matches('`')
                        .to_owned()
                })
                .unwrap_or_default();
            assert_eq!(
                &got, want,
                "{PUBLIC_BENCH_DOC} §6 shipped default for {} disagrees with \
                 RateLimitConfig::default()",
                cells[0]
            );
            checked += 1;
        }
        assert!(
            checked >= expected.len(),
            "{PUBLIC_BENCH_DOC}: only matched {checked} of {} rate-limit rows — \
             §6 table format changed?",
            expected.len()
        );
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
}

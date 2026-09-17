//! Security settings model with org/tenant inheritance.
//!
//! Organizations set a security baseline. Tenants may override
//! settings, but only to be **more restrictive** (never weaker).
//! The effective settings for a tenant = org baseline merged with
//! tenant overrides.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AxiamError, AxiamResult};
use crate::models::opaque::{
    OpaqueKsf, OpaqueMode, OpaqueSuite, opaque_ksf_is_at_least, opaque_suite_is_at_least,
};
use crate::models::webauthn_policy::{WebauthnUserVerification, user_verification_is_at_least};

// -----------------------------------------------------------------------
// Sub-policy structs
// -----------------------------------------------------------------------

/// Password complexity and history requirements.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PasswordPolicy {
    pub min_length: u32,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digits: bool,
    pub require_symbols: bool,
    pub password_history_count: u32,
    pub hibp_check_enabled: bool,
}

/// Multi-factor authentication policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MfaPolicy {
    pub mfa_enforced: bool,
    pub mfa_challenge_lifetime_secs: u64,
}

/// Account lockout rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LockoutPolicy {
    pub max_failed_login_attempts: u32,
    pub lockout_duration_secs: u64,
    pub lockout_backoff_multiplier: f64,
    pub max_lockout_duration_secs: u64,
}

/// Token lifetime configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TokenPolicy {
    pub access_token_lifetime_secs: u64,
    pub refresh_token_lifetime_secs: u64,
}

/// Email verification requirements.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EmailVerificationPolicy {
    pub email_verification_required: bool,
    pub email_verification_grace_period_hours: u32,
}

/// Certificate issuance constraints.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CertificatePolicy {
    pub default_cert_validity_days: u32,
    pub max_cert_validity_days: u32,
}

/// Admin notification preferences.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NotificationPolicy {
    pub admin_notifications_enabled: bool,
}

/// Data-retention rules that apply after a subject asks to be erased.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PrivacyPolicy {
    /// How long a requested account erasure stays cancellable before the purge
    /// runs, in days.
    ///
    /// The window exists so an erasure triggered by mistake, or under
    /// coercion, can be undone — `POST /api/v1/auth/account/delete/cancel`
    /// works for exactly this long. It was fixed at 30 days in the handler,
    /// which meant the "cancel a pending deletion" control in the admin UI
    /// referred to a duration no operator could see or change.
    ///
    /// Shorter is the more restrictive direction, so a tenant may lower it and
    /// not raise it: it is time spent holding data the subject has already
    /// asked to have erased, and GDPR Art. 17(1) asks for that to be
    /// "without undue delay". The upper bound of 90 days is where Art. 12(3)'s
    /// one-month response deadline plus its two-month extension for complex
    /// cases runs out; anything past 30 wants a reason recorded.
    pub deletion_grace_period_days: u32,
}

/// Secure Remote Password policy.
///
/// `suite` and `ksf` are the parameters a *new* registration record is enrolled
/// with. They deliberately do not apply retroactively: an existing record is
/// only valid under the suite and KSF it was created with, so tightening these
/// takes effect as users next set a password rather than invalidating
/// everybody at once.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OpaquePolicy {
    /// Whether OPAQUE is offered, and whether password login is still accepted.
    #[schema(value_type = String, example = "disabled")]
    pub opaque_mode: OpaqueMode,
    /// RFC 9807 ciphersuite new records are enrolled under.
    #[schema(value_type = String, example = "ristretto255_sha512")]
    pub opaque_suite: OpaqueSuite,
    /// Key-stretching function new records are enrolled under. Both variants
    /// are memory-hard; see [`opaque_ksf_is_at_least`] for the tighten-only
    /// ordering.
    #[schema(value_type = String, example = "argon2id")]
    pub opaque_ksf: OpaqueKsf,
}

/// WebAuthn ceremony policy.
///
/// One field today. It is a struct rather than a bare field on
/// [`SecuritySettings`] so that the next WebAuthn control has an obvious home,
/// and so the admin UI can group them.
///
/// The *attestation* policy is deliberately not here: it lives in
/// [`crate::models::webauthn_policy::WebauthnAttestationPolicy`], is
/// tenant-only, and cannot join this model because AAGUID allow/block lists
/// have no "more restrictive than" ordering to validate an override against.
/// User verification does, so it can.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct WebauthnPolicy {
    /// How hard the authenticator must prove *who* is present.
    ///
    /// Applies to enrolment and to second-factor authentication. Usernameless
    /// sign-in is held to `required` whatever this says — see
    /// [`WebauthnUserVerification`].
    #[schema(value_type = String, example = "preferred")]
    pub webauthn_user_verification: WebauthnUserVerification,
}

/// Whether, and on what terms, a client may register itself through
/// RFC 7591 dynamic client registration (T21.4).
///
/// Three values rather than a `bool` plus a second `bool`, because the middle
/// one is the whole point: a deployment that wants MCP Inspector to register
/// itself during a demonstration and a deployment that wants Claude Code to
/// register itself in production want different things, and the difference is
/// whether an administrator handed out a credential first.
///
/// [`Disabled`](Self::Disabled) is the serde default and the system default
/// (I1). `POST /oauth2/register` exists on every deployment and answers `403`
/// on every one that has not chosen otherwise — the path is there, the feature
/// is not, and a scanner learns nothing from the difference because there is
/// none to learn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DynamicRegistrationMode {
    /// No self-registration. Every client is an administrator's decision,
    /// which is what every AXIAM deployment does today.
    #[default]
    Disabled,
    /// Self-registration, but only for a caller presenting a single-use
    /// initial access token minted by `POST /oauth2-clients/registration-tokens`.
    /// RFC 7591 §1.2's "protected" profile: the endpoint is open, the act is
    /// not.
    InitialAccessToken,
    /// Self-registration by anybody who can reach the endpoint. RFC 7591 §1.2's
    /// "open" profile, and the one MCP Inspector and the desktop clients
    /// actually use. Refused while
    /// [`OidcPolicy::external_client_allowed_resources`] is empty — see D3.
    Anonymous,
}

impl DynamicRegistrationMode {
    /// The stored/wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::InitialAccessToken => "initial_access_token",
            Self::Anonymous => "anonymous",
        }
    }

    /// Parse a stored/wire value. `None` for anything unrecognised, for the
    /// reason `ClientProfile::from_wire` gives: a typo that degraded to a
    /// permissive default would open an unauthenticated write endpoint.
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "disabled" => Some(Self::Disabled),
            "initial_access_token" => Some(Self::InitialAccessToken),
            "anonymous" => Some(Self::Anonymous),
            _ => None,
        }
    }

    /// Whether the endpoint does anything at all on this policy.
    pub const fn is_enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// How permissive this mode is, for the tenant-override ordering.
    ///
    /// The only field of [`OidcPolicy`] added by T21.4 that *has* a
    /// restrictiveness: `disabled` refuses everybody, `anonymous` refuses
    /// nobody, and `initial_access_token` sits between them because the set of
    /// callers it admits is a subset of `anonymous`'s and a superset of
    /// `disabled`'s. A tenant may move down this ladder and never up.
    const fn permissiveness(self) -> u8 {
        match self {
            Self::Disabled => 0,
            Self::InitialAccessToken => 1,
            Self::Anonymous => 2,
        }
    }
}

impl std::fmt::Display for DynamicRegistrationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether `tenant` admits no more callers than `org` does.
pub const fn dynamic_registration_is_at_most(
    tenant: DynamicRegistrationMode,
    org: DynamicRegistrationMode,
) -> bool {
    tenant.permissiveness() <= org.permissiveness()
}

/// How many self-registered clients a tenant may hold when nothing says
/// otherwise (T21.4).
///
/// A ceiling rather than no ceiling because `dynamic_registration: anonymous`
/// is an unauthenticated write endpoint, and the only thing standing between
/// it and an unbounded table is this number and the per-IP rate limit. Twenty
/// is enough for every MCP client a tenant's people actually run and small
/// enough that hitting it is a signal rather than a milestone.
pub const DEFAULT_DCR_MAX_CLIENTS: u32 = 20;

/// How long a self-registered client survives without being authorized, in
/// days, when nothing says otherwise (T21.4).
///
/// Thirty days: long enough that a client somebody uses monthly is not swept
/// out from under them, short enough that a registration made once by a tool
/// nobody kept does not sit in the table forever. The sweeper only ever
/// touches `managed_by: dcr` rows — see `OAuth2Client::managed_by`.
pub const DEFAULT_DCR_UNUSED_CLIENT_TTL_DAYS: u32 = 30;

/// How long a self-registered client that was **never authorized** survives,
/// in seconds (T21.8 / MCP-05). One hour.
///
/// # Why a second clock at all
///
/// [`DEFAULT_DCR_UNUSED_CLIENT_TTL_DAYS`] is sized, in its own doc comment,
/// for "a client somebody uses monthly". A client registered and never
/// authorized is not that client: every MCP client Phase 21 exists to serve —
/// Inspector, Claude Code, VS Code — authorizes within seconds of registering,
/// because registration is the first step of the same flow. A never-authorized
/// row that is an hour old is either abandoned or hostile.
///
/// One TTL was serving two situations that have nothing in common, and that is
/// what made [`OidcPolicy::dcr_max_clients`] an *availability* budget as well
/// as a storage one: in `anonymous` mode a stranger could fill the quota in
/// about four minutes and hold it for thirty days. The sweeper could always
/// tell the two situations apart with no new data, because the row carries
/// `last_authorized_at: None` — so the fix is a second clock rather than a
/// bigger quota.
///
/// # Why a constant rather than a tenant setting
///
/// **Every other sweep window in AXIAM is a tenant setting, and this one
/// should be too.** The owner of the decision is the tenant, not the
/// datastore, which is the argument the sweeper's own doc comment makes about
/// [`DEFAULT_DCR_UNUSED_CLIENT_TTL_DAYS`]; and this is the one sweep that
/// deletes rows created by strangers, so it is the last window an operator
/// should be unable to see or change. The T21.8 fix plan's §4 recommends the
/// field for exactly those reasons and this constant is its stated fallback.
///
/// What the plan got wrong is the cost. Its §4 recorded "no migration —
/// `OidcPolicy` lives in the settings JSON; a missing key deserialises to the
/// default". That is true of [`OidcPolicy::cimd`], which is one
/// `oidc_cimd_json` column, and of the tenant override, which is
/// `overrides_json`. It is **not** true of `OidcPolicy`'s scalars: they are
/// individual columns on a `SCHEMAFULL` `security_settings` table
/// (`oidc_dcr_max_clients`, `oidc_dcr_unused_client_ttl_days`, both added by
/// migration v64), so a fifth DCR number is a `DEFINE FIELD`, a migration
/// v66 and a bump to the schema tripwire.
///
/// The field is therefore the maintainer's call and not this task's, and it is
/// one migration rather than one line away. Everything else about it is
/// already written here: the value, the mode gate, the sweeper's predicate and
/// its tests are identical either way, so promoting the constant to
/// `OidcPolicy::dcr_unauthorized_client_ttl_secs` is v66, eight mirrored
/// sites, an ordering map, a range check, the admin card and a spec
/// regeneration — and no change at all to the behaviour below.
pub const DCR_UNAUTHORIZED_CLIENT_TTL_SECS: u32 = 3_600;

/// OpenID Connect surface controls (X7 G8, plan §4.6/§4.8; T21.4).
///
/// Settings that are not password rules, here because this is the
/// org-baseline-plus-tenant-override surface every other per-tenant control
/// lives on. They are not all of the same kind as each other, and which is
/// which is the whole of what [`validate_tenant_override`] and
/// [`clamp_overrides_to_org`] read, so it is set out rather than inferred.
///
/// **Ordered** — a tenant may be stricter than its organization and never more
/// permissive:
///
/// * [`Self::sensitive_scopes_enabled`], validated **disable-only** — the
///   mirror image of `mfa_enforced`, because releasing personal data is the
///   less-restrictive direction, so a tenant can turn its organization's
///   decision off but never on.
/// * [`Self::dynamic_registration`], on the ladder
///   `disabled` → `initial_access_token` → `anonymous`: a tenant may move down
///   it and never up.
/// * [`Self::dcr_max_clients`] and [`Self::dcr_unused_client_ttl_days`], on the
///   ordinary `tenant <= org` rule — with the wrinkle that `0` on the second
///   means *never sweep*, which is the longest window of all and is handled by
///   [`dcr_ttl_strictness`].
///
/// **Not ordered**, therefore never validated against the baseline and never
/// clamped:
///
/// * [`Self::default_locale`]. A language is a presentation preference; there
///   is no sense in which Italian is stricter than French.
/// * [`Self::dcr_allowed_scopes`], [`Self::dcr_allowed_redirect_hosts`] and
///   [`Self::external_client_allowed_resources`]. Each names per-tenant
///   resources — *this* tenant's MCP servers, *this* tenant's callback hosts —
///   and there is no sense in which one such list is stricter than another. A
///   subset rule would force an organization to enumerate every tenant's
///   resource servers in its own baseline before any tenant could name one.
///
/// The model's rule is "a tenant may only be more restrictive", which binds
/// every field that *has* a restrictiveness; a field that has none cannot
/// violate it.
///
/// One cross-field interlock spans both groups and is checked on the resolved
/// policy rather than on either input: see [`validate_dcr_policy`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OidcPolicy {
    /// Whether `address` and `phone` may be registered on a client, requested
    /// at the authorization endpoint, and released at UserInfo (X7 G8).
    ///
    /// **Off unless an organization turns it on.** The two scopes release a
    /// postal address and a telephone number — categories of personal data
    /// AXIAM has no other use for — so the deployment that has never thought
    /// about them releases nothing, and the operator who has thought about
    /// them says so once, at the organization level, where the lawful basis
    /// for holding the data was decided.
    ///
    /// The switch is a *capability*, not a grant: with it on, a client still
    /// has to register the scope, the request still has to ask for it, and the
    /// user still has to have consented. It is the first of four gates, and it
    /// is the only one an operator can close for everybody at once.
    pub sensitive_scopes_enabled: bool,
    /// The BCP 47 tag the sign-in page falls back to when the relying party's
    /// `ui_locales` selects nothing (W5's chain, plan §4.6).
    ///
    /// `None` means "no tenant preference", which lands on the deployment
    /// default (`en`) — the behaviour every deployment had before this field
    /// existed. A tag this build does not ship also lands there: the parse is
    /// exact rather than a language lookup, so a stored `fr-CA` reads as
    /// "somebody wrote something this binary does not ship" rather than as a
    /// guess at French.
    ///
    /// Stored as a string rather than as the `Locale` enum because that enum
    /// lives in `axiam-oauth2`, four layers above this crate, and the crate
    /// layering points inward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_locale: Option<String>,
    /// T21.4 — whether a client may register itself (RFC 7591), and on what
    /// terms. `disabled` unless somebody says otherwise (I1).
    #[serde(default)]
    #[schema(value_type = String, example = "disabled")]
    pub dynamic_registration: DynamicRegistrationMode,
    /// T21.4 — the scopes a self-registered client may ask for. A `scope` a
    /// registration names that is not on this list is
    /// `invalid_client_metadata`; an empty list means a self-registered client
    /// gets no scopes at all, which is the honest default for a tenant that
    /// has turned registration on without deciding what it grants.
    ///
    /// May not contain `address` or `phone` — see this module's
    /// [`sensitive_scope_in_dcr_list`].
    #[serde(default)]
    pub dcr_allowed_scopes: Vec<String>,
    /// T21.4 — hosts a self-registered client's `redirect_uris` may point at,
    /// as globs (`*.example.com`, or `*` for any). The loopback hosts
    /// (`127.0.0.1`, `[::1]`, `localhost`) are always allowed whatever this
    /// says, because RFC 8252 §7.3 is how every desktop MCP client receives
    /// its callback and a tenant that forbade them would have turned
    /// registration on for nobody.
    #[serde(default)]
    pub dcr_allowed_redirect_hosts: Vec<String>,
    /// **D3** — the audiences an externally registered client may address.
    ///
    /// The single most important field on this policy, and the reason the
    /// settings handler refuses `dynamic_registration: anonymous` while it is
    /// empty. A client an unrelated party registered cannot declare its own
    /// `allowed_resources`; it inherits this list verbatim, so what a stranger
    /// can mint a token *for* is a decision the tenant took in advance rather
    /// than one the registration request makes.
    ///
    /// Empty means an externally registered client can obtain only today's
    /// `axiam:user` tokens — which AXIAM's own APIs accept. That is why the
    /// interlock exists: the empty list is not a safe default for an *open*
    /// registration endpoint, it is the most dangerous one.
    ///
    /// Shared with T5 (CIMD), which inherits the same list for the same
    /// reason.
    #[serde(default)]
    pub external_client_allowed_resources: Vec<String>,
    /// T21.4 — how many externally registered clients this tenant may hold.
    /// See [`DEFAULT_DCR_MAX_CLIENTS`].
    ///
    /// **Counted once per mechanism, against the same number** (T21.8):
    /// `managed_by: dcr` rows and `managed_by: cimd` rows each have this many.
    /// So a tenant running both cannot have shadow rows materialised from
    /// documents exhaust the allowance for self-registration, or the reverse.
    /// The CIMD count is checked *before* the document is fetched, so a tenant
    /// at its ceiling is not an outbound amplifier either. It keeps its `dcr_`
    /// name because dynamic registration defined it, on the same precedent as
    /// [`Self::dcr_allowed_scopes`].
    #[serde(default = "default_dcr_max_clients")]
    #[schema(example = 20)]
    pub dcr_max_clients: u32,
    /// T21.4 — how long an externally registered client survives without
    /// being used. See [`DEFAULT_DCR_UNUSED_CLIENT_TTL_DAYS`]. `0` disables
    /// the sweep for this tenant, which an operator who prunes out of band
    /// may legitimately want.
    ///
    /// **Two sweeps read it, over different clocks** (T21.8). A
    /// `managed_by: dcr` row is measured from its last authorization, falling
    /// back to when it was registered. A `managed_by: cimd` row is measured
    /// from the last time its document was *presented*, which every authorize,
    /// token and PAR request moves — so a document in daily use is never swept
    /// however old its registration is, and one nobody has presented since the
    /// window is, and re-materialises on the next request if it is still
    /// published. Like the ceiling, it keeps its `dcr_` name.
    #[serde(default = "default_dcr_unused_client_ttl_days")]
    #[schema(example = 30)]
    pub dcr_unused_client_ttl_days: u32,
    /// T21.5 — whether a URL-shaped `client_id` is resolved by fetching the
    /// document it names, and on what terms. See [`CimdPolicy`]; off unless
    /// somebody turns it on (I1).
    ///
    /// Nested, and therefore inherited or overridden **whole**: the fields are
    /// terms of one decision, and a half-merged posture is one neither the
    /// organization nor the tenant wrote.
    #[serde(default)]
    pub cimd: CimdPolicy,
}

/// See [`DEFAULT_DCR_MAX_CLIENTS`]. A function because `serde(default = ..)`
/// takes one, and because a settings row written before T21.4 must decode to
/// the shipped ceiling rather than to `0` — which would read as "no
/// self-registered client may exist" on a tenant that never made a decision.
fn default_dcr_max_clients() -> u32 {
    DEFAULT_DCR_MAX_CLIENTS
}

/// See [`DEFAULT_DCR_UNUSED_CLIENT_TTL_DAYS`], and
/// [`default_dcr_max_clients`] for why this is a function.
fn default_dcr_unused_client_ttl_days() -> u32 {
    DEFAULT_DCR_UNUSED_CLIENT_TTL_DAYS
}

/// How strict a `dcr_unused_client_ttl_days` value is, as a number that
/// increases with permissiveness (T21.4).
///
/// `0` means "never sweep", which is the **most** permissive value and not the
/// least — an unused self-registered client kept forever is exactly what the
/// TTL exists to prevent. A plain `tenant <= org` comparison would therefore
/// have read `0` as the strictest possible override and let a tenant turn the
/// sweeper off under an organization that had turned it on. Mapping `0` to the
/// top of the range is what makes the ordinary comparison mean what it says.
const fn dcr_ttl_strictness(days: u32) -> u32 {
    if days == 0 { u32::MAX } else { days }
}

/// Everything wrong with a resolved dynamic-registration policy, as operator
/// sentences (T21.4).
///
/// A function of the **effective** policy rather than of an input, because
/// both ways in produce one: an organization baseline is a policy, and a
/// tenant override merged onto its baseline is a policy. The interlock this
/// enforces would be trivially bypassable otherwise — a tenant that set
/// `anonymous` while inheriting an empty
/// [`OidcPolicy::external_client_allowed_resources`] from its organization
/// would pass a check that only looked at what the request carried.
///
/// # The D3 interlock
///
/// `anonymous` registration with an empty `external_client_allowed_resources`
/// is refused. This is a security control, not a validation nicety. An
/// externally registered client inherits that list as its
/// `allowed_resources`, and an empty one leaves it able to obtain only
/// `axiam:user` tokens — the audience **AXIAM's own APIs accept**. So the
/// combination is not "a registration endpoint that grants nothing"; it is an
/// unauthenticated endpoint that mints clients able to ask for tokens against
/// AXIAM itself. The operator has to name the MCP servers this tenant fronts
/// before strangers may register for them.
///
/// `initial_access_token` is deliberately **not** interlocked: a caller there
/// presented a credential an administrator minted, so an administrator has
/// already decided this registration should happen, and a deployment that
/// wants exactly today's `axiam:user` behaviour for a hand-issued client is
/// making a choice rather than leaving a door open.
pub fn validate_dcr_policy(oidc: &OidcPolicy) -> Vec<String> {
    let mut violations = Vec::new();

    if oidc.dynamic_registration == DynamicRegistrationMode::Anonymous
        && oidc.external_client_allowed_resources.is_empty()
    {
        violations.push(
            "dynamic_registration: anonymous registration cannot be enabled while \
             external_client_allowed_resources is empty (D3). A client registered by an \
             unrelated party inherits that list as its allowed_resources, and an empty list \
             leaves it able to obtain only the axiam:user tokens AXIAM's own APIs accept. \
             Name the MCP servers this tenant fronts first"
                .into(),
        );
    }

    if let Some(scope) = sensitive_scope_in_dcr_list(&oidc.dcr_allowed_scopes) {
        violations.push(format!(
            "dcr_allowed_scopes: {scope} releases personal data under W7's per-client consent \
             record and cannot be offered to a self-registered client, which already carries a \
             forced consent record of its own (D4). Register a client for it through \
             POST /oauth2-clients instead"
        ));
    }

    violations
}

/// The GDPR-sensitive scope a `dcr_allowed_scopes` list names, if it names one
/// (T21.4 amendment 1).
///
/// W7 gates `address` and `phone` behind a consent record per relying party,
/// and D4 gates every externally registered client behind a consent record of
/// its own. Both records live in the `oidc_scope_release:<client_id>`
/// namespace, so a self-registered client holding `address` would need two of
/// them — two consent screens for one authorization, or one record standing
/// for the other while the UserInfo gate, which re-reads the sensitive record
/// on every call, releases nothing anyway.
///
/// Refusing the combination is also the answer D3's reasoning points at on its
/// own: a party that registered itself, unauthenticated, must not be able to
/// *ask* for a postal address, whatever the tenant's sensitive-scope switch
/// says.
///
/// The two names are written here rather than taken from
/// `axiam_oauth2::sensitive::SENSITIVE_SCOPES` because that constant lives
/// four layers out and this crate is layer 0. `axiam-oauth2`'s own test
/// asserts the two lists agree.
pub fn sensitive_scope_in_dcr_list(scopes: &[String]) -> Option<&str> {
    scopes
        .iter()
        .find(|s| matches!(s.trim(), "address" | "phone"))
        .map(String::as_str)
}

// -----------------------------------------------------------------------
// Client ID Metadata Documents (T21.5)
// -----------------------------------------------------------------------

/// The shortest cache lifetime a tenant may give a client metadata document,
/// in seconds.
///
/// A bound rather than a preference. The document is fetched from a URL an
/// **unauthenticated** caller chooses, so the cache lifetime is what stands
/// between one authorization request and one outbound HTTP request: a tenant
/// that set it to zero would have turned its authorization endpoint into a
/// request amplifier pointed at whatever host is on its trusted list. Sixty
/// seconds is the floor; the shipped default is five minutes.
pub const CIMD_MIN_CACHE_FLOOR_SECS: u64 = 60;

/// The longest cache lifetime a tenant may give a client metadata document,
/// in seconds (seven days).
///
/// The other end of the same control. A cached document is a *live client
/// registration* that nobody at this deployment created, so the ceiling is the
/// longest a stranger may pin one for after taking their document down. Seven
/// days is an upper bound on the tenant's own `max_cache_secs`, whose shipped
/// default is three.
pub const CIMD_MAX_CACHE_CEILING_SECS: u64 = 604_800;

/// The largest `max_metadata_bytes` a tenant may configure (64 KiB).
///
/// An unbounded read of an attacker-chosen URL is a memory-exhaustion
/// primitive, and a tenant-configurable cap with no ceiling is an unbounded
/// read with extra steps. A client metadata document that does not fit in
/// 64 KiB is not a client metadata document; the shipped default is 5 000
/// bytes, which is the draft's own suggestion and roughly ten times what a
/// real one weighs.
pub const CIMD_MAX_METADATA_BYTES_CEILING: u64 = 65_536;

/// The shipped cache bounds and size cap. See [`CimdPolicy`].
pub const DEFAULT_CIMD_MIN_CACHE_SECS: u64 = 300;
/// See [`DEFAULT_CIMD_MIN_CACHE_SECS`].
pub const DEFAULT_CIMD_MAX_CACHE_SECS: u64 = 259_200;
/// See [`DEFAULT_CIMD_MIN_CACHE_SECS`].
pub const DEFAULT_CIMD_MAX_METADATA_BYTES: u64 = 5_000;

/// Whether, and on what terms, a `client_id` that is a URL is resolved by
/// fetching the document it names (T21.5,
/// `draft-ietf-oauth-client-id-metadata-document`).
///
/// # Why this is one nested policy rather than nine fields
///
/// Every field here is a term of a single decision — *do we fetch a stranger's
/// URL and make a client out of what comes back* — and none of them means
/// anything without [`Self::enabled`]. A tenant that states a CIMD posture
/// states all of it; a tenant that states none inherits its organization's
/// whole posture rather than half of one, which is the only merge that cannot
/// produce a combination neither party wrote.
///
/// # The two fields that can widen, and the seven that cannot
///
/// [`Self::enabled`] and [`Self::allow_http`] are **ordered**: a tenant may
/// turn either off but never on, exactly as `dynamic_registration` may only
/// move down its ladder. Everything else names *this tenant's* domains or
/// *this tenant's* bounds, and there is no sense in which one tenant's list of
/// trusted publishers is stricter than another's — the same argument
/// [`OidcPolicy`] already makes for `dcr_allowed_redirect_hosts`.
///
/// # Every bound here is a security control
///
/// [`Self::max_metadata_bytes`], [`Self::min_cache_secs`] and
/// [`Self::max_cache_secs`] are not tuning knobs. They are, respectively, the
/// ceiling on a read from an attacker-chosen URL, the floor under how often
/// that read may be repeated, and the ceiling on how long its result may be
/// trusted. Each is clamped again in code against the three constants above,
/// so a settings row written by hand cannot lift them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CimdPolicy {
    /// **Off unless somebody turns it on** (I1). With this `false`, a
    /// URL-shaped `client_id` is exactly today's unknown client: nothing is
    /// fetched, nothing is materialised, and the ordinary repository lookup
    /// answers as it always has.
    #[serde(default)]
    pub enabled: bool,
    /// Permit an `http://` `client_id` and an `http://` fetch.
    ///
    /// **Development only, and it does more than its name says.** AXIAM's
    /// shared SSRF guard couples the scheme rule to the address rule — the
    /// same seam that lets an integration test point a fetch at a loopback
    /// mock server — so a tenant that allows `http` also allows the first hop
    /// to resolve to a private address. Redirect hops are validated strictly
    /// whatever this says, and a public deployment that sets it has removed
    /// the control that makes `169.254.169.254` unreachable.
    #[serde(default)]
    pub allow_http: bool,
    /// The hosts whose documents this tenant will fetch at all, as globs
    /// (`mcp.example.com`, or `*.example.com` for every host under one
    /// domain).
    ///
    /// **An empty list resolves nothing**, and enabling CIMD while it is empty
    /// is refused — see [`validate_cimd_policy`]. That is a deliberate
    /// departure from "a URL is a client identifier, so any URL will do": the
    /// fetch is triggered by an unauthenticated request naming the URL, so an
    /// unrestricted list is a request-forgery primitive offered to strangers,
    /// bounded only by the SSRF guard's address rules. Naming the publishers a
    /// tenant actually fronts costs one settings field and removes the class.
    ///
    /// **`*` is refused here, and so is a wildcard over a whole top-level
    /// domain** (`*.com`): both are the posture the empty list is refused for,
    /// spelled differently, and a control with no second control behind it
    /// cannot have a one-character bypass and still be the control. It is a
    /// floor and not a public-suffix check — `*.github.io` passes, and
    /// trusting shared hosting stays the operator's decision, bounded by the
    /// per-tenant quota rather than by this field. `*` remains valid in
    /// [`CimdPolicy::trusted_redirect_domains`], whose entries are not fetch
    /// targets.
    #[serde(default)]
    pub trusted_client_id_domains: Vec<String>,
    /// The hosts a document's `redirect_uris` may point at, as globs.
    ///
    /// The loopback hosts (`127.0.0.1`, `[::1]`, `localhost`) are always
    /// allowed, because RFC 8252 §7.3 is how every desktop MCP client receives
    /// its callback — so an empty list is not a refusal of everything, it is
    /// "loopback only", which is exactly the Claude Code and VS Code profile.
    #[serde(default)]
    pub trusted_redirect_domains: Vec<String>,
    /// Require every `redirect_uris` host in the document to equal the host of
    /// the `client_id` URL itself.
    ///
    /// **On by default**, because the document says who the client is and a
    /// redirect to somewhere else is the one thing a stolen or mirrored
    /// document would want to change. It is turned **off** for the desktop MCP
    /// clients, whose callbacks are on loopback and therefore can never share
    /// a host with a `https://` `client_id`; `docs/admin/client-id-metadata-documents.md`
    /// says so and says why.
    #[serde(default = "default_true")]
    pub restrict_same_domain: bool,
    /// Refuse a document whose `token_endpoint_auth_method` is `none`.
    ///
    /// Off by default, because `none` is what every MCP desktop client is. A
    /// tenant that turns it on accepts only `private_key_jwt` documents, which
    /// is the posture for a deployment whose CIMD clients are servers rather
    /// than desktops.
    #[serde(default)]
    pub confidential_only: bool,
    /// The floor under a document's cache lifetime, in seconds. Clamped to
    /// [`CIMD_MIN_CACHE_FLOOR_SECS`].
    #[serde(default = "default_cimd_min_cache_secs")]
    #[schema(example = 300)]
    pub min_cache_secs: u64,
    /// The ceiling on a document's cache lifetime, in seconds. Clamped to
    /// [`CIMD_MAX_CACHE_CEILING_SECS`].
    #[serde(default = "default_cimd_max_cache_secs")]
    #[schema(example = 259_200)]
    pub max_cache_secs: u64,
    /// The hard cap on how many bytes of a document are read, before it is
    /// parsed. Clamped to [`CIMD_MAX_METADATA_BYTES_CEILING`].
    #[serde(default = "default_cimd_max_metadata_bytes")]
    #[schema(example = 5_000)]
    pub max_metadata_bytes: u64,
}

impl Default for CimdPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_http: false,
            trusted_client_id_domains: Vec::new(),
            trusted_redirect_domains: Vec::new(),
            restrict_same_domain: true,
            confidential_only: false,
            min_cache_secs: DEFAULT_CIMD_MIN_CACHE_SECS,
            max_cache_secs: DEFAULT_CIMD_MAX_CACHE_SECS,
            max_metadata_bytes: DEFAULT_CIMD_MAX_METADATA_BYTES,
        }
    }
}

impl CimdPolicy {
    /// The cache lifetime to give a document that advertised `advertised`
    /// seconds, or that advertised nothing (`None`).
    ///
    /// Clamped twice: once to this tenant's own bounds, and once to the
    /// deployment constants, so neither a hostile `Cache-Control` nor a
    /// hand-edited settings row can push it out of range. A document that
    /// advertises nothing gets the floor rather than the ceiling — the least
    /// trust for the least information.
    pub fn clamp_cache_secs(&self, advertised: Option<u64>) -> u64 {
        let floor = self.min_cache_secs.max(CIMD_MIN_CACHE_FLOOR_SECS);
        let ceiling = self
            .max_cache_secs
            .min(CIMD_MAX_CACHE_CEILING_SECS)
            .max(floor);
        advertised.unwrap_or(floor).clamp(floor, ceiling)
    }

    /// The byte cap to read this tenant's documents with, clamped to
    /// [`CIMD_MAX_METADATA_BYTES_CEILING`]. Zero is read as the shipped
    /// default rather than as "read nothing", which no operator means.
    pub fn effective_max_metadata_bytes(&self) -> usize {
        let raw = if self.max_metadata_bytes == 0 {
            DEFAULT_CIMD_MAX_METADATA_BYTES
        } else {
            self.max_metadata_bytes
        };
        usize::try_from(raw.min(CIMD_MAX_METADATA_BYTES_CEILING))
            .unwrap_or(DEFAULT_CIMD_MAX_METADATA_BYTES as usize)
    }
}

/// `serde(default)` cannot name a literal `true`.
fn default_true() -> bool {
    true
}

/// See [`DEFAULT_CIMD_MIN_CACHE_SECS`], and [`default_dcr_max_clients`] for
/// why these are functions.
fn default_cimd_min_cache_secs() -> u64 {
    DEFAULT_CIMD_MIN_CACHE_SECS
}

/// See [`DEFAULT_CIMD_MAX_CACHE_SECS`].
fn default_cimd_max_cache_secs() -> u64 {
    DEFAULT_CIMD_MAX_CACHE_SECS
}

/// See [`DEFAULT_CIMD_MAX_METADATA_BYTES`].
fn default_cimd_max_metadata_bytes() -> u64 {
    DEFAULT_CIMD_MAX_METADATA_BYTES
}

/// Everything wrong with a resolved CIMD policy, as operator sentences
/// (T21.5).
///
/// A function of the **effective** policy, for the reason
/// [`validate_dcr_policy`] gives: a tenant that enables CIMD while inheriting
/// an empty resource list from its organization is precisely the state the
/// first interlock exists to refuse.
///
/// # The two interlocks
///
/// **D3.** Enabling CIMD with an empty
/// [`OidcPolicy::external_client_allowed_resources`] is refused, word for word
/// the reasoning `dynamic_registration: anonymous` is refused for: a client
/// materialised from a stranger's document inherits that list as its
/// `allowed_resources`, and an empty list leaves it able to obtain only the
/// `axiam:user` tokens AXIAM's own APIs accept.
///
/// **The trusted-publisher list.** Enabling CIMD with an empty
/// [`CimdPolicy::trusted_client_id_domains`] is refused, because the fetch is
/// reachable by an unauthenticated caller who chooses the URL.
///
/// The rest are range checks, and they are here rather than left to the
/// clamping accessors so that an operator who writes an impossible bound is
/// told, rather than quietly given a different one.
pub fn validate_cimd_policy(oidc: &OidcPolicy) -> Vec<String> {
    let mut violations = Vec::new();
    let cimd = &oidc.cimd;

    if !cimd.enabled {
        // Nothing below can be reached by a request, so nothing below is
        // refused. A tenant may stage a CIMD policy before turning it on.
        return violations;
    }

    if oidc.external_client_allowed_resources.is_empty() {
        violations.push(
            "cimd.enabled: client ID metadata documents cannot be enabled while \
             external_client_allowed_resources is empty (D3). A client materialised from a \
             stranger's document inherits that list as its allowed_resources, and an empty \
             list leaves it able to obtain only the axiam:user tokens AXIAM's own APIs \
             accept. Name the MCP servers this tenant fronts first"
                .into(),
        );
    }

    if cimd.trusted_client_id_domains.is_empty() {
        violations.push(
            "cimd.trusted_client_id_domains: client ID metadata documents cannot be enabled \
             with no trusted publisher domain. The document is fetched because an \
             unauthenticated request named its URL, so an unrestricted list is an outbound \
             fetch a stranger chooses the target of. Name the hosts whose documents this \
             tenant accepts (globs are allowed: *.example.com)"
                .into(),
        );
    }

    // ...and the same refusal, for the spellings that mean the same thing.
    //
    // T21.8 / MCP-03. The refusal above was worth having for one reason: an
    // unrestricted trusted-publisher list is a request-forgery primitive
    // offered to strangers **and there is no second control that does that
    // job** — the SSRF guard bounds which addresses a fetch may reach, not
    // which hosts a caller may name. A control with no second control behind
    // it cannot have a one-character bypass and still be the control, and
    // `["*"]` was exactly that: refused as `[]`, admitted as `["*"]`, with the
    // validator's own entry-shape message forty lines down recommending the
    // spelling that produced it.
    //
    // A single-label wildcard suffix goes with it. `*.com` is `*` for one
    // top-level domain, spelled longer, and the honest statement of the
    // finding is "the list must name a publisher" rather than "the list must
    // not contain one particular character".
    //
    // **It is a floor, and it is stated as one.** This is not a public-suffix
    // check: `*.github.io` still passes, and so does `*.pages.dev`. Trusting
    // shared hosting remains the operator's decision to make, and what bounds
    // it is the per-tenant quota and the sweep, not this condition. If the
    // narrower fix is wanted — refuse `*` and nothing else — deleting the
    // `labels` arm below is one line and no test depends on it.
    //
    // `trusted_redirect_domains` keeps `*`, because those entries are not
    // fetch targets: they bound where a *document* may point a browser, the
    // loopback three are allowed whatever the list says, and an empty list is
    // a working posture there rather than a refusal.
    for entry in &cimd.trusted_client_id_domains {
        let e = entry.trim();
        let offence = if e == "*" {
            Some("matches every host")
        } else if let Some(suffix) = e.strip_prefix("*.")
            && !suffix.contains('*')
            && !suffix.is_empty()
            && suffix.split('.').count() == 1
        {
            Some("is a wildcard over a whole top-level domain")
        } else {
            None
        };
        if let Some(offence) = offence {
            violations.push(format!(
                "cimd.trusted_client_id_domains: {entry:?} {offence}, which is the posture an \
                 empty list is refused for. The document is fetched because an \
                 unauthenticated request named its URL, so the list has to name a publisher: \
                 a host (mcp.example.com) or a wildcard over one (*.example.com)"
            ));
        }
    }

    // A host glob, not a URL. `host_glob_matches` answers `false` for an entry
    // carrying a scheme, a path or a port, so a tenant that typed one would
    // have a trusted list that silently matches nothing — fail-closed, but
    // indistinguishable from a working list until somebody tries to sign in.
    //
    // The two fields get different advice, because `*` is valid in one of them
    // and refused in the other (above). Offering it here for
    // `trusted_client_id_domains` is what made the empty-list refusal
    // self-defeating in the first place.
    for (field, entries, forms) in [
        (
            "cimd.trusted_client_id_domains",
            &cimd.trusted_client_id_domains,
            "Write a host (mcp.example.com) or a leftmost-label wildcard over one \
             (*.example.com)",
        ),
        (
            "cimd.trusted_redirect_domains",
            &cimd.trusted_redirect_domains,
            "Write a host (app.example.com), a leftmost-label wildcard (*.example.com) or *",
        ),
    ] {
        for entry in entries {
            let e = entry.trim();
            if e.is_empty()
                || e.contains("://")
                || e.contains('/')
                || e.contains(':')
                || e.split_whitespace().count() != 1
            {
                violations.push(format!(
                    "{field}: {entry:?} is not a host pattern. {forms} — not a URL, a path or \
                     a host:port"
                ));
            }
        }
    }

    if cimd.min_cache_secs < CIMD_MIN_CACHE_FLOOR_SECS {
        violations.push(format!(
            "cimd.min_cache_secs ({}) must be >= {CIMD_MIN_CACHE_FLOOR_SECS}: the cache \
             lifetime is what stands between one authorization request and one outbound \
             fetch",
            cimd.min_cache_secs,
        ));
    }

    if cimd.max_cache_secs > CIMD_MAX_CACHE_CEILING_SECS {
        violations.push(format!(
            "cimd.max_cache_secs ({}) must be <= {CIMD_MAX_CACHE_CEILING_SECS}: a cached \
             document is a live client registration nobody here created",
            cimd.max_cache_secs,
        ));
    }

    if cimd.min_cache_secs > cimd.max_cache_secs {
        violations.push(format!(
            "cimd.min_cache_secs ({}) must be <= cimd.max_cache_secs ({})",
            cimd.min_cache_secs, cimd.max_cache_secs,
        ));
    }

    if cimd.max_metadata_bytes == 0 || cimd.max_metadata_bytes > CIMD_MAX_METADATA_BYTES_CEILING {
        violations.push(format!(
            "cimd.max_metadata_bytes ({}) must be between 1 and \
             {CIMD_MAX_METADATA_BYTES_CEILING}: an unbounded read of an attacker-chosen URL \
             is a memory-exhaustion primitive",
            cimd.max_metadata_bytes,
        ));
    }

    violations
}

// -----------------------------------------------------------------------
// Scope enum
// -----------------------------------------------------------------------

/// Whether a settings row belongs to an organization or a tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum SettingsScope {
    Org,
    Tenant,
}

impl std::fmt::Display for SettingsScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Org => write!(f, "org"),
            Self::Tenant => write!(f, "tenant"),
        }
    }
}

impl std::str::FromStr for SettingsScope {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "org" => Ok(Self::Org),
            "tenant" => Ok(Self::Tenant),
            other => Err(format!("invalid settings scope: {other}")),
        }
    }
}

// -----------------------------------------------------------------------
// Main domain type — fully resolved
// -----------------------------------------------------------------------

/// Fully resolved security settings (all fields present).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SecuritySettings {
    pub id: Uuid,
    pub scope: SettingsScope,
    pub scope_id: Uuid,
    pub password: PasswordPolicy,
    pub mfa: MfaPolicy,
    pub lockout: LockoutPolicy,
    pub token: TokenPolicy,
    pub email: EmailVerificationPolicy,
    pub certificate: CertificatePolicy,
    pub notification: NotificationPolicy,
    pub opaque: OpaquePolicy,
    pub privacy: PrivacyPolicy,
    pub webauthn: WebauthnPolicy,
    pub oidc: OidcPolicy,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// -----------------------------------------------------------------------
// Tenant override — all Option<T> for partial overrides
// -----------------------------------------------------------------------

/// Partial tenant overrides. `None` = inherit from org baseline.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TenantSettingsOverride {
    // Password
    pub min_length: Option<u32>,
    pub require_uppercase: Option<bool>,
    pub require_lowercase: Option<bool>,
    pub require_digits: Option<bool>,
    pub require_symbols: Option<bool>,
    pub password_history_count: Option<u32>,
    pub hibp_check_enabled: Option<bool>,
    // MFA
    pub mfa_enforced: Option<bool>,
    pub mfa_challenge_lifetime_secs: Option<u64>,
    // Lockout
    pub max_failed_login_attempts: Option<u32>,
    pub lockout_duration_secs: Option<u64>,
    pub lockout_backoff_multiplier: Option<f64>,
    pub max_lockout_duration_secs: Option<u64>,
    // Token
    pub access_token_lifetime_secs: Option<u64>,
    pub refresh_token_lifetime_secs: Option<u64>,
    // Email
    pub email_verification_required: Option<bool>,
    pub email_verification_grace_period_hours: Option<u32>,
    // Certificate
    pub default_cert_validity_days: Option<u32>,
    pub max_cert_validity_days: Option<u32>,
    // Notification
    pub admin_notifications_enabled: Option<bool>,
    // OPAQUE
    #[schema(value_type = Option<String>)]
    pub opaque_mode: Option<OpaqueMode>,
    #[schema(value_type = Option<String>)]
    pub opaque_suite: Option<OpaqueSuite>,
    #[schema(value_type = Option<String>)]
    pub opaque_ksf: Option<OpaqueKsf>,
    // Privacy
    pub deletion_grace_period_days: Option<u32>,
    // WebAuthn
    #[schema(value_type = Option<String>)]
    pub webauthn_user_verification: Option<WebauthnUserVerification>,
    // OIDC (X7 G8 / plan §4.6). Disable-only; see `OidcPolicy`.
    pub sensitive_scopes_enabled: Option<bool>,
    /// The tenant's fallback UI language. Not ordered, therefore not validated
    /// against the baseline and never clamped — see [`OidcPolicy`].
    pub default_locale: Option<String>,
    // Dynamic client registration (T21.4). Only `dynamic_registration`,
    // `dcr_max_clients` and `dcr_unused_client_ttl_days` are ordered; the
    // three lists are not, for the reason stated on `OidcPolicy`.
    #[schema(value_type = Option<String>)]
    pub dynamic_registration: Option<DynamicRegistrationMode>,
    pub dcr_allowed_scopes: Option<Vec<String>>,
    pub dcr_allowed_redirect_hosts: Option<Vec<String>>,
    pub external_client_allowed_resources: Option<Vec<String>>,
    pub dcr_max_clients: Option<u32>,
    pub dcr_unused_client_ttl_days: Option<u32>,
    /// T21.5 — the whole CIMD posture, or nothing. Only `enabled` and
    /// `allow_http` are ordered against the organization's; see [`CimdPolicy`].
    pub cimd: Option<CimdPolicy>,
}

impl TenantSettingsOverride {
    /// Returns `true` if every field is `None` (no overrides).
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

// -----------------------------------------------------------------------
// Input DTOs
// -----------------------------------------------------------------------

/// Input for setting organization-level security settings.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SetOrgSettings {
    // Password
    pub min_length: u32,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digits: bool,
    pub require_symbols: bool,
    pub password_history_count: u32,
    pub hibp_check_enabled: bool,
    // MFA
    pub mfa_enforced: bool,
    pub mfa_challenge_lifetime_secs: u64,
    // Lockout
    pub max_failed_login_attempts: u32,
    pub lockout_duration_secs: u64,
    pub lockout_backoff_multiplier: f64,
    pub max_lockout_duration_secs: u64,
    // Token
    pub access_token_lifetime_secs: u64,
    pub refresh_token_lifetime_secs: u64,
    // Email
    pub email_verification_required: bool,
    pub email_verification_grace_period_hours: u32,
    // Certificate
    pub default_cert_validity_days: u32,
    pub max_cert_validity_days: u32,
    // Notification
    pub admin_notifications_enabled: bool,
    // OPAQUE — defaulted so an existing API client that has never heard of
    // OPAQUE keeps working unchanged and lands on `disabled`.
    #[serde(default)]
    #[schema(value_type = String, example = "disabled")]
    pub opaque_mode: OpaqueMode,
    #[serde(default)]
    #[schema(value_type = String, example = "ristretto255_sha512")]
    pub opaque_suite: OpaqueSuite,
    #[serde(default)]
    #[schema(value_type = String, example = "argon2id")]
    pub opaque_ksf: OpaqueKsf,
    // Privacy — defaulted so a client written before the field keeps the
    // 30 days the erasure handler used to hard-code.
    #[serde(default = "default_deletion_grace_period_days")]
    #[schema(example = 30)]
    pub deletion_grace_period_days: u32,
    // WebAuthn — defaulted so a client written before the field lands on
    // `preferred`, which is also what an un-migrated row decodes to.
    #[serde(default)]
    #[schema(value_type = String, example = "preferred")]
    pub webauthn_user_verification: WebauthnUserVerification,
    // OIDC — defaulted so a client written before X7 G8 keeps releasing no
    // sensitive scope and expressing no locale preference, which is what every
    // deployment did before the fields existed.
    #[serde(default)]
    #[schema(example = false)]
    pub sensitive_scopes_enabled: bool,
    #[serde(default)]
    #[schema(example = "it")]
    pub default_locale: Option<String>,
    // Dynamic client registration (T21.4) — every one defaulted, so an API
    // client written before this task lands on `disabled` with empty lists,
    // which is what every deployment did before the endpoint existed (I1).
    #[serde(default)]
    #[schema(value_type = String, example = "disabled")]
    pub dynamic_registration: DynamicRegistrationMode,
    #[serde(default)]
    pub dcr_allowed_scopes: Vec<String>,
    #[serde(default)]
    pub dcr_allowed_redirect_hosts: Vec<String>,
    #[serde(default)]
    pub external_client_allowed_resources: Vec<String>,
    #[serde(default = "default_dcr_max_clients")]
    #[schema(example = 20)]
    pub dcr_max_clients: u32,
    #[serde(default = "default_dcr_unused_client_ttl_days")]
    #[schema(example = 30)]
    pub dcr_unused_client_ttl_days: u32,
    /// T21.5 — defaulted, so an API client written before this task lands on
    /// `enabled: false`, which is what every deployment did before client ID
    /// metadata documents existed (I1).
    #[serde(default)]
    pub cimd: CimdPolicy,
}

/// The erasure grace window a deployment gets when nothing says otherwise.
///
/// 30 days is what `POST /api/v1/auth/account/delete` used before the window
/// was configurable, so an upgrade changes nothing for anybody.
fn default_deletion_grace_period_days() -> u32 {
    30
}

/// The longest erasure grace window the server will accept, in days.
///
/// GDPR Art. 12(3) gives one month to respond, extensible by two further
/// months for complex cases; a window past that is retention dressed as a
/// safety net.
pub const MAX_DELETION_GRACE_PERIOD_DAYS: u32 = 90;

/// Input for setting tenant-level overrides (partial).
pub type SetTenantOverride = TenantSettingsOverride;

// -----------------------------------------------------------------------
// System defaults (OWASP-aligned, matching AuthConfig::default)
// -----------------------------------------------------------------------

/// OWASP-aligned system defaults matching the current `AuthConfig`.
pub fn system_defaults() -> SetOrgSettings {
    SetOrgSettings {
        // Password — OWASP ASVS v4.0 §2.1
        min_length: 12,
        require_uppercase: true,
        require_lowercase: true,
        require_digits: true,
        require_symbols: false,
        password_history_count: 5,
        hibp_check_enabled: true,
        // MFA
        mfa_enforced: false,
        mfa_challenge_lifetime_secs: 300,
        // Lockout — OWASP ASVS §2.2
        max_failed_login_attempts: 5,
        lockout_duration_secs: 300,
        lockout_backoff_multiplier: 2.0,
        max_lockout_duration_secs: 3600,
        // Token — short-lived access, 30-day refresh
        access_token_lifetime_secs: 900,
        refresh_token_lifetime_secs: 2_592_000,
        // Email
        email_verification_required: true,
        email_verification_grace_period_hours: 24,
        // Certificate
        default_cert_validity_days: 365,
        max_cert_validity_days: 730,
        // Notification
        admin_notifications_enabled: true,
        // OPAQUE — off by default. Turning it on is a deliberate operator
        // decision, and defaulting it on would change the login wire protocol
        // for every existing deployment on upgrade.
        opaque_mode: OpaqueMode::Disabled,
        opaque_suite: OpaqueSuite::Ristretto255Sha512,
        opaque_ksf: OpaqueKsf::Argon2id,
        // Privacy — the value the erasure handler used to hard-code.
        deletion_grace_period_days: default_deletion_grace_period_days(),
        // WebAuthn — `preferred` accepts a security key whether or not it has
        // a PIN, and records which happened. `required` would refuse every
        // PIN-less authenticator at enrolment, which reads to the user as
        // "AXIAM does not support my YubiKey" rather than as a policy.
        // Usernameless sign-in does not rely on this default: it requires user
        // verification unconditionally, because there the key is the only
        // factor (see `WebauthnUserVerification`).
        webauthn_user_verification: WebauthnUserVerification::Preferred,
        // OIDC — X7 G8's stricter default (invariant I3). `address` and
        // `phone` release personal data, so the deployment that has never
        // made a decision about them makes the one that releases nothing.
        sensitive_scopes_enabled: false,
        // No tenant preference: the sign-in page falls back to the deployment
        // default, exactly as it did before W5 shipped the chain.
        default_locale: None,
        // T21.4 — self-registration off, and every list empty. A deployment
        // that has never thought about RFC 7591 registers no client it did not
        // create, which is exactly what it did before the endpoint existed
        // (I1). The two numbers carry their shipped values rather than zero so
        // that turning the switch on is one decision rather than three.
        dynamic_registration: DynamicRegistrationMode::Disabled,
        dcr_allowed_scopes: Vec::new(),
        dcr_allowed_redirect_hosts: Vec::new(),
        external_client_allowed_resources: Vec::new(),
        dcr_max_clients: DEFAULT_DCR_MAX_CLIENTS,
        dcr_unused_client_ttl_days: DEFAULT_DCR_UNUSED_CLIENT_TTL_DAYS,
        // T21.5 — a URL-shaped `client_id` is an unknown client, which is what
        // it was before this task existed (I1). The bounds carry their shipped
        // values rather than zero so that turning the switch on is one
        // decision rather than four.
        cimd: CimdPolicy::default(),
    }
}

// -----------------------------------------------------------------------
// Org settings validation (internal invariants)
// -----------------------------------------------------------------------

/// Validate internal invariants of organization-level settings.
///
/// Checks relationships between fields (e.g., max >= min) and rejects
/// obviously invalid values (zero lifetimes where required).
pub fn validate_org_settings(input: &SetOrgSettings) -> AxiamResult<()> {
    let mut violations = Vec::new();

    if input.max_lockout_duration_secs < input.lockout_duration_secs {
        violations.push(format!(
            "max_lockout_duration_secs ({}) must be >= \
             lockout_duration_secs ({})",
            input.max_lockout_duration_secs, input.lockout_duration_secs,
        ));
    }

    if input.max_cert_validity_days < input.default_cert_validity_days {
        violations.push(format!(
            "max_cert_validity_days ({}) must be >= \
             default_cert_validity_days ({})",
            input.max_cert_validity_days, input.default_cert_validity_days,
        ));
    }

    if input.lockout_backoff_multiplier < 1.0 {
        violations.push(format!(
            "lockout_backoff_multiplier ({}) must be >= 1.0",
            input.lockout_backoff_multiplier,
        ));
    }

    if input.access_token_lifetime_secs == 0 {
        violations.push("access_token_lifetime_secs must be > 0".into());
    }

    if input.refresh_token_lifetime_secs == 0 {
        violations.push("refresh_token_lifetime_secs must be > 0".into());
    }

    if input.mfa_challenge_lifetime_secs == 0 {
        violations.push("mfa_challenge_lifetime_secs must be > 0".into());
    }

    // A zero-day window would purge on the same request that scheduled the
    // erasure, leaving the cancel link in the confirmation email pointing at
    // an account that is already gone.
    if input.deletion_grace_period_days == 0 {
        violations.push("deletion_grace_period_days must be >= 1".into());
    } else if input.deletion_grace_period_days > MAX_DELETION_GRACE_PERIOD_DAYS {
        violations.push(format!(
            "deletion_grace_period_days ({}) must be <= {} \
             (GDPR Art. 12(3): one month, extensible by two)",
            input.deletion_grace_period_days, MAX_DELETION_GRACE_PERIOD_DAYS,
        ));
    }

    // T21.4 — the dynamic-registration interlocks, on the policy this input
    // resolves to. An organization baseline reaches every tenant that has not
    // overridden it, so a baseline naming `anonymous` with no resources is the
    // same open door as a tenant one; see `validate_dcr_policy`.
    let oidc = OidcPolicy {
        sensitive_scopes_enabled: input.sensitive_scopes_enabled,
        default_locale: input.default_locale.clone(),
        dynamic_registration: input.dynamic_registration,
        dcr_allowed_scopes: input.dcr_allowed_scopes.clone(),
        dcr_allowed_redirect_hosts: input.dcr_allowed_redirect_hosts.clone(),
        external_client_allowed_resources: input.external_client_allowed_resources.clone(),
        dcr_max_clients: input.dcr_max_clients,
        dcr_unused_client_ttl_days: input.dcr_unused_client_ttl_days,
        cimd: input.cimd.clone(),
    };
    violations.extend(validate_dcr_policy(&oidc));
    // T21.5 — the same argument, for the mechanism that reaches further: a
    // baseline that enables CIMD with no resource list and no trusted
    // publisher opens it for every tenant that has not overridden it.
    violations.extend(validate_cimd_policy(&oidc));

    if violations.is_empty() {
        Ok(())
    } else {
        Err(AxiamError::Validation {
            message: format!("Invalid org settings: {}", violations.join("; "),),
        })
    }
}

// -----------------------------------------------------------------------
// Inheritance engine — pure functions
// -----------------------------------------------------------------------

/// Merge org baseline with tenant overrides to produce effective settings.
///
/// Any `Some` field in the override replaces the org baseline value.
/// `None` fields inherit from the org baseline unchanged.
pub fn effective_settings(
    org: &SecuritySettings,
    tenant_override: &TenantSettingsOverride,
    tenant_id: Uuid,
    result_id: Uuid,
) -> SecuritySettings {
    SecuritySettings {
        id: result_id,
        scope: SettingsScope::Tenant,
        scope_id: tenant_id,
        password: PasswordPolicy {
            min_length: tenant_override
                .min_length
                .unwrap_or(org.password.min_length),
            require_uppercase: tenant_override
                .require_uppercase
                .unwrap_or(org.password.require_uppercase),
            require_lowercase: tenant_override
                .require_lowercase
                .unwrap_or(org.password.require_lowercase),
            require_digits: tenant_override
                .require_digits
                .unwrap_or(org.password.require_digits),
            require_symbols: tenant_override
                .require_symbols
                .unwrap_or(org.password.require_symbols),
            password_history_count: tenant_override
                .password_history_count
                .unwrap_or(org.password.password_history_count),
            hibp_check_enabled: tenant_override
                .hibp_check_enabled
                .unwrap_or(org.password.hibp_check_enabled),
        },
        mfa: MfaPolicy {
            mfa_enforced: tenant_override.mfa_enforced.unwrap_or(org.mfa.mfa_enforced),
            mfa_challenge_lifetime_secs: tenant_override
                .mfa_challenge_lifetime_secs
                .unwrap_or(org.mfa.mfa_challenge_lifetime_secs),
        },
        lockout: LockoutPolicy {
            max_failed_login_attempts: tenant_override
                .max_failed_login_attempts
                .unwrap_or(org.lockout.max_failed_login_attempts),
            lockout_duration_secs: tenant_override
                .lockout_duration_secs
                .unwrap_or(org.lockout.lockout_duration_secs),
            lockout_backoff_multiplier: tenant_override
                .lockout_backoff_multiplier
                .unwrap_or(org.lockout.lockout_backoff_multiplier),
            max_lockout_duration_secs: tenant_override
                .max_lockout_duration_secs
                .unwrap_or(org.lockout.max_lockout_duration_secs),
        },
        token: TokenPolicy {
            access_token_lifetime_secs: tenant_override
                .access_token_lifetime_secs
                .unwrap_or(org.token.access_token_lifetime_secs),
            refresh_token_lifetime_secs: tenant_override
                .refresh_token_lifetime_secs
                .unwrap_or(org.token.refresh_token_lifetime_secs),
        },
        email: EmailVerificationPolicy {
            email_verification_required: tenant_override
                .email_verification_required
                .unwrap_or(org.email.email_verification_required),
            email_verification_grace_period_hours: tenant_override
                .email_verification_grace_period_hours
                .unwrap_or(org.email.email_verification_grace_period_hours),
        },
        certificate: CertificatePolicy {
            default_cert_validity_days: tenant_override
                .default_cert_validity_days
                .unwrap_or(org.certificate.default_cert_validity_days),
            max_cert_validity_days: tenant_override
                .max_cert_validity_days
                .unwrap_or(org.certificate.max_cert_validity_days),
        },
        notification: NotificationPolicy {
            admin_notifications_enabled: tenant_override
                .admin_notifications_enabled
                .unwrap_or(org.notification.admin_notifications_enabled),
        },
        opaque: OpaquePolicy {
            opaque_mode: tenant_override
                .opaque_mode
                .unwrap_or(org.opaque.opaque_mode),
            opaque_suite: tenant_override
                .opaque_suite
                .unwrap_or(org.opaque.opaque_suite),
            opaque_ksf: tenant_override.opaque_ksf.unwrap_or(org.opaque.opaque_ksf),
        },
        privacy: PrivacyPolicy {
            deletion_grace_period_days: tenant_override
                .deletion_grace_period_days
                .unwrap_or(org.privacy.deletion_grace_period_days),
        },
        webauthn: WebauthnPolicy {
            webauthn_user_verification: tenant_override
                .webauthn_user_verification
                .unwrap_or(org.webauthn.webauthn_user_verification),
        },
        oidc: OidcPolicy {
            sensitive_scopes_enabled: tenant_override
                .sensitive_scopes_enabled
                .unwrap_or(org.oidc.sensitive_scopes_enabled),
            default_locale: tenant_override
                .default_locale
                .clone()
                .or_else(|| org.oidc.default_locale.clone()),
            // T21.4. `unwrap_or` on each, exactly as every other field here:
            // an absent override inherits. The three lists inherit *whole* —
            // a tenant that sets `external_client_allowed_resources` replaces
            // the organization's list rather than adding to it, which is the
            // same whole-list semantics `allowed_resources` has on a client
            // and for the same reason: a list assembled from two places is a
            // list nobody can state from one request.
            dynamic_registration: tenant_override
                .dynamic_registration
                .unwrap_or(org.oidc.dynamic_registration),
            dcr_allowed_scopes: tenant_override
                .dcr_allowed_scopes
                .clone()
                .unwrap_or_else(|| org.oidc.dcr_allowed_scopes.clone()),
            dcr_allowed_redirect_hosts: tenant_override
                .dcr_allowed_redirect_hosts
                .clone()
                .unwrap_or_else(|| org.oidc.dcr_allowed_redirect_hosts.clone()),
            external_client_allowed_resources: tenant_override
                .external_client_allowed_resources
                .clone()
                .unwrap_or_else(|| org.oidc.external_client_allowed_resources.clone()),
            dcr_max_clients: tenant_override
                .dcr_max_clients
                .unwrap_or(org.oidc.dcr_max_clients),
            dcr_unused_client_ttl_days: tenant_override
                .dcr_unused_client_ttl_days
                .unwrap_or(org.oidc.dcr_unused_client_ttl_days),
            // T21.5 — whole or nothing, for the reason `CimdPolicy`'s own
            // documentation gives: a per-field merge could produce a posture
            // neither party wrote — this tenant's trusted publishers under the
            // organization's `enabled`, say.
            cimd: tenant_override
                .cimd
                .clone()
                .unwrap_or_else(|| org.oidc.cimd.clone()),
        },
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Drop every tenant override that the org baseline has since overtaken.
///
/// Returns the names of the fields cleared, in declaration order — empty when
/// the override was already compliant.
///
/// # Why this exists
///
/// [`validate_tenant_override`] enforces "a tenant may only tighten" at the
/// moment a tenant writes one. Nothing enforced it afterwards, and an
/// organization baseline is not a constant: raise `min_length` to 16, or switch
/// `opaque_mode` from `disabled` to `required`, and every tenant that had
/// written an override for that field kept the old, weaker value forever. The
/// setting appeared to apply — the organization row said so, and tenants with no
/// override did inherit it — while the tenants that had ever visited their own
/// settings page silently did not. Which tenants those were was not visible
/// anywhere.
///
/// Clearing the field rather than rewriting it to the org value is deliberate:
/// an absent override *tracks* the baseline, so the tenant also picks up the
/// next change. Writing the value in would freeze it again at the new level and
/// reproduce the same defect one baseline later.
///
/// Overrides that are still **stricter** than the baseline are left exactly as
/// they are. A tenant that chose a 24-character minimum does not lose it because
/// the organization moved from 12 to 16.
pub fn clamp_overrides_to_org(
    org: &SecuritySettings,
    overrides: &mut TenantSettingsOverride,
) -> Vec<&'static str> {
    let mut cleared = Vec::new();

    // `tenant >= org`: a higher minimum is the more restrictive one.
    macro_rules! clamp_min {
        ($field:ident, $org_path:expr, $label:expr) => {
            if overrides.$field.is_some_and(|val| val < $org_path) {
                overrides.$field = None;
                cleared.push($label);
            }
        };
    }
    clamp_min!(min_length, org.password.min_length, "min_length");
    clamp_min!(
        password_history_count,
        org.password.password_history_count,
        "password_history_count"
    );
    clamp_min!(
        lockout_duration_secs,
        org.lockout.lockout_duration_secs,
        "lockout_duration_secs"
    );
    clamp_min!(
        max_lockout_duration_secs,
        org.lockout.max_lockout_duration_secs,
        "max_lockout_duration_secs"
    );
    if overrides
        .lockout_backoff_multiplier
        .is_some_and(|val| val < org.lockout.lockout_backoff_multiplier)
    {
        overrides.lockout_backoff_multiplier = None;
        cleared.push("lockout_backoff_multiplier");
    }

    // `tenant <= org`: a lower cap or shorter lifetime is the more restrictive one.
    macro_rules! clamp_max {
        ($field:ident, $org_path:expr, $label:expr) => {
            if overrides.$field.is_some_and(|val| val > $org_path) {
                overrides.$field = None;
                cleared.push($label);
            }
        };
    }
    clamp_max!(
        max_failed_login_attempts,
        org.lockout.max_failed_login_attempts,
        "max_failed_login_attempts"
    );
    clamp_max!(
        access_token_lifetime_secs,
        org.token.access_token_lifetime_secs,
        "access_token_lifetime_secs"
    );
    clamp_max!(
        refresh_token_lifetime_secs,
        org.token.refresh_token_lifetime_secs,
        "refresh_token_lifetime_secs"
    );
    clamp_max!(
        mfa_challenge_lifetime_secs,
        org.mfa.mfa_challenge_lifetime_secs,
        "mfa_challenge_lifetime_secs"
    );
    clamp_max!(
        default_cert_validity_days,
        org.certificate.default_cert_validity_days,
        "default_cert_validity_days"
    );
    clamp_max!(
        max_cert_validity_days,
        org.certificate.max_cert_validity_days,
        "max_cert_validity_days"
    );
    clamp_max!(
        email_verification_grace_period_hours,
        org.email.email_verification_grace_period_hours,
        "email_verification_grace_period_hours"
    );
    clamp_max!(
        deletion_grace_period_days,
        org.privacy.deletion_grace_period_days,
        "deletion_grace_period_days"
    );

    // Enable-only: a tenant may turn a control on, never off.
    macro_rules! clamp_enable_only {
        ($field:ident, $org_val:expr, $label:expr) => {
            if $org_val && overrides.$field == Some(false) {
                overrides.$field = None;
                cleared.push($label);
            }
        };
    }
    clamp_enable_only!(
        require_uppercase,
        org.password.require_uppercase,
        "require_uppercase"
    );
    clamp_enable_only!(
        require_lowercase,
        org.password.require_lowercase,
        "require_lowercase"
    );
    clamp_enable_only!(
        require_digits,
        org.password.require_digits,
        "require_digits"
    );
    clamp_enable_only!(
        require_symbols,
        org.password.require_symbols,
        "require_symbols"
    );
    clamp_enable_only!(mfa_enforced, org.mfa.mfa_enforced, "mfa_enforced");
    clamp_enable_only!(
        hibp_check_enabled,
        org.password.hibp_check_enabled,
        "hibp_check_enabled"
    );
    clamp_enable_only!(
        email_verification_required,
        org.email.email_verification_required,
        "email_verification_required"
    );
    clamp_enable_only!(
        admin_notifications_enabled,
        org.notification.admin_notifications_enabled,
        "admin_notifications_enabled"
    );

    // OPAQUE, on the same ordering `validate_tenant_override` uses.
    if overrides
        .opaque_mode
        .is_some_and(|mode| mode < org.opaque.opaque_mode)
    {
        overrides.opaque_mode = None;
        cleared.push("opaque_mode");
    }
    if overrides
        .opaque_suite
        .is_some_and(|suite| !opaque_suite_is_at_least(suite, org.opaque.opaque_suite))
    {
        overrides.opaque_suite = None;
        cleared.push("opaque_suite");
    }
    if overrides
        .opaque_ksf
        .is_some_and(|ksf| !opaque_ksf_is_at_least(ksf, org.opaque.opaque_ksf))
    {
        overrides.opaque_ksf = None;
        cleared.push("opaque_ksf");
    }

    // WebAuthn user verification, on the same ordering
    // `validate_tenant_override` uses.
    if overrides.webauthn_user_verification.is_some_and(|uv| {
        !user_verification_is_at_least(uv, org.webauthn.webauthn_user_verification)
    }) {
        overrides.webauthn_user_verification = None;
        cleared.push("webauthn_user_verification");
    }

    // X7 G8, and the only *disable*-only control in the model: the org value
    // `true` is the permissive one, so a tenant override of `false` is the
    // tightening direction and is kept, while `Some(true)` against an org
    // baseline of `false` is a tenant granting itself a release its
    // organization did not authorise. `default_locale` is deliberately absent
    // from this function — see `OidcPolicy`.
    if !org.oidc.sensitive_scopes_enabled && overrides.sensitive_scopes_enabled == Some(true) {
        overrides.sensitive_scopes_enabled = None;
        cleared.push("sensitive_scopes_enabled");
    }

    // T21.4 — the three ordered dynamic-registration controls, on the same
    // ordering `validate_tenant_override` uses. The three *lists* are
    // deliberately absent for the reason `OidcPolicy` gives: they name
    // per-tenant resources (this tenant's MCP servers, this tenant's callback
    // hosts), and there is no sense in which one such list is stricter than
    // another, so an organization baseline cannot overtake one.
    if overrides
        .dynamic_registration
        .is_some_and(|m| !dynamic_registration_is_at_most(m, org.oidc.dynamic_registration))
    {
        overrides.dynamic_registration = None;
        cleared.push("dynamic_registration");
    }
    if overrides
        .dcr_max_clients
        .is_some_and(|n| n > org.oidc.dcr_max_clients)
    {
        overrides.dcr_max_clients = None;
        cleared.push("dcr_max_clients");
    }
    if overrides.dcr_unused_client_ttl_days.is_some_and(|d| {
        dcr_ttl_strictness(d) > dcr_ttl_strictness(org.oidc.dcr_unused_client_ttl_days)
    }) {
        overrides.dcr_unused_client_ttl_days = None;
        cleared.push("dcr_unused_client_ttl_days");
    }
    // T21.5 — the posture is overridden whole, so it is cleared whole: a
    // tenant CIMD block that turns on what the organization turned off is
    // dropped in favour of the baseline rather than half-kept.
    if overrides.cimd.as_ref().is_some_and(|c| {
        (c.enabled && !org.oidc.cimd.enabled) || (c.allow_http && !org.oidc.cimd.allow_http)
    }) {
        overrides.cimd = None;
        cleared.push("cimd");
    }

    cleared
}

/// Validate that a tenant override is only **more restrictive** than
/// the org baseline. Collects all violations into one error message.
///
/// Rules:
/// - `tenant >= org` for: min_length, password_history_count,
///   lockout_duration_secs, lockout_backoff_multiplier,
///   max_lockout_duration_secs
/// - `tenant <= org` for: max_failed_login_attempts,
///   access_token_lifetime_secs, refresh_token_lifetime_secs,
///   mfa_challenge_lifetime_secs, default_cert_validity_days,
///   max_cert_validity_days, email_verification_grace_period_hours
/// - enable-only (false->true OK, true->false NOT OK):
///   require_uppercase/lowercase/digits/symbols, mfa_enforced,
///   hibp_check_enabled, email_verification_required,
///   admin_notifications_enabled
pub fn validate_tenant_override(
    org: &SecuritySettings,
    overrides: &TenantSettingsOverride,
) -> AxiamResult<()> {
    let mut violations = Vec::new();

    // --- tenant >= org (higher minimum is more restrictive) ---
    macro_rules! check_min {
        ($field:ident, $org_path:expr, $label:expr) => {
            if let Some(val) = overrides.$field {
                if val < $org_path {
                    violations.push(format!(
                        "{}: tenant value {} is less restrictive \
                         than org baseline {}",
                        $label, val, $org_path,
                    ));
                }
            }
        };
    }

    check_min!(min_length, org.password.min_length, "min_length");
    check_min!(
        password_history_count,
        org.password.password_history_count,
        "password_history_count"
    );
    check_min!(
        lockout_duration_secs,
        org.lockout.lockout_duration_secs,
        "lockout_duration_secs"
    );
    check_min!(
        max_lockout_duration_secs,
        org.lockout.max_lockout_duration_secs,
        "max_lockout_duration_secs"
    );

    // lockout_backoff_multiplier (f64 — compare with partial_cmp)
    if let Some(val) = overrides.lockout_backoff_multiplier
        && val < org.lockout.lockout_backoff_multiplier
    {
        violations.push(format!(
            "lockout_backoff_multiplier: tenant value {} is \
             less restrictive than org baseline {}",
            val, org.lockout.lockout_backoff_multiplier,
        ));
    }

    // --- tenant <= org (lower max / shorter lifetime is more restrictive) ---
    macro_rules! check_max {
        ($field:ident, $org_path:expr, $label:expr) => {
            if let Some(val) = overrides.$field {
                if val > $org_path {
                    violations.push(format!(
                        "{}: tenant value {} is less restrictive \
                         than org baseline {}",
                        $label, val, $org_path,
                    ));
                }
            }
        };
    }

    check_max!(
        max_failed_login_attempts,
        org.lockout.max_failed_login_attempts,
        "max_failed_login_attempts"
    );
    check_max!(
        access_token_lifetime_secs,
        org.token.access_token_lifetime_secs,
        "access_token_lifetime_secs"
    );
    check_max!(
        refresh_token_lifetime_secs,
        org.token.refresh_token_lifetime_secs,
        "refresh_token_lifetime_secs"
    );
    check_max!(
        mfa_challenge_lifetime_secs,
        org.mfa.mfa_challenge_lifetime_secs,
        "mfa_challenge_lifetime_secs"
    );
    check_max!(
        default_cert_validity_days,
        org.certificate.default_cert_validity_days,
        "default_cert_validity_days"
    );
    check_max!(
        max_cert_validity_days,
        org.certificate.max_cert_validity_days,
        "max_cert_validity_days"
    );
    check_max!(
        email_verification_grace_period_hours,
        org.email.email_verification_grace_period_hours,
        "email_verification_grace_period_hours"
    );
    // Shorter is more restrictive: it is time spent holding data the subject
    // has already asked to have erased.
    check_max!(
        deletion_grace_period_days,
        org.privacy.deletion_grace_period_days,
        "deletion_grace_period_days"
    );

    // --- enable-only (false->true OK, true->false NOT OK) ---
    macro_rules! check_enable_only {
        ($field:ident, $org_val:expr, $label:expr) => {
            if let Some(val) = overrides.$field {
                if $org_val && !val {
                    violations.push(format!(
                        "{}: cannot disable at tenant level when \
                         enabled at org level",
                        $label,
                    ));
                }
            }
        };
    }

    check_enable_only!(
        require_uppercase,
        org.password.require_uppercase,
        "require_uppercase"
    );
    check_enable_only!(
        require_lowercase,
        org.password.require_lowercase,
        "require_lowercase"
    );
    check_enable_only!(
        require_digits,
        org.password.require_digits,
        "require_digits"
    );
    check_enable_only!(
        require_symbols,
        org.password.require_symbols,
        "require_symbols"
    );
    check_enable_only!(mfa_enforced, org.mfa.mfa_enforced, "mfa_enforced");
    check_enable_only!(
        hibp_check_enabled,
        org.password.hibp_check_enabled,
        "hibp_check_enabled"
    );
    check_enable_only!(
        email_verification_required,
        org.email.email_verification_required,
        "email_verification_required"
    );
    check_enable_only!(
        admin_notifications_enabled,
        org.notification.admin_notifications_enabled,
        "admin_notifications_enabled"
    );

    // --- OPAQUE: tighten-only ---
    //
    // `OpaqueMode` derives `Ord` as Disabled < Optional < Required, which is
    // exactly the restrictiveness order, so this is a plain comparison. Suite
    // and KSF strength are ranked explicitly rather than by declaration order,
    // so that adding a variant forces a decision about where it sits.
    if let Some(mode) = overrides.opaque_mode
        && mode < org.opaque.opaque_mode
    {
        violations.push(format!(
            "opaque_mode: tenant value {} is less restrictive than org baseline {}",
            mode, org.opaque.opaque_mode,
        ));
    }
    if let Some(suite) = overrides.opaque_suite
        && !opaque_suite_is_at_least(suite, org.opaque.opaque_suite)
    {
        violations.push(format!(
            "opaque_suite: tenant value {} is weaker than org baseline {}",
            suite, org.opaque.opaque_suite,
        ));
    }
    if let Some(ksf) = overrides.opaque_ksf
        && !opaque_ksf_is_at_least(ksf, org.opaque.opaque_ksf)
    {
        violations.push(format!(
            "opaque_ksf: tenant value {} is weaker than org baseline {}",
            ksf, org.opaque.opaque_ksf,
        ));
    }

    // --- WebAuthn user verification: tighten-only ---
    //
    // `required` > `preferred` > `discouraged`. A tenant handling regulated
    // data may demand a PIN where the organization only asks for one; it may
    // not quietly stop asking where the organization insists.
    if let Some(uv) = overrides.webauthn_user_verification
        && !user_verification_is_at_least(uv, org.webauthn.webauthn_user_verification)
    {
        violations.push(format!(
            "webauthn_user_verification: tenant value {} is less restrictive than \
             org baseline {}",
            uv, org.webauthn.webauthn_user_verification,
        ));
    }

    // --- X7 G8 sensitive scopes: disable-only ---
    //
    // The mirror image of `check_enable_only`, and the only control in this
    // model that runs that way, because it is the only one whose `true` is the
    // permissive value. A tenant may refuse to release postal addresses and
    // telephone numbers that its organization allows; it may not decide on its
    // own to start releasing them. The lawful basis for holding the data was
    // established at the organization level and the tenant does not get to
    // widen it.
    //
    // `default_locale` is deliberately not checked here. See `OidcPolicy`.
    if overrides.sensitive_scopes_enabled == Some(true) && !org.oidc.sensitive_scopes_enabled {
        violations.push(
            "sensitive_scopes_enabled: cannot enable at tenant level when disabled at org level              (the address and phone scopes release personal data under the organization's              lawful basis, not the tenant's)"
                .into(),
        );
    }

    // --- T21.4 dynamic client registration: three ordered controls ---
    //
    // A tenant may refuse a registration mode its organization allows; it may
    // not admit callers the organization does not. `dcr_max_clients` and
    // `dcr_unused_client_ttl_days` run the ordinary "tenant <= org" way: a
    // smaller ceiling and a shorter unused-client lifetime are both the
    // stricter direction, and a tenant raising either would be granting itself
    // more self-registered clients, for longer, than the organization allowed.
    //
    // The three lists are not checked, for the reason `OidcPolicy` states:
    // `external_client_allowed_resources` names the MCP servers *this* tenant
    // fronts, and a subset rule would force an organization to enumerate every
    // tenant's resource servers in its own baseline before any tenant could
    // name one.
    if let Some(mode) = overrides.dynamic_registration
        && !dynamic_registration_is_at_most(mode, org.oidc.dynamic_registration)
    {
        violations.push(format!(
            "dynamic_registration: tenant value {mode} admits callers the org baseline {} \
             does not",
            org.oidc.dynamic_registration,
        ));
    }
    if let Some(n) = overrides.dcr_max_clients
        && n > org.oidc.dcr_max_clients
    {
        violations.push(format!(
            "dcr_max_clients ({n}) must be <= org baseline ({})",
            org.oidc.dcr_max_clients,
        ));
    }
    if let Some(d) = overrides.dcr_unused_client_ttl_days
        && dcr_ttl_strictness(d) > dcr_ttl_strictness(org.oidc.dcr_unused_client_ttl_days)
    {
        violations.push(format!(
            "dcr_unused_client_ttl_days ({d}) keeps an unused self-registered client longer \
             than the org baseline ({}); 0 means never sweep, which is the longest value of \
             all",
            org.oidc.dcr_unused_client_ttl_days,
        ));
    }

    // T21.5 — the two halves of the CIMD posture that can *widen*. Everything
    // else on `CimdPolicy` names this tenant's own publishers, callbacks and
    // bounds, and is unordered for the reason the three DCR lists are.
    if let Some(cimd) = &overrides.cimd {
        if cimd.enabled && !org.oidc.cimd.enabled {
            violations.push(
                "cimd.enabled: cannot enable client ID metadata documents at tenant level \
                 when disabled at org level (materialising a client from a stranger's \
                 document is a decision taken where the outbound fetch is paid for)"
                    .into(),
            );
        }
        if cimd.allow_http && !org.oidc.cimd.allow_http {
            violations.push(
                "cimd.allow_http: cannot allow plaintext metadata fetches at tenant level \
                 when the org baseline forbids them; the same seam also admits private \
                 addresses on the first hop"
                    .into(),
            );
        }
    }

    if !violations.is_empty() {
        return Err(AxiamError::Validation {
            message: format!(
                "Tenant override violates org baseline: {}",
                violations.join("; "),
            ),
        });
    }

    // Cross-field invariant check: merge org + overrides and verify
    // the effective policy is internally consistent.
    let merged = effective_settings(org, overrides, Uuid::nil(), Uuid::nil());
    let mut cross = Vec::new();

    // Non-zero lifetime invariants (0 passes "more restrictive" checks
    // but produces an unusable policy).
    if merged.token.access_token_lifetime_secs == 0 {
        cross.push("effective access_token_lifetime_secs must be > 0".into());
    }
    if merged.token.refresh_token_lifetime_secs == 0 {
        cross.push("effective refresh_token_lifetime_secs must be > 0".into());
    }
    if merged.mfa.mfa_challenge_lifetime_secs == 0 {
        cross.push("effective mfa_challenge_lifetime_secs must be > 0".into());
    }
    // 0 passes "more restrictive" and produces an erasure that cannot be
    // cancelled at all, including by the link in its own confirmation email.
    if merged.privacy.deletion_grace_period_days == 0 {
        cross.push("effective deletion_grace_period_days must be >= 1".into());
    }

    // T21.4 — the D3 interlock and the sensitive-scope refusal, on the policy
    // the tenant will actually run under. Checked on the *merge* rather than
    // on the override, because a tenant that names `anonymous` while
    // inheriting an empty resource list from its organization is exactly the
    // state the interlock exists to refuse.
    cross.extend(validate_dcr_policy(&merged.oidc));
    // T21.5 — the D3 interlock and the trusted-publisher refusal, on the
    // policy the tenant will actually run under. A tenant that enables CIMD
    // while inheriting an empty resource list is exactly what this refuses.
    cross.extend(validate_cimd_policy(&merged.oidc));

    if merged.lockout.max_lockout_duration_secs < merged.lockout.lockout_duration_secs {
        cross.push(format!(
            "effective max_lockout_duration_secs ({}) must be >= \
             lockout_duration_secs ({})",
            merged.lockout.max_lockout_duration_secs, merged.lockout.lockout_duration_secs,
        ));
    }
    if merged.certificate.max_cert_validity_days < merged.certificate.default_cert_validity_days {
        cross.push(format!(
            "effective max_cert_validity_days ({}) must be >= \
             default_cert_validity_days ({})",
            merged.certificate.max_cert_validity_days,
            merged.certificate.default_cert_validity_days,
        ));
    }

    if cross.is_empty() {
        Ok(())
    } else {
        Err(AxiamError::Validation {
            message: format!(
                "Tenant override produces inconsistent effective policy: {}",
                cross.join("; "),
            ),
        })
    }
}

/// Compute the diff between a complete tenant settings row and the
/// org baseline, producing a `TenantSettingsOverride` with only the
/// fields that differ set to `Some`.
pub fn diff_against_org(
    org: &SecuritySettings,
    tenant: &SecuritySettings,
) -> TenantSettingsOverride {
    macro_rules! diff {
        ($field:ident, $org_path:expr, $tenant_path:expr) => {
            if $tenant_path != $org_path {
                Some($tenant_path)
            } else {
                None
            }
        };
    }

    TenantSettingsOverride {
        min_length: diff!(
            min_length,
            org.password.min_length,
            tenant.password.min_length
        ),
        require_uppercase: diff!(
            require_uppercase,
            org.password.require_uppercase,
            tenant.password.require_uppercase
        ),
        require_lowercase: diff!(
            require_lowercase,
            org.password.require_lowercase,
            tenant.password.require_lowercase
        ),
        require_digits: diff!(
            require_digits,
            org.password.require_digits,
            tenant.password.require_digits
        ),
        require_symbols: diff!(
            require_symbols,
            org.password.require_symbols,
            tenant.password.require_symbols
        ),
        password_history_count: diff!(
            password_history_count,
            org.password.password_history_count,
            tenant.password.password_history_count
        ),
        hibp_check_enabled: diff!(
            hibp_check_enabled,
            org.password.hibp_check_enabled,
            tenant.password.hibp_check_enabled
        ),
        mfa_enforced: diff!(mfa_enforced, org.mfa.mfa_enforced, tenant.mfa.mfa_enforced),
        mfa_challenge_lifetime_secs: diff!(
            mfa_challenge_lifetime_secs,
            org.mfa.mfa_challenge_lifetime_secs,
            tenant.mfa.mfa_challenge_lifetime_secs
        ),
        max_failed_login_attempts: diff!(
            max_failed_login_attempts,
            org.lockout.max_failed_login_attempts,
            tenant.lockout.max_failed_login_attempts
        ),
        lockout_duration_secs: diff!(
            lockout_duration_secs,
            org.lockout.lockout_duration_secs,
            tenant.lockout.lockout_duration_secs
        ),
        lockout_backoff_multiplier: diff!(
            lockout_backoff_multiplier,
            org.lockout.lockout_backoff_multiplier,
            tenant.lockout.lockout_backoff_multiplier
        ),
        max_lockout_duration_secs: diff!(
            max_lockout_duration_secs,
            org.lockout.max_lockout_duration_secs,
            tenant.lockout.max_lockout_duration_secs
        ),
        access_token_lifetime_secs: diff!(
            access_token_lifetime_secs,
            org.token.access_token_lifetime_secs,
            tenant.token.access_token_lifetime_secs
        ),
        refresh_token_lifetime_secs: diff!(
            refresh_token_lifetime_secs,
            org.token.refresh_token_lifetime_secs,
            tenant.token.refresh_token_lifetime_secs
        ),
        email_verification_required: diff!(
            email_verification_required,
            org.email.email_verification_required,
            tenant.email.email_verification_required
        ),
        email_verification_grace_period_hours: diff!(
            email_verification_grace_period_hours,
            org.email.email_verification_grace_period_hours,
            tenant.email.email_verification_grace_period_hours
        ),
        default_cert_validity_days: diff!(
            default_cert_validity_days,
            org.certificate.default_cert_validity_days,
            tenant.certificate.default_cert_validity_days
        ),
        max_cert_validity_days: diff!(
            max_cert_validity_days,
            org.certificate.max_cert_validity_days,
            tenant.certificate.max_cert_validity_days
        ),
        admin_notifications_enabled: diff!(
            admin_notifications_enabled,
            org.notification.admin_notifications_enabled,
            tenant.notification.admin_notifications_enabled
        ),
        opaque_mode: diff!(
            opaque_mode,
            org.opaque.opaque_mode,
            tenant.opaque.opaque_mode
        ),
        opaque_suite: diff!(
            opaque_suite,
            org.opaque.opaque_suite,
            tenant.opaque.opaque_suite
        ),
        opaque_ksf: diff!(opaque_ksf, org.opaque.opaque_ksf, tenant.opaque.opaque_ksf),
        deletion_grace_period_days: diff!(
            deletion_grace_period_days,
            org.privacy.deletion_grace_period_days,
            tenant.privacy.deletion_grace_period_days
        ),
        webauthn_user_verification: diff!(
            webauthn_user_verification,
            org.webauthn.webauthn_user_verification,
            tenant.webauthn.webauthn_user_verification
        ),
        sensitive_scopes_enabled: diff!(
            sensitive_scopes_enabled,
            org.oidc.sensitive_scopes_enabled,
            tenant.oidc.sensitive_scopes_enabled
        ),
        // Not the `diff!` macro: the override field is itself the value type
        // (`Option<String>`), so `Some(tenant_value)` would be one `Option`
        // too many. The consequence is that this function cannot express
        // "the tenant explicitly has no locale while the organization has
        // one" — an absent override means inherit, and clearing a tenant
        // locale therefore restores the organization's. That is the same
        // limitation every other field here has and it is the safe direction:
        // a locale is a presentation preference, so inheriting one is never a
        // policy failure.
        dynamic_registration: diff!(
            dynamic_registration,
            org.oidc.dynamic_registration,
            tenant.oidc.dynamic_registration
        ),
        // The three list fields cannot use the `diff!` macro: it yields
        // `Some($tenant_path)` by value, and a `Vec` behind a `&` has to be
        // cloned rather than moved out of the borrow.
        dcr_allowed_scopes: if tenant.oidc.dcr_allowed_scopes != org.oidc.dcr_allowed_scopes {
            Some(tenant.oidc.dcr_allowed_scopes.clone())
        } else {
            None
        },
        dcr_allowed_redirect_hosts: if tenant.oidc.dcr_allowed_redirect_hosts
            != org.oidc.dcr_allowed_redirect_hosts
        {
            Some(tenant.oidc.dcr_allowed_redirect_hosts.clone())
        } else {
            None
        },
        external_client_allowed_resources: if tenant.oidc.external_client_allowed_resources
            != org.oidc.external_client_allowed_resources
        {
            Some(tenant.oidc.external_client_allowed_resources.clone())
        } else {
            None
        },
        dcr_max_clients: diff!(
            dcr_max_clients,
            org.oidc.dcr_max_clients,
            tenant.oidc.dcr_max_clients
        ),
        dcr_unused_client_ttl_days: diff!(
            dcr_unused_client_ttl_days,
            org.oidc.dcr_unused_client_ttl_days,
            tenant.oidc.dcr_unused_client_ttl_days
        ),
        // T21.5 — compared and carried whole, as it is merged whole. A tenant
        // whose CIMD posture differs from the baseline in one field overrides
        // all nine, which is the only diff that round-trips through
        // `effective_settings`.
        cimd: if tenant.oidc.cimd != org.oidc.cimd {
            Some(tenant.oidc.cimd.clone())
        } else {
            None
        },
        default_locale: if tenant.oidc.default_locale != org.oidc.default_locale {
            tenant.oidc.default_locale.clone()
        } else {
            None
        },
    }
}

/// Build a `SecuritySettings` from a `SetOrgSettings` input.
pub fn settings_from_org_input(id: Uuid, org_id: Uuid, input: &SetOrgSettings) -> SecuritySettings {
    let now = Utc::now();
    SecuritySettings {
        id,
        scope: SettingsScope::Org,
        scope_id: org_id,
        password: PasswordPolicy {
            min_length: input.min_length,
            require_uppercase: input.require_uppercase,
            require_lowercase: input.require_lowercase,
            require_digits: input.require_digits,
            require_symbols: input.require_symbols,
            password_history_count: input.password_history_count,
            hibp_check_enabled: input.hibp_check_enabled,
        },
        mfa: MfaPolicy {
            mfa_enforced: input.mfa_enforced,
            mfa_challenge_lifetime_secs: input.mfa_challenge_lifetime_secs,
        },
        lockout: LockoutPolicy {
            max_failed_login_attempts: input.max_failed_login_attempts,
            lockout_duration_secs: input.lockout_duration_secs,
            lockout_backoff_multiplier: input.lockout_backoff_multiplier,
            max_lockout_duration_secs: input.max_lockout_duration_secs,
        },
        token: TokenPolicy {
            access_token_lifetime_secs: input.access_token_lifetime_secs,
            refresh_token_lifetime_secs: input.refresh_token_lifetime_secs,
        },
        email: EmailVerificationPolicy {
            email_verification_required: input.email_verification_required,
            email_verification_grace_period_hours: input.email_verification_grace_period_hours,
        },
        certificate: CertificatePolicy {
            default_cert_validity_days: input.default_cert_validity_days,
            max_cert_validity_days: input.max_cert_validity_days,
        },
        notification: NotificationPolicy {
            admin_notifications_enabled: input.admin_notifications_enabled,
        },
        opaque: OpaquePolicy {
            opaque_mode: input.opaque_mode,
            opaque_suite: input.opaque_suite,
            opaque_ksf: input.opaque_ksf,
        },
        privacy: PrivacyPolicy {
            deletion_grace_period_days: input.deletion_grace_period_days,
        },
        webauthn: WebauthnPolicy {
            webauthn_user_verification: input.webauthn_user_verification,
        },
        oidc: OidcPolicy {
            sensitive_scopes_enabled: input.sensitive_scopes_enabled,
            default_locale: input.default_locale.clone(),
            dynamic_registration: input.dynamic_registration,
            dcr_allowed_scopes: input.dcr_allowed_scopes.clone(),
            dcr_allowed_redirect_hosts: input.dcr_allowed_redirect_hosts.clone(),
            external_client_allowed_resources: input.external_client_allowed_resources.clone(),
            dcr_max_clients: input.dcr_max_clients,
            dcr_unused_client_ttl_days: input.dcr_unused_client_ttl_days,
            cimd: input.cimd.clone(),
        },
        created_at: now,
        updated_at: now,
    }
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build an org `SecuritySettings` from system defaults.
    fn org_settings() -> SecuritySettings {
        let defaults = system_defaults();
        settings_from_org_input(Uuid::new_v4(), Uuid::new_v4(), &defaults)
    }

    // --- system_defaults sanity ---

    #[test]
    fn system_defaults_has_sane_values() {
        let d = system_defaults();
        assert!(d.min_length >= 8);
        assert!(d.access_token_lifetime_secs <= 3600);
        assert!(d.refresh_token_lifetime_secs > 0);
        assert!(d.max_failed_login_attempts > 0);
        assert!(d.lockout_duration_secs > 0);
        assert!(d.lockout_backoff_multiplier >= 1.0);
        assert!(d.max_lockout_duration_secs >= d.lockout_duration_secs);
        assert!(d.mfa_challenge_lifetime_secs > 0);
        assert!(d.default_cert_validity_days > 0);
        assert!(d.max_cert_validity_days >= d.default_cert_validity_days);
    }

    // --- OPAQUE policy ---

    #[test]
    fn opaque_defaults_to_disabled_so_an_upgrade_changes_no_wire_protocol() {
        let org = org_settings();
        assert_eq!(org.opaque.opaque_mode, OpaqueMode::Disabled);
        assert_eq!(org.opaque.opaque_suite, OpaqueSuite::Ristretto255Sha512);
        assert_eq!(org.opaque.opaque_ksf, OpaqueKsf::Argon2id);
    }

    #[test]
    fn a_tenant_may_tighten_opaque_mode_but_never_relax_it() {
        let mut org = org_settings();
        org.opaque.opaque_mode = OpaqueMode::Optional;

        let tighten = TenantSettingsOverride {
            opaque_mode: Some(OpaqueMode::Required),
            ..Default::default()
        };
        assert!(validate_tenant_override(&org, &tighten).is_ok());

        let relax = TenantSettingsOverride {
            opaque_mode: Some(OpaqueMode::Disabled),
            ..Default::default()
        };
        let err = validate_tenant_override(&org, &relax).unwrap_err();
        assert!(err.to_string().contains("opaque_mode"), "{err}");
    }

    #[test]
    fn a_tenant_may_restate_the_org_suite_but_not_weaken_it() {
        // One suite ships today, so the reachable assertion is that an equal
        // value passes. The check itself is kept live (rather than deleted
        // until a second suite exists) so that adding `P256Sha256` is an
        // additive change to a lattice that already works.
        let org = org_settings();
        let same = TenantSettingsOverride {
            opaque_suite: Some(OpaqueSuite::Ristretto255Sha512),
            ..Default::default()
        };
        assert!(validate_tenant_override(&org, &same).is_ok());
    }

    #[test]
    fn a_tenant_may_not_downgrade_argon2id_to_scrypt() {
        // Doing so would weaken every record enrolled after the change, which
        // is exactly what the tighten-only rule exists to prevent.
        let org = org_settings(); // argon2id baseline
        let downgrade = TenantSettingsOverride {
            opaque_ksf: Some(OpaqueKsf::Scrypt),
            ..Default::default()
        };
        let err = validate_tenant_override(&org, &downgrade).unwrap_err();
        assert!(err.to_string().contains("opaque_ksf"), "{err}");

        let mut weak_org = org_settings();
        weak_org.opaque.opaque_ksf = OpaqueKsf::Scrypt;
        let upgrade = TenantSettingsOverride {
            opaque_ksf: Some(OpaqueKsf::Argon2id),
            ..Default::default()
        };
        assert!(validate_tenant_override(&weak_org, &upgrade).is_ok());
    }

    #[test]
    fn opaque_overrides_flow_through_the_merge_and_back_out_of_the_diff() {
        let mut org = org_settings();
        org.opaque.opaque_mode = OpaqueMode::Optional;

        let overrides = TenantSettingsOverride {
            opaque_mode: Some(OpaqueMode::Required),
            ..Default::default()
        };
        let merged = effective_settings(&org, &overrides, Uuid::new_v4(), Uuid::new_v4());
        assert_eq!(merged.opaque.opaque_mode, OpaqueMode::Required);
        // Unset fields still inherit.
        assert_eq!(merged.opaque.opaque_suite, org.opaque.opaque_suite);
        assert_eq!(merged.opaque.opaque_ksf, org.opaque.opaque_ksf);

        let round_tripped = diff_against_org(&org, &merged);
        assert_eq!(round_tripped.opaque_mode, Some(OpaqueMode::Required));
        assert_eq!(round_tripped.opaque_suite, None);
        assert_eq!(round_tripped.opaque_ksf, None);
    }

    // -------------------------------------------------------------------
    // T21.4 — dynamic client registration
    // -------------------------------------------------------------------

    /// I1, as the first assertion about this feature: a deployment that has
    /// never heard of RFC 7591 registers no client it did not create.
    #[test]
    fn dynamic_registration_is_off_and_empty_by_default() {
        let d = system_defaults();
        assert_eq!(d.dynamic_registration, DynamicRegistrationMode::Disabled);
        assert!(d.dcr_allowed_scopes.is_empty());
        assert!(d.dcr_allowed_redirect_hosts.is_empty());
        assert!(d.external_client_allowed_resources.is_empty());
        // The two numbers carry their shipped values rather than zero, so
        // turning the switch on is one decision rather than three.
        assert_eq!(d.dcr_max_clients, DEFAULT_DCR_MAX_CLIENTS);
        assert_eq!(
            d.dcr_unused_client_ttl_days,
            DEFAULT_DCR_UNUSED_CLIENT_TTL_DAYS
        );
        // And the default policy is internally consistent, so nothing an
        // existing deployment writes starts failing validation.
        assert!(validate_org_settings(&d).is_ok());
    }

    /// The D3 interlock, at the organization. This is a security control:
    /// without it an open registration endpoint mints clients able to obtain
    /// the `axiam:user` tokens AXIAM's own APIs accept.
    #[test]
    fn anonymous_registration_needs_at_least_one_audience() {
        let refused = SetOrgSettings {
            dynamic_registration: DynamicRegistrationMode::Anonymous,
            external_client_allowed_resources: Vec::new(),
            ..system_defaults()
        };
        let err = validate_org_settings(&refused)
            .expect_err("anonymous with no audiences must be refused")
            .to_string();
        assert!(err.contains("D3"), "{err}");
        assert!(err.contains("external_client_allowed_resources"), "{err}");

        let accepted = SetOrgSettings {
            external_client_allowed_resources: vec!["https://mcp.example.com/mcp".into()],
            ..refused
        };
        assert!(validate_org_settings(&accepted).is_ok());
    }

    /// The interlock binds `anonymous` and nothing else: in
    /// `initial_access_token` mode an administrator has already decided this
    /// registration should happen.
    #[test]
    fn the_interlock_does_not_bind_the_initial_access_token_mode() {
        assert!(
            validate_org_settings(&SetOrgSettings {
                dynamic_registration: DynamicRegistrationMode::InitialAccessToken,
                external_client_allowed_resources: Vec::new(),
                ..system_defaults()
            })
            .is_ok()
        );
    }

    /// The T21.4 amendment: a self-registered client cannot be offered a scope
    /// W7 gates, so an end user never answers two consent screens for one
    /// authorization.
    #[test]
    fn a_sensitive_scope_cannot_be_offered_to_self_registered_clients() {
        for scope in ["address", "phone"] {
            let err = validate_org_settings(&SetOrgSettings {
                dcr_allowed_scopes: vec!["openid".into(), scope.into()],
                ..system_defaults()
            })
            .expect_err("{scope} must be refused in dcr_allowed_scopes")
            .to_string();
            assert!(
                err.contains(scope),
                "the refusal must name the scope: {err}"
            );
        }
        assert_eq!(
            sensitive_scope_in_dcr_list(&["openid".into(), "profile".into()]),
            None
        );
    }

    /// The tenant-override ordering: a tenant may refuse what its organization
    /// allows and may never admit callers the organization does not.
    #[test]
    fn a_tenant_may_narrow_the_registration_mode_but_never_widen_it() {
        let org = settings_from_org_input(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &SetOrgSettings {
                dynamic_registration: DynamicRegistrationMode::InitialAccessToken,
                external_client_allowed_resources: vec!["https://mcp.example.com/mcp".into()],
                ..system_defaults()
            },
        );

        for narrower in [
            DynamicRegistrationMode::Disabled,
            DynamicRegistrationMode::InitialAccessToken,
        ] {
            assert!(
                validate_tenant_override(
                    &org,
                    &TenantSettingsOverride {
                        dynamic_registration: Some(narrower),
                        ..Default::default()
                    }
                )
                .is_ok(),
                "{narrower} is no more permissive than the baseline"
            );
        }

        let err = validate_tenant_override(
            &org,
            &TenantSettingsOverride {
                dynamic_registration: Some(DynamicRegistrationMode::Anonymous),
                ..Default::default()
            },
        )
        .expect_err("a tenant may not open registration wider than its organization")
        .to_string();
        assert!(err.contains("dynamic_registration"), "{err}");
    }

    /// `0` is the **most** permissive TTL, not the least. A plain
    /// `tenant <= org` comparison would have read it as the strictest possible
    /// override and let a tenant turn the sweeper off under an organization
    /// that had turned it on.
    #[test]
    fn a_tenant_cannot_disable_the_sweeper_its_organization_enabled() {
        let org = settings_from_org_input(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &SetOrgSettings {
                dcr_unused_client_ttl_days: 30,
                ..system_defaults()
            },
        );

        // Shorter is stricter and allowed.
        assert!(
            validate_tenant_override(
                &org,
                &TenantSettingsOverride {
                    dcr_unused_client_ttl_days: Some(7),
                    ..Default::default()
                }
            )
            .is_ok()
        );
        // Longer is not.
        assert!(
            validate_tenant_override(
                &org,
                &TenantSettingsOverride {
                    dcr_unused_client_ttl_days: Some(90),
                    ..Default::default()
                }
            )
            .is_err()
        );
        // And neither is "never".
        assert!(
            validate_tenant_override(
                &org,
                &TenantSettingsOverride {
                    dcr_unused_client_ttl_days: Some(0),
                    ..Default::default()
                }
            )
            .is_err(),
            "0 means never sweep, which is longer than any window"
        );
    }

    /// `clamp_overrides_to_org` is what keeps an override honest **after** the
    /// baseline moves. Every ordered T21.4 field is cleared; the three lists
    /// are deliberately left alone, because they name per-tenant resources.
    #[test]
    fn a_baseline_that_tightens_clears_the_overtaken_registration_overrides() {
        let org = settings_from_org_input(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &SetOrgSettings {
                dynamic_registration: DynamicRegistrationMode::Disabled,
                dcr_max_clients: 5,
                dcr_unused_client_ttl_days: 10,
                ..system_defaults()
            },
        );
        let mut overrides = TenantSettingsOverride {
            dynamic_registration: Some(DynamicRegistrationMode::Anonymous),
            dcr_max_clients: Some(50),
            dcr_unused_client_ttl_days: Some(0),
            // Not ordered, so not cleared.
            external_client_allowed_resources: Some(vec!["https://mcp.example.com".into()]),
            ..Default::default()
        };
        let cleared = clamp_overrides_to_org(&org, &mut overrides);

        for field in [
            "dynamic_registration",
            "dcr_max_clients",
            "dcr_unused_client_ttl_days",
        ] {
            assert!(
                cleared.contains(&field),
                "{field} must be cleared: {cleared:?}"
            );
        }
        assert_eq!(overrides.dynamic_registration, None);
        assert_eq!(overrides.dcr_max_clients, None);
        assert_eq!(overrides.dcr_unused_client_ttl_days, None);
        assert!(
            overrides.external_client_allowed_resources.is_some(),
            "a list that names this tenant's own MCP servers is not something the \
             organization baseline can overtake"
        );
    }

    /// The interlock runs on the **merge**, so a tenant that names `anonymous`
    /// while inheriting an empty resource list is refused — which is the state
    /// a check that looked only at the request would have let through.
    #[test]
    fn the_interlock_is_checked_against_the_merged_policy() {
        let org = settings_from_org_input(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &SetOrgSettings {
                dynamic_registration: DynamicRegistrationMode::Anonymous,
                external_client_allowed_resources: vec!["https://mcp.example.com/mcp".into()],
                ..system_defaults()
            },
        );

        // The tenant keeps the mode and withdraws the audiences.
        let err = validate_tenant_override(
            &org,
            &TenantSettingsOverride {
                external_client_allowed_resources: Some(Vec::new()),
                ..Default::default()
            },
        )
        .expect_err("withdrawing the last audience under anonymous must be refused")
        .to_string();
        assert!(err.contains("D3"), "{err}");
    }

    /// A tenant override merges whole rather than adding to the baseline, and
    /// an absent one inherits. Both halves, because a list that silently
    /// unioned would be a list nobody could state from one request.
    #[test]
    fn a_registration_list_override_replaces_rather_than_adds() {
        let org = settings_from_org_input(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &SetOrgSettings {
                external_client_allowed_resources: vec!["https://a.example.com".into()],
                dcr_allowed_scopes: vec!["openid".into()],
                ..system_defaults()
            },
        );

        let inherited = effective_settings(
            &org,
            &TenantSettingsOverride::default(),
            Uuid::nil(),
            Uuid::nil(),
        );
        assert_eq!(
            inherited.oidc.external_client_allowed_resources,
            vec!["https://a.example.com".to_string()]
        );

        let replaced = effective_settings(
            &org,
            &TenantSettingsOverride {
                external_client_allowed_resources: Some(vec!["https://b.example.com".into()]),
                ..Default::default()
            },
            Uuid::nil(),
            Uuid::nil(),
        );
        assert_eq!(
            replaced.oidc.external_client_allowed_resources,
            vec!["https://b.example.com".to_string()],
            "an override replaces the baseline list; it does not union with it"
        );
    }

    /// The wire spellings, round-tripped. `from_wire` must refuse anything it
    /// does not recognise: a typo that degraded to a permissive default would
    /// open an unauthenticated write endpoint.
    #[test]
    fn the_registration_mode_round_trips_and_refuses_anything_else() {
        for mode in [
            DynamicRegistrationMode::Disabled,
            DynamicRegistrationMode::InitialAccessToken,
            DynamicRegistrationMode::Anonymous,
        ] {
            assert_eq!(
                DynamicRegistrationMode::from_wire(mode.as_str()),
                Some(mode)
            );
        }
        // Whitespace and case are forgiven, as they are for every other
        // stored enum in this file — a stored value is not user input.
        assert_eq!(
            DynamicRegistrationMode::from_wire("  Anonymous "),
            Some(DynamicRegistrationMode::Anonymous)
        );
        // A value that names nothing resolves to nothing. `""` and `"enabled"`
        // are the two an operator might plausibly type, and neither may become
        // a mode: the permissive direction here opens an unauthenticated write
        // endpoint.
        for bad in ["", "open", "enabled", "true", "nonsense", "dcr"] {
            assert_eq!(
                DynamicRegistrationMode::from_wire(bad),
                None,
                "{bad:?} names no mode and must not be guessed at"
            );
        }
        assert!(!DynamicRegistrationMode::default().is_enabled());
    }

    // --- validate_org_settings ---

    #[test]
    fn validate_org_settings_accepts_system_defaults() {
        assert!(validate_org_settings(&system_defaults()).is_ok());
    }

    #[test]
    fn validate_org_settings_rejects_each_invariant_violation() {
        // max_lockout_duration_secs < lockout_duration_secs
        let mut s = system_defaults();
        s.max_lockout_duration_secs = 100;
        s.lockout_duration_secs = 200;
        assert!(validate_org_settings(&s).is_err());

        // max_cert_validity_days < default_cert_validity_days
        let mut s = system_defaults();
        s.max_cert_validity_days = 10;
        s.default_cert_validity_days = 100;
        assert!(validate_org_settings(&s).is_err());

        // lockout_backoff_multiplier < 1.0
        let mut s = system_defaults();
        s.lockout_backoff_multiplier = 0.5;
        assert!(validate_org_settings(&s).is_err());

        // zero token / challenge lifetimes
        for mutate in [
            (|s: &mut SetOrgSettings| s.access_token_lifetime_secs = 0) as fn(&mut SetOrgSettings),
            |s: &mut SetOrgSettings| s.refresh_token_lifetime_secs = 0,
            |s: &mut SetOrgSettings| s.mfa_challenge_lifetime_secs = 0,
        ] {
            let mut s = system_defaults();
            mutate(&mut s);
            assert!(validate_org_settings(&s).is_err());
        }
    }

    #[test]
    fn validate_org_settings_reports_all_violations_together() {
        let mut s = system_defaults();
        s.access_token_lifetime_secs = 0;
        s.refresh_token_lifetime_secs = 0;
        let err = validate_org_settings(&s).unwrap_err().to_string();
        assert!(err.contains("access_token_lifetime_secs"));
        assert!(err.contains("refresh_token_lifetime_secs"));
    }

    // --- diff_against_org ---

    #[test]
    fn diff_against_identical_settings_is_empty() {
        let s = org_settings();
        assert!(diff_against_org(&s, &s).is_empty());
    }

    #[test]
    fn diff_against_org_detects_changed_fields() {
        let org = org_settings();
        let mut modified = system_defaults();
        modified.min_length += 4;
        modified.mfa_enforced = !modified.mfa_enforced;
        modified.access_token_lifetime_secs += 100;
        modified.admin_notifications_enabled = !modified.admin_notifications_enabled;
        let tenant = settings_from_org_input(Uuid::new_v4(), Uuid::new_v4(), &modified);

        let diff = diff_against_org(&org, &tenant);
        assert!(!diff.is_empty());
        assert_eq!(diff.min_length, Some(modified.min_length));
        assert_eq!(
            diff.access_token_lifetime_secs,
            Some(modified.access_token_lifetime_secs)
        );
        assert_eq!(diff.mfa_enforced, Some(modified.mfa_enforced));
        // Unchanged fields stay None.
        assert_eq!(diff.require_uppercase, None);
    }

    // --- validate_tenant_override: valid cases ---

    #[test]
    fn all_none_override_is_valid() {
        let org = org_settings();
        let overrides = TenantSettingsOverride::default();
        assert!(validate_tenant_override(&org, &overrides).is_ok());
    }

    #[test]
    fn more_restrictive_values_are_valid() {
        let org = org_settings();
        let overrides = TenantSettingsOverride {
            min_length: Some(16),                            // higher min
            max_failed_login_attempts: Some(3),              // lower max
            access_token_lifetime_secs: Some(600),           // shorter
            refresh_token_lifetime_secs: Some(86_400),       // shorter
            lockout_duration_secs: Some(600),                // longer lockout
            max_lockout_duration_secs: Some(7200),           // longer
            mfa_challenge_lifetime_secs: Some(120),          // shorter
            default_cert_validity_days: Some(180),           // shorter
            max_cert_validity_days: Some(365),               // shorter
            email_verification_grace_period_hours: Some(12), // shorter
            password_history_count: Some(10),                // higher
            lockout_backoff_multiplier: Some(3.0),           // higher
            ..Default::default()
        };
        assert!(validate_tenant_override(&org, &overrides).is_ok());
    }

    #[test]
    fn enable_only_true_is_valid() {
        let org = org_settings();
        // org has require_symbols = false, so tenant can enable it
        let overrides = TenantSettingsOverride {
            require_symbols: Some(true),
            mfa_enforced: Some(true),
            ..Default::default()
        };
        assert!(validate_tenant_override(&org, &overrides).is_ok());
    }

    #[test]
    fn equal_values_are_valid_boundary() {
        let org = org_settings();
        let overrides = TenantSettingsOverride {
            min_length: Some(org.password.min_length),
            max_failed_login_attempts: Some(org.lockout.max_failed_login_attempts),
            access_token_lifetime_secs: Some(org.token.access_token_lifetime_secs),
            ..Default::default()
        };
        assert!(validate_tenant_override(&org, &overrides).is_ok());
    }

    // --- validate_tenant_override: invalid cases ---

    #[test]
    fn less_restrictive_min_length_is_invalid() {
        let org = org_settings();
        let overrides = TenantSettingsOverride {
            min_length: Some(6), // weaker
            ..Default::default()
        };
        let err = validate_tenant_override(&org, &overrides).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("min_length"), "got: {msg}");
    }

    #[test]
    fn disable_mfa_enforced_is_invalid() {
        let mut org = org_settings();
        org.mfa.mfa_enforced = true; // org enforces MFA
        let overrides = TenantSettingsOverride {
            mfa_enforced: Some(false), // tenant tries to disable
            ..Default::default()
        };
        let err = validate_tenant_override(&org, &overrides).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("mfa_enforced"), "got: {msg}");
    }

    #[test]
    fn longer_token_lifetime_is_invalid() {
        let org = org_settings();
        let overrides = TenantSettingsOverride {
            access_token_lifetime_secs: Some(7200), // longer than 900
            ..Default::default()
        };
        let err = validate_tenant_override(&org, &overrides).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("access_token_lifetime_secs"), "got: {msg}");
    }

    #[test]
    fn higher_cert_validity_is_invalid() {
        let org = org_settings();
        let overrides = TenantSettingsOverride {
            max_cert_validity_days: Some(1000), // > 730
            ..Default::default()
        };
        let err = validate_tenant_override(&org, &overrides).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("max_cert_validity_days"), "got: {msg}");
    }

    #[test]
    fn multiple_violations_reported_together() {
        let mut org = org_settings();
        org.mfa.mfa_enforced = true;
        let overrides = TenantSettingsOverride {
            min_length: Some(4),                    // weaker
            mfa_enforced: Some(false),              // disabling
            access_token_lifetime_secs: Some(9999), // longer
            ..Default::default()
        };
        let err = validate_tenant_override(&org, &overrides).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("min_length"), "got: {msg}");
        assert!(msg.contains("mfa_enforced"), "got: {msg}");
        assert!(msg.contains("access_token_lifetime_secs"), "got: {msg}");
    }

    // --- cross-field invariant: zero lifetimes rejected ---

    #[test]
    fn zero_access_token_lifetime_is_rejected() {
        let org = org_settings();
        let overrides = TenantSettingsOverride {
            access_token_lifetime_secs: Some(0),
            ..Default::default()
        };
        let err = validate_tenant_override(&org, &overrides).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("access_token_lifetime_secs must be > 0"),
            "got: {msg}",
        );
    }

    #[test]
    fn zero_mfa_challenge_lifetime_is_rejected() {
        let org = org_settings();
        let overrides = TenantSettingsOverride {
            mfa_challenge_lifetime_secs: Some(0),
            ..Default::default()
        };
        let err = validate_tenant_override(&org, &overrides).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mfa_challenge_lifetime_secs must be > 0"),
            "got: {msg}",
        );
    }

    // --- effective_settings merging ---

    #[test]
    fn effective_settings_inherits_from_org() {
        let org = org_settings();
        let overrides = TenantSettingsOverride::default();
        let tenant_id = Uuid::new_v4();
        let result_id = Uuid::new_v4();
        let eff = effective_settings(&org, &overrides, tenant_id, result_id);
        assert_eq!(eff.password.min_length, org.password.min_length);
        assert_eq!(
            eff.token.access_token_lifetime_secs,
            org.token.access_token_lifetime_secs
        );
        assert_eq!(eff.scope, SettingsScope::Tenant);
        assert_eq!(eff.scope_id, tenant_id);
    }

    #[test]
    fn effective_settings_applies_overrides() {
        let org = org_settings();
        let overrides = TenantSettingsOverride {
            min_length: Some(20),
            access_token_lifetime_secs: Some(300),
            mfa_enforced: Some(true),
            ..Default::default()
        };
        let tenant_id = Uuid::new_v4();
        let result_id = Uuid::new_v4();
        let eff = effective_settings(&org, &overrides, tenant_id, result_id);
        assert_eq!(eff.password.min_length, 20);
        assert_eq!(eff.token.access_token_lifetime_secs, 300);
        assert!(eff.mfa.mfa_enforced);
        // Non-overridden fields inherit from org
        assert_eq!(
            eff.lockout.max_failed_login_attempts,
            org.lockout.max_failed_login_attempts,
        );
    }

    // --- diff_against_org ---

    #[test]
    fn diff_identical_settings_produces_empty_override() {
        let org = org_settings();
        let tenant = org.clone();
        let diff = diff_against_org(&org, &tenant);
        assert!(diff.is_empty());
    }

    #[test]
    fn diff_detects_changed_fields() {
        let org = org_settings();
        let mut tenant = org.clone();
        tenant.password.min_length = 20;
        tenant.token.access_token_lifetime_secs = 300;
        let diff = diff_against_org(&org, &tenant);
        assert_eq!(diff.min_length, Some(20));
        assert_eq!(diff.access_token_lifetime_secs, Some(300));
        // Unchanged fields are None
        assert_eq!(diff.mfa_enforced, None);
        assert_eq!(diff.max_failed_login_attempts, None);
    }

    // --- SettingsScope Display / FromStr ---

    #[test]
    fn settings_scope_round_trips_through_its_string_form() {
        // These strings are persisted and appear in API payloads, so Display
        // and FromStr have to stay each other's inverse.
        for scope in [SettingsScope::Org, SettingsScope::Tenant] {
            let text = scope.to_string();
            let parsed: SettingsScope = text.parse().unwrap();
            assert_eq!(parsed, scope, "{text} must parse back to itself");
        }
        assert_eq!(SettingsScope::Org.to_string(), "org");
        assert_eq!(SettingsScope::Tenant.to_string(), "tenant");
    }

    #[test]
    fn an_unknown_settings_scope_is_an_error_naming_the_input() {
        let err = "organisation".parse::<SettingsScope>().unwrap_err();
        assert!(
            err.contains("organisation"),
            "the error must name what was rejected: {err}"
        );
        assert!(
            "Org".parse::<SettingsScope>().is_err(),
            "parsing is case-sensitive"
        );
        assert!("".parse::<SettingsScope>().is_err());
    }

    // --- diff_against_org completeness ---

    /// Every overridable field must appear in the diff when it differs.
    ///
    /// The existing `diff_against_org` tests change four fields, which leaves
    /// the other nineteen comparisons executed only down their "same" branch.
    /// That is precisely the shape of bug this guards: a field added to
    /// `SecuritySettings` and forgotten in `diff_against_org` produces a tenant
    /// override that silently drops it, so an administrator sets a value, the
    /// API accepts it, and the setting never takes effect. Nothing errors.
    #[test]
    fn diff_against_org_reports_every_field_that_differs() {
        let org = org_settings();

        let mut changed = system_defaults();
        changed.min_length += 4;
        changed.require_uppercase = !changed.require_uppercase;
        changed.require_lowercase = !changed.require_lowercase;
        changed.require_digits = !changed.require_digits;
        changed.require_symbols = !changed.require_symbols;
        changed.password_history_count += 3;
        changed.hibp_check_enabled = !changed.hibp_check_enabled;
        changed.mfa_enforced = !changed.mfa_enforced;
        changed.mfa_challenge_lifetime_secs += 60;
        changed.max_failed_login_attempts += 2;
        changed.lockout_duration_secs += 30;
        changed.lockout_backoff_multiplier += 0.5;
        // Kept >= lockout_duration_secs so the row stays internally consistent;
        // this test is about the diff, not about validation rejecting nonsense.
        changed.max_lockout_duration_secs += 3_600;
        changed.access_token_lifetime_secs += 100;
        changed.refresh_token_lifetime_secs += 1_000;
        changed.email_verification_required = !changed.email_verification_required;
        changed.email_verification_grace_period_hours += 12;
        changed.default_cert_validity_days += 5;
        changed.max_cert_validity_days += 50;
        changed.admin_notifications_enabled = !changed.admin_notifications_enabled;
        changed.opaque_mode = OpaqueMode::Optional;
        changed.opaque_ksf = OpaqueKsf::Scrypt;
        // `opaque_suite` is deliberately NOT changed: `OpaqueSuite` has exactly
        // one variant, so it cannot differ from the baseline and its branch is
        // unreachable until a second suite exists.

        let tenant = settings_from_org_input(Uuid::new_v4(), Uuid::new_v4(), &changed);
        let diff = diff_against_org(&org, &tenant);

        assert_eq!(diff.min_length, Some(changed.min_length));
        assert_eq!(diff.require_uppercase, Some(changed.require_uppercase));
        assert_eq!(diff.require_lowercase, Some(changed.require_lowercase));
        assert_eq!(diff.require_digits, Some(changed.require_digits));
        assert_eq!(diff.require_symbols, Some(changed.require_symbols));
        assert_eq!(
            diff.password_history_count,
            Some(changed.password_history_count)
        );
        assert_eq!(diff.hibp_check_enabled, Some(changed.hibp_check_enabled));
        assert_eq!(diff.mfa_enforced, Some(changed.mfa_enforced));
        assert_eq!(
            diff.mfa_challenge_lifetime_secs,
            Some(changed.mfa_challenge_lifetime_secs)
        );
        assert_eq!(
            diff.max_failed_login_attempts,
            Some(changed.max_failed_login_attempts)
        );
        assert_eq!(
            diff.lockout_duration_secs,
            Some(changed.lockout_duration_secs)
        );
        assert_eq!(
            diff.lockout_backoff_multiplier,
            Some(changed.lockout_backoff_multiplier)
        );
        assert_eq!(
            diff.max_lockout_duration_secs,
            Some(changed.max_lockout_duration_secs)
        );
        assert_eq!(
            diff.access_token_lifetime_secs,
            Some(changed.access_token_lifetime_secs)
        );
        assert_eq!(
            diff.refresh_token_lifetime_secs,
            Some(changed.refresh_token_lifetime_secs)
        );
        assert_eq!(
            diff.email_verification_required,
            Some(changed.email_verification_required)
        );
        assert_eq!(
            diff.email_verification_grace_period_hours,
            Some(changed.email_verification_grace_period_hours)
        );
        assert_eq!(
            diff.default_cert_validity_days,
            Some(changed.default_cert_validity_days)
        );
        assert_eq!(
            diff.max_cert_validity_days,
            Some(changed.max_cert_validity_days)
        );
        assert_eq!(
            diff.admin_notifications_enabled,
            Some(changed.admin_notifications_enabled)
        );
        assert_eq!(diff.opaque_mode, Some(changed.opaque_mode));
        assert_eq!(diff.opaque_ksf, Some(changed.opaque_ksf));
    }

    /// The mirror of the test above: an identical tenant produces an override
    /// with nothing set, so re-saving unchanged settings does not manufacture
    /// overrides that then pin the tenant against future org-baseline changes.
    #[test]
    fn diff_against_org_sets_nothing_when_the_tenant_matches_the_baseline() {
        let org = org_settings();
        let same = settings_from_org_input(Uuid::new_v4(), Uuid::new_v4(), &system_defaults());
        assert!(diff_against_org(&org, &same).is_empty());
    }

    // --- Privacy: the erasure grace window ---

    #[test]
    fn the_default_grace_window_is_the_thirty_days_the_handler_hard_coded() {
        assert_eq!(system_defaults().deletion_grace_period_days, 30);
    }

    #[test]
    fn a_zero_day_grace_window_is_refused() {
        // It would purge on the same request that scheduled the erasure,
        // leaving the cancel link in the confirmation email pointing at an
        // account that is already gone.
        let mut input = system_defaults();
        input.deletion_grace_period_days = 0;
        let err = validate_org_settings(&input).unwrap_err();
        assert!(err.to_string().contains("deletion_grace_period_days"));
    }

    #[test]
    fn a_grace_window_past_the_gdpr_ceiling_is_refused() {
        let mut input = system_defaults();
        input.deletion_grace_period_days = MAX_DELETION_GRACE_PERIOD_DAYS + 1;
        let err = validate_org_settings(&input).unwrap_err();
        assert!(err.to_string().contains("Art. 12(3)"), "{err}");

        input.deletion_grace_period_days = MAX_DELETION_GRACE_PERIOD_DAYS;
        assert!(validate_org_settings(&input).is_ok());
    }

    // -------------------------------------------------------------------
    // WebAuthn user verification
    // -------------------------------------------------------------------

    #[test]
    fn user_verification_defaults_to_preferred_so_a_pinless_security_key_enrols() {
        // The bug this setting exists for: `webauthn-rs` hard-codes
        // `UserVerificationPolicy::Required` on the passkey ceremony, so a
        // YubiKey with no PIN — which can only ever set the UP bit, never UV —
        // was refused at `finish_registration` with "The user verified bit is
        // not set, and required by policy". Defaulting to `required` here would
        // reproduce that for every new deployment.
        assert_eq!(
            system_defaults().webauthn_user_verification,
            WebauthnUserVerification::Preferred,
        );
    }

    #[test]
    fn user_verification_is_ranked_by_strictness_not_declaration_order() {
        use WebauthnUserVerification::{Discouraged, Preferred, Required};
        assert!(user_verification_is_at_least(Required, Discouraged));
        assert!(user_verification_is_at_least(Required, Preferred));
        assert!(user_verification_is_at_least(Preferred, Discouraged));
        // Equal is "at least", which is what lets a tenant restate the
        // baseline without the write being rejected.
        assert!(user_verification_is_at_least(Preferred, Preferred));
        assert!(!user_verification_is_at_least(Preferred, Required));
        assert!(!user_verification_is_at_least(Discouraged, Preferred));
    }

    #[test]
    fn a_tenant_may_demand_user_verification_the_org_only_prefers() {
        let org = org_settings();
        let overrides = TenantSettingsOverride {
            webauthn_user_verification: Some(WebauthnUserVerification::Required),
            ..Default::default()
        };
        assert!(validate_tenant_override(&org, &overrides).is_ok());

        let merged = effective_settings(&org, &overrides, Uuid::nil(), Uuid::nil());
        assert_eq!(
            merged.webauthn.webauthn_user_verification,
            WebauthnUserVerification::Required,
        );
    }

    #[test]
    fn a_tenant_may_not_stop_requiring_user_verification_the_org_requires() {
        let mut org = org_settings();
        org.webauthn.webauthn_user_verification = WebauthnUserVerification::Required;
        let overrides = TenantSettingsOverride {
            webauthn_user_verification: Some(WebauthnUserVerification::Discouraged),
            ..Default::default()
        };
        let err = validate_tenant_override(&org, &overrides)
            .expect_err("relaxing the org baseline must be refused");
        assert!(
            err.to_string().contains("webauthn_user_verification"),
            "the error must name the offending field: {err}",
        );
    }

    #[test]
    fn raising_the_org_baseline_clears_a_tenant_override_it_has_overtaken() {
        // The org moves from `preferred` to `required`; a tenant that had
        // pinned `preferred` must not keep it. Clearing rather than rewriting
        // is what makes the tenant track the baseline from now on.
        let mut org = org_settings();
        org.webauthn.webauthn_user_verification = WebauthnUserVerification::Required;
        let mut overrides = TenantSettingsOverride {
            webauthn_user_verification: Some(WebauthnUserVerification::Preferred),
            ..Default::default()
        };
        let cleared = clamp_overrides_to_org(&org, &mut overrides);
        assert_eq!(cleared, vec!["webauthn_user_verification"]);
        assert_eq!(overrides.webauthn_user_verification, None);
    }

    #[test]
    fn a_stricter_tenant_override_survives_a_raised_org_baseline() {
        let org = org_settings(); // preferred
        let mut overrides = TenantSettingsOverride {
            webauthn_user_verification: Some(WebauthnUserVerification::Required),
            ..Default::default()
        };
        let cleared = clamp_overrides_to_org(&org, &mut overrides);
        assert!(cleared.is_empty(), "cleared: {cleared:?}");
        assert_eq!(
            overrides.webauthn_user_verification,
            Some(WebauthnUserVerification::Required),
        );
    }

    #[test]
    fn user_verification_round_trips_through_the_sparse_diff() {
        let org = org_settings();
        let mut tenant = org.clone();
        tenant.webauthn.webauthn_user_verification = WebauthnUserVerification::Required;

        let diff = diff_against_org(&org, &tenant);
        assert_eq!(
            diff.webauthn_user_verification,
            Some(WebauthnUserVerification::Required),
        );

        let merged = effective_settings(&org, &diff, Uuid::nil(), Uuid::nil());
        assert_eq!(
            merged.webauthn.webauthn_user_verification,
            WebauthnUserVerification::Required,
        );
    }

    #[test]
    fn user_verification_survives_its_string_form_in_both_directions() {
        // The DB column stores the `Display` form and parses it back; a
        // spelling that did not round-trip would silently decode to the
        // default, which for this field means a policy quietly relaxing.
        for uv in [
            WebauthnUserVerification::Discouraged,
            WebauthnUserVerification::Preferred,
            WebauthnUserVerification::Required,
        ] {
            let parsed: WebauthnUserVerification = uv
                .to_string()
                .parse()
                .expect("the Display form must parse back");
            assert_eq!(parsed, uv);
        }
        assert!("sometimes".parse::<WebauthnUserVerification>().is_err());
    }

    #[test]
    fn a_tenant_may_shorten_the_grace_window_but_not_lengthen_it() {
        // Shorter is more restrictive: less time holding data the subject has
        // already asked to have erased.
        let org = org_settings();

        let shorter = TenantSettingsOverride {
            deletion_grace_period_days: Some(7),
            ..Default::default()
        };
        assert!(validate_tenant_override(&org, &shorter).is_ok());

        let longer = TenantSettingsOverride {
            deletion_grace_period_days: Some(60),
            ..Default::default()
        };
        let err = validate_tenant_override(&org, &longer).unwrap_err();
        assert!(
            err.to_string().contains("deletion_grace_period_days"),
            "{err}"
        );
    }

    #[test]
    fn a_zero_day_tenant_override_is_refused_by_the_cross_field_check() {
        // 0 passes the "more restrictive" comparison on its own, and produces
        // an erasure nothing can cancel.
        let org = org_settings();
        let zero = TenantSettingsOverride {
            deletion_grace_period_days: Some(0),
            ..Default::default()
        };
        let err = validate_tenant_override(&org, &zero).unwrap_err();
        assert!(
            err.to_string().contains("deletion_grace_period_days"),
            "{err}"
        );
    }

    #[test]
    fn an_omitted_grace_window_inherits_the_org_baseline() {
        let mut input = system_defaults();
        input.deletion_grace_period_days = 14;
        let org = settings_from_org_input(Uuid::new_v4(), Uuid::new_v4(), &input);

        let merged = effective_settings(
            &org,
            &TenantSettingsOverride::default(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        assert_eq!(merged.privacy.deletion_grace_period_days, 14);
    }

    #[test]
    fn the_grace_window_round_trips_through_the_sparse_diff() {
        let org = org_settings();
        let overrides = TenantSettingsOverride {
            deletion_grace_period_days: Some(3),
            ..Default::default()
        };
        let merged = effective_settings(&org, &overrides, Uuid::new_v4(), Uuid::new_v4());
        assert_eq!(
            diff_against_org(&org, &merged).deletion_grace_period_days,
            Some(3)
        );
    }

    // -------------------------------------------------------------------
    // X7 G8 — the sensitive-scopes switch and the tenant default locale
    // -------------------------------------------------------------------

    /// I3, at the model layer: a deployment that has configured nothing
    /// releases no sensitive scope.
    #[test]
    fn sensitive_scopes_are_off_in_the_system_defaults() {
        assert!(!system_defaults().sensitive_scopes_enabled);
        assert!(!org_settings().oidc.sensitive_scopes_enabled);
        assert_eq!(system_defaults().default_locale, None);
    }

    /// The switch is disable-only. A tenant may refuse a release its
    /// organization allows; it may not authorise one its organization did not.
    #[test]
    fn a_tenant_may_not_enable_sensitive_scopes_its_org_disabled() {
        let org = org_settings();
        assert!(!org.oidc.sensitive_scopes_enabled);
        let overrides = TenantSettingsOverride {
            sensitive_scopes_enabled: Some(true),
            ..Default::default()
        };
        let err = validate_tenant_override(&org, &overrides)
            .expect_err("enabling a release the org disabled must be refused");
        assert!(
            err.to_string().contains("sensitive_scopes_enabled"),
            "the violation must name the field: {err}"
        );
    }

    /// The tightening direction is accepted, and it takes effect.
    #[test]
    fn a_tenant_may_disable_sensitive_scopes_its_org_enabled() {
        let mut org = org_settings();
        org.oidc.sensitive_scopes_enabled = true;
        let overrides = TenantSettingsOverride {
            sensitive_scopes_enabled: Some(false),
            ..Default::default()
        };
        validate_tenant_override(&org, &overrides).expect("turning a release off must be allowed");
        let merged = effective_settings(&org, &overrides, Uuid::nil(), Uuid::nil());
        assert!(!merged.oidc.sensitive_scopes_enabled);
    }

    /// An organization that turns the switch back off takes it away from every
    /// tenant that had opted in, rather than leaving them releasing data on a
    /// baseline that no longer permits it. The clamp is what makes the
    /// disable-only rule survive a baseline change, exactly as it does for
    /// `mfa_enforced`.
    #[test]
    fn clamping_drops_a_tenant_optin_the_org_has_since_withdrawn() {
        let org = org_settings();
        let mut overrides = TenantSettingsOverride {
            sensitive_scopes_enabled: Some(true),
            ..Default::default()
        };
        let cleared = clamp_overrides_to_org(&org, &mut overrides);
        assert!(cleared.contains(&"sensitive_scopes_enabled"));
        assert_eq!(overrides.sensitive_scopes_enabled, None);
        assert!(
            !effective_settings(&org, &overrides, Uuid::nil(), Uuid::nil())
                .oidc
                .sensitive_scopes_enabled
        );
    }

    /// A tenant that says `false` against an org that says `false` is not
    /// cleared — it is already the restrictive value, and clearing it would
    /// silently re-enable the tenant the day the org enables the switch.
    #[test]
    fn clamping_keeps_a_tenant_optout() {
        let org = org_settings();
        let mut overrides = TenantSettingsOverride {
            sensitive_scopes_enabled: Some(false),
            ..Default::default()
        };
        assert!(clamp_overrides_to_org(&org, &mut overrides).is_empty());
        assert_eq!(overrides.sensitive_scopes_enabled, Some(false));
    }

    /// `default_locale` has no restrictiveness ordering, so neither gate
    /// touches it: any tag validates, and the clamp never clears it. This is
    /// the property `OidcPolicy`'s docs claim, asserted rather than described.
    #[test]
    fn the_tenant_default_locale_is_neither_validated_nor_clamped() {
        let org = org_settings();
        let mut overrides = TenantSettingsOverride {
            default_locale: Some("it".into()),
            ..Default::default()
        };
        validate_tenant_override(&org, &overrides)
            .expect("a locale cannot be less restrictive than another locale");
        assert!(clamp_overrides_to_org(&org, &mut overrides).is_empty());
        assert_eq!(overrides.default_locale.as_deref(), Some("it"));
        assert_eq!(
            effective_settings(&org, &overrides, Uuid::nil(), Uuid::nil())
                .oidc
                .default_locale
                .as_deref(),
            Some("it")
        );
    }

    /// An absent tenant locale inherits the organization's, which is what
    /// makes it a *default* rather than a per-tenant requirement.
    #[test]
    fn an_absent_tenant_locale_inherits_the_org_baseline() {
        let mut org = org_settings();
        org.oidc.default_locale = Some("de".into());
        let merged = effective_settings(
            &org,
            &TenantSettingsOverride::default(),
            Uuid::nil(),
            Uuid::nil(),
        );
        assert_eq!(merged.oidc.default_locale.as_deref(), Some("de"));
    }

    /// I4 at this layer: an override written before X7 G8 existed carries
    /// neither field, and merging it changes nothing.
    #[test]
    fn an_override_from_before_this_wave_still_deserialises_and_changes_nothing() {
        let legacy: TenantSettingsOverride =
            serde_json::from_str(r#"{"min_length": 16}"#).expect("a pre-W7 override must decode");
        assert_eq!(legacy.sensitive_scopes_enabled, None);
        assert_eq!(legacy.default_locale, None);
        let org = org_settings();
        let merged = effective_settings(&org, &legacy, Uuid::nil(), Uuid::nil());
        assert_eq!(
            merged.oidc, org.oidc,
            "an override that says nothing about the OIDC policy must inherit all of it"
        );
    }

    /// `diff_against_org` round-trips both fields, so the admin UI's
    /// "what has this tenant changed" view does not lose them.
    #[test]
    fn diff_against_org_reports_both_oidc_fields() {
        let mut org = org_settings();
        org.oidc.sensitive_scopes_enabled = true;
        let overrides = TenantSettingsOverride {
            sensitive_scopes_enabled: Some(false),
            default_locale: Some("fr".into()),
            ..Default::default()
        };
        let merged = effective_settings(&org, &overrides, Uuid::nil(), Uuid::nil());
        let diff = diff_against_org(&org, &merged);
        assert_eq!(diff.sensitive_scopes_enabled, Some(false));
        assert_eq!(diff.default_locale.as_deref(), Some("fr"));
    }

    // -----------------------------------------------------------------------
    // The clamp, field by field
    //
    // `clamp_overrides_to_org` is the control that stops a tenant keeping a
    // weaker policy after the organization tightens its baseline. Three tests
    // covered three fields; the other twenty arms were asserted nowhere, and an
    // arm that silently stops clearing looks exactly like an arm that had
    // nothing to clear. These walk every one in a single pass, in both
    // directions.
    // -----------------------------------------------------------------------

    /// An org baseline with every boolean requirement switched ON, so that a
    /// tenant saying `false` is unambiguously the weaker position.
    fn a_demanding_org() -> SecuritySettings {
        let mut org = org_settings();
        org.password.require_uppercase = true;
        org.password.require_lowercase = true;
        org.password.require_digits = true;
        org.password.require_symbols = true;
        org.password.hibp_check_enabled = true;
        org.mfa.mfa_enforced = true;
        org.email.email_verification_required = true;
        org.notification.admin_notifications_enabled = true;
        org
    }

    /// Every clamped field set one step *weaker* than `org`.
    fn every_field_weaker_than(org: &SecuritySettings) -> TenantSettingsOverride {
        TenantSettingsOverride {
            // `tenant >= org` — a lower minimum is the weaker one.
            min_length: Some(org.password.min_length - 1),
            password_history_count: Some(org.password.password_history_count - 1),
            lockout_duration_secs: Some(org.lockout.lockout_duration_secs - 1),
            max_lockout_duration_secs: Some(org.lockout.max_lockout_duration_secs - 1),
            lockout_backoff_multiplier: Some(org.lockout.lockout_backoff_multiplier - 0.5),
            // `tenant <= org` — a larger cap or longer lifetime is the weaker one.
            max_failed_login_attempts: Some(org.lockout.max_failed_login_attempts + 1),
            access_token_lifetime_secs: Some(org.token.access_token_lifetime_secs + 1),
            refresh_token_lifetime_secs: Some(org.token.refresh_token_lifetime_secs + 1),
            mfa_challenge_lifetime_secs: Some(org.mfa.mfa_challenge_lifetime_secs + 1),
            default_cert_validity_days: Some(org.certificate.default_cert_validity_days + 1),
            max_cert_validity_days: Some(org.certificate.max_cert_validity_days + 1),
            email_verification_grace_period_hours: Some(
                org.email.email_verification_grace_period_hours + 1,
            ),
            deletion_grace_period_days: Some(org.privacy.deletion_grace_period_days + 1),
            // Opt-in only — the org requires it, the tenant tries to switch off.
            require_uppercase: Some(false),
            require_lowercase: Some(false),
            require_digits: Some(false),
            require_symbols: Some(false),
            hibp_check_enabled: Some(false),
            mfa_enforced: Some(false),
            email_verification_required: Some(false),
            admin_notifications_enabled: Some(false),
            ..Default::default()
        }
    }

    #[test]
    fn every_clamped_field_is_cleared_when_the_tenant_is_the_weaker_of_the_two() {
        let org = a_demanding_org();
        let mut overrides = every_field_weaker_than(&org);

        let cleared = clamp_overrides_to_org(&org, &mut overrides);

        for field in [
            "min_length",
            "password_history_count",
            "lockout_duration_secs",
            "max_lockout_duration_secs",
            "lockout_backoff_multiplier",
            "max_failed_login_attempts",
            "access_token_lifetime_secs",
            "refresh_token_lifetime_secs",
            "mfa_challenge_lifetime_secs",
            "default_cert_validity_days",
            "max_cert_validity_days",
            "email_verification_grace_period_hours",
            "deletion_grace_period_days",
            "require_uppercase",
            "require_lowercase",
            "require_digits",
            "require_symbols",
            "hibp_check_enabled",
            "mfa_enforced",
            "email_verification_required",
            "admin_notifications_enabled",
        ] {
            assert!(
                cleared.contains(&field),
                "{field} was left in place though the tenant value is weaker; cleared: {cleared:?}"
            );
        }
    }

    #[test]
    fn a_cleared_field_is_removed_rather_than_rewritten_to_the_org_value() {
        // The distinction the doc calls out: an absent override *tracks* the
        // baseline, so the tenant also picks up the next tightening. Writing
        // the org's current value in would freeze it again and reproduce the
        // original defect one baseline later.
        let org = a_demanding_org();
        let mut overrides = every_field_weaker_than(&org);

        clamp_overrides_to_org(&org, &mut overrides);

        assert_eq!(overrides.min_length, None);
        assert_eq!(overrides.access_token_lifetime_secs, None);
        assert_eq!(overrides.mfa_enforced, None);
        assert_eq!(overrides.lockout_backoff_multiplier, None);
    }

    #[test]
    fn a_tenant_stricter_than_the_org_keeps_every_field_it_chose() {
        // The other half of the contract, and the one a too-eager clamp would
        // break: a tenant that picked a 24-character minimum does not lose it
        // because the organization moved from 12 to 16.
        let org = a_demanding_org();
        let mut overrides = TenantSettingsOverride {
            min_length: Some(org.password.min_length + 1),
            password_history_count: Some(org.password.password_history_count + 1),
            lockout_duration_secs: Some(org.lockout.lockout_duration_secs + 1),
            max_lockout_duration_secs: Some(org.lockout.max_lockout_duration_secs + 1),
            lockout_backoff_multiplier: Some(org.lockout.lockout_backoff_multiplier + 0.5),
            max_failed_login_attempts: Some(org.lockout.max_failed_login_attempts - 1),
            access_token_lifetime_secs: Some(org.token.access_token_lifetime_secs - 1),
            refresh_token_lifetime_secs: Some(org.token.refresh_token_lifetime_secs - 1),
            mfa_challenge_lifetime_secs: Some(org.mfa.mfa_challenge_lifetime_secs - 1),
            default_cert_validity_days: Some(org.certificate.default_cert_validity_days - 1),
            max_cert_validity_days: Some(org.certificate.max_cert_validity_days - 1),
            email_verification_grace_period_hours: Some(
                org.email.email_verification_grace_period_hours - 1,
            ),
            deletion_grace_period_days: Some(org.privacy.deletion_grace_period_days - 1),
            require_uppercase: Some(true),
            require_lowercase: Some(true),
            require_digits: Some(true),
            require_symbols: Some(true),
            hibp_check_enabled: Some(true),
            mfa_enforced: Some(true),
            email_verification_required: Some(true),
            admin_notifications_enabled: Some(true),
            ..Default::default()
        };

        let cleared = clamp_overrides_to_org(&org, &mut overrides);

        assert!(cleared.is_empty(), "wrongly cleared: {cleared:?}");
        assert_eq!(overrides.min_length, Some(org.password.min_length + 1));
    }

    #[test]
    fn an_override_that_matches_the_org_exactly_is_left_alone() {
        // Equality is compliance on both sides of the comparison. Clearing here
        // would be harmless for the effective value but would report a field as
        // "cleared" that the tenant never weakened, and that list is what an
        // operator is shown.
        let org = a_demanding_org();
        let mut overrides = TenantSettingsOverride {
            min_length: Some(org.password.min_length),
            max_failed_login_attempts: Some(org.lockout.max_failed_login_attempts),
            access_token_lifetime_secs: Some(org.token.access_token_lifetime_secs),
            mfa_enforced: Some(true),
            ..Default::default()
        };

        let cleared = clamp_overrides_to_org(&org, &mut overrides);

        assert!(cleared.is_empty(), "wrongly cleared: {cleared:?}");
    }

    #[test]
    fn an_override_that_sets_nothing_clears_nothing() {
        let org = a_demanding_org();
        let mut overrides = TenantSettingsOverride::default();

        assert!(clamp_overrides_to_org(&org, &mut overrides).is_empty());
    }

    // -------------------------------------------------------------------
    // T21.5 — client ID metadata documents
    // -------------------------------------------------------------------

    /// I1, at the settings layer: a deployment that changes nothing resolves
    /// no URL-shaped `client_id`, and the shipped policy is internally
    /// consistent so nothing an existing deployment writes starts failing.
    #[test]
    fn cimd_is_off_and_consistent_by_default() {
        let d = system_defaults();
        assert!(!d.cimd.enabled);
        assert!(!d.cimd.allow_http);
        assert!(d.cimd.trusted_client_id_domains.is_empty());
        assert!(d.cimd.restrict_same_domain, "the stricter default");
        assert_eq!(d.cimd.min_cache_secs, DEFAULT_CIMD_MIN_CACHE_SECS);
        assert_eq!(d.cimd.max_cache_secs, DEFAULT_CIMD_MAX_CACHE_SECS);
        assert_eq!(d.cimd.max_metadata_bytes, DEFAULT_CIMD_MAX_METADATA_BYTES);
        assert!(validate_org_settings(&d).is_ok());
    }

    /// A staged posture — every field set, `enabled` still false — is not
    /// validated, so an operator can prepare one before turning it on.
    #[test]
    fn a_disabled_cimd_policy_is_not_validated() {
        assert!(
            validate_org_settings(&SetOrgSettings {
                cimd: CimdPolicy {
                    enabled: false,
                    min_cache_secs: 1,
                    max_metadata_bytes: 0,
                    ..CimdPolicy::default()
                },
                ..system_defaults()
            })
            .is_ok()
        );
    }

    /// The D3 interlock, for the second external mechanism. Same control,
    /// same reason as `anonymous_registration_needs_at_least_one_audience`.
    #[test]
    fn enabling_cimd_needs_at_least_one_audience() {
        let base = SetOrgSettings {
            cimd: CimdPolicy {
                enabled: true,
                trusted_client_id_domains: vec!["*.example.com".into()],
                ..CimdPolicy::default()
            },
            external_client_allowed_resources: Vec::new(),
            ..system_defaults()
        };
        let err = validate_org_settings(&base)
            .expect_err("cimd with no audiences must be refused")
            .to_string();
        assert!(err.contains("D3"), "{err}");
        assert!(err.contains("external_client_allowed_resources"), "{err}");

        assert!(
            validate_org_settings(&SetOrgSettings {
                external_client_allowed_resources: vec!["https://mcp.example.com/mcp".into()],
                ..base
            })
            .is_ok()
        );
    }

    /// The second interlock, which is AXIAM's own: the fetch is reachable by
    /// an unauthenticated caller who chooses the URL, so the publishers are
    /// named in advance or the mechanism does not turn on.
    #[test]
    fn enabling_cimd_needs_at_least_one_trusted_publisher() {
        let err = validate_org_settings(&SetOrgSettings {
            cimd: CimdPolicy {
                enabled: true,
                trusted_client_id_domains: Vec::new(),
                ..CimdPolicy::default()
            },
            external_client_allowed_resources: vec!["https://mcp.example.com/mcp".into()],
            ..system_defaults()
        })
        .expect_err("cimd with no trusted publisher must be refused")
        .to_string();
        assert!(err.contains("trusted_client_id_domains"), "{err}");
    }

    /// **T21.8 / MCP-03.** A trusted-publisher list that names every host is
    /// refused, at both settings doors, in every spelling that means it.
    ///
    /// The empty list is refused because an unrestricted trusted-publisher
    /// list is a request-forgery primitive offered to strangers and no second
    /// control does that job. `["*"]` produced that posture and was admitted,
    /// so the refusal had a one-character bypass and was not the control it
    /// claimed to be. `["*.com"]` is the same posture over one top-level
    /// domain.
    #[test]
    fn a_wildcard_trusted_publisher_is_refused() {
        let wide = |entries: Vec<String>| CimdPolicy {
            enabled: true,
            trusted_client_id_domains: entries,
            ..CimdPolicy::default()
        };
        let resources = vec!["https://mcp.example.com/mcp".into()];

        for entry in ["*", " * ", "*.com", "*.io", "*.LOCALHOST"] {
            // Door 1: the organization baseline.
            let err = validate_org_settings(&SetOrgSettings {
                cimd: wide(vec![entry.into()]),
                external_client_allowed_resources: resources.clone(),
                ..system_defaults()
            })
            .expect_err("a wildcard publisher must be refused at the org door")
            .to_string();
            assert!(
                err.contains("trusted_client_id_domains"),
                "the refusal must name the field for {entry:?}: {err}"
            );

            // Door 2: a tenant override, validated on the merged policy. The
            // organization here is a legal, narrow posture, so a refusal can
            // only come from the tenant's own entry.
            let org = settings_from_org_input(
                Uuid::new_v4(),
                Uuid::new_v4(),
                &SetOrgSettings {
                    cimd: wide(vec!["*.example.com".into()]),
                    external_client_allowed_resources: resources.clone(),
                    ..system_defaults()
                },
            );
            let err = validate_tenant_override(
                &org,
                &TenantSettingsOverride {
                    cimd: Some(wide(vec![entry.into()])),
                    ..Default::default()
                },
            )
            .expect_err("a wildcard publisher must be refused at the tenant door")
            .to_string();
            assert!(
                err.contains("trusted_client_id_domains"),
                "the tenant door must refuse {entry:?} too: {err}"
            );
        }

        // What still passes, and must: naming a publisher, and naming one that
        // happens to be shared hosting. This is a floor, not a public-suffix
        // check — `*.github.io` is the operator's decision to make, bounded by
        // the per-tenant quota rather than by this condition.
        for entry in ["mcp.example.com", "*.example.com", "*.github.io", "*.co.uk"] {
            assert!(
                validate_org_settings(&SetOrgSettings {
                    cimd: wide(vec![entry.into()]),
                    external_client_allowed_resources: resources.clone(),
                    ..system_defaults()
                })
                .is_ok(),
                "{entry:?} names a publisher and must be accepted"
            );
        }

        // And `*` keeps working where it was never the finding: a redirect
        // domain is not a fetch target, the loopback three are allowed
        // whatever the list says, and an empty list is a working posture.
        assert!(
            validate_org_settings(&SetOrgSettings {
                cimd: CimdPolicy {
                    enabled: true,
                    trusted_client_id_domains: vec!["*.example.com".into()],
                    trusted_redirect_domains: vec!["*".into()],
                    ..CimdPolicy::default()
                },
                external_client_allowed_resources: resources.clone(),
                ..system_defaults()
            })
            .is_ok(),
            "* is still valid for trusted_redirect_domains"
        );

        // I1: with CIMD off the condition is unreachable, so a staged posture
        // carrying `*` is stored as it was before T21.8. The validator returns
        // before the trusted-publisher rules are read at all.
        assert!(
            validate_org_settings(&SetOrgSettings {
                cimd: CimdPolicy {
                    trusted_client_id_domains: vec!["*".into()],
                    ..CimdPolicy::default()
                },
                external_client_allowed_resources: resources,
                ..system_defaults()
            })
            .is_ok(),
            "a disabled CIMD policy is not validated: nothing on the request path reads it"
        );
    }

    /// Each bound is refused outside its range, rather than silently clamped:
    /// an operator who writes an impossible bound is told.
    #[test]
    fn every_cimd_bound_is_refused_out_of_range() {
        let enabled = |cimd: CimdPolicy| SetOrgSettings {
            cimd,
            external_client_allowed_resources: vec!["https://mcp.example.com/mcp".into()],
            ..system_defaults()
        };
        let base = CimdPolicy {
            enabled: true,
            trusted_client_id_domains: vec!["*.example.com".into()],
            ..CimdPolicy::default()
        };

        for (cimd, needle) in [
            (
                CimdPolicy {
                    min_cache_secs: 5,
                    ..base.clone()
                },
                "min_cache_secs",
            ),
            (
                CimdPolicy {
                    max_cache_secs: CIMD_MAX_CACHE_CEILING_SECS + 1,
                    ..base.clone()
                },
                "max_cache_secs",
            ),
            (
                CimdPolicy {
                    min_cache_secs: 4_000,
                    max_cache_secs: 1_000,
                    ..base.clone()
                },
                "min_cache_secs",
            ),
            (
                CimdPolicy {
                    max_metadata_bytes: 0,
                    ..base.clone()
                },
                "max_metadata_bytes",
            ),
            (
                CimdPolicy {
                    max_metadata_bytes: CIMD_MAX_METADATA_BYTES_CEILING + 1,
                    ..base.clone()
                },
                "max_metadata_bytes",
            ),
            (
                CimdPolicy {
                    trusted_client_id_domains: vec!["https://example.com/mcp.json".into()],
                    ..base.clone()
                },
                "trusted_client_id_domains",
            ),
            (
                CimdPolicy {
                    trusted_redirect_domains: vec!["example.com:8443".into()],
                    ..base.clone()
                },
                "trusted_redirect_domains",
            ),
        ] {
            let err = validate_org_settings(&enabled(cimd))
                .expect_err("out-of-range bound must be refused")
                .to_string();
            assert!(
                err.contains(needle),
                "the refusal must name {needle}: {err}"
            );
        }
    }

    /// The clamping accessors are the second line: whatever is stored, what
    /// the fetch path uses is inside the deployment's own range.
    #[test]
    fn the_clamping_accessors_bound_a_hand_edited_row() {
        let wild = CimdPolicy {
            min_cache_secs: 0,
            max_cache_secs: u64::MAX,
            max_metadata_bytes: u64::MAX,
            ..CimdPolicy::default()
        };
        assert_eq!(wild.clamp_cache_secs(Some(1)), CIMD_MIN_CACHE_FLOOR_SECS);
        assert_eq!(wild.clamp_cache_secs(None), CIMD_MIN_CACHE_FLOOR_SECS);
        assert_eq!(
            wild.clamp_cache_secs(Some(u64::MAX)),
            CIMD_MAX_CACHE_CEILING_SECS
        );
        assert_eq!(
            wild.effective_max_metadata_bytes() as u64,
            CIMD_MAX_METADATA_BYTES_CEILING
        );

        // A publisher's own value inside the range is honoured.
        let ordinary = CimdPolicy::default();
        assert_eq!(ordinary.clamp_cache_secs(Some(1_800)), 1_800);
    }

    /// The two halves of the posture that can widen are ordered against the
    /// organization's; the other seven are not.
    #[test]
    fn a_tenant_may_not_enable_cimd_its_organization_disabled() {
        let org = settings_from_org_input(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &SetOrgSettings {
                external_client_allowed_resources: vec!["https://mcp.example.com/mcp".into()],
                ..system_defaults()
            },
        );
        let tenant_on = TenantSettingsOverride {
            cimd: Some(CimdPolicy {
                enabled: true,
                trusted_client_id_domains: vec!["*.example.com".into()],
                ..CimdPolicy::default()
            }),
            ..Default::default()
        };
        let err = validate_tenant_override(&org, &tenant_on)
            .expect_err("a tenant may not enable what the org disabled")
            .to_string();
        assert!(err.contains("cimd.enabled"), "{err}");

        // And the clamp drops the whole block rather than half-keeping it.
        let mut clamped = tenant_on.clone();
        let cleared = clamp_overrides_to_org(&org, &mut clamped);
        assert!(cleared.contains(&"cimd"), "{cleared:?}");
        assert!(clamped.cimd.is_none());
    }

    /// The same, for the flag that also opens the SSRF guard's address rule.
    #[test]
    fn a_tenant_may_not_allow_http_its_organization_forbade() {
        let org = settings_from_org_input(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &SetOrgSettings {
                external_client_allowed_resources: vec!["https://mcp.example.com/mcp".into()],
                cimd: CimdPolicy {
                    enabled: true,
                    allow_http: false,
                    trusted_client_id_domains: vec!["*.example.com".into()],
                    ..CimdPolicy::default()
                },
                ..system_defaults()
            },
        );
        let err = validate_tenant_override(
            &org,
            &TenantSettingsOverride {
                cimd: Some(CimdPolicy {
                    enabled: true,
                    allow_http: true,
                    trusted_client_id_domains: vec!["*.example.com".into()],
                    ..CimdPolicy::default()
                }),
                ..Default::default()
            },
        )
        .expect_err("a tenant may not allow http the org forbade")
        .to_string();
        assert!(err.contains("cimd.allow_http"), "{err}");
    }

    /// A tenant may narrow freely: its own publishers, its own bounds, and
    /// the mechanism turned off entirely.
    #[test]
    fn a_tenant_may_state_a_stricter_cimd_posture() {
        let org = settings_from_org_input(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &SetOrgSettings {
                external_client_allowed_resources: vec!["https://mcp.example.com/mcp".into()],
                cimd: CimdPolicy {
                    enabled: true,
                    // A wide-but-legal fixture. `["*"]` read more naturally
                    // here and was what this test used until T21.8 refused it
                    // (MCP-03); neither assertion in this test is about the
                    // value, only about a tenant being able to narrow from it.
                    trusted_client_id_domains: vec!["*.example.com".into()],
                    ..CimdPolicy::default()
                },
                ..system_defaults()
            },
        );
        for candidate in [
            CimdPolicy {
                enabled: false,
                ..CimdPolicy::default()
            },
            CimdPolicy {
                enabled: true,
                confidential_only: true,
                trusted_client_id_domains: vec!["mcp.example.com".into()],
                max_metadata_bytes: 2_000,
                ..CimdPolicy::default()
            },
        ] {
            assert!(
                validate_tenant_override(
                    &org,
                    &TenantSettingsOverride {
                        cimd: Some(candidate.clone()),
                        ..Default::default()
                    }
                )
                .is_ok(),
                "{candidate:?} is stricter and must be accepted"
            );
        }
    }

    /// The posture merges whole, and round-trips through the diff: a tenant
    /// that differs in one field overrides all nine.
    #[test]
    fn the_cimd_posture_merges_and_diffs_whole() {
        let org = settings_from_org_input(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &SetOrgSettings {
                external_client_allowed_resources: vec!["https://mcp.example.com/mcp".into()],
                cimd: CimdPolicy {
                    enabled: true,
                    // A wide-but-legal fixture. `["*"]` read more naturally
                    // here and was what this test used until T21.8 refused it
                    // (MCP-03); neither assertion in this test is about the
                    // value, only about a tenant being able to narrow from it.
                    trusted_client_id_domains: vec!["*.example.com".into()],
                    ..CimdPolicy::default()
                },
                ..system_defaults()
            },
        );
        let tenant_id = Uuid::new_v4();

        // No override: the organization's posture, verbatim.
        let inherited = effective_settings(
            &org,
            &TenantSettingsOverride::default(),
            tenant_id,
            Uuid::new_v4(),
        );
        assert_eq!(inherited.oidc.cimd, org.oidc.cimd);

        // An override: the tenant's posture, verbatim, and the diff recovers it.
        let own = CimdPolicy {
            enabled: true,
            trusted_client_id_domains: vec!["mcp.example.com".into()],
            confidential_only: true,
            ..CimdPolicy::default()
        };
        let merged = effective_settings(
            &org,
            &TenantSettingsOverride {
                cimd: Some(own.clone()),
                ..Default::default()
            },
            tenant_id,
            Uuid::new_v4(),
        );
        assert_eq!(merged.oidc.cimd, own);
        assert_eq!(diff_against_org(&org, &merged).cimd, Some(own));
    }

    /// A settings row written before T21.5 decodes to the closed posture.
    #[test]
    fn a_cimd_policy_missing_every_member_decodes_to_the_default() {
        let decoded: CimdPolicy = serde_json::from_value(serde_json::json!({})).expect("decodes");
        assert_eq!(decoded, CimdPolicy::default());
        assert!(!decoded.enabled);
        assert!(decoded.restrict_same_domain);
    }
}

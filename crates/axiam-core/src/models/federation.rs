//! Federation configuration domain model.
//!
//! Supports external OIDC identity providers (including social login)
//! and SAML service provider integration.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub enum FederationProtocol {
    /// OpenID Connect: a discovery document, and a signed `id_token` that
    /// carries the authentication assertion.
    OidcConnect,
    /// SAML 2.0: a signed assertion posted to the ACS endpoint.
    Saml,
    /// Plain OAuth2, authenticating by a **userinfo call** rather than a
    /// signed ID token.
    ///
    /// This is deliberately a third variant rather than a flag on
    /// [`FederationProtocol::OidcConnect`], because it is a *different trust
    /// statement* and the difference must be visible everywhere the protocol
    /// is: there is no signature, no `nonce` and no `aud` to check. The whole
    /// assurance is "the access token we just received, at a token endpoint we
    /// configured, using a secret only we hold, works against a userinfo
    /// endpoint we configured".
    ///
    /// It exists because GitHub publishes no discovery document and issues no
    /// ID token at all, and because Facebook's web authorization-code flow
    /// returns only an access token to a confidential client. See
    /// `claude_dev/federation-sso-login-design.md` §3.
    OAuth2,
}

impl FederationProtocol {
    /// The wire/storage spelling. One function so the REST layer, the
    /// repository and the schema `ASSERT` cannot drift apart.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OidcConnect => "OidcConnect",
            Self::Saml => "Saml",
            Self::OAuth2 => "OAuth2",
        }
    }

    /// Parse a wire value. Unknown values yield `None` so a caller can refuse
    /// them rather than silently defaulting — a typo must not become OIDC.
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw.trim() {
            "OidcConnect" => Some(Self::OidcConnect),
            "Saml" => Some(Self::Saml),
            "OAuth2" => Some(Self::OAuth2),
            _ => None,
        }
    }

    /// Whether this protocol authenticates without a verifiable signed
    /// assertion, and therefore carries reduced assurance.
    pub const fn is_unsigned_assertion(self) -> bool {
        matches!(self, Self::OAuth2)
    }
}

// ---------------------------------------------------------------------------
// Provider kind
// ---------------------------------------------------------------------------

/// Which identity provider a federation config is for.
///
/// Distinct from `provider`, which is a free-text display name an operator can
/// put anything into. Three separate jobs needed a key that is *not* free text
/// and they all needed the same one: choosing the sign-in button's branding,
/// choosing the per-kind defaults below, and deciding whether a tenant config
/// overrides an inherited organization one (see
/// [`FederationConfig::override_key`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// Google, via OIDC discovery at `accounts.google.com`.
    Google,
    /// GitHub. **Not OIDC** — no discovery document, no ID token.
    Github,
    /// Facebook. Defaults to the OAuth2 variant: the web authorization-code
    /// flow returns only an access token to a confidential client.
    Facebook,
    /// Sign in with Apple. OIDC, with an ES256 client secret AXIAM mints
    /// per exchange rather than storing (see the `apple_*` fields).
    Apple,
    /// Microsoft Entra ID. OIDC; a `common`/`organizations` authority
    /// publishes a templated issuer — see `allowed_issuer_tenants`.
    Microsoft,
    /// Any other OIDC provider.
    GenericOidc,
    /// Any other plain-OAuth2 provider.
    GenericOauth2,
    /// Any SAML 2.0 identity provider.
    GenericSaml,
}

impl ProviderKind {
    /// The wire/storage spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Github => "github",
            Self::Facebook => "facebook",
            Self::Apple => "apple",
            Self::Microsoft => "microsoft",
            Self::GenericOidc => "generic_oidc",
            Self::GenericOauth2 => "generic_oauth2",
            Self::GenericSaml => "generic_saml",
        }
    }

    /// Parse a wire value; unknown values yield `None`.
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw.trim() {
            "google" => Some(Self::Google),
            "github" => Some(Self::Github),
            "facebook" => Some(Self::Facebook),
            "apple" => Some(Self::Apple),
            "microsoft" => Some(Self::Microsoft),
            "generic_oidc" => Some(Self::GenericOidc),
            "generic_oauth2" => Some(Self::GenericOauth2),
            "generic_saml" => Some(Self::GenericSaml),
            _ => None,
        }
    }

    /// Every kind, for enumeration in tests and in the admin UI's option list.
    pub const ALL: &'static [Self] = &[
        Self::Google,
        Self::Github,
        Self::Facebook,
        Self::Apple,
        Self::Microsoft,
        Self::GenericOidc,
        Self::GenericOauth2,
        Self::GenericSaml,
    ];

    /// The kind a row written before `provider_kind` existed reads back as.
    ///
    /// Derived from the protocol rather than guessed from the display name:
    /// `provider` is free text, and a config called "Google SSO (old)" is not
    /// evidence of anything. The generic kinds carry no per-kind behaviour
    /// beyond the OIDC/SAML defaults such a row already had, so this is a
    /// faithful reading of an existing row, not a reclassification.
    pub const fn from_legacy_protocol(protocol: FederationProtocol) -> Self {
        match protocol {
            FederationProtocol::OidcConnect => Self::GenericOidc,
            FederationProtocol::Saml => Self::GenericSaml,
            // Unreachable for a legacy row — `OAuth2` did not exist before
            // `provider_kind` did — but total rather than panicking.
            FederationProtocol::OAuth2 => Self::GenericOauth2,
        }
    }

    /// The protocol this kind uses.
    ///
    /// Not merely a default: [`validate_protocol_for_kind`] refuses any other
    /// pairing for the branded kinds, which is what stops the reduced-assurance
    /// OAuth2 variant being selected for a provider that supports OIDC
    /// properly.
    pub const fn protocol(self) -> FederationProtocol {
        match self {
            Self::Google | Self::Apple | Self::Microsoft | Self::GenericOidc => {
                FederationProtocol::OidcConnect
            }
            Self::Github | Self::GenericOauth2 => FederationProtocol::OAuth2,
            // Facebook's *default*; the one kind where both are admissible.
            // See `validate_protocol_for_kind`.
            Self::Facebook => FederationProtocol::OAuth2,
            Self::GenericSaml => FederationProtocol::Saml,
        }
    }

    /// Whether AXIAM ships this provider's own sign-in mark.
    ///
    /// The branded kinds do, and their marks are **not** replaceable: Google,
    /// Apple and Microsoft all publish sign-in-button rules that require their
    /// own logo, wording and colours, so letting an operator substitute a
    /// picture would produce a button that violates the guidelines it is meant
    /// to follow. The generic kinds have no mark to ship, which is exactly why
    /// they may carry a custom one.
    pub const fn has_bundled_mark(self) -> bool {
        !self.uses_slug()
    }

    /// Whether this kind takes an operator-chosen [`FederationConfig::provider_slug`].
    ///
    /// Only the generic kinds do. A branded kind is its own key, which is what
    /// makes "the tenant's Google overrides the organization's Google" a
    /// well-defined sentence; an organization legitimately federates to two
    /// different Okta tenants, and then the slug is what tells them apart.
    pub const fn uses_slug(self) -> bool {
        matches!(
            self,
            Self::GenericOidc | Self::GenericOauth2 | Self::GenericSaml
        )
    }

    /// Default OAuth/OIDC scopes when the config names none.
    ///
    /// Apple is the reason this is per-kind rather than a constant: it rejects
    /// `profile`, and the previously hard-coded `openid email profile` is
    /// exactly why Apple could not have worked.
    pub fn default_scopes(self) -> Vec<String> {
        let s: &[&str] = match self {
            Self::Google | Self::Microsoft | Self::GenericOidc => &["openid", "email", "profile"],
            Self::Apple => &["name", "email"],
            Self::Github => &["read:user", "user:email"],
            Self::Facebook => &["email", "public_profile"],
            // No safe default: a plain-OAuth2 provider's scope names are its
            // own, and guessing one produces an authorize URL that fails at the
            // provider with an error the operator cannot map back to us.
            Self::GenericOauth2 => &[],
            Self::GenericSaml => &[],
        };
        s.iter().map(|v| (*v).to_string()).collect()
    }

    /// Default accepted ID-token signing algorithms.
    ///
    /// Empty for SAML (where the field means assertion signature algorithms and
    /// the SAML path reads it separately) and for OAuth2 (where there is no
    /// signature at all — see [`ProviderKind::uses_allowed_algorithms`]).
    pub fn default_allowed_algorithms(self) -> Vec<String> {
        match self.protocol() {
            FederationProtocol::OidcConnect => vec!["RS256".to_string()],
            FederationProtocol::Saml | FederationProtocol::OAuth2 => Vec::new(),
        }
    }

    /// Whether `allowed_algorithms` means anything for this kind.
    ///
    /// `false` for the OAuth2 variant: there is no signature to constrain, and
    /// an inert control implying a check that does not happen is worse than no
    /// control.
    pub const fn uses_allowed_algorithms(self) -> bool {
        !matches!(self.protocol(), FederationProtocol::OAuth2)
    }
}

/// Why a `(provider_kind, protocol)` pair was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolKindMismatch {
    /// The kind that was submitted.
    pub kind: ProviderKind,
    /// The protocol that was submitted alongside it.
    pub submitted: FederationProtocol,
}

impl std::fmt::Display for ProtocolKindMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.submitted.is_unsigned_assertion() {
            write!(
                f,
                "provider_kind '{}' supports OpenID Connect, which verifies a signed \
                 ID token; the OAuth2 variant authenticates by an unsigned userinfo \
                 call and must not be selected for it. Use protocol '{}'.",
                self.kind.as_str(),
                self.kind.protocol().as_str()
            )
        } else {
            write!(
                f,
                "provider_kind '{}' uses protocol '{}', not '{}'",
                self.kind.as_str(),
                self.kind.protocol().as_str(),
                self.submitted.as_str()
            )
        }
    }
}

/// Refuse a `(kind, protocol)` pair that cannot work — or that would silently
/// downgrade assurance.
///
/// The rule that earns its keep: a kind whose provider supports OIDC properly
/// (`google`, `microsoft`, `apple`) may **not** be configured as
/// [`FederationProtocol::OAuth2`]. Facebook is the single kind that admits
/// both, because its web flow genuinely returns no ID token to a confidential
/// client while its Limited Login path does.
pub fn validate_protocol_for_kind(
    kind: ProviderKind,
    protocol: FederationProtocol,
) -> Result<(), ProtocolKindMismatch> {
    let ok = match kind {
        ProviderKind::Facebook => matches!(
            protocol,
            FederationProtocol::OAuth2 | FederationProtocol::OidcConnect
        ),
        other => protocol == other.protocol(),
    };
    if ok {
        Ok(())
    } else {
        Err(ProtocolKindMismatch {
            kind,
            submitted: protocol,
        })
    }
}

/// Edge length, in pixels, of a custom sign-in-button icon.
///
/// The admin UI crops and rescales whatever an operator uploads to exactly
/// this, so the stored image is always square and always small. 64 px renders
/// crisply at the ~20 px a button actually draws it at, on a 2× display,
/// without storing a photograph.
pub const PROVIDER_ICON_SIZE_PX: u32 = 64;

/// Bound on the **decoded** size of a custom icon, in bytes.
///
/// A 64×64 PNG is typically one to four kilobytes; sixteen is generous even for
/// a photographic one. The limit is expressed on the decoded image because that
/// is the number an operator can act on — "your PNG is too big" — rather than
/// on the base64 text, which is a detail of how it is carried.
///
/// It is a limit rather than a suggestion because this image is served by the
/// **unauthenticated** providers endpoint on every login-page render. Without a
/// bound, one operator pasting a photograph makes every visitor of that login
/// page download it.
pub const MAX_PROVIDER_ICON_BYTES: usize = 16 * 1024;

/// Bound on the stored data-URL, derived from [`MAX_PROVIDER_ICON_BYTES`].
///
/// Base64 is 4 characters per 3 bytes; the slack covers the longest allowed
/// `data:image/…;base64,` prefix. The decoded-size check is what actually
/// decides — this one exists so a multi-megabyte paste is rejected before
/// anything walks it byte by byte.
pub const MAX_PROVIDER_ICON_LEN: usize = MAX_PROVIDER_ICON_BYTES.div_ceil(3) * 4 + 64;

/// Data-URL prefixes a custom icon may use.
///
/// Raster formats only. `image/svg+xml` is deliberately absent: an SVG is a
/// document with its own parser, and this one is served to every visitor of a
/// login page. A PNG cannot be made to do anything but be a picture.
pub const ALLOWED_PROVIDER_ICON_PREFIXES: &[&str] = &[
    "data:image/png;base64,",
    "data:image/jpeg;base64,",
    "data:image/webp;base64,",
];

/// Validate a custom sign-in-button icon.
///
/// Structural only — this does not decode the image. What it guarantees is that
/// the stored value is a bounded, base64 raster data-URL, which is what makes it
/// safe to hand to an `<img src>` under the SPA's
/// `default-src 'self'; img-src 'self' data:` CSP.
pub fn validate_provider_icon(data_url: &str) -> Result<(), String> {
    // Cheap length check first, so a multi-megabyte paste is rejected before
    // anything walks it byte by byte.
    if data_url.len() > MAX_PROVIDER_ICON_LEN {
        return Err(icon_too_large_message(decoded_len(data_url.len())));
    }
    let Some(prefix) = ALLOWED_PROVIDER_ICON_PREFIXES
        .iter()
        .find(|p| data_url.starts_with(**p))
    else {
        return Err(format!(
            "the button icon must be a base64 data URL in one of: {}. SVG is not \
             accepted — it is a document with its own parser, and this image is \
             served to everyone who loads a login page",
            ALLOWED_PROVIDER_ICON_PREFIXES.join(", ")
        ));
    };
    let payload = &data_url[prefix.len()..];
    if payload.is_empty() {
        return Err("the button icon data URL carries no image data".into());
    }
    // Standard base64 with padding, which is what `canvas.toDataURL` emits.
    if !payload
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
    {
        return Err("the button icon data URL is not valid base64".into());
    }
    let padding = payload.bytes().filter(|b| *b == b'=').count();
    let decoded = decoded_len(payload.len()).saturating_sub(padding);
    if decoded > MAX_PROVIDER_ICON_BYTES {
        return Err(icon_too_large_message(decoded));
    }
    Ok(())
}

/// Decoded byte count for a base64 payload of `n` characters, before padding is
/// subtracted.
const fn decoded_len(n: usize) -> usize {
    n / 4 * 3
}

/// The one message both size checks produce.
///
/// Stated in kibibytes of *image*, because the operator has a PNG in a file
/// picker, not a data URL in a text field — and it says why the limit exists,
/// because "too big" invites the question this answers.
fn icon_too_large_message(decoded: usize) -> String {
    format!(
        "the button icon decodes to about {} KiB; the maximum is {} KiB. It is served \
         to everyone who loads a login page, so it has to stay small — the admin UI \
         crops to {PROVIDER_ICON_SIZE_PX}×{PROVIDER_ICON_SIZE_PX}, which is normally a \
         few kilobytes",
        decoded.div_ceil(1024),
        MAX_PROVIDER_ICON_BYTES / 1024,
    )
}

/// Bound on a `provider_slug`. Long enough for a readable name, short enough
/// that it cannot be used to smuggle a payload into an override key.
pub const MAX_PROVIDER_SLUG_LEN: usize = 64;

/// Validate an operator-chosen provider slug.
///
/// Lowercase `[a-z0-9-]`, non-empty, no leading/trailing or doubled hyphen —
/// the same shape as every other slug in AXIAM, and restrictive enough that the
/// `kind:slug` override key has exactly one spelling per provider.
pub fn validate_provider_slug(slug: &str) -> Result<(), String> {
    if slug.is_empty() {
        return Err("provider_slug must not be empty".into());
    }
    if slug.len() > MAX_PROVIDER_SLUG_LEN {
        return Err(format!(
            "provider_slug is {} characters; the maximum is {MAX_PROVIDER_SLUG_LEN}",
            slug.len()
        ));
    }
    if !slug
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("provider_slug may contain only lowercase letters, digits and hyphens".into());
    }
    if slug.starts_with('-') || slug.ends_with('-') || slug.contains("--") {
        return Err("provider_slug must not start or end with a hyphen, or contain '--'".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// X4 — external-IdP token exchange trust
// ---------------------------------------------------------------------------

/// How an external subject with no existing federation link is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SubjectMapping {
    /// Refuse. The user must already have logged in through this provider (or
    /// been linked by an admin) before their partner token buys anything.
    #[default]
    LinkedOnly,
    /// Provision an AXIAM user on first sight, via the existing federation JIT
    /// path. Audited as such — it is the only record that a partner's IdP
    /// created a local user.
    JitProvision,
}

impl SubjectMapping {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LinkedOnly => "linked_only",
            Self::JitProvision => "jit_provision",
        }
    }

    /// Parse a wire value. Unknown values yield `None` so a caller can refuse
    /// them: a typo'd `"jit_provsion"` must not silently become the default,
    /// and the default is the *stricter* of the two, so a silent fallback
    /// would fail closed here and open in the next revision that flips it.
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw.trim() {
            "linked_only" => Some(Self::LinkedOnly),
            "jit_provision" => Some(Self::JitProvision),
            _ => None,
        }
    }
}

/// Default bound on `now - iat` for an accepted external subject token.
pub const DEFAULT_MAX_TOKEN_AGE_SECS: i64 = 300;

/// Hard ceiling on `max_token_age_secs`. An hour is already generous for a
/// token being replayed at a trust boundary; beyond that the operator is
/// asking for a bearer credential with a day's replay window.
pub const MAX_TOKEN_AGE_CEILING_SECS: i64 = 3600;

/// Bound on how many audiences and map entries a provider may carry.
///
/// Not tidiness: both are read on every external exchange and the map is
/// walked once per asserted value, so an unbounded config is an unbounded
/// per-request cost an admin can set.
pub const MAX_ACCEPTED_AUDIENCES: usize = 64;
pub const MAX_SCOPE_MAP_ENTRIES: usize = 256;

/// Per-provider trust configuration for RFC 8693 exchange of that provider's
/// tokens (X4).
///
/// See `claude_dev/external-token-exchange-design.md`. The one sentence that
/// governs every field: **an external subject token is evidence of
/// authentication, never a grant of authorization.** Nothing here can widen
/// what the resolved user may do; every field can only narrow it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TokenExchangeTrust {
    /// Off unless an operator says otherwise, per provider.
    ///
    /// An operator who configured Okta for *login* did not thereby agree to
    /// accept Okta tokens as API credentials. Those are different trust
    /// statements, so they get different switches.
    pub enabled: bool,
    /// Audiences an incoming subject token may name. **Non-empty when
    /// `enabled`** — there is deliberately no "any audience" value.
    ///
    /// A token that was not addressed to us is a token we captured, not a
    /// token we were given.
    pub accepted_audiences: Vec<String>,
    pub subject_mapping: SubjectMapping,
    /// External asserted value → AXIAM scopes. Deny-by-default: a value with
    /// no entry contributes nothing, and there is no passthrough mode.
    ///
    /// `BTreeMap` rather than `HashMap` so serialization is stable — this is
    /// admin config that shows up in diffs and audit records.
    pub scope_map: BTreeMap<String, Vec<String>>,
    /// Bound on `now - iat`, independent of the token's own `exp`.
    pub max_token_age_secs: i64,
    /// Optional per-provider ceiling on the *issued* AXIAM token's lifetime,
    /// applied on top of "never outlives its subject" and the server-wide
    /// exchange maximum.
    pub max_lifetime_secs: Option<i64>,
}

impl Default for TokenExchangeTrust {
    fn default() -> Self {
        Self {
            enabled: false,
            accepted_audiences: Vec::new(),
            subject_mapping: SubjectMapping::LinkedOnly,
            scope_map: BTreeMap::new(),
            max_token_age_secs: DEFAULT_MAX_TOKEN_AGE_SECS,
            max_lifetime_secs: None,
        }
    }
}

/// Why a submitted [`TokenExchangeTrust`] was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustConfigError {
    NoAcceptedAudiences,
    BlankAudience,
    TooManyAudiences(usize),
    TokenAgeOutOfRange(i64),
    NonPositiveLifetime(i64),
    TooManyScopeMapEntries(usize),
    BlankScopeMapKey,
    EmptyScopeMapValue(String),
    BlankScopeName(String),
}

impl std::fmt::Display for TrustConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAcceptedAudiences => write!(
                f,
                "token_exchange.accepted_audiences must name at least one audience \
                 when token exchange is enabled; there is no accept-all value"
            ),
            Self::BlankAudience => {
                write!(
                    f,
                    "token_exchange.accepted_audiences contains a blank entry"
                )
            }
            Self::TooManyAudiences(n) => write!(
                f,
                "token_exchange.accepted_audiences has {n} entries; \
                 the maximum is {MAX_ACCEPTED_AUDIENCES}"
            ),
            Self::TokenAgeOutOfRange(v) => write!(
                f,
                "token_exchange.max_token_age_secs is {v}; \
                 it must be between 1 and {MAX_TOKEN_AGE_CEILING_SECS}"
            ),
            Self::NonPositiveLifetime(v) => write!(
                f,
                "token_exchange.max_lifetime_secs is {v}; it must be positive"
            ),
            Self::TooManyScopeMapEntries(n) => write!(
                f,
                "token_exchange.scope_map has {n} entries; \
                 the maximum is {MAX_SCOPE_MAP_ENTRIES}"
            ),
            Self::BlankScopeMapKey => write!(f, "token_exchange.scope_map has a blank key"),
            Self::EmptyScopeMapValue(k) => write!(
                f,
                "token_exchange.scope_map entry '{k}' maps to no AXIAM scopes; \
                 remove the entry instead — an empty mapping is not a grant of nothing, \
                 it is a mapping nobody can read"
            ),
            Self::BlankScopeName(k) => write!(
                f,
                "token_exchange.scope_map entry '{k}' maps to a blank scope name"
            ),
        }
    }
}

impl TokenExchangeTrust {
    /// Reject a configuration that cannot be enforced safely.
    ///
    /// Validation runs **whether or not `enabled` is set**, except for the
    /// non-empty-audience rule: a disabled block with nonsense in it becomes
    /// an enabled block with nonsense in it the moment someone flips a
    /// checkbox, and that flip is not where an operator expects to be told
    /// their `scope_map` was malformed.
    pub fn validate(&self) -> Result<(), TrustConfigError> {
        if self.enabled && self.accepted_audiences.is_empty() {
            return Err(TrustConfigError::NoAcceptedAudiences);
        }
        if self.accepted_audiences.len() > MAX_ACCEPTED_AUDIENCES {
            return Err(TrustConfigError::TooManyAudiences(
                self.accepted_audiences.len(),
            ));
        }
        if self.accepted_audiences.iter().any(|a| a.trim().is_empty()) {
            return Err(TrustConfigError::BlankAudience);
        }
        if self.max_token_age_secs < 1 || self.max_token_age_secs > MAX_TOKEN_AGE_CEILING_SECS {
            return Err(TrustConfigError::TokenAgeOutOfRange(
                self.max_token_age_secs,
            ));
        }
        if let Some(l) = self.max_lifetime_secs
            && l < 1
        {
            return Err(TrustConfigError::NonPositiveLifetime(l));
        }
        if self.scope_map.len() > MAX_SCOPE_MAP_ENTRIES {
            return Err(TrustConfigError::TooManyScopeMapEntries(
                self.scope_map.len(),
            ));
        }
        for (key, scopes) in &self.scope_map {
            if key.trim().is_empty() {
                return Err(TrustConfigError::BlankScopeMapKey);
            }
            if scopes.is_empty() {
                return Err(TrustConfigError::EmptyScopeMapValue(key.clone()));
            }
            if scopes.iter().any(|s| s.trim().is_empty()) {
                return Err(TrustConfigError::BlankScopeName(key.clone()));
            }
        }
        Ok(())
    }

    /// Whether `aud` (already flattened to a list) names an accepted audience.
    ///
    /// Exact string equality, both directions. No normalisation: a trailing
    /// slash is a different URI as far as this check is concerned, because
    /// "close enough" comparisons at a trust boundary are how a token minted
    /// for `https://api.partner.example.evil.com` gets accepted as
    /// `https://api.partner.example`.
    pub fn audience_accepted(&self, token_audiences: &[String]) -> bool {
        token_audiences
            .iter()
            .any(|a| self.accepted_audiences.iter().any(|acc| acc == a))
    }

    /// Map what the external token asserted onto AXIAM scope names.
    ///
    /// Deny-by-default in the literal sense: an asserted value with no entry
    /// contributes nothing and is not reported as an error — the partner's
    /// token legitimately carries scopes that mean nothing here.
    ///
    /// Order follows `asserted`, then the map's own order, with duplicates
    /// collapsed, so the result is deterministic and diffable.
    pub fn map_scopes(&self, asserted: &[String]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for value in asserted {
            let Some(mapped) = self.scope_map.get(value) else {
                continue;
            };
            for scope in mapped {
                if !out.contains(scope) {
                    out.push(scope.clone());
                }
            }
        }
        out
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FederationConfig {
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// Display name for the identity provider (e.g., `Google`, `Okta`).
    pub provider: String,
    pub protocol: FederationProtocol,
    /// OIDC discovery URL or SAML metadata URL.
    pub metadata_url: Option<String>,
    pub client_id: String,
    /// Legacy plaintext client secret (kept for back-compat; nulled by plan 04-02 backfill).
    #[serde(skip_serializing)]
    pub client_secret: String,
    /// Maps external IdP attributes to AXIAM user fields.
    pub attribute_map: serde_json::Value,
    pub enabled: bool,
    // ------------------------------------------------------------------
    // Phase 4 additions (D-10 / D-11)
    // ------------------------------------------------------------------
    /// JWT signing algorithms accepted from this IdP's ID tokens.
    ///
    /// Default: `["RS256"]` for OIDC configs; empty for SAML configs.
    pub allowed_algorithms: Vec<String>,
    /// PEM-encoded X.509 certificate used to verify this IdP's SAML assertions
    /// or fallback OIDC signatures (when JWKS is unavailable).
    pub idp_signing_cert_pem: Option<String>,
    /// AES-256-GCM ciphertext of the OAuth2 client secret (base64, no nonce prefix).
    /// Stored separately from `client_secret_nonce` — see `axiam_auth::crypto::encrypt_separate`.
    #[serde(skip_serializing)]
    pub client_secret_ciphertext: Option<String>,
    /// Base64-encoded 12-byte AES-256-GCM nonce corresponding to `client_secret_ciphertext`.
    #[serde(skip_serializing)]
    pub client_secret_nonce: Option<String>,
    /// Key version used when encrypting `client_secret_ciphertext`.
    /// Enables key rotation without re-encrypting all secrets at once.
    #[serde(skip_serializing)]
    pub client_secret_key_version: Option<i64>,
    // ------------------------------------------------------------------
    // X4 addition
    // ------------------------------------------------------------------
    /// RFC 8693 trust for tokens *issued by this provider* (X4).
    ///
    /// Meaningful only for [`FederationProtocol::OidcConnect`] rows. Absent in
    /// the datastore for every pre-X4 row, which reads back as
    /// [`TokenExchangeTrust::default()`] — `enabled: false`, i.e. exactly
    /// today's behaviour.
    #[serde(default)]
    pub token_exchange: TokenExchangeTrust,
    // ------------------------------------------------------------------
    // Login-provider additions (schema v52) — see
    // `claude_dev/federation-sso-login-design.md`.
    //
    // Every one of these reads back from a pre-v52 row as the value that
    // preserves that row's existing behaviour exactly. Nothing is backfilled.
    // ------------------------------------------------------------------
    /// Which provider this is, for branding, per-kind defaults, and override
    /// identity. A pre-v52 row derives it from `protocol`
    /// ([`ProviderKind::from_legacy_protocol`]).
    #[serde(default = "default_provider_kind")]
    pub provider_kind: ProviderKind,
    /// Operator-chosen identifier, for the `generic_*` kinds only.
    ///
    /// Part of the override key so an organization can federate to two
    /// different generic providers of the same kind and a tenant can override
    /// exactly one of them.
    #[serde(default)]
    pub provider_slug: Option<String>,
    /// Whether tenants of this organization may inherit this provider.
    ///
    /// Only meaningful on a config that lives in the organization-scope
    /// tenant. **Default `false`**: an existing row stays private to the tenant
    /// that owns it, which is what it has always been.
    #[serde(default)]
    pub allow_tenant_inheritance: bool,
    /// Scopes requested at the authorization endpoint.
    ///
    /// Empty means "use [`ProviderKind::default_scopes`]", which for an OIDC
    /// config is `openid email profile` — the value that used to be hard-coded
    /// in `build_authorization_url`, so an untouched row is unchanged.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// OAuth2-variant authorization endpoint. There is no discovery document
    /// to derive it from; validated as absolute HTTPS on write.
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    /// OAuth2-variant token endpoint.
    #[serde(default)]
    pub token_endpoint: Option<String>,
    /// OAuth2-variant userinfo endpoint — the *entire* authentication
    /// assertion on that path, which is why it is explicit and HTTPS-only.
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    /// External IdP tenant identifiers accepted when the discovered issuer is
    /// templated (Entra ID's `{tenantid}`).
    ///
    /// **Required, non-empty, whenever the issuer is templated.** Empty with a
    /// templated issuer would mean "every Microsoft account on earth may sign
    /// in here", which is occasionally intended and never intended by accident;
    /// the config is refused rather than accepted with that meaning.
    #[serde(default)]
    pub allowed_issuer_tenants: Vec<String>,
    /// Apple: the 10-character Team ID that becomes the client secret's `iss`.
    #[serde(default)]
    pub apple_team_id: Option<String>,
    /// Apple: the 10-character Key ID of the `.p8` signing key, carried in the
    /// client secret's JOSE `kid` header.
    ///
    /// Its presence is what selects server-side secret minting: with both
    /// `apple_team_id` and `apple_key_id` set, the stored secret is the `.p8`
    /// private key and AXIAM mints a fresh 5-minute ES256 JWT per exchange.
    /// Without them the stored secret is used verbatim, which is the escape
    /// hatch for an operator who manages the JWT themselves.
    #[serde(default)]
    pub apple_key_id: Option<String>,
    /// Custom sign-in-button icon for a generic provider, as a bounded raster
    /// data URL.
    ///
    /// Only the `generic_*` kinds may carry one — see
    /// [`ProviderKind::has_bundled_mark`]. `None` for every config written
    /// before this field existed, and the button falls back to a neutral glyph
    /// beside "Sign in with <provider>".
    ///
    /// Returned by the **unauthenticated** providers endpoint, because a login
    /// button cannot render without it. It is branding, not configuration:
    /// nothing about the provider's identity or credentials is derivable from
    /// it.
    #[serde(default)]
    pub button_icon: Option<String>,
    /// Send PKCE (`S256`) on the authorization request.
    ///
    /// Forced on for [`FederationProtocol::OAuth2`] regardless of this flag —
    /// it is the only replay protection left there once `nonce` is gone. Opt-in
    /// for OIDC, where the server-side nonce already provides it and where
    /// requiring it would break every config written before this field existed.
    #[serde(default)]
    pub require_pkce: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Serde default for [`FederationConfig::provider_kind`].
///
/// Only reached when deserializing a payload that predates the field. The
/// datastore path does not use it — the repository derives the kind from the
/// row's own `protocol`, which is strictly better information.
fn default_provider_kind() -> ProviderKind {
    ProviderKind::GenericOidc
}

impl FederationConfig {
    /// The key on which a tenant config shadows an inherited organization one.
    ///
    /// The branded kinds key on the kind alone: "the tenant's Google overrides
    /// the organization's Google" has to be a well-defined sentence, and it only
    /// is if a tenant cannot hold two Googles. The `generic_*` kinds key on
    /// `kind:slug`, because an organization legitimately federates to two
    /// different Okta tenants.
    ///
    /// The slug is optional, so a generic config without one keys on `kind:` —
    /// exactly as a branded kind keys on its kind alone. That is deliberate:
    /// requiring a slug would turn every pre-existing `POST /federation-configs`
    /// call into a 400, because a request that omits `provider_kind` derives a
    /// generic kind. The admin UI fills a slug in from the display name, so
    /// configs created through it get distinct keys without the API having to
    /// demand one.
    pub fn override_key(&self) -> String {
        if self.provider_kind.uses_slug() {
            format!(
                "{}:{}",
                self.provider_kind.as_str(),
                self.provider_slug.as_deref().unwrap_or("")
            )
        } else {
            self.provider_kind.as_str().to_string()
        }
    }

    /// Scopes to request, resolving the empty-means-default rule.
    pub fn effective_scopes(&self) -> Vec<String> {
        if self.scopes.is_empty() {
            self.provider_kind.default_scopes()
        } else {
            self.scopes.clone()
        }
    }

    /// Whether PKCE must be sent for this config.
    ///
    /// Unconditional for the OAuth2 variant — see [`FederationConfig::require_pkce`].
    pub fn pkce_required(&self) -> bool {
        self.require_pkce || self.protocol.is_unsigned_assertion()
    }

    /// Whether AXIAM mints this config's client secret itself rather than
    /// sending the stored one.
    pub fn mints_client_secret(&self) -> bool {
        self.provider_kind == ProviderKind::Apple
            && self.apple_team_id.is_some()
            && self.apple_key_id.is_some()
    }
}

/// Manual `Debug` impl (SECHRD-09 / D-06): redacts the four secret-bearing
/// fields so `{:?}` never prints the plaintext or encrypted client secret,
/// while keeping all other fields human-readable for logs/traces.
impl std::fmt::Debug for FederationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FederationConfig")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("provider", &self.provider)
            .field("protocol", &self.protocol)
            .field("metadata_url", &self.metadata_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("attribute_map", &self.attribute_map)
            .field("enabled", &self.enabled)
            .field("allowed_algorithms", &self.allowed_algorithms)
            .field("idp_signing_cert_pem", &self.idp_signing_cert_pem)
            .field("client_secret_ciphertext", &"[REDACTED]")
            .field("client_secret_nonce", &"[REDACTED]")
            .field("client_secret_key_version", &"[REDACTED]")
            .field("token_exchange", &self.token_exchange)
            .field("provider_kind", &self.provider_kind)
            .field("provider_slug", &self.provider_slug)
            .field("allow_tenant_inheritance", &self.allow_tenant_inheritance)
            .field("scopes", &self.scopes)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .field("userinfo_endpoint", &self.userinfo_endpoint)
            .field("allowed_issuer_tenants", &self.allowed_issuer_tenants)
            .field("apple_team_id", &self.apple_team_id)
            .field("apple_key_id", &self.apple_key_id)
            .field("require_pkce", &self.require_pkce)
            // Length only: a 32 KiB base64 blob in a log line is noise, and
            // the one thing a reader wants to know is whether one is set.
            .field(
                "button_icon",
                &self.button_icon.as_ref().map(|i| format!("<{} chars>", i.len())),
            )
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateFederationConfig {
    pub tenant_id: Uuid,
    pub provider: String,
    pub protocol: FederationProtocol,
    pub metadata_url: Option<String>,
    pub client_id: String,
    pub client_secret: String,
    pub attribute_map: Option<serde_json::Value>,
    /// PEM-encoded X.509 cert used to verify SAML assertions (CQ-B40/REQ-14 AC-5).
    pub idp_signing_cert_pem: Option<String>,
    /// JWT signing algorithms accepted from this IdP (CQ-B40/REQ-14 AC-5).
    pub allowed_algorithms: Option<Vec<String>>,
    /// X4 trust for exchanging this provider's tokens. Omitted ⇒ disabled.
    pub token_exchange: Option<TokenExchangeTrust>,
    // --- schema v52 login-provider fields ---
    /// Which provider this is. Omitted ⇒ derived from `protocol`.
    pub provider_kind: Option<ProviderKind>,
    /// Operator-chosen identifier, required for the `generic_*` kinds.
    pub provider_slug: Option<String>,
    /// Whether tenants may inherit this organization-level provider.
    pub allow_tenant_inheritance: Option<bool>,
    /// Requested scopes. Omitted or empty ⇒ [`ProviderKind::default_scopes`].
    pub scopes: Option<Vec<String>>,
    /// OAuth2-variant authorization endpoint (required for that protocol).
    pub authorization_endpoint: Option<String>,
    /// OAuth2-variant token endpoint (required for that protocol).
    pub token_endpoint: Option<String>,
    /// OAuth2-variant userinfo endpoint (required for that protocol).
    pub userinfo_endpoint: Option<String>,
    /// Accepted external IdP tenants for a templated issuer.
    pub allowed_issuer_tenants: Option<Vec<String>>,
    /// Apple Team ID.
    pub apple_team_id: Option<String>,
    /// Apple Key ID of the `.p8` signing key.
    pub apple_key_id: Option<String>,
    /// Send PKCE on the authorization request (forced on for OAuth2).
    pub require_pkce: Option<bool>,
    /// Custom sign-in-button icon (generic kinds only).
    pub button_icon: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateFederationConfig {
    pub provider: Option<String>,
    pub metadata_url: Option<Option<String>>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub attribute_map: Option<serde_json::Value>,
    pub enabled: Option<bool>,
    /// PEM-encoded X.509 cert used to verify SAML assertions (CQ-B40/REQ-14 AC-5).
    pub idp_signing_cert_pem: Option<Option<String>>,
    /// JWT signing algorithms accepted from this IdP (CQ-B40/REQ-14 AC-5).
    pub allowed_algorithms: Option<Vec<String>>,
    /// X4 trust block. Replaced wholesale when present — a partial merge of a
    /// trust configuration is how an operator ends up with an
    /// `accepted_audiences` they did not intend to keep.
    pub token_exchange: Option<TokenExchangeTrust>,
    // --- schema v52 login-provider fields ---
    /// Operator-chosen identifier. `Some(None)` clears it.
    ///
    /// `provider_kind` is deliberately **not** updatable: it selects the
    /// protocol and the override key, and changing it on a live config would
    /// silently re-point which inherited provider a tenant is shadowing.
    pub provider_slug: Option<Option<String>>,
    /// Whether tenants may inherit this organization-level provider.
    pub allow_tenant_inheritance: Option<bool>,
    /// Requested scopes. Replaced wholesale; an empty vector restores the
    /// per-kind default.
    pub scopes: Option<Vec<String>>,
    /// OAuth2-variant authorization endpoint. `Some(None)` clears it.
    pub authorization_endpoint: Option<Option<String>>,
    /// OAuth2-variant token endpoint. `Some(None)` clears it.
    pub token_endpoint: Option<Option<String>>,
    /// OAuth2-variant userinfo endpoint. `Some(None)` clears it.
    pub userinfo_endpoint: Option<Option<String>>,
    /// Accepted external IdP tenants for a templated issuer. Replaced wholesale.
    pub allowed_issuer_tenants: Option<Vec<String>>,
    /// Apple Team ID. `Some(None)` clears it.
    pub apple_team_id: Option<Option<String>>,
    /// Apple Key ID. `Some(None)` clears it.
    pub apple_key_id: Option<Option<String>>,
    /// Send PKCE on the authorization request.
    pub require_pkce: Option<bool>,
    /// Custom sign-in-button icon. `Some(None)` clears it.
    pub button_icon: Option<Option<String>>,
}

/// Tracks the link between an AXIAM user and their external IdP identity.
///
/// Each link binds a local user to an external subject identifier (the `sub`
/// claim from the external OIDC provider), scoped to a specific federation
/// configuration within a tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationLink {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub federation_config_id: Uuid,
    /// The `sub` claim from the external IdP's ID token.
    pub external_subject: String,
    /// The email claim from the external IdP, if available.
    pub external_email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateFederationLink {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub federation_config_id: Uuid,
    pub external_subject: String,
    pub external_email: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::certificate::{CaCertificate, CertificateStatus, KeyAlgorithm};

    /// SECHRD-09 / D-06 / SC #4b: neither the serialized JSON nor the Debug
    /// output of a `FederationConfig` may contain a plaintext or encrypted
    /// secret substring — proves `skip_serializing` + the manual redacting
    /// `Debug` impl actually close the leak (not just compile).
    #[test]
    fn federation_config_secret_not_serialized() {
        const PLAINTEXT_SECRET: &str = "super-secret-oauth-client-value-do-not-leak";
        const CIPHERTEXT: &str = "cGxhY2Vob2xkZXItY2lwaGVydGV4dC1kby1ub3QtbGVhaw==";
        const NONCE: &str = "bm9uY2UtZG8tbm90LWxlYWs=";

        let config = FederationConfig {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            provider: "Okta".to_string(),
            protocol: FederationProtocol::OidcConnect,
            metadata_url: Some("https://example.com/.well-known/openid-configuration".into()),
            client_id: "client-123".to_string(),
            client_secret: PLAINTEXT_SECRET.to_string(),
            attribute_map: serde_json::json!({}),
            enabled: true,
            allowed_algorithms: vec!["RS256".to_string()],
            idp_signing_cert_pem: None,
            client_secret_ciphertext: Some(CIPHERTEXT.to_string()),
            client_secret_nonce: Some(NONCE.to_string()),
            client_secret_key_version: Some(1),
            token_exchange: TokenExchangeTrust::default(),
            provider_kind: ProviderKind::GenericOidc,
            provider_slug: None,
            allow_tenant_inheritance: false,
            scopes: Vec::new(),
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            allowed_issuer_tenants: Vec::new(),
            apple_team_id: None,
            apple_key_id: None,
            require_pkce: false,
            button_icon: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_string(&config).expect("serialization must succeed");
        assert!(
            !json.contains(PLAINTEXT_SECRET),
            "serialized JSON must not contain the plaintext client secret"
        );
        assert!(
            !json.contains(CIPHERTEXT),
            "serialized JSON must not contain the encrypted client secret ciphertext"
        );
        assert!(
            !json.contains(NONCE),
            "serialized JSON must not contain the client secret nonce"
        );

        let debug_output = format!("{config:?}");
        assert!(
            !debug_output.contains(PLAINTEXT_SECRET),
            "Debug output must not contain the plaintext client secret"
        );
        assert!(
            !debug_output.contains(CIPHERTEXT),
            "Debug output must not contain the encrypted client secret ciphertext"
        );
        assert!(
            !debug_output.contains(NONCE),
            "Debug output must not contain the client secret nonce"
        );
    }

    /// Companion assertion (SECHRD-09 / D-06): `CaCertificate`'s manual
    /// `Debug` impl redacts `encrypted_private_key`, closing the residual
    /// leak that `#[serde(skip_serializing)]` alone (Serialize-only) missed.
    #[test]
    fn ca_certificate_debug_redacts_private_key() {
        const KEY_MARKER: &[u8] = b"do-not-leak-private-key-bytes";

        let cert = CaCertificate {
            id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            tenant_id: None,
            parent_ca_id: None,
            subject: "CN=Test Root CA".to_string(),
            public_cert_pem: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
                .to_string(),
            chain_pem: None,
            fingerprint: "aa:bb:cc".to_string(),
            key_algorithm: KeyAlgorithm::Ed25519,
            not_before: Utc::now(),
            not_after: Utc::now(),
            status: CertificateStatus::Active,
            encrypted_private_key: Some(KEY_MARKER.to_vec()),
            key_custody: crate::ca_keys::CaKeyCustody::Database,
            key_locator: None,
            mtls_trust_anchor: false,
            created_at: Utc::now(),
        };

        let debug_output = format!("{cert:?}");
        assert!(
            !debug_output.contains("do-not-leak-private-key-bytes"),
            "Debug output must not contain the encrypted private key bytes"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output must show a redaction marker for encrypted_private_key"
        );
    }

    // -----------------------------------------------------------------
    // X4 — TokenExchangeTrust
    // -----------------------------------------------------------------

    fn trust() -> TokenExchangeTrust {
        TokenExchangeTrust {
            enabled: true,
            accepted_audiences: vec!["https://api.axiam.example".into()],
            ..TokenExchangeTrust::default()
        }
    }

    /// The headline default: X4 is off, and a config nobody touched behaves
    /// exactly as it did before X4 existed.
    #[test]
    fn the_default_trust_block_is_disabled_and_trusts_nothing() {
        let d = TokenExchangeTrust::default();
        assert!(!d.enabled);
        assert!(d.accepted_audiences.is_empty());
        assert_eq!(d.subject_mapping, SubjectMapping::LinkedOnly);
        assert!(d.scope_map.is_empty());
        assert_eq!(d.max_token_age_secs, DEFAULT_MAX_TOKEN_AGE_SECS);
        assert!(d.validate().is_ok(), "the default must be a valid config");
    }

    /// There is no accept-all audience, so enabling without one is refused.
    #[test]
    fn enabling_without_an_accepted_audience_is_refused() {
        let t = TokenExchangeTrust {
            enabled: true,
            ..TokenExchangeTrust::default()
        };
        assert_eq!(t.validate(), Err(TrustConfigError::NoAcceptedAudiences));
    }

    /// …but a *disabled* block with no audiences is fine — that is the
    /// default, and refusing it would make every pre-X4 row invalid.
    #[test]
    fn a_disabled_block_needs_no_audiences() {
        assert!(TokenExchangeTrust::default().validate().is_ok());
    }

    #[test]
    fn a_malformed_scope_map_is_refused_even_while_disabled() {
        let mut t = TokenExchangeTrust::default();
        t.scope_map.insert("partner.read".into(), vec![]);
        assert_eq!(
            t.validate(),
            Err(TrustConfigError::EmptyScopeMapValue("partner.read".into())),
            "a malformed map must be caught at write time, not at the checkbox flip"
        );
    }

    #[test]
    fn token_age_is_bounded_at_both_ends() {
        for bad in [0, -1, MAX_TOKEN_AGE_CEILING_SECS + 1] {
            let t = TokenExchangeTrust {
                max_token_age_secs: bad,
                ..trust()
            };
            assert_eq!(t.validate(), Err(TrustConfigError::TokenAgeOutOfRange(bad)));
        }
        for good in [1, DEFAULT_MAX_TOKEN_AGE_SECS, MAX_TOKEN_AGE_CEILING_SECS] {
            let t = TokenExchangeTrust {
                max_token_age_secs: good,
                ..trust()
            };
            assert!(t.validate().is_ok(), "{good} should be accepted");
        }
    }

    #[test]
    fn audience_matching_is_exact_in_both_directions() {
        let t = trust();
        assert!(t.audience_accepted(&["https://api.axiam.example".to_string()]));
        // A trailing slash is a different URI. "Close enough" here is how a
        // token minted for a lookalike host gets accepted.
        assert!(!t.audience_accepted(&["https://api.axiam.example/".to_string()]));
        assert!(!t.audience_accepted(&["https://api.axiam.example.evil.test".to_string()]));
        assert!(!t.audience_accepted(&[]));
        // Multi-valued `aud`: one match is enough, which is what the spec says.
        assert!(t.audience_accepted(&[
            "https://other.example".to_string(),
            "https://api.axiam.example".to_string(),
        ]));
    }

    #[test]
    fn unmapped_external_values_contribute_nothing() {
        let mut t = trust();
        t.scope_map
            .insert("partner.orders.read".into(), vec!["read:orders".into()]);

        assert_eq!(
            t.map_scopes(&[
                "partner.orders.read".into(),
                "partner.admin".into(), // no entry — silently contributes nothing
            ]),
            vec!["read:orders".to_string()],
        );
        // An entirely unmapped token maps to nothing at all, rather than to
        // "everything the partner asked for".
        assert!(t.map_scopes(&["partner.admin".into()]).is_empty());
    }

    #[test]
    fn mapping_collapses_duplicates_and_keeps_a_deterministic_order() {
        let mut t = trust();
        t.scope_map.insert(
            "a".into(),
            vec!["read:orders".into(), "read:invoices".into()],
        );
        t.scope_map.insert("b".into(), vec!["read:orders".into()]);

        assert_eq!(
            t.map_scopes(&["a".into(), "b".into(), "a".into()]),
            vec!["read:orders".to_string(), "read:invoices".to_string()],
        );
    }

    /// The property the map exists to have: whatever comes out was named by
    /// the map, never by the partner's token.
    #[test]
    fn mapped_output_is_always_a_subset_of_the_maps_own_range() {
        let mut t = trust();
        t.scope_map.insert("x".into(), vec!["read".into()]);
        t.scope_map.insert("y".into(), vec!["write".into()]);
        let range: Vec<String> = t.scope_map.values().flatten().cloned().collect();

        for asserted in [
            vec![],
            vec!["x".to_string()],
            vec!["y".to_string()],
            vec!["x".to_string(), "y".to_string()],
            // Values the partner invented, including ones that *look* like
            // AXIAM scope names.
            vec!["read".to_string(), "admin".to_string(), "z".to_string()],
        ] {
            for got in t.map_scopes(&asserted) {
                assert!(range.contains(&got), "{got} escaped the map's range");
            }
        }
    }

    // -----------------------------------------------------------------
    // Login providers — ProviderKind, protocol pairing, override identity
    // -----------------------------------------------------------------

    fn config(kind: ProviderKind, slug: Option<&str>) -> FederationConfig {
        FederationConfig {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            provider: "display name".into(),
            protocol: kind.protocol(),
            metadata_url: None,
            client_id: "cid".into(),
            client_secret: String::new(),
            attribute_map: serde_json::json!({}),
            enabled: true,
            allowed_algorithms: kind.default_allowed_algorithms(),
            idp_signing_cert_pem: None,
            client_secret_ciphertext: None,
            client_secret_nonce: None,
            client_secret_key_version: None,
            token_exchange: TokenExchangeTrust::default(),
            provider_kind: kind,
            provider_slug: slug.map(str::to_string),
            allow_tenant_inheritance: false,
            scopes: Vec::new(),
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            allowed_issuer_tenants: Vec::new(),
            apple_team_id: None,
            apple_key_id: None,
            require_pkce: false,
            button_icon: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn every_kind_round_trips_through_its_wire_spelling() {
        for kind in ProviderKind::ALL {
            assert_eq!(ProviderKind::from_wire(kind.as_str()), Some(*kind));
        }
        assert_eq!(ProviderKind::from_wire("Google"), None, "case matters");
        assert_eq!(ProviderKind::from_wire("googl"), None);
    }

    #[test]
    fn every_protocol_round_trips_through_its_wire_spelling() {
        for p in [
            FederationProtocol::OidcConnect,
            FederationProtocol::Saml,
            FederationProtocol::OAuth2,
        ] {
            assert_eq!(FederationProtocol::from_wire(p.as_str()), Some(p));
        }
        assert_eq!(FederationProtocol::from_wire("oauth2"), None);
    }

    /// The rule that keeps the reduced-assurance path from being chosen by
    /// accident for a provider that does OIDC properly.
    #[test]
    fn a_provider_that_does_oidc_cannot_be_configured_as_plain_oauth2() {
        for kind in [
            ProviderKind::Google,
            ProviderKind::Microsoft,
            ProviderKind::Apple,
            ProviderKind::GenericOidc,
        ] {
            let err = validate_protocol_for_kind(kind, FederationProtocol::OAuth2)
                .expect_err("must be refused");
            assert_eq!(err.kind, kind);
            // The message has to say *why*, because "not allowed" invites a
            // workaround and "it has no signature to check" does not.
            assert!(err.to_string().contains("unsigned userinfo call"));
        }
    }

    /// Facebook is the single kind that admits both, and the reason is on the
    /// wire, not in our preferences: its web flow returns no ID token to a
    /// confidential client, while Limited Login does.
    #[test]
    fn facebook_admits_both_protocols_and_nothing_else_does() {
        assert!(
            validate_protocol_for_kind(ProviderKind::Facebook, FederationProtocol::OAuth2).is_ok()
        );
        assert!(
            validate_protocol_for_kind(ProviderKind::Facebook, FederationProtocol::OidcConnect)
                .is_ok()
        );
        assert!(
            validate_protocol_for_kind(ProviderKind::Facebook, FederationProtocol::Saml).is_err()
        );
        for kind in ProviderKind::ALL {
            if *kind == ProviderKind::Facebook {
                continue;
            }
            let admissible = [
                FederationProtocol::OidcConnect,
                FederationProtocol::Saml,
                FederationProtocol::OAuth2,
            ]
            .into_iter()
            .filter(|p| validate_protocol_for_kind(*kind, *p).is_ok())
            .count();
            assert_eq!(admissible, 1, "{kind:?} must admit exactly one protocol");
        }
    }

    #[test]
    fn a_branded_kind_keys_on_the_kind_and_a_generic_one_on_its_slug() {
        assert_eq!(config(ProviderKind::Google, None).override_key(), "google");
        // A slug on a branded kind is not part of the key — otherwise a tenant
        // could fail to override the organization's Google by typing a
        // different display slug.
        assert_eq!(
            config(ProviderKind::Google, Some("anything")).override_key(),
            "google"
        );
        assert_eq!(
            config(ProviderKind::GenericOidc, Some("okta-eu")).override_key(),
            "generic_oidc:okta-eu"
        );
        assert_ne!(
            config(ProviderKind::GenericOidc, Some("okta-eu")).override_key(),
            config(ProviderKind::GenericOidc, Some("okta-us")).override_key(),
        );
        // Two generic kinds with the same slug are still different providers.
        assert_ne!(
            config(ProviderKind::GenericOidc, Some("x")).override_key(),
            config(ProviderKind::GenericOauth2, Some("x")).override_key(),
        );
    }

    #[test]
    fn a_legacy_row_reads_back_as_the_generic_kind_of_its_protocol() {
        assert_eq!(
            ProviderKind::from_legacy_protocol(FederationProtocol::OidcConnect),
            ProviderKind::GenericOidc
        );
        assert_eq!(
            ProviderKind::from_legacy_protocol(FederationProtocol::Saml),
            ProviderKind::GenericSaml
        );
    }

    /// The compatibility property that matters most: an untouched OIDC config
    /// still asks for exactly the scopes `build_authorization_url` used to
    /// hard-code.
    #[test]
    fn empty_scopes_resolve_to_the_previously_hard_coded_oidc_set() {
        let c = config(ProviderKind::GenericOidc, None);
        assert_eq!(
            c.effective_scopes(),
            vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string()
            ]
        );
    }

    /// …and Apple's is different, which is the whole reason the hard-coding
    /// was wrong: Apple rejects `profile`.
    #[test]
    fn apple_does_not_get_the_profile_scope() {
        let scopes = ProviderKind::Apple.default_scopes();
        assert!(!scopes.contains(&"profile".to_string()));
        assert_eq!(scopes, vec!["name".to_string(), "email".to_string()]);
    }

    #[test]
    fn configured_scopes_win_over_the_default() {
        let mut c = config(ProviderKind::Google, None);
        c.scopes = vec!["openid".into()];
        assert_eq!(c.effective_scopes(), vec!["openid".to_string()]);
    }

    #[test]
    fn pkce_is_unconditional_for_the_oauth2_variant() {
        // Not merely defaulted — a config with the flag off still gets it,
        // because it is the only replay protection left there.
        let mut c = config(ProviderKind::Github, None);
        c.require_pkce = false;
        assert!(c.pkce_required());
        // On OIDC it stays opt-in, so an existing config is unchanged.
        let mut c = config(ProviderKind::Google, None);
        c.require_pkce = false;
        assert!(!c.pkce_required());
        c.require_pkce = true;
        assert!(c.pkce_required());
    }

    #[test]
    fn allowed_algorithms_is_meaningless_for_the_oauth2_variant() {
        assert!(!ProviderKind::Github.uses_allowed_algorithms());
        assert!(ProviderKind::Google.uses_allowed_algorithms());
        assert!(ProviderKind::GenericSaml.uses_allowed_algorithms());
        assert!(ProviderKind::Github.default_allowed_algorithms().is_empty());
        assert_eq!(
            ProviderKind::Apple.default_allowed_algorithms(),
            vec!["RS256".to_string()]
        );
    }

    #[test]
    fn apple_mints_its_own_secret_only_when_both_ids_are_present() {
        let mut c = config(ProviderKind::Apple, None);
        assert!(!c.mints_client_secret(), "no ids: use the stored secret");
        c.apple_team_id = Some("ABCDE12345".into());
        assert!(
            !c.mints_client_secret(),
            "half-configured is not configured"
        );
        c.apple_key_id = Some("KEYID67890".into());
        assert!(c.mints_client_secret());
        // The mechanism is Apple-only; another kind with stray ids does not
        // acquire it.
        let mut g = config(ProviderKind::Google, None);
        g.apple_team_id = Some("ABCDE12345".into());
        g.apple_key_id = Some("KEYID67890".into());
        assert!(!g.mints_client_secret());
    }

    /// The rule that keeps a mandated mark mandated: only the kinds AXIAM
    /// ships no logo for may carry a custom one.
    #[test]
    fn only_the_generic_kinds_lack_a_bundled_mark() {
        for kind in [
            ProviderKind::Google,
            ProviderKind::Github,
            ProviderKind::Facebook,
            ProviderKind::Apple,
            ProviderKind::Microsoft,
        ] {
            assert!(kind.has_bundled_mark(), "{kind:?} ships its own mark");
        }
        for kind in [
            ProviderKind::GenericOidc,
            ProviderKind::GenericOauth2,
            ProviderKind::GenericSaml,
        ] {
            assert!(!kind.has_bundled_mark(), "{kind:?} has no mark to ship");
        }
    }

    #[test]
    fn a_button_icon_must_be_a_bounded_raster_data_url() {
        assert!(validate_provider_icon("data:image/png;base64,iVBORw0KGgo=").is_ok());
        assert!(validate_provider_icon("data:image/jpeg;base64,/9j/4AAQ").is_ok());
        assert!(validate_provider_icon("data:image/webp;base64,UklGRg==").is_ok());

        // SVG is a document with a parser, served to everyone who loads a
        // login page. The message has to say so, or somebody will "fix" it.
        let err = validate_provider_icon("data:image/svg+xml;base64,PHN2Zz4=").unwrap_err();
        assert!(err.contains("SVG is not accepted"));

        // A remote URL would be blocked by the SPA's CSP anyway — silently,
        // which is the worst way to find out.
        assert!(validate_provider_icon("https://cdn.example/logo.png").is_err());
        assert!(validate_provider_icon("javascript:alert(1)").is_err());
        assert!(validate_provider_icon("data:image/png;base64,").is_err());
        assert!(validate_provider_icon("data:image/png;base64,not base64!").is_err());

        // Bounded, because this is served by an unauthenticated endpoint on
        // every render of a login page.
        let too_big = format!(
            "data:image/png;base64,{}",
            "A".repeat(MAX_PROVIDER_ICON_BYTES.div_ceil(3) * 4 + 8)
        );
        let err = validate_provider_icon(&too_big).unwrap_err();
        assert!(err.contains("maximum"), "{err}");
        // Stated in KiB of image: the operator has a PNG, not a data URL.
        assert!(err.contains("KiB"), "{err}");
        assert!(
            err.contains(&PROVIDER_ICON_SIZE_PX.to_string()),
            "the message should tell the operator what size to aim at: {err}"
        );

        // …and an icon just under the limit is accepted, so this is a bound
        // rather than an off-by-one that rejects a legitimate image.
        let at_limit = format!(
            "data:image/png;base64,{}",
            "A".repeat(MAX_PROVIDER_ICON_BYTES / 3 * 4)
        );
        assert!(validate_provider_icon(&at_limit).is_ok());
    }

    /// A 32 KiB blob in `{:?}` is noise, and the only thing a reader wants is
    /// whether one is set at all.
    #[test]
    fn debug_summarises_the_button_icon_rather_than_printing_it() {
        let mut c = config(ProviderKind::GenericOidc, Some("okta"));
        c.button_icon = Some(format!("data:image/png;base64,{}", "Q".repeat(400)));
        let debug = format!("{c:?}");
        assert!(!debug.contains(&"Q".repeat(400)));
        assert!(debug.contains("chars"));
    }

    #[test]
    fn provider_slugs_have_exactly_one_spelling() {
        for good in ["okta", "okta-eu", "idp1", "a"] {
            assert!(validate_provider_slug(good).is_ok(), "{good}");
        }
        for bad in ["", "Okta", "okta_eu", "-okta", "okta-", "okta--eu", "ok ta"] {
            assert!(validate_provider_slug(bad).is_err(), "{bad}");
        }
        assert!(validate_provider_slug(&"a".repeat(MAX_PROVIDER_SLUG_LEN)).is_ok());
        assert!(validate_provider_slug(&"a".repeat(MAX_PROVIDER_SLUG_LEN + 1)).is_err());
    }

    /// The new columns must not become a leak. Restates the existing
    /// SECHRD-09 property against the widened struct.
    #[test]
    fn the_widened_config_still_redacts_every_secret() {
        let mut c = config(ProviderKind::Apple, None);
        c.client_secret = "PLAINTEXT-SECRET-MARKER".into();
        c.client_secret_ciphertext = Some("CIPHERTEXT-MARKER".into());
        c.client_secret_nonce = Some("NONCE-MARKER".into());
        let debug = format!("{c:?}");
        let json = serde_json::to_string(&c).unwrap();
        for marker in [
            "PLAINTEXT-SECRET-MARKER",
            "CIPHERTEXT-MARKER",
            "NONCE-MARKER",
        ] {
            assert!(!debug.contains(marker), "Debug leaked {marker}");
            assert!(!json.contains(marker), "JSON leaked {marker}");
        }
        // …while the new non-secret fields stay legible, which is the point of
        // a manual Debug impl rather than a blanket redaction.
        assert!(debug.contains("provider_kind"));
        assert!(debug.contains("allow_tenant_inheritance"));
    }

    #[test]
    fn an_unknown_subject_mapping_is_refused_rather_than_defaulted() {
        assert_eq!(
            SubjectMapping::from_wire("linked_only"),
            Some(SubjectMapping::LinkedOnly)
        );
        assert_eq!(
            SubjectMapping::from_wire("jit_provision"),
            Some(SubjectMapping::JitProvision)
        );
        assert_eq!(SubjectMapping::from_wire("jit_provsion"), None);
        assert_eq!(SubjectMapping::from_wire(""), None);
    }
}

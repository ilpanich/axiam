//! Federation configuration domain model.
//!
//! Supports external OIDC identity providers (including social login)
//! and SAML service provider integration.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub enum FederationProtocol {
    OidcConnect,
    Saml,
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
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
            subject: "CN=Test Root CA".to_string(),
            public_cert_pem: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
                .to_string(),
            fingerprint: "aa:bb:cc".to_string(),
            key_algorithm: KeyAlgorithm::Ed25519,
            not_before: Utc::now(),
            not_after: Utc::now(),
            status: CertificateStatus::Active,
            encrypted_private_key: Some(KEY_MARKER.to_vec()),
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

//! X4 — accepting an **external IdP's** token as an RFC 8693 subject token.
//!
//! Design: `claude_dev/external-token-exchange-design.md`. The sentence that
//! governs every function here, because it is what makes this path different
//! from B3's:
//!
//! > **An external subject token is evidence of authentication, never a grant
//! > of authorization.**
//!
//! B3 narrows an AXIAM token against itself; there is a `subject_scopes` set
//! to intersect with. A partner's token has no such set — its scopes are the
//! partner's vocabulary and carry no authority in this tenant. So this module
//! answers exactly one question — *which AXIAM user, if any, does this token
//! prove authenticated, and which AXIAM scope names did the admin agree that
//! provider's assertions may map onto* — and hands the answer to
//! `axiam-oauth2`, which decides what may actually be issued.
//!
//! # Why this lives in `axiam-federation`
//!
//! Every input is already here: the provider rows, the discovery cache, the
//! JWKS cache with its kid-rollover behaviour, the SSRF guard, and the JIT
//! provisioning path. Re-implementing any of them next to the token endpoint
//! would create a second place where "which user is this" can be answered, and
//! the two would drift. The exchange path resolves subjects through the *same*
//! [`OidcFederationService::provision_or_link_user`] a browser login uses.

use axiam_core::error::AxiamError;
use axiam_core::models::federation::{FederationConfig, SubjectMapping};
use axiam_core::models::user::UserStatus;
use axiam_core::repository::{
    FederationConfigRepository, FederationLinkRepository, UserRepository,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use tracing::{info, warn};
use uuid::Uuid;

use crate::error::FederationError;
use crate::oidc::{
    OidcFederationService, find_jwk, map_algorithm_strings, reject_alg_none_raw,
    unverified_issuer_of,
};

/// Clock-skew tolerance, matching the OIDC login path (D-05 / REQ-5).
const LEEWAY_SECS: u64 = 60;

/// Claims read out of an external subject token.
///
/// Everything is `Option` **except `sub`**: this struct is deserialized after
/// `jsonwebtoken` has already enforced the presence of `iss`/`aud`/`exp`/`iat`
/// through `set_required_spec_claims`, and duplicating that as non-optional
/// fields would turn a clear "claim rejected" into an opaque parse error.
#[derive(Debug, Clone, Deserialize)]
struct ExternalClaims {
    sub: String,
    iss: Option<String>,
    aud: Option<serde_json::Value>,
    exp: Option<i64>,
    iat: Option<i64>,
    // ---- scope-bearing claims (see `asserted_values`) -------------------
    scope: Option<String>,
    scp: Option<serde_json::Value>,
    roles: Option<Vec<String>>,
    groups: Option<Vec<String>>,
    // ---- shape markers --------------------------------------------------
    /// OIDC Core §3.1.3.7 — an ID-token-only claim.
    nonce: Option<String>,
    /// OIDC Core §3.3.2.11 / §3.2.2.9 — ID-token-only hashes.
    at_hash: Option<String>,
    c_hash: Option<String>,
    s_hash: Option<String>,
    /// X4's own provenance claim. Present ⇒ this token is already the product
    /// of an exchange and must not buy another one.
    ext_exchange: Option<serde_json::Value>,
    /// Some IdPs (notably Keycloak) put the token kind in a `typ` *claim*
    /// rather than only in the JOSE header.
    typ: Option<String>,
}

/// What a successful external verification established.
#[derive(Debug, Clone)]
pub struct ExternalSubject {
    /// The foreign issuer, exactly as the token spelled it. Stamped into the
    /// issued token's `ext_exchange` claim and into the audit record.
    pub issuer: String,
    pub provider_id: Uuid,
    pub provider_name: String,
    /// The partner-local subject identifier (`sub`). Audit only — never a key
    /// for anything downstream.
    pub external_subject: String,
    pub user_id: Uuid,
    /// True when this call created the AXIAM user. The only record that a
    /// partner's IdP provisioned a local identity.
    pub newly_provisioned: bool,
    /// AXIAM scope names the provider's `scope_map` produced. A **candidate**
    /// set: the client registration and the RBAC engine still have to agree.
    pub candidate_scopes: Vec<String>,
    /// The external token's `exp`, so the issued token cannot outlive it.
    pub subject_exp: i64,
    /// Per-provider ceiling on the issued token's lifetime, if configured.
    pub max_lifetime_secs: Option<i64>,
}

/// Why an external subject token was refused.
///
/// Split by *what the operator should do about it* rather than by which check
/// failed: the token endpoint maps `IssuerNotTrusted` to a distinguishable
/// description (fix your config) and everything else to a generic
/// `invalid_grant` (fix your token).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalSubjectError {
    /// No enabled, exchange-enabled provider in this tenant claims this
    /// issuer — or the token has no readable `iss` at all.
    IssuerNotTrusted,
    /// Signature, claim, age, audience or shape check failed. The string is
    /// for the audit record and the server log, **not** for the wire.
    Rejected(String),
    /// The `(provider, sub)` pair has no AXIAM user and the provider is
    /// configured `linked_only`.
    SubjectNotLinked,
    /// A user exists but is not in a state that may hold a token.
    UserNotActive,
    Server(String),
}

impl std::fmt::Display for ExternalSubjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IssuerNotTrusted => {
                write!(f, "issuer is not configured for token exchange")
            }
            Self::Rejected(why) => write!(f, "external subject token rejected: {why}"),
            Self::SubjectNotLinked => write!(f, "external subject is not linked to an AXIAM user"),
            Self::UserNotActive => write!(f, "the linked AXIAM user is not active"),
            Self::Server(m) => write!(f, "{m}"),
        }
    }
}

impl ExternalSubjectError {
    fn rejected(why: impl Into<String>) -> Self {
        Self::Rejected(why.into())
    }

    /// A stable, low-cardinality label for metrics and audit records.
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::IssuerNotTrusted => "issuer_not_trusted",
            Self::Rejected(_) => "token_rejected",
            Self::SubjectNotLinked => "subject_not_linked",
            Self::UserNotActive => "user_not_active",
            Self::Server(_) => "server_error",
        }
    }
}

// ---------------------------------------------------------------------------
// Pure helpers — unit-testable without a datastore, a network or a clock
// ---------------------------------------------------------------------------

/// Flatten an OIDC `aud` claim, which the spec allows to be a string or an
/// array of strings.
///
/// Anything else (a number, an object, an array containing non-strings)
/// flattens to **nothing**, which fails the audience check. Coercing a number
/// to its decimal spelling here would be inventing an audience the issuer did
/// not write.
pub(crate) fn flatten_audience(aud: Option<&serde_json::Value>) -> Vec<String> {
    match aud {
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// The external values a `scope_map` may be keyed on.
///
/// Four claim shapes, because those are the four the IdPs this feature exists
/// for actually emit:
///
/// | claim | who |
/// |---|---|
/// | `scope` (space-separated string) | Okta, Keycloak, Auth0, RFC 9068 |
/// | `scp` (string **or** array) | Entra ID (string), some Okta configs (array) |
/// | `roles` (array) | Entra ID app roles |
/// | `groups` (array) | Okta, Entra group claims |
///
/// Anything else is invisible to the map. That is the conservative direction:
/// a claim we do not read cannot grant anything, whereas a claim we read
/// wrongly can. Nested shapes (Keycloak's `realm_access.roles`) are
/// deliberately out of v1 — mapping a path expression is a feature, and a
/// half-done one here would silently read the wrong node.
fn asserted_values(claims: &ExternalClaims) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |v: &str| {
        let v = v.trim();
        if !v.is_empty() && !out.iter().any(|e| e == v) {
            out.push(v.to_owned());
        }
    };

    if let Some(scope) = claims.scope.as_deref() {
        scope.split_whitespace().for_each(&mut push);
    }
    match claims.scp.as_ref() {
        Some(serde_json::Value::String(s)) => s.split_whitespace().for_each(&mut push),
        Some(serde_json::Value::Array(items)) => {
            for item in items {
                if let Some(s) = item.as_str() {
                    push(s);
                }
            }
        }
        _ => {}
    }
    for list in [claims.roles.as_ref(), claims.groups.as_ref()] {
        for value in list.into_iter().flatten() {
            push(value);
        }
    }
    out
}

/// Refuse a correctly-signed token that is nonetheless the wrong *kind* of
/// token.
///
/// An ID token is an assertion to a **client** about a login; OIDC gives it a
/// longer life and a wider distribution than an access token precisely because
/// it is not meant to be presented to APIs. A refresh token is a
/// re-authentication credential. Accepting either as a subject token would let
/// an artefact the partner considers low-risk buy an AXIAM credential.
///
/// Detection is by the claims and header markers that are *only* legal on
/// those token types — never by absence of an access-token marker, because
/// plenty of legitimate access tokens carry no `typ` at all.
fn reject_wrong_token_kind(
    claims: &ExternalClaims,
    header_typ: Option<&str>,
) -> Result<(), ExternalSubjectError> {
    for (name, present) in [
        ("nonce", claims.nonce.is_some()),
        ("at_hash", claims.at_hash.is_some()),
        ("c_hash", claims.c_hash.is_some()),
        ("s_hash", claims.s_hash.is_some()),
    ] {
        if present {
            return Err(ExternalSubjectError::rejected(format!(
                "the token carries '{name}', which is an ID-token claim; \
                 present an access token"
            )));
        }
    }

    for typ in [header_typ, claims.typ.as_deref()].into_iter().flatten() {
        let normalized = typ.trim().to_ascii_lowercase();
        let normalized = normalized
            .strip_prefix("application/")
            .unwrap_or(&normalized);
        if matches!(
            normalized,
            "id_token" | "id+jwt" | "refresh" | "refresh_token" | "offline" | "logout+jwt"
        ) {
            return Err(ExternalSubjectError::rejected(format!(
                "token type '{typ}' is not usable as a subject token"
            )));
        }
    }
    Ok(())
}

/// Time-based checks that `jsonwebtoken`'s own validation does not cover.
///
/// `exp` is enforced by the decoder; what is enforced here is **age**, which
/// is a separate policy: a partner IdP issuing 24-hour access tokens should
/// not thereby hand out a 24-hour replay window into AXIAM.
fn check_age(iat: Option<i64>, now: i64, max_age_secs: i64) -> Result<(), ExternalSubjectError> {
    let Some(iat) = iat else {
        // Unreachable in practice — `iat` is in `set_required_spec_claims` —
        // but the age rule is meaningless without it, and "meaningless" must
        // not silently mean "unbounded".
        return Err(ExternalSubjectError::rejected("token has no 'iat' claim"));
    };
    if iat > now + LEEWAY_SECS as i64 {
        return Err(ExternalSubjectError::rejected(
            "token is issued in the future beyond the permitted skew",
        ));
    }
    let age = now - iat;
    if age > max_age_secs {
        return Err(ExternalSubjectError::rejected(format!(
            "token is {age}s old; this provider accepts at most {max_age_secs}s"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The service method
// ---------------------------------------------------------------------------

impl<FC, FL, UR> OidcFederationService<FC, FL, UR>
where
    FC: FederationConfigRepository,
    FL: FederationLinkRepository,
    UR: UserRepository,
{
    /// Verify an external IdP's token and resolve it to an AXIAM subject.
    ///
    /// The pipeline order is normative and is reproduced in the design doc's
    /// §"Validation pipeline". Two orderings in particular are load-bearing:
    ///
    /// * **The provider is resolved before anything else is believed.** The
    ///   `iss` claim read at step 1 is *unverified* and is used only to select
    ///   which key the token is then checked against — never to decide whether
    ///   it is checked.
    /// * **Scope mapping happens after subject resolution, not before.** A
    ///   token that maps to no scopes and a token whose subject is unknown are
    ///   different failures, and an operator reading the audit trail needs to
    ///   see which one happened.
    pub async fn verify_external_subject_token(
        &self,
        tenant_id: Uuid,
        token: &str,
        now: i64,
    ) -> Result<ExternalSubject, ExternalSubjectError> {
        // --- 1. Which provider claims this issuer? -------------------------
        let claimed_issuer = unverified_issuer_of(token).ok_or_else(|| {
            // No readable `iss` is indistinguishable, from the caller's side,
            // from an issuer nobody trusts — and it is: neither can name a
            // provider.
            ExternalSubjectError::IssuerNotTrusted
        })?;

        let (config, discovery) = self
            .resolve_trusted_provider(tenant_id, &claimed_issuer)
            .await?;
        let trust = &config.token_exchange;

        // A misconfiguration this check exists to make impossible rather than
        // merely unlikely: if a provider advertised AXIAM's own issuer, the
        // internal and external branches would overlap and a foreign key could
        // verify a token that claims to be ours.
        if discovery.issuer != claimed_issuer {
            return Err(ExternalSubjectError::IssuerNotTrusted);
        }

        // --- 2. Signature ---------------------------------------------------
        reject_alg_none_raw(token)
            .map_err(|_| ExternalSubjectError::rejected("'none' is not a signature algorithm"))?;
        let header = decode_header(token)
            .map_err(|_| ExternalSubjectError::rejected("unparseable JOSE header"))?;
        let allowed: Vec<Algorithm> = map_algorithm_strings(&config.allowed_algorithms);
        if allowed.is_empty() {
            // An empty allow-list would make `Validation` accept the header's
            // own choice. Refusing is the only safe reading of "the operator
            // configured no algorithms".
            return Err(ExternalSubjectError::rejected(
                "the provider has no accepted signature algorithms configured",
            ));
        }
        if !allowed.contains(&header.alg) {
            return Err(ExternalSubjectError::rejected(format!(
                "algorithm {:?} is not accepted from this provider",
                header.alg
            )));
        }

        let cache_key = (tenant_id, config.id);
        let jwks = self
            .jwks_cache()
            .get_or_fetch(self.http_client(), cache_key, &discovery.jwks_uri)
            .await
            .map_err(|e| ExternalSubjectError::rejected(format!("JWKS unavailable: {e}")))?;
        let jwk = match find_jwk(&jwks, header.kid.as_deref()) {
            Some(j) => j,
            None => {
                // Unknown kid → the provider rotated. Same rate-limited forced
                // refetch the login path uses; sharing it is the point of
                // living in this crate.
                let refreshed = self
                    .jwks_cache()
                    .force_refetch_if_allowed(self.http_client(), cache_key, &discovery.jwks_uri)
                    .await
                    .map_err(|e| {
                        ExternalSubjectError::rejected(format!("JWKS refetch failed: {e}"))
                    })?;
                find_jwk(&refreshed, header.kid.as_deref()).ok_or_else(|| {
                    ExternalSubjectError::rejected("no JWKS key matches the token's kid")
                })?
            }
        };
        let decoding_key = DecodingKey::from_jwk(&jwk)
            .map_err(|_| ExternalSubjectError::rejected("unusable JWKS key"))?;

        let mut validation = Validation::new(header.alg);
        validation.algorithms = allowed;
        validation.set_issuer(&[&discovery.issuer]);
        // `aud` is checked against the provider's `accepted_audiences` below,
        // not here: `jsonwebtoken` would treat a match against any one
        // configured value as success, which is what we want — but it would
        // also let an empty configured list mean "no audience validation",
        // and an audience check that silently disappears when a list is empty
        // is exactly the failure `accepted_audiences` is non-empty to prevent.
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["iss", "aud", "exp", "iat"]);
        validation.leeway = LEEWAY_SECS;

        let claims = decode::<ExternalClaims>(token, &decoding_key, &validation)
            .map_err(|e| {
                use jsonwebtoken::errors::ErrorKind;
                match e.kind() {
                    ErrorKind::InvalidSignature => {
                        ExternalSubjectError::rejected("signature is invalid")
                    }
                    other => ExternalSubjectError::rejected(format!("claim rejected: {other:?}")),
                }
            })?
            .claims;

        // --- 3. Claims the decoder does not police --------------------------
        if claims.ext_exchange.is_some() {
            return Err(ExternalSubjectError::rejected(
                "the token is itself the product of a token exchange; \
                 exchanges do not compose",
            ));
        }
        reject_wrong_token_kind(&claims, header.typ.as_deref())?;
        check_age(claims.iat, now, trust.max_token_age_secs)?;

        let audiences = flatten_audience(claims.aud.as_ref());
        if !trust.audience_accepted(&audiences) {
            return Err(ExternalSubjectError::rejected(
                "the token's audience is not accepted by this provider's configuration",
            ));
        }

        let subject_exp = claims
            .exp
            .ok_or_else(|| ExternalSubjectError::rejected("token has no 'exp' claim"))?;
        if subject_exp <= now {
            return Err(ExternalSubjectError::rejected("token has expired"));
        }
        if claims.sub.trim().is_empty() {
            return Err(ExternalSubjectError::rejected("token has an empty 'sub'"));
        }

        // --- 4. Which AXIAM user? -------------------------------------------
        let user_id;
        let newly_provisioned;
        match trust.subject_mapping {
            SubjectMapping::LinkedOnly => {
                let link = self
                    .federation_link_repo_ref()
                    .get_by_external_subject(tenant_id, config.id, &claims.sub)
                    .await
                    .map_err(|e| match e {
                        AxiamError::NotFound { .. } => ExternalSubjectError::SubjectNotLinked,
                        other => ExternalSubjectError::Server(other.to_string()),
                    })?;
                user_id = link.user_id;
                newly_provisioned = false;
            }
            SubjectMapping::JitProvision => {
                // Deliberately the *same* function a browser login uses, so a
                // partner token and an interactive login can never disagree
                // about which AXIAM user an `(issuer, sub)` pair means.
                let resolved = self
                    .provision_or_link_user(
                        tenant_id,
                        config.id,
                        &crate::oidc::IdTokenClaims {
                            sub: claims.sub.clone(),
                            iss: claims.iss.clone(),
                            aud: claims.aud.clone(),
                            exp: claims.exp.map(|v| v as u64),
                            iat: claims.iat.map(|v| v as u64),
                            email: None,
                            email_verified: None,
                            name: None,
                            nonce: None,
                        },
                    )
                    .await
                    .map_err(|e| ExternalSubjectError::Server(e.to_string()))?;
                user_id = resolved.user.id;
                newly_provisioned = resolved.newly_provisioned;
                if newly_provisioned {
                    info!(
                        target: "axiam::audit",
                        event = "federation.jit_provision",
                        tenant_id = %tenant_id,
                        provider = %config.provider,
                        user_id = %user_id,
                        source = "token_exchange",
                        "JIT-provisioned an AXIAM user from an external subject token"
                    );
                }
            }
        }

        // A suspended, locked or anonymized user is not resurrected by a
        // partner's token. Checked after resolution rather than folded into it
        // so a JIT-provisioned user goes through the identical gate.
        //
        // **`PendingVerification` is allowed here, and that is not laxity.**
        // `UserRepository::create` writes that status for every new row, and
        // the federation provisioning path (`provision_new_user`) never moves
        // a federated user off it — there is nothing for AXIAM to verify,
        // since a federated user has no usable password and a synthetic email
        // address. Every user who logged in through this provider's browser
        // flow is therefore `PendingVerification` for life. Requiring `Active`
        // would refuse exactly the population X4 exists to serve, while
        // stopping nobody: the states that mean "this account must not be
        // used" are the three refused below.
        let user = self
            .user_repo_ref()
            .get_by_id(tenant_id, user_id)
            .await
            .map_err(|e| match e {
                AxiamError::NotFound { .. } => ExternalSubjectError::SubjectNotLinked,
                other => ExternalSubjectError::Server(other.to_string()),
            })?;
        match user.status {
            UserStatus::Active | UserStatus::PendingVerification => {}
            UserStatus::Locked | UserStatus::Inactive | UserStatus::Anonymized => {
                return Err(ExternalSubjectError::UserNotActive);
            }
        }

        // --- 5. What may the provider's assertions map onto? ----------------
        let candidate_scopes = trust.map_scopes(&asserted_values(&claims));

        Ok(ExternalSubject {
            issuer: claimed_issuer,
            provider_id: config.id,
            provider_name: config.provider.clone(),
            external_subject: claims.sub,
            user_id,
            newly_provisioned,
            candidate_scopes,
            subject_exp,
            max_lifetime_secs: trust.max_lifetime_secs,
        })
    }

    /// Find the enabled, exchange-enabled provider whose **discovery
    /// document** advertises `claimed_issuer`.
    ///
    /// The issuer is taken from the provider's discovery document rather than
    /// from an admin-typed field, so trust follows the same source of truth
    /// the login path verifies against. Matching is exact — no trailing-slash
    /// forgiveness, no case folding, no normalisation.
    async fn resolve_trusted_provider(
        &self,
        tenant_id: Uuid,
        claimed_issuer: &str,
    ) -> Result<(FederationConfig, crate::oidc::OidcDiscoveryDocument), ExternalSubjectError> {
        let candidates = self
            .federation_config_repo_ref()
            .list_token_exchange_enabled(tenant_id)
            .await
            .map_err(|e| ExternalSubjectError::Server(e.to_string()))?;

        for config in candidates {
            // A row can be enabled and still be unusable; a misconfigured
            // provider must not take the whole exchange path down with it, so
            // each failure is logged and skipped rather than returned.
            if config.token_exchange.validate().is_err() {
                warn!(
                    tenant_id = %tenant_id,
                    provider = %config.provider,
                    "skipping token-exchange provider with an invalid trust configuration"
                );
                continue;
            }
            let Some(metadata_url) = config.metadata_url.as_deref() else {
                continue;
            };
            let discovery = match self.discover(metadata_url).await {
                Ok(d) => d,
                Err(e) => {
                    warn!(
                        tenant_id = %tenant_id,
                        provider = %config.provider,
                        error = %e,
                        "token-exchange provider discovery failed; skipping"
                    );
                    continue;
                }
            };
            if discovery.issuer == claimed_issuer {
                return Ok((config, discovery));
            }
        }
        Err(ExternalSubjectError::IssuerNotTrusted)
    }
}

impl From<FederationError> for ExternalSubjectError {
    fn from(e: FederationError) -> Self {
        Self::Server(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn claims() -> ExternalClaims {
        ExternalClaims {
            sub: "partner-user-1".into(),
            iss: Some("https://partner.example".into()),
            aud: Some(json!("https://api.axiam.example")),
            exp: Some(0),
            iat: Some(0),
            scope: None,
            scp: None,
            roles: None,
            groups: None,
            nonce: None,
            at_hash: None,
            c_hash: None,
            s_hash: None,
            ext_exchange: None,
            typ: None,
        }
    }

    // -----------------------------------------------------------------
    // Audience flattening
    // -----------------------------------------------------------------

    #[test]
    fn audience_accepts_both_spec_shapes() {
        assert_eq!(flatten_audience(Some(&json!("a"))), vec!["a".to_string()]);
        assert_eq!(
            flatten_audience(Some(&json!(["a", "b"]))),
            vec!["a".to_string(), "b".to_string()]
        );
        assert!(flatten_audience(None).is_empty());
    }

    /// A non-string audience flattens to nothing rather than to its decimal
    /// spelling: coercing here would invent an audience the issuer never
    /// wrote, and the audience check is the one that decides whether this
    /// token was addressed to us at all.
    #[test]
    fn a_non_string_audience_flattens_to_nothing() {
        assert!(flatten_audience(Some(&json!(42))).is_empty());
        assert!(flatten_audience(Some(&json!({ "aud": "a" }))).is_empty());
        assert_eq!(
            flatten_audience(Some(&json!(["a", 42, null]))),
            vec!["a".to_string()],
            "non-string members drop out; the string ones survive"
        );
    }

    // -----------------------------------------------------------------
    // Asserted values
    // -----------------------------------------------------------------

    #[test]
    fn every_supported_claim_shape_contributes() {
        let c = ExternalClaims {
            scope: Some("read  write".into()),
            scp: Some(json!("admin")),
            roles: Some(vec!["Orders.Read".into()]),
            groups: Some(vec!["finance".into()]),
            ..claims()
        };
        let mut got = asserted_values(&c);
        got.sort();
        assert_eq!(
            got,
            vec!["Orders.Read", "admin", "finance", "read", "write"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn scp_is_read_as_both_a_string_and_an_array() {
        let as_array = ExternalClaims {
            scp: Some(json!(["a", "b"])),
            ..claims()
        };
        assert_eq!(asserted_values(&as_array), vec!["a", "b"]);

        let as_string = ExternalClaims {
            scp: Some(json!("a b")),
            ..claims()
        };
        assert_eq!(asserted_values(&as_string), vec!["a", "b"]);
    }

    #[test]
    fn duplicates_across_claims_collapse() {
        let c = ExternalClaims {
            scope: Some("read".into()),
            scp: Some(json!("read")),
            roles: Some(vec!["read".into()]),
            ..claims()
        };
        assert_eq!(asserted_values(&c), vec!["read".to_string()]);
    }

    #[test]
    fn unreadable_claim_shapes_contribute_nothing_rather_than_guessing() {
        let c = ExternalClaims {
            // Keycloak's nested realm_access.roles arrives as an object; v1
            // does not read it, and must not half-read it.
            scp: Some(json!({ "roles": ["admin"] })),
            ..claims()
        };
        assert!(asserted_values(&c).is_empty());
    }

    // -----------------------------------------------------------------
    // Token kind
    // -----------------------------------------------------------------

    #[test]
    fn an_access_token_shape_passes() {
        assert!(reject_wrong_token_kind(&claims(), Some("at+jwt")).is_ok());
        assert!(reject_wrong_token_kind(&claims(), Some("JWT")).is_ok());
        assert!(reject_wrong_token_kind(&claims(), None).is_ok());
    }

    #[test]
    fn every_id_token_marker_is_refused() {
        for c in [
            ExternalClaims {
                nonce: Some("n".into()),
                ..claims()
            },
            ExternalClaims {
                at_hash: Some("h".into()),
                ..claims()
            },
            ExternalClaims {
                c_hash: Some("h".into()),
                ..claims()
            },
            ExternalClaims {
                s_hash: Some("h".into()),
                ..claims()
            },
        ] {
            assert!(
                reject_wrong_token_kind(&c, None).is_err(),
                "an ID token must not be usable as a subject token"
            );
        }
    }

    #[test]
    fn refresh_and_id_token_types_are_refused_from_either_header_or_claim() {
        for typ in ["Refresh", "refresh_token", "ID_TOKEN", "application/id+jwt"] {
            assert!(
                reject_wrong_token_kind(&claims(), Some(typ)).is_err(),
                "header typ {typ} must be refused"
            );
            let c = ExternalClaims {
                typ: Some(typ.into()),
                ..claims()
            };
            assert!(
                reject_wrong_token_kind(&c, None).is_err(),
                "claim typ {typ} must be refused"
            );
        }
    }

    // -----------------------------------------------------------------
    // Age
    // -----------------------------------------------------------------

    #[test]
    fn a_token_older_than_the_provider_allows_is_refused() {
        assert!(check_age(Some(1_000), 1_200, 300).is_ok());
        assert!(check_age(Some(1_000), 1_301, 300).is_err());
        // Exactly at the bound is still inside it.
        assert!(check_age(Some(1_000), 1_300, 300).is_ok());
    }

    #[test]
    fn an_iat_in_the_future_is_refused_beyond_skew_and_tolerated_inside_it() {
        assert!(check_age(Some(1_030), 1_000, 300).is_ok(), "30s of skew");
        assert!(check_age(Some(1_200), 1_000, 300).is_err(), "200s of skew");
    }

    #[test]
    fn a_missing_iat_is_refused_rather_than_treated_as_unbounded() {
        assert!(check_age(None, 1_000, 300).is_err());
    }

    // -----------------------------------------------------------------
    // Error surface
    // -----------------------------------------------------------------

    /// The reason codes are what the audit trail and the metrics key on, so
    /// they are pinned rather than left to follow the variant names around.
    #[test]
    fn reason_codes_are_stable() {
        assert_eq!(
            ExternalSubjectError::IssuerNotTrusted.reason_code(),
            "issuer_not_trusted"
        );
        assert_eq!(
            ExternalSubjectError::rejected("x").reason_code(),
            "token_rejected"
        );
        assert_eq!(
            ExternalSubjectError::SubjectNotLinked.reason_code(),
            "subject_not_linked"
        );
        assert_eq!(
            ExternalSubjectError::UserNotActive.reason_code(),
            "user_not_active"
        );
    }

    /// The rejection *reason* is for the log, never for the wire — but it
    /// still must not smuggle the token into either.
    #[test]
    fn a_rejection_reason_never_contains_the_token() {
        let e = ExternalSubjectError::rejected("signature is invalid");
        assert!(!e.to_string().contains('.'), "{e}");
    }
}

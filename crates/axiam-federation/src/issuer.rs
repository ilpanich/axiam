//! Templated OIDC issuers.
//!
//! # The problem, verified live
//!
//! `https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration`
//! publishes
//!
//! ```text
//! issuer = https://login.microsoftonline.com/{tenantid}/v2.0
//! ```
//!
//! with the placeholder literally in the string. `verify_id_token` does
//! `validation.set_issuer(&[&discovery.issuer])`, so a token whose `iss` is
//! `…/9188040d-…/v2.0` fails against `…/{tenantid}/v2.0` and every multi-tenant
//! Entra login is rejected with a claim error.
//!
//! # The rule
//!
//! When the discovered issuer is templated, the token's `tid` claim is read
//! from the **unverified** payload — solely to pick which concrete issuer
//! string to require — checked against the config's `allowed_issuer_tenants`,
//! and substituted. Signature verification is unchanged: the JWKS still comes
//! from the discovery document, and the *verified* token's `iss` must then equal
//! the constructed string.
//!
//! Reading a claim before verifying the signature is the part that deserves
//! scrutiny. It is safe here because the value can only *select* from a closed,
//! operator-written set: a forged `tid` either names a tenant the operator
//! listed — and then the signature still has to verify against the provider's
//! keys, and the verified `iss` still has to match — or it does not, and the
//! login is refused. It can never widen the accepted set.
//!
//! # Why the allow-list is mandatory
//!
//! Microsoft signs every tenant's tokens at `common` with the same keys. A
//! templated issuer with an empty allow-list therefore means *every Microsoft
//! account on earth may sign in here*. That is occasionally what an operator
//! wants and never what they want by accident, so the configuration is refused
//! rather than accepted with that meaning — and the message says how to get
//! either outcome deliberately.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::error::FederationError;

/// The placeholder Entra ID publishes at the `common`/`organizations`
/// authorities.
pub const TENANT_PLACEHOLDER: &str = "{tenantid}";

/// Whether a discovered issuer names a tenant it does not know yet.
pub fn is_templated(issuer: &str) -> bool {
    issuer.contains(TENANT_PLACEHOLDER)
}

/// Refuse a templated issuer that accepts everyone.
///
/// Called at config write time, which is the only moment an operator is in a
/// position to do something about it.
pub fn validate_allow_list(issuer: &str, allowed: &[String]) -> Result<(), FederationError> {
    if !is_templated(issuer) {
        return Ok(());
    }
    if allowed.iter().any(|t| !t.trim().is_empty()) {
        return Ok(());
    }
    Err(FederationError::ConfigInvalid(format!(
        "the provider's discovery document publishes a templated issuer \
         ('{issuer}'), which means any of the provider's tenants can sign in. \
         Either point metadata_url at a tenant-specific authority, which \
         publishes a concrete issuer, or list the provider tenant IDs you \
         accept in allowed_issuer_tenants — there is deliberately no accept-all \
         value"
    )))
}

/// Resolve the concrete issuer to require for one token.
///
/// Returns the discovered issuer unchanged when it is not templated, so the
/// overwhelmingly common path costs one `contains`.
pub fn resolve_expected_issuer(
    discovered_issuer: &str,
    token: &str,
    allowed: &[String],
) -> Result<String, FederationError> {
    if !is_templated(discovered_issuer) {
        return Ok(discovered_issuer.to_string());
    }

    // Belt: the empty allow-list is refused at write time, but a row written
    // before that check existed — or a provider that started templating its
    // issuer after the config was saved — must not fall through to "accept
    // anyone" at sign-in time.
    validate_allow_list(discovered_issuer, allowed)?;

    let tid = unverified_tenant_id(token)?;

    // A `tid` must be a UUID. Without this, a crafted value could substitute
    // path segments into the issuer string and make it match some *other*
    // allowed entry by construction.
    if uuid::Uuid::parse_str(&tid).is_err() {
        return Err(FederationError::JwtClaimRejected(
            "the ID token's `tid` claim is not a tenant identifier".into(),
        ));
    }

    // Case-insensitive, because Entra emits lowercase GUIDs and operators paste
    // whatever the portal showed them. Comparing the *parsed* UUIDs would be
    // stricter still, but an operator's list can legitimately hold a
    // non-Microsoft provider's tenant identifier, so the comparison stays
    // textual and the UUID check above is what bounds the shape.
    if !allowed.iter().any(|a| a.trim().eq_ignore_ascii_case(&tid)) {
        return Err(FederationError::IssuerTenantNotAllowed);
    }

    Ok(discovered_issuer.replace(TENANT_PLACEHOLDER, &tid))
}

/// Read `tid` from a JWT payload **without verifying the signature**.
///
/// See the module docs for why that is sound here. The value is used only to
/// select an expected issuer from a closed set; it authorises nothing.
fn unverified_tenant_id(token: &str) -> Result<String, FederationError> {
    let payload_b64 = token.split('.').nth(1).ok_or_else(|| {
        FederationError::JwtClaimRejected("ID token is not a well-formed JWT".into())
    })?;
    let bytes = URL_SAFE_NO_PAD.decode(payload_b64).map_err(|_| {
        FederationError::JwtClaimRejected("ID token payload is not valid base64url".into())
    })?;
    let payload: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| {
        FederationError::JwtClaimRejected("ID token payload is not valid JSON".into())
    })?;
    payload
        .get("tid")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| {
            FederationError::JwtClaimRejected(
                "the provider publishes a templated issuer but the ID token carries no `tid` claim"
                    .into(),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS_COMMON: &str = "https://login.microsoftonline.com/{tenantid}/v2.0";
    const TENANT_A: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";
    const TENANT_B: &str = "72f988bf-86f1-41af-91ab-2d7cd011db47";

    fn token_with_tid(tid: &str) -> String {
        let payload = serde_json::json!({ "tid": tid, "sub": "s" });
        format!(
            "eyJhbGciOiJSUzI1NiJ9.{}.sig",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
        )
    }

    /// Verified live against Microsoft's own document while this was written:
    /// the placeholder is literal, not a docs convention.
    #[test]
    fn microsofts_common_authority_issuer_is_recognised_as_templated() {
        assert!(is_templated(MS_COMMON));
        assert!(!is_templated("https://accounts.google.com"));
        assert!(!is_templated(
            "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0"
        ));
    }

    /// The headline rule: templated and unlisted is refused, and the refusal
    /// explains both ways out rather than just saying no.
    #[test]
    fn a_templated_issuer_with_no_allow_list_is_refused() {
        let err = validate_allow_list(MS_COMMON, &[]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("tenant-specific authority"));
        assert!(msg.contains("allowed_issuer_tenants"));
        // Whitespace is not a list.
        assert!(validate_allow_list(MS_COMMON, &["  ".to_string()]).is_err());
        assert!(validate_allow_list(MS_COMMON, &[TENANT_A.to_string()]).is_ok());
        // A concrete issuer needs no list at all.
        assert!(validate_allow_list("https://accounts.google.com", &[]).is_ok());
    }

    #[test]
    fn a_concrete_issuer_passes_through_untouched() {
        let got = resolve_expected_issuer(
            "https://accounts.google.com",
            &token_with_tid(TENANT_A),
            &[],
        )
        .unwrap();
        assert_eq!(got, "https://accounts.google.com");
    }

    #[test]
    fn a_listed_tenant_substitutes_into_the_issuer() {
        let got = resolve_expected_issuer(
            MS_COMMON,
            &token_with_tid(TENANT_A),
            &[TENANT_A.to_string()],
        )
        .unwrap();
        assert_eq!(
            got,
            format!("https://login.microsoftonline.com/{TENANT_A}/v2.0")
        );
        // Case is not what distinguishes two tenants.
        let upper = TENANT_A.to_uppercase();
        assert!(
            resolve_expected_issuer(MS_COMMON, &token_with_tid(&upper), &[TENANT_A.to_string()])
                .is_ok()
        );
    }

    /// The property the whole mechanism exists to preserve: a token from a
    /// tenant the operator did not list is refused, even though its signature
    /// would verify against exactly the same Microsoft keys.
    #[test]
    fn an_unlisted_tenant_is_refused_even_though_the_signature_would_verify() {
        let err = resolve_expected_issuer(
            MS_COMMON,
            &token_with_tid(TENANT_B),
            &[TENANT_A.to_string()],
        )
        .unwrap_err();
        assert!(matches!(err, FederationError::IssuerTenantNotAllowed));
    }

    /// A `tid` that is not a tenant identifier could otherwise inject path
    /// segments into the issuer string.
    #[test]
    fn a_tid_that_is_not_a_uuid_is_refused() {
        for bad in [
            "../../evil",
            "9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
            "",
            "not-a-uuid",
        ] {
            let err = resolve_expected_issuer(
                MS_COMMON,
                &token_with_tid(bad),
                &[bad.to_string(), TENANT_A.to_string()],
            )
            .unwrap_err();
            assert!(
                matches!(err, FederationError::JwtClaimRejected(_)),
                "{bad} produced {err:?}"
            );
        }
    }

    #[test]
    fn a_templated_issuer_with_no_tid_claim_is_refused_with_a_useful_message() {
        let token = format!(
            "eyJhbGciOiJSUzI1NiJ9.{}.sig",
            URL_SAFE_NO_PAD.encode(br#"{"sub":"s"}"#)
        );
        let err = resolve_expected_issuer(MS_COMMON, &token, &[TENANT_A.to_string()]).unwrap_err();
        assert!(err.to_string().contains("`tid` claim"));
    }

    #[test]
    fn a_malformed_token_does_not_panic_its_way_to_an_issuer() {
        for bad in ["", "notajwt", "a.b", "a.!!!.c"] {
            assert!(resolve_expected_issuer(MS_COMMON, bad, &[TENANT_A.to_string()]).is_err());
        }
    }
}

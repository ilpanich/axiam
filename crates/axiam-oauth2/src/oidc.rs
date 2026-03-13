//! OpenID Connect Discovery, JWKS, and UserInfo types.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde::Serialize;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Discovery Document (RFC 8414 / OpenID Connect Discovery 1.0)
// ---------------------------------------------------------------------------

/// OpenID Connect Discovery 1.0 metadata document.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct OidcDiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub revocation_endpoint: String,
    pub introspection_endpoint: String,
    pub response_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub claims_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
}

/// Build a fully-populated OIDC discovery document for the given issuer URL.
pub fn build_discovery_document(issuer: &str) -> OidcDiscoveryDocument {
    let issuer = issuer.trim_end_matches('/');
    OidcDiscoveryDocument {
        issuer: issuer.to_string(),
        authorization_endpoint: format!("{issuer}/oauth2/authorize"),
        token_endpoint: format!("{issuer}/oauth2/token"),
        userinfo_endpoint: format!("{issuer}/oauth2/userinfo"),
        jwks_uri: format!("{issuer}/oauth2/jwks"),
        revocation_endpoint: format!("{issuer}/oauth2/revoke"),
        introspection_endpoint: format!("{issuer}/oauth2/introspect"),
        response_types_supported: vec!["code".into()],
        subject_types_supported: vec!["public".into()],
        id_token_signing_alg_values_supported: vec!["EdDSA".into()],
        scopes_supported: vec!["openid".into(), "profile".into(), "email".into()],
        token_endpoint_auth_methods_supported: vec!["client_secret_post".into()],
        claims_supported: vec![
            "sub".into(),
            "iss".into(),
            "aud".into(),
            "exp".into(),
            "iat".into(),
            "nonce".into(),
            "email".into(),
            "preferred_username".into(),
            "tenant_id".into(),
            "org_id".into(),
        ],
        grant_types_supported: vec![
            "authorization_code".into(),
            "client_credentials".into(),
            "refresh_token".into(),
        ],
    }
}

// ---------------------------------------------------------------------------
// JWKS (RFC 7517)
// ---------------------------------------------------------------------------

/// JSON Web Key per RFC 7517.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub kid: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub alg: String,
}

/// JSON Web Key Set document.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct JwksDocument {
    pub keys: Vec<Jwk>,
}

/// Build a JWKS document from an Ed25519 public key in PEM format.
///
/// The PEM must contain a SubjectPublicKeyInfo structure (44 bytes
/// when DER-decoded: 12-byte OID header + 32-byte raw Ed25519 key).
/// The `kid` is derived deterministically as the first 8 hex
/// characters of the SHA-256 hash of the raw public key bytes.
pub fn build_jwks(public_key_pem: &str) -> Result<JwksDocument, String> {
    // Strip PEM headers and decode base64.
    let b64: String = public_key_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let der = STANDARD
        .decode(&b64)
        .map_err(|e| format!("PEM decode: {e}"))?;

    // Ed25519 SubjectPublicKeyInfo is exactly 44 bytes:
    // 12-byte ASN.1/OID header + 32-byte raw public key.
    if der.len() != 44 {
        return Err(format!("expected 44-byte Ed25519 SPKI, got {}", der.len()));
    }
    let raw_key = &der[12..44];

    // Base64url-encode the raw key bytes for the JWK `x` parameter.
    let x = URL_SAFE_NO_PAD.encode(raw_key);

    // Deterministic kid: first 16 hex chars of SHA-256(raw_key).
    let kid = {
        let mut h = Sha256::new();
        h.update(raw_key);
        hex::encode(h.finalize())[..16].to_string()
    };

    Ok(JwksDocument {
        keys: vec![Jwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x,
            kid,
            use_: "sig".into(),
            alg: "EdDSA".into(),
        }],
    })
}

// ---------------------------------------------------------------------------
// UserInfo Response (OIDC Core 5.3)
// ---------------------------------------------------------------------------

/// OIDC UserInfo response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UserInfoResponse {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    pub tenant_id: String,
    pub org_id: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_document_has_required_fields() {
        let doc = build_discovery_document("https://auth.example.com");
        assert_eq!(doc.issuer, "https://auth.example.com");
        assert_eq!(
            doc.authorization_endpoint,
            "https://auth.example.com/oauth2/authorize"
        );
        assert!(doc.response_types_supported.contains(&"code".into()));
        assert!(doc.scopes_supported.contains(&"openid".into()));
    }

    #[test]
    fn jwks_parses_ed25519_pem() {
        let pem = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";
        let jwks = build_jwks(pem).unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kty, "OKP");
        assert_eq!(jwks.keys[0].crv, "Ed25519");
        assert_eq!(jwks.keys[0].alg, "EdDSA");
        assert_eq!(jwks.keys[0].use_, "sig");
        assert!(!jwks.keys[0].x.is_empty());
        assert!(!jwks.keys[0].kid.is_empty());
    }

    #[test]
    fn jwk_kid_is_deterministic() {
        let pem = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";
        let jwks1 = build_jwks(pem).unwrap();
        let jwks2 = build_jwks(pem).unwrap();
        assert_eq!(jwks1.keys[0].kid, jwks2.keys[0].kid);
    }
}

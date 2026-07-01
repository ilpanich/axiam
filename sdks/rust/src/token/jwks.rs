//! Local JWKS fetch/cache/verification (D-03/D-11).
//!
//! Mirrors `crates/axiam-federation/src/oidc.rs:370-429,600-657` — the
//! server's own proven EdDSA/JWKS verification pattern — applied here by
//! the SDK to AXIAM's own tokens. This module does **not** import any
//! `axiam-*` server crate; every type below is the SDK's own plain
//! equivalent (CONTEXT.md domain boundary, 16-PATTERNS.md).
//!
//! Endpoint: `GET {base_url}/oauth2/jwks` — a single, organization-wide
//! endpoint. This is NOT the common OIDC discovery-style JWKS path some
//! other IdPs serve, and it is NOT tenant-scoped.

#[cfg(feature = "rest")]
use std::sync::RwLock;
#[cfg(feature = "rest")]
use std::time::{Duration, Instant};

#[cfg(feature = "rest")]
use jsonwebtoken::jwk::JwkSet;
#[cfg(feature = "rest")]
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

#[cfg(feature = "rest")]
use crate::AxiamError;

/// The AXIAM JWKS endpoint path — organization-wide, not tenant-scoped
/// (RESEARCH.md D-11). This is the only correct path; do not substitute a
/// generic OIDC discovery-style JWKS path here.
pub const JWKS_PATH: &str = "/oauth2/jwks";

/// How long a fetched `JwkSet` is cached before a normal (non-forced)
/// refetch is attempted.
#[cfg(feature = "rest")]
const JWKS_CACHE_TTL: Duration = Duration::from_secs(300);

/// Minimum interval between forced refetches triggered by an unknown `kid`,
/// to avoid a hostile/rotating token stream hammering the JWKS endpoint.
#[cfg(feature = "rest")]
const FORCED_REFETCH_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// The SDK's own plain claims struct, matching the field names AXIAM issues
/// in its access tokens (`crates/axiam-auth/src/token.rs::AccessTokenClaims`)
/// — mirrored, not imported.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — user ID (UUID string).
    pub sub: String,
    /// Tenant ID (UUID string).
    pub tenant_id: String,
    /// Organization ID (UUID string).
    #[serde(default)]
    pub org_id: Option<String>,
    /// Issuer.
    pub iss: String,
    /// Issued-at (Unix timestamp).
    #[serde(default)]
    pub iat: Option<i64>,
    /// Expiration (Unix timestamp).
    pub exp: i64,
    /// Unique token ID / session id.
    #[serde(default)]
    pub jti: Option<String>,
    /// Token audience — `"axiam:user"` or `"axiam:m2m"`.
    #[serde(default)]
    pub aud: Option<String>,
    /// OAuth2 scopes (space-separated string), if any.
    #[serde(default)]
    pub scope: Option<String>,
}

#[cfg(feature = "rest")]
struct CachedJwks {
    jwks: JwkSet,
    fetched_at: Instant,
    last_forced_refetch: Option<Instant>,
}

/// Fetches, caches, and verifies AXIAM access tokens locally against the
/// organization-wide EdDSA JWKS.
///
/// **Feature gating note:** this type owns a `reqwest::Client` to perform
/// the JWKS fetch, so it is gated behind `feature = "rest"` to preserve
/// 16-01's `cargo build --no-default-features` invariant. 16-05's Actix
/// extractor also needs this type via its own `actix` feature; when that
/// feature is added, broaden this `cfg` to `any(feature = "rest", feature =
/// "actix")` rather than duplicating the implementation.
#[cfg(feature = "rest")]
pub struct JwksVerifier {
    http_client: reqwest::Client,
    jwks_url: url::Url,
    cache: RwLock<Option<CachedJwks>>,
}

#[cfg(feature = "rest")]
impl JwksVerifier {
    /// Construct a verifier that will fetch `{base_url}/oauth2/jwks` lazily
    /// on first use.
    pub fn new(http_client: reqwest::Client, base_url: &url::Url) -> Result<Self, AxiamError> {
        let jwks_url = base_url.join(JWKS_PATH).map_err(|e| AxiamError::Network {
            message: format!("invalid JWKS URL: {e}"),
            source: None,
        })?;
        Ok(Self {
            http_client,
            jwks_url,
            cache: RwLock::new(None),
        })
    }

    /// Verify `token`'s EdDSA signature and standard claims (`exp`) against
    /// the cached JWKS, fetching/refetching as needed. Rejects any
    /// non-EdDSA `alg` header.
    pub async fn verify(&self, token: &str) -> Result<Claims, AxiamError> {
        let header = decode_header(token).map_err(|e| AxiamError::Auth {
            message: format!("invalid token header: {e}"),
        })?;

        if header.alg != Algorithm::EdDSA {
            return Err(AxiamError::Auth {
                message: "unexpected alg: only EdDSA is accepted".into(),
            });
        }

        let jwks = self.get_or_fetch().await?;
        let jwk = find_jwk(&jwks, header.kid.as_deref());

        let jwk = match jwk {
            Some(j) => j,
            None => {
                // Unknown kid → forced refetch (rate-limited), matching the
                // server's own kid-rotation handling (D-11).
                let refreshed = self.force_refetch_if_allowed().await?;
                find_jwk(&refreshed, header.kid.as_deref()).ok_or_else(|| AxiamError::Auth {
                    message: "unknown kid after JWKS refetch".into(),
                })?
            }
        };

        let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|_| AxiamError::Auth {
            message: "unable to build decoding key from JWK".into(),
        })?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.leeway = 0; // SDK talks to its own issuer; no federation clock skew.

        let data = decode::<Claims>(token, &decoding_key, &validation).map_err(|e| {
            use jsonwebtoken::errors::ErrorKind;
            match e.kind() {
                ErrorKind::InvalidSignature => AxiamError::Auth {
                    message: "token signature invalid".into(),
                },
                ErrorKind::ExpiredSignature => AxiamError::Auth {
                    message: "token expired".into(),
                },
                _ => AxiamError::Auth {
                    message: format!("token claim validation failed: {e}"),
                },
            }
        })?;

        Ok(data.claims)
    }

    async fn get_or_fetch(&self) -> Result<JwkSet, AxiamError> {
        if let Some(jwks) = self.cached_if_fresh() {
            return Ok(jwks);
        }
        self.fetch_and_cache(false).await
    }

    fn cached_if_fresh(&self) -> Option<JwkSet> {
        let cache = self.cache.read().ok()?;
        let entry = cache.as_ref()?;
        if entry.fetched_at.elapsed() < JWKS_CACHE_TTL {
            Some(entry.jwks.clone())
        } else {
            None
        }
    }

    /// Force a refetch, but rate-limited to at most once per
    /// `FORCED_REFETCH_MIN_INTERVAL` to avoid a rotating/hostile `kid`
    /// stream hammering the JWKS endpoint.
    async fn force_refetch_if_allowed(&self) -> Result<JwkSet, AxiamError> {
        let allowed = {
            let cache = self.cache.read().ok();
            match cache.as_ref().and_then(|c| c.as_ref()) {
                Some(entry) => match entry.last_forced_refetch {
                    Some(last) => last.elapsed() >= FORCED_REFETCH_MIN_INTERVAL,
                    None => true,
                },
                None => true,
            }
        };

        if allowed {
            self.fetch_and_cache(true).await
        } else if let Some(jwks) = self
            .cache
            .read()
            .ok()
            .and_then(|c| c.as_ref().map(|e| e.jwks.clone()))
        {
            Ok(jwks)
        } else {
            self.fetch_and_cache(true).await
        }
    }

    async fn fetch_and_cache(&self, is_forced: bool) -> Result<JwkSet, AxiamError> {
        let response = self
            .http_client
            .get(self.jwks_url.clone())
            .send()
            .await
            .map_err(|e| AxiamError::Network {
                message: format!("JWKS fetch failed: {e}"),
                source: Some(Box::new(e)),
            })?;

        if !response.status().is_success() {
            return Err(AxiamError::from_http_status(
                response.status().as_u16(),
                "JWKS endpoint returned a non-success status".to_string(),
            ));
        }

        let jwks: JwkSet = response.json().await.map_err(|e| AxiamError::Network {
            message: format!("JWKS response parse failed: {e}"),
            source: Some(Box::new(e)),
        })?;

        let now = Instant::now();
        if let Ok(mut cache) = self.cache.write() {
            *cache = Some(CachedJwks {
                jwks: jwks.clone(),
                fetched_at: now,
                last_forced_refetch: if is_forced { Some(now) } else { None },
            });
        }

        Ok(jwks)
    }
}

/// Find a JWK by `kid` in a JWK set. If `kid` is `None` and the set has
/// exactly one key, returns that key as a best-effort match — AXIAM's
/// `/oauth2/jwks` serves exactly one org-wide Ed25519 key (D-11).
///
/// Mirrors `crates/axiam-federation/src/oidc.rs::find_jwk` exactly.
#[cfg(feature = "rest")]
fn find_jwk(jwks: &JwkSet, kid: Option<&str>) -> Option<jsonwebtoken::jwk::Jwk> {
    match kid {
        Some(k) => jwks
            .keys
            .iter()
            .find(|j| j.common.key_id.as_deref() == Some(k))
            .cloned(),
        None if jwks.keys.len() == 1 => jwks.keys.first().cloned(),
        None => None,
    }
}

#[cfg(all(test, feature = "rest"))]
mod tests {
    use super::*;
    use jsonwebtoken::{jwk::*, EncodingKey, Header};

    /// A fixed, valid Ed25519 public key `x` coordinate (base64url, no
    /// padding) used only to exercise `find_jwk`'s selection logic in these
    /// tests. `find_jwk` never verifies a signature itself, so an arbitrary
    /// (but well-formed) OKP key is sufficient here — no signing key or
    /// extra crypto dependency needed.
    const TEST_PUBLIC_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

    fn ed25519_test_jwk(kid: Option<&str>) -> Jwk {
        Jwk {
            common: CommonParameters {
                key_algorithm: Some(jsonwebtoken::jwk::KeyAlgorithm::EdDSA),
                key_id: kid.map(str::to_string),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                key_type: OctetKeyPairType::OctetKeyPair,
                curve: EllipticCurve::Ed25519,
                x: TEST_PUBLIC_X.to_string(),
            }),
        }
    }

    #[test]
    fn rejects_non_eddsa_alg_header() {
        // A well-formed HS256 token header must be rejected before any
        // signature/JWK lookup happens.
        let claims = Claims {
            sub: "u".into(),
            tenant_id: "t".into(),
            org_id: None,
            iss: "axiam".into(),
            iat: None,
            exp: 9_999_999_999,
            jti: None,
            aud: None,
            scope: None,
        };
        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"irrelevant"),
        )
        .expect("encode HS256 test token");

        let header = decode_header(&token).expect("decode header");
        assert_ne!(header.alg, Algorithm::EdDSA);
    }

    #[test]
    fn find_jwk_single_key_fallback_when_kid_absent() {
        let jwk = ed25519_test_jwk(Some("test-kid"));
        let jwks = JwkSet { keys: vec![jwk] };
        let found = find_jwk(&jwks, None);
        assert!(
            found.is_some(),
            "single-key fallback must match on kid=None"
        );
    }

    #[test]
    fn find_jwk_no_fallback_with_multiple_keys() {
        let jwk1 = ed25519_test_jwk(Some("kid-1"));
        let jwk2 = ed25519_test_jwk(Some("kid-2"));
        let jwks = JwkSet {
            keys: vec![jwk1, jwk2],
        };
        let found = find_jwk(&jwks, None);
        assert!(
            found.is_none(),
            "must not fall back to a key when multiple keys exist and kid is absent"
        );
    }

    #[test]
    fn find_jwk_matches_by_kid() {
        let jwk1 = ed25519_test_jwk(Some("kid-1"));
        let jwk2 = ed25519_test_jwk(Some("kid-2"));
        let jwks = JwkSet {
            keys: vec![jwk1, jwk2],
        };
        let found = find_jwk(&jwks, Some("kid-2"));
        assert_eq!(found.unwrap().common.key_id.as_deref(), Some("kid-2"));
    }
}

//! gRPC auth interceptor — validates bearer JWT on every inbound request.
//!
//! SEC-003: Any caller that reaches the authorization service must present a
//! cryptographically verified bearer token.  The interceptor extracts the
//! `authorization` metadata header, strips the `Bearer ` prefix, delegates
//! to `axiam_auth::token::validate_access_token`, and — on success — stores
//! the [`ValidatedClaims`] in the request extensions so downstream service
//! handlers can derive `tenant_id`/`subject_id` from verified claims rather
//! than trusting the request body.

use axiam_auth::config::AuthConfig;
use axiam_auth::token::{
    AUD_M2M, AUD_USER, PresentedProofs, validate_access_token, verify_token_binding,
};
use tonic::service::Interceptor;
use tonic::{Request, Status};

/// Tonic interceptor that enforces bearer JWT authentication.
///
/// Clone-safe: `AuthConfig` derives `Clone`, so `AuthInterceptor` can be
/// cloned for each new connection (Tonic 0.14 requirement for
/// `with_interceptor`).
#[derive(Clone)]
pub struct AuthInterceptor {
    auth_config: AuthConfig,
}

impl AuthInterceptor {
    /// Create a new interceptor backed by the given [`AuthConfig`].
    pub fn new(auth_config: AuthConfig) -> Self {
        Self { auth_config }
    }
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        let token = req
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("missing bearer token"))?;

        let claims = validate_access_token(token, &self.auth_config)
            .map_err(|_| Status::unauthenticated("invalid or expired token"))?;

        // §17.2 residual 2: the audience policy on this transport used to be
        // entirely implicit. `decode_access_token` accepts both audiences, and
        // deliberately **skips** the audience check altogether when the claim
        // is absent (the D-20 pre-Phase-4 back-compat window) — so a token
        // with no `aud` reached the authorization service with no narrowing
        // applied and nothing recorded about it. The REST extractors gate that
        // same case on `allow_missing_aud_as_user` and warn on every use; this
        // transport did neither.
        //
        // gRPC accepts **both** audiences on purpose, and that is now stated
        // rather than inherited: this is the low-latency check surface for a
        // service mesh, so machine callers are the norm, while user tokens
        // reach it through SDK callers doing the same checks. What is fixed
        // here is the *unstated* third case.
        match claims.0.aud.as_deref() {
            Some(AUD_USER) | Some(AUD_M2M) => {}
            None => {
                if !self.auth_config.allow_missing_aud_as_user {
                    return Err(Status::unauthenticated("aud required"));
                }
                tracing::warn!(
                    token_jti = %claims.0.jti,
                    "grpc: accepted access token without aud — backward-compat window active"
                );
            }
            Some(_) => return Err(Status::unauthenticated("unknown audience")),
        }

        enforce_sender_constraint(&req, &claims.0)?;

        req.extensions_mut().insert(claims);
        Ok(req)
    }
}

/// Enforce a token's `cnf` sender constraint on the gRPC transport
/// (X5.1; RFC 8705 §3.2, RFC 9449 §7.1).
///
/// AXIAM's gRPC surface is a resource server for AXIAM's own tokens, so it owes
/// the same obligation the REST extractor does and that SDK contract §10.1
/// rule 9 places on every SDK: **a token carrying `cnf` is not a bearer token.**
/// Before this existed, a certificate-bound or DPoP-bound token presented here
/// was accepted exactly as an unbound one — which made the binding decorative
/// for any deployment whose authorization checks go through the mesh.
///
/// # Ordinary callers are untouched
///
/// A token with no `cnf` — every token AXIAM issued before X5.1, and every
/// token it issues to a client that has not asked for binding — returns `Ok`
/// without the peer chain being read. That is asserted directly by
/// `an_unbound_token_is_accepted_with_no_evidence`, and it is the property this
/// function is most likely to break.
///
/// # What this transport can and cannot check
///
/// | Confirmation | Checkable here? | Why |
/// |---|---|---|
/// | `x5t#S256` | **yes** | `Request::peer_certs()` gives the chain rustls verified for this connection, and the leaf's thumbprint is one SHA-256 over bytes already in memory |
/// | `jkt` (DPoP) | **no** | RFC 9449 binds a proof to an HTTP method and URI (`htm`/`htu`). A tonic interceptor sees neither — it runs on `Request<()>`, before the RPC path is bound to a request — so a proof cannot be checked against what it was minted for. Verifying it *without* `htm`/`htu` would accept a proof captured from any other endpoint, which is worse than not verifying at all |
///
/// The `jkt` row is a refusal, not a gap to be papered over: rule 9's rule is
/// **reject when you cannot verify**, so a DPoP-bound token presented to this
/// transport is refused. An operator who needs DPoP-bound tokens against the
/// mesh should terminate them at the REST surface, which has the method and URI.
fn enforce_sender_constraint(
    req: &Request<()>,
    claims: &axiam_auth::token::AccessTokenClaims,
) -> Result<(), Status> {
    // The fast path, and the common one: nothing claimed, nothing read.
    if claims.cnf.is_none() {
        return Ok(());
    }

    // The leaf is the first certificate in the chain rustls verified for this
    // connection. Taking it from anywhere else — a metadata header, say —
    // would make the whole mechanism decorative, which is why this reads
    // `peer_certs()` and nothing else.
    let certificate_thumbprint = req
        .peer_certs()
        .and_then(|chain| chain.first().map(|leaf| thumbprint_s256(leaf.as_ref())));

    verify_token_binding(
        claims,
        PresentedProofs {
            certificate_thumbprint: certificate_thumbprint.as_deref(),
            // See the table above: a DPoP proof cannot be verified without the
            // method and URI it was minted for, and this interceptor has
            // neither. `None` here means a `jkt`-bound token is refused.
            dpop_thumbprint: None,
        },
    )
    .map_err(|e| {
        tracing::debug!(
            token_jti = %claims.jti,
            error = %e,
            "grpc: refused a sender-constrained token"
        );
        Status::unauthenticated("invalid or expired token")
    })
}

/// RFC 8705 §3.1 `x5t#S256`: base64url-unpadded SHA-256 of the DER certificate.
///
/// Inlined rather than calling `axiam_oauth2::mtls::thumbprint_s256`: this
/// crate does not depend on `axiam-oauth2` and should not acquire the whole
/// OAuth2 authorization server to compute one digest. The operation is a
/// SHA-256 plus a base64url encode either way, and
/// `the_thumbprint_agrees_with_the_oauth2_crates_definition` pins the two
/// against a shared vector so they cannot drift.
fn thumbprint_s256(der: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(der))
}

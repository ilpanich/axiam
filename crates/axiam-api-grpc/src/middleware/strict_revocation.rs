//! Opt-in per-request session-revocation enforcement for the gRPC data plane
//! (A4/J10).
//!
//! # The posture this makes explicit
//!
//! REST and gRPC have never agreed about revocation, and until now that
//! disagreement was implicit — visible only by reading
//! `middleware::auth::AuthInterceptor` and noticing what it does *not* do:
//!
//! | | REST | gRPC (default) | gRPC (`strict`) |
//! |---|---|---|---|
//! | token signature/expiry | ✅ | ✅ | ✅ |
//! | session revoked since issue? | ✅ per request | ❌ **not checked** | ✅ per request |
//! | revocation takes effect after | immediately (or cache TTL) | **token expiry — up to 15 min** | immediately (or cache TTL) |
//!
//! The default is a deliberate trade, not an oversight: gRPC is the
//! low-latency service-mesh check surface, and skipping a datastore read per
//! request is a meaningful part of why it measures where it does. But a trade
//! nobody wrote down is indistinguishable from a bug, and "logged-out user
//! keeps passing mesh authorization for 15 minutes" is not a property an
//! operator should discover from a benchmark analysis. So: the default keeps
//! its speed, the posture is documented, and an operator who needs REST's
//! revocation semantics on gRPC can now have them with one flag.
//!
//! # Why a `tower::Layer` and not the interceptor
//!
//! `tonic::service::Interceptor::call` is **synchronous**. A revocation check
//! that can miss its cache needs a datastore read, which needs an `await`, so
//! it cannot live there — the only way to fit it into the interceptor would be
//! `block_on`, which would park a runtime worker on every cache miss. This is
//! the same reason the shared rate-limit pre-check is a layer rather than a
//! `governor::StateStore` (see `middleware::rate_limit`'s Pitfall 1 note).
//!
//! # Why deciding on *unverified* claims is sound here
//!
//! This layer runs before tonic routes, so it runs before the interceptor that
//! verifies the token. Rather than verify the signature a second time — an
//! extra Ed25519 verify on a path that sustains ~12 700 reads/s — it decodes
//! the claims without verifying and uses them only to look up a session.
//!
//! That is safe because of a strict asymmetry: **this layer can only ever
//! deny.** It never admits anything; a request it lets pass still faces the
//! full verifying interceptor immediately afterwards. So the worst a forged
//! token can achieve here is to be allowed through this layer and then
//! rejected by the next one. There is no path by which unverified claims grant
//! access.
//!
//! Concretely, a request is denied if and only if its claims decode to a
//! `(tenant_id, jti)` pair naming a session that is **known to be gone**. An
//! undecodable token, a malformed claim, or a datastore error all fall
//! through to the interceptor, which is stricter than this layer, not weaker.
//!
//! # Cost
//!
//! One session-validity check per request. With the session-validation cache
//! enabled (`AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS`) that is a hash
//! lookup on the hot path and a datastore read only on a miss; the cache
//! instance is the SAME one the REST path uses, so every REST-side
//! invalidation hook — logout, password change, MFA reset, refresh rotation —
//! already serves gRPC, and event-path revocation is immediate in strict mode
//! too. Without the cache it is one datastore read per request, which is
//! REST's un-cached profile and should be expected to measure like it.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axiam_auth::config::AuthConfig;
use axiam_auth::token::decode_access_token;
use http::{Request, Response};
use tower::{Layer, Service};
use uuid::Uuid;

/// Async session-revocation check, implemented by the session repository.
///
/// Defined here (rather than reusing `axiam_api_rest::SessionValidator`) so
/// the gRPC crate does not depend on the REST crate for one trait. The
/// *implementation* handed in at the composition root is the same repository
/// instance, holding the same validation cache, so both transports observe the
/// same invalidations.
pub trait SessionRevocationCheck: Send + Sync + 'static {
    /// `true` when the session is still usable.
    ///
    /// Implementations MUST fail **open** on a datastore error — returning
    /// `false` for "I could not tell" would turn a datastore blip into a mesh-
    /// wide outage. Denying is reserved for sessions known to be gone.
    fn is_session_active(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + '_>>;
}

impl<C: surrealdb::Connection> SessionRevocationCheck for axiam_db::SurrealSessionRepository<C> {
    fn is_session_active(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async move { self.is_session_active_checked(tenant_id, session_id).await })
    }
}

/// Builds the `UNAUTHENTICATED` response for a revoked session.
///
/// `UNAUTHENTICATED` and not `PERMISSION_DENIED`: the caller's *credential* is
/// no longer valid, which is exactly the case a client should respond to by
/// re-authenticating. `PERMISSION_DENIED` would tell a well-behaved client to
/// give up instead of refreshing.
fn revoked_response() -> Response<tonic::body::Body> {
    tonic::Status::unauthenticated("session revoked").into_http()
}

/// `tower::Layer` enforcing per-request session revocation on gRPC.
///
/// Only constructed when `AXIAM__GRPC__STRICT_REVOCATION=true`; when the flag
/// is off the layer is never built, so the default path carries no cost at
/// all — not even a branch.
#[derive(Clone)]
pub struct GrpcStrictRevocationLayer {
    checker: Arc<dyn SessionRevocationCheck>,
    auth_config: AuthConfig,
}

impl GrpcStrictRevocationLayer {
    /// Build the layer over the session repository that owns the validation
    /// cache. Pass the SAME instance the REST path uses — a second instance
    /// would have a second cache, and a cache the REST invalidation hooks do
    /// not reach is exactly the stale-allow this layer exists to prevent.
    pub fn new(checker: Arc<dyn SessionRevocationCheck>, auth_config: AuthConfig) -> Self {
        Self {
            checker,
            auth_config,
        }
    }
}

impl<S> Layer<S> for GrpcStrictRevocationLayer {
    type Service = GrpcStrictRevocationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GrpcStrictRevocationService {
            inner,
            checker: Arc::clone(&self.checker),
            auth_config: self.auth_config.clone(),
        }
    }
}

/// Inner service produced by [`GrpcStrictRevocationLayer`].
#[derive(Clone)]
pub struct GrpcStrictRevocationService<S> {
    inner: S,
    checker: Arc<dyn SessionRevocationCheck>,
    auth_config: AuthConfig,
}

/// The `(tenant_id, session_id)` a request's bearer token names, or `None`
/// when there is nothing to check.
///
/// `None` covers every "cannot tell" case — no header, no `Bearer ` prefix,
/// undecodable token, unparseable claim — and every one of them means *fall
/// through to the interceptor*, which will reject anything genuinely invalid.
pub(crate) fn session_ref_from_request<T>(
    req: &Request<T>,
    auth_config: &AuthConfig,
) -> Option<(Uuid, Uuid)> {
    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))?;

    let claims = decode_access_token(token, auth_config).ok()?;
    // D-15: `jti` IS the session id on this token family.
    let session_id = Uuid::parse_str(&claims.jti).ok()?;
    let tenant_id = Uuid::parse_str(&claims.tenant_id).ok()?;
    Some((tenant_id, session_id))
}

impl<S> Service<Request<tonic::body::Body>> for GrpcStrictRevocationService<S>
where
    S: Service<Request<tonic::body::Body>, Response = Response<tonic::body::Body>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<tonic::body::Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<tonic::body::Body>) -> Self::Future {
        // Standard clone-and-swap so the returned future owns a ready copy.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        let session_ref = session_ref_from_request(&req, &self.auth_config);
        let checker = Arc::clone(&self.checker);

        Box::pin(async move {
            if let Some((tenant_id, session_id)) = session_ref
                && !checker.is_session_active(tenant_id, session_id).await
            {
                tracing::debug!(
                    %tenant_id,
                    "grpc strict revocation: denying a request whose session is gone"
                );
                return Ok(revoked_response());
            }
            inner.call(req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_auth::token::{AUD_USER, issue_access_token};

    fn test_config() -> AuthConfig {
        AuthConfig {
            jwt_private_key_pem: "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n-----END PRIVATE KEY-----".into(), // nosemgrep: generic.secrets.security.detected-private-key
            jwt_public_key_pem: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n-----END PUBLIC KEY-----".into(),
            ..AuthConfig::default()
        }
    }

    fn req_with_auth(value: Option<&str>) -> Request<()> {
        let mut builder = Request::builder();
        if let Some(value) = value {
            builder = builder.header("authorization", value);
        }
        builder.body(()).unwrap()
    }

    #[test]
    fn extracts_the_tenant_and_session_from_a_valid_token() {
        let config = test_config();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();

        let token = issue_access_token(
            user_id,
            tenant_id,
            Uuid::new_v4(),
            &[],
            &config,
            session_id.to_string(),
            AUD_USER,
        )
        .expect("issue token");

        let extracted =
            session_ref_from_request(&req_with_auth(Some(&format!("Bearer {token}"))), &config);

        assert_eq!(
            extracted,
            Some((tenant_id, session_id)),
            "jti is the session id (D-15) and must be read as such"
        );
    }

    /// Every "cannot tell" case must yield `None` — i.e. fall through to the
    /// verifying interceptor rather than deny. This layer only ever denies
    /// sessions it can positively identify as gone.
    #[test]
    fn unreadable_credentials_fall_through_rather_than_denying() {
        let config = test_config();

        for (label, header) in [
            ("no authorization header", None),
            ("no Bearer prefix", Some("Basic abc")),
            ("garbage token", Some("Bearer not-a-jwt")),
            (
                "well-formed but unsigned-by-us",
                Some("Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0."),
            ),
        ] {
            assert_eq!(
                session_ref_from_request(&req_with_auth(header), &config),
                None,
                "{label}: must fall through to the interceptor, not be denied here"
            );
        }
    }

    /// A token whose `jti` is not a UUID names no session, so there is nothing
    /// to check — fall through rather than invent a session id.
    #[test]
    fn non_uuid_jti_falls_through() {
        let config = test_config();
        let token = issue_access_token(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            &[],
            &config,
            "not-a-uuid".to_string(),
            AUD_USER,
        )
        .expect("issue token");

        assert_eq!(
            session_ref_from_request(&req_with_auth(Some(&format!("Bearer {token}"))), &config),
            None
        );
    }
}

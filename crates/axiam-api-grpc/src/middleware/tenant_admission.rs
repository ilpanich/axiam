//! Per-request tenant lifecycle enforcement for the gRPC listener (SA-13, N16,
//! D-3).
//!
//! A suspended tenant's principals are refused at every authentication door,
//! and this listener is one: a token a suspended tenant's user or service
//! account obtained before the suspension stays cryptographically valid until
//! it expires, and the verifying interceptor (`middleware::auth`) checks
//! nothing else. Unlike the session check (`middleware::strict_revocation`,
//! opt-in for latency), this one is **always on** — D-3 makes suspension
//! refuse API requests, with no transport excepted.
//!
//! # Why a `tower::Layer` and not the interceptor
//!
//! For the reason `strict_revocation` gives: `Interceptor::call` is
//! synchronous, and the tenant's status is a datastore read.
//!
//! # Why deciding on unverified claims is sound
//!
//! Also `strict_revocation`'s argument: this layer can only **deny**. A request
//! it lets through still meets the verifying interceptor, so a forged token can
//! at most be passed on here and refused there. It denies when the claims name
//! a tenant whose stored status does not admit principals
//! (`axiam_core::models::tenant::tenant_accepts_principals`).
//!
//! An undecodable token, and a tenant that is not stored, fall through: the
//! interceptor refuses the first, and the second is a tombstoned or unknown
//! tenant, whose sessions and clients are revoked elsewhere.
//!
//! # A datastore error refuses
//!
//! Unlike `strict_revocation`, this layer **fails closed**: when the tenant
//! cannot be read the call is answered `UNAVAILABLE` with a generic message
//! (the error itself is logged). No service behind the listener re-checks the
//! tenant's status, so passing the call on would admit a possibly suspended
//! tenant's token whenever the read failed. This matches the REST extractor
//! and the AMQP consumer, which also refuse on "could not tell".
//!
//! # Cost
//!
//! One tenant read per authenticated call. There is no tenant-status cache to
//! reuse (`tenant_org_cache` caches the organization mapping, which never
//! changes; status does), and none is added: a suspension takes effect at the
//! next call, on every replica.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axiam_auth::config::AuthConfig;
use axiam_auth::token::decode_access_token;
use axiam_core::error::AxiamError;
use axiam_core::models::tenant::TenantAdmission;
use http::{Request, Response};
use tower::{Layer, Service};
use uuid::Uuid;

/// The status a suspended tenant's call is answered with.
///
/// `PERMISSION_DENIED`, not `UNAUTHENTICATED`: the credential is genuine, and a
/// client told to re-authenticate would only be refused again. The message is
/// the stable code first, so a client can match on it.
fn suspended_response() -> Response<tonic::body::Body> {
    tonic::Status::permission_denied(format!("tenant_suspended: {}", AxiamError::TenantSuspended))
        .into_http()
}

/// The status a call is answered with when its tenant cannot be read.
///
/// `UNAVAILABLE` — transient server state, which a client retries — with a
/// generic message: the datastore's own words belong in the log.
fn unavailable_response() -> Response<tonic::body::Body> {
    tonic::Status::unavailable("the tenant could not be checked; retry this call").into_http()
}

/// `tower::Layer` refusing calls whose token names a suspended tenant.
#[derive(Clone)]
pub struct GrpcTenantAdmissionLayer {
    tenants: Arc<dyn TenantAdmission>,
    auth_config: AuthConfig,
}

impl GrpcTenantAdmissionLayer {
    /// Build the layer over the tenant lookup (the tenant repository in
    /// production).
    pub fn new(tenants: Arc<dyn TenantAdmission>, auth_config: AuthConfig) -> Self {
        Self {
            tenants,
            auth_config,
        }
    }
}

impl<S> Layer<S> for GrpcTenantAdmissionLayer {
    type Service = GrpcTenantAdmissionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GrpcTenantAdmissionService {
            inner,
            tenants: Arc::clone(&self.tenants),
            auth_config: self.auth_config.clone(),
        }
    }
}

/// Inner service produced by [`GrpcTenantAdmissionLayer`].
#[derive(Clone)]
pub struct GrpcTenantAdmissionService<S> {
    inner: S,
    tenants: Arc<dyn TenantAdmission>,
    auth_config: AuthConfig,
}

/// The tenant a request's bearer token names, or `None` when there is nothing
/// to check (no header, no `Bearer ` prefix, undecodable token or claim).
pub(crate) fn tenant_of_request<T>(req: &Request<T>, auth_config: &AuthConfig) -> Option<Uuid> {
    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))?;
    let claims = decode_access_token(token, auth_config).ok()?;
    Uuid::parse_str(&claims.tenant_id).ok()
}

impl<S> Service<Request<tonic::body::Body>> for GrpcTenantAdmissionService<S>
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
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        let tenant = tenant_of_request(&req, &self.auth_config);
        let tenants = Arc::clone(&self.tenants);

        Box::pin(async move {
            // Admitted or not stored: passed on. Suspended: refused. Not
            // readable: refused too (see the module docs).
            if let Some(tenant_id) = tenant {
                match tenants.admit(tenant_id).await {
                    Ok(()) => {}
                    Err(AxiamError::TenantSuspended) => {
                        tracing::debug!(
                            %tenant_id,
                            "grpc: denying a call from a suspended tenant (SA-13)"
                        );
                        return Ok(suspended_response());
                    }
                    Err(error) => {
                        tracing::error!(
                            %tenant_id,
                            %error,
                            "grpc: the tenant of a call could not be read; refusing it (SA-13)"
                        );
                        return Ok(unavailable_response());
                    }
                }
            }
            inner.call(req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axiam_auth::token::{AUD_M2M, AUD_USER, issue_access_token};
    use axiam_core::models::organization::CreateOrganization;
    use axiam_core::models::tenant::{CreateTenant, TenantKind, TenantStatus, UpdateTenant};
    use axiam_core::repository::{OrganizationRepository, TenantRepository};
    use axiam_db::{SurrealOrganizationRepository, SurrealTenantRepository};
    use surrealdb::Surreal;
    use surrealdb::engine::local::{Db, Mem};

    fn test_config() -> AuthConfig {
        AuthConfig {
            jwt_private_key_pem: "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n-----END PRIVATE KEY-----".into(), // nosemgrep: generic.secrets.security.detected-private-key
            jwt_public_key_pem: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n-----END PUBLIC KEY-----".into(),
            ..AuthConfig::default()
        }
    }

    /// Counts the calls that reached the service behind the layer.
    #[derive(Clone)]
    struct Downstream(Arc<AtomicUsize>);

    impl Service<Request<tonic::body::Body>> for Downstream {
        type Response = Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Request<tonic::body::Body>) -> Self::Future {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Ok(Response::builder()
                    .status(200)
                    .body(tonic::body::Body::empty())
                    .expect("a 200 with an empty body always builds"))
            })
        }
    }

    fn bearer_request(
        config: &AuthConfig,
        tenant_id: Uuid,
        aud: &str,
    ) -> Request<tonic::body::Body> {
        let token = issue_access_token(
            Uuid::new_v4(),
            tenant_id,
            Uuid::new_v4(),
            &[],
            config,
            Uuid::new_v4().to_string(),
            aud,
        )
        .expect("issue token");
        Request::builder()
            .header("authorization", format!("Bearer {token}"))
            .body(tonic::body::Body::empty())
            .expect("request builds")
    }

    /// The `grpc-status` a response carries in its headers (tonic puts a
    /// refusal's status there, with no body).
    fn grpc_status(response: &Response<tonic::body::Body>) -> Option<String> {
        response
            .headers()
            .get("grpc-status")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    }

    async fn through_the_layer(
        tenants: Arc<dyn TenantAdmission>,
        req: Request<tonic::body::Body>,
        config: AuthConfig,
    ) -> (Option<String>, Option<String>, usize) {
        let reached = Arc::new(AtomicUsize::new(0));
        let layer = GrpcTenantAdmissionLayer::new(tenants, config);
        let mut service = layer.layer(Downstream(Arc::clone(&reached)));
        let response = service.call(req).await.expect("infallible downstream");
        let message = response
            .headers()
            .get("grpc-message")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        (
            grpc_status(&response),
            message,
            reached.load(Ordering::SeqCst),
        )
    }

    /// A real tenant repository over an in-memory datastore, and one Standard
    /// tenant in it.
    async fn tenant_store() -> (SurrealTenantRepository<Db>, Uuid) {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        axiam_db::run_migrations(&db).await.unwrap();
        let org = SurrealOrganizationRepository::new(db.clone())
            .create(CreateOrganization {
                name: "gRPC Org".into(),
                slug: "grpc-org".into(),
                metadata: None,
            })
            .await
            .unwrap();
        let tenants = SurrealTenantRepository::new(db.clone());
        let tenant = tenants
            .create(CreateTenant {
                organization_id: org.id,
                kind: TenantKind::Standard,
                name: "gRPC Tenant".into(),
                slug: "grpc-tenant".into(),
                metadata: None,
            })
            .await
            .unwrap();
        (tenants, tenant.id)
    }

    /// SA-13 (N16): a call whose token — user or machine — names a suspended
    /// tenant is refused `PERMISSION_DENIED` `tenant_suspended`, and the
    /// service behind the layer never runs; un-suspending lets it through.
    #[tokio::test]
    async fn a_suspended_tenants_call_is_refused_and_never_reaches_the_service() {
        let config = test_config();
        let (repo, tenant_id) = tenant_store().await;
        let tenants: Arc<dyn TenantAdmission> = Arc::new(repo.clone());

        for aud in [AUD_USER, AUD_M2M] {
            let (status, _, reached) = through_the_layer(
                Arc::clone(&tenants),
                bearer_request(&config, tenant_id, aud),
                config.clone(),
            )
            .await;
            assert_eq!(status, None, "{aud}: an active tenant's call passes");
            assert_eq!(reached, 1, "{aud}");
        }

        repo.update(
            tenant_id,
            UpdateTenant {
                status: Some(TenantStatus::Suspended),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        for aud in [AUD_USER, AUD_M2M] {
            let (status, message, reached) = through_the_layer(
                Arc::clone(&tenants),
                bearer_request(&config, tenant_id, aud),
                config.clone(),
            )
            .await;
            assert_eq!(
                status.as_deref(),
                Some((tonic::Code::PermissionDenied as i32).to_string().as_str()),
                "{aud}: a suspended tenant's call is PERMISSION_DENIED"
            );
            assert!(
                message.is_some_and(|m| m.starts_with("tenant_suspended")),
                "{aud}: the message leads with the stable code"
            );
            assert_eq!(reached, 0, "{aud}: the service must not run");
        }

        repo.update(
            tenant_id,
            UpdateTenant {
                status: Some(TenantStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let (status, _, reached) = through_the_layer(
            tenants,
            bearer_request(&config, tenant_id, AUD_USER),
            config,
        )
        .await;
        assert_eq!(status, None, "un-suspending restores the tenant's calls");
        assert_eq!(reached, 1);
    }

    /// A tenant lookup that cannot be answered.
    struct Unreadable;

    impl TenantAdmission for Unreadable {
        fn admit(
            &self,
            _tenant_id: Uuid,
        ) -> Pin<Box<dyn Future<Output = axiam_core::error::AxiamResult<()>> + Send + '_>> {
            Box::pin(async { Err(AxiamError::Database("connection reset".into())) })
        }
    }

    /// SA-13 review: no service re-checks the tenant's status, so a call whose
    /// tenant cannot be read is refused `UNAVAILABLE` (generic message, never
    /// the datastore's words) rather than admitted — "could not tell" must not
    /// read as an admission of a possibly suspended tenant.
    #[tokio::test]
    async fn a_call_whose_tenant_cannot_be_read_is_refused_unavailable() {
        let config = test_config();
        let (status, message, reached) = through_the_layer(
            Arc::new(Unreadable),
            bearer_request(&config, Uuid::new_v4(), AUD_USER),
            config,
        )
        .await;
        assert_eq!(
            status.as_deref(),
            Some((tonic::Code::Unavailable as i32).to_string().as_str()),
            "an unreadable tenant is UNAVAILABLE"
        );
        assert!(
            message.is_some_and(|m| !m.contains("connection reset")),
            "the datastore's words stay in the log"
        );
        assert_eq!(reached, 0, "the service must not run");
    }

    /// Nothing to check is not this layer's to refuse: no credential (health,
    /// reflection), or a tenant that is not stored, falls through to the
    /// interceptor and the services.
    #[tokio::test]
    async fn a_call_naming_no_stored_tenant_falls_through() {
        let config = test_config();
        let (repo, _) = tenant_store().await;
        let tenants: Arc<dyn TenantAdmission> = Arc::new(repo);

        let (status, _, reached) = through_the_layer(
            Arc::clone(&tenants),
            Request::builder()
                .body(tonic::body::Body::empty())
                .expect("request builds"),
            config.clone(),
        )
        .await;
        assert_eq!((status, reached), (None, 1), "no credential");

        let (status, _, reached) = through_the_layer(
            tenants,
            bearer_request(&config, Uuid::new_v4(), AUD_USER),
            config,
        )
        .await;
        assert_eq!((status, reached), (None, 1), "unknown tenant");
    }
}

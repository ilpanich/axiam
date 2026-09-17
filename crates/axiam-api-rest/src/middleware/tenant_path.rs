//! The `/t/{tenant_id}` scope: per-tenant path issuers (T21.6).
//!
//! RFC 8414 §2 forbids a query component in an issuer identifier, so AXIAM's
//! `{root}` plus `?tenant_id=` cannot be published as the issuer of one tenant.
//! An MCP server naming AXIAM in its RFC 9728 `authorization_servers` therefore
//! had no way to point a client at anything but the deployment's default
//! tenant. `{root}/t/{tenant_id}` is an issuer a client can turn into a
//! discovery URL by the RFC 8414 §3 rule with no query at all.
//!
//! The whole feature is opt-in
//! (`AXIAM__AUTH__TENANT_ISSUER_PATHS`, [`AuthConfig::tenant_issuer_paths`]).
//! With it unset this scope is not mounted, so nothing in this module runs.
//!
//! # What the middleware does, and why it is a middleware at all
//!
//! Every OAuth2 handler already resolves its tenant from a `tenant_id` query
//! parameter — the token, revocation, introspection, device-authorization, PAR
//! and end-session endpoints all require one, and `/oauth2/authorize` needs one
//! for any request without a principal. So the tenant path does not need new
//! handlers; it needs the tenant the *path* named to arrive where the handlers
//! already look. This middleware rewrites the request's query string to carry
//! it, and the eleven handlers underneath are the same functions serving
//! `/oauth2/…`, byte for byte.
//!
//! It also records a [`TenantPathBinding`] in the request's extensions. Two
//! things read it:
//!
//! * the four places that **stamp** an `iss` — the access token, the ID token,
//!   the logout token and the RFC 9207 authorization-response parameter — so
//!   that all four say `{root}/t/{tenant_id}`, which is what the discovery
//!   document the client read says and what OIDC Core §2 requires them to
//!   match;
//! * [`AuthenticatedUser`](crate::extractors::AuthenticatedUser), which refuses
//!   a principal whose tenant is not the tenant the path named.
//!
//! # The two refusals, and why both are fail-closed
//!
//! **A tenant segment that is not a UUID** is `invalid_request`, decided from
//! the path alone with no repository read. Nothing is normalised and nothing is
//! looked up, so `/t/../oauth2/token` and `/t/%2e%2e/oauth2/token` are refused
//! for the same reason a typo is: they are not a UUID.
//!
//! **A `tenant_id` query parameter on a tenant path** is `invalid_request`,
//! whether or not it agrees with the path. Two tenant selectors on one request
//! is exactly the shape a confused-deputy bug takes — one component reads the
//! path, another reads the query, and they answer differently — and the cheapest
//! way to have no such bug is to have no such request. A client that followed
//! the tenant discovery document never sends one: every endpoint URL in it is
//! bare, which is the point of the path form.
//!
//! Note what is deliberately *not* checked here: whether the tenant exists.
//! Discovery is public and unauthenticated, and a `404` for an unknown tenant
//! id would make this scope a tenant-enumeration oracle. An unknown tenant gets
//! exactly what `?tenant_id=<unknown>` gets today — whatever the handler
//! underneath answers, which for every credential-taking endpoint is
//! `invalid_client`.

use std::borrow::Cow;
use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::sync::Arc;

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::uri::{PathAndQuery, Uri};
use actix_web::{Error, HttpMessage, HttpRequest, HttpResponse};
use axiam_auth::config::AuthConfig;
use uuid::Uuid;

use crate::handlers::oauth2::OAuth2ErrorResponse;

/// The tenant a request arrived under, and the issuer it therefore mints with.
///
/// Present in a request's extensions exactly when that request came through the
/// `/t/{tenant_id}` scope. Absent on every other request, which is every
/// request on a deployment with `AXIAM__AUTH__TENANT_ISSUER_PATHS` unset.
///
/// The [`AuthConfig`] is a whole clone rather than just the issuer string so
/// that a handler can pass `&AuthConfig` to the token-minting functions
/// unchanged — none of them learns that tenant paths exist, which is what keeps
/// the four `iss` stamping sites from drifting apart.
#[derive(Debug, Clone)]
pub struct TenantPathBinding {
    /// The tenant named by the path segment, already parsed.
    pub tenant_id: Uuid,
    /// The deployment's config with
    /// [`request_issuer`](AuthConfig::request_issuer) set to
    /// `{root}/t/{tenant_id}`.
    ///
    /// `Arc` because several extractors and handlers read it on one request and
    /// none of them mutates it.
    pub auth_config: Arc<AuthConfig>,
}

impl TenantPathBinding {
    /// The tenant issuer this request mints under.
    #[must_use]
    pub fn issuer(&self) -> &str {
        self.auth_config.effective_issuer()
    }
}

/// The tenant binding of a request, if it arrived on a tenant path.
#[must_use]
pub fn binding_of(req: &HttpRequest) -> Option<TenantPathBinding> {
    req.extensions().get::<TenantPathBinding>().cloned()
}

/// The config a request mints its tokens under.
///
/// `Borrowed(deployment)` — and therefore exactly today's behaviour, with no
/// allocation — for every request that did not arrive on a tenant path.
#[must_use]
pub fn minting_config<'a>(req: &HttpRequest, deployment: &'a AuthConfig) -> Cow<'a, AuthConfig> {
    match binding_of(req) {
        None => Cow::Borrowed(deployment),
        Some(binding) => Cow::Owned((*binding.auth_config).clone()),
    }
}

/// Wrap the `/t/{tenant_id}` scope with this (T21.6).
///
/// See the module documentation for what it does and what it refuses.
pub struct TenantPathScope;

impl<S, B> Transform<S, ServiceRequest> for TenantPathScope
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = TenantPathScopeService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(TenantPathScopeService { inner: service }))
    }
}

/// The running half of [`TenantPathScope`].
pub struct TenantPathScopeService<S> {
    inner: S,
}

/// The RFC 6749 §5.2-shaped refusal this middleware answers with.
///
/// JSON rather than actix's `text/plain` default, because every endpoint under
/// this scope answers errors as a JSON object and a refusal that arrives before
/// the handler must not be the one exception a client cannot parse.
fn invalid_request(description: &str) -> HttpResponse {
    HttpResponse::BadRequest().json(OAuth2ErrorResponse {
        error: "invalid_request".into(),
        error_description: description.to_owned(),
    })
}

/// `path?query` with `tenant_id` appended, as a `Uri` (T21.6).
///
/// Only the query is rewritten. The path is left exactly as actix matched it,
/// because the scope's inner routing reads the already-captured match info
/// rather than this string — rewriting the path here would change what the
/// handlers see (`req.path()` feeds the DPoP `htu`, RFC 9449 §4.3) without
/// changing what was routed, which is the definition of a confusing bug.
fn uri_with_tenant(uri: &Uri, tenant_id: Uuid) -> Option<Uri> {
    let path = uri.path();
    let query = uri.query().unwrap_or_default();
    let rewritten = if query.is_empty() {
        format!("{path}?tenant_id={tenant_id}")
    } else {
        format!("{path}?{query}&tenant_id={tenant_id}")
    };
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(PathAndQuery::try_from(rewritten).ok()?);
    Uri::from_parts(parts).ok()
}

impl<S, B> Service<ServiceRequest> for TenantPathScopeService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let refuse = |req: ServiceRequest, response: HttpResponse| {
            let (http_req, _payload) = req.into_parts();
            let res = ServiceResponse::new(http_req, response).map_into_right_body();
            Box::pin(async move { Ok(res) })
                as Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>
        };

        // 1. The tenant segment, parsed. Never looked up: see the module docs
        //    on why an unknown tenant is not this middleware's business.
        let Some(tenant_id) = req
            .match_info()
            .get("tenant_id")
            .and_then(|raw| Uuid::parse_str(raw).ok())
        else {
            return refuse(
                req,
                invalid_request("the tenant segment of the path is not a UUID"),
            );
        };

        // 2. Two tenant selectors on one request is refused outright, agreeing
        //    or not. See the module docs.
        if req
            .query_string()
            .split('&')
            .any(|pair| pair == "tenant_id" || pair.starts_with("tenant_id="))
        {
            return refuse(
                req,
                invalid_request(
                    "tenant_id must not be sent as a query parameter on a \
                     per-tenant issuer path; the tenant is the path segment",
                ),
            );
        }

        // 3. The tenant issuer. `None` means this deployment does not serve
        //    tenant paths at all — unreachable, because the scope carrying this
        //    middleware is mounted only when it does, and answered rather than
        //    unwrapped so that a future caller cannot make it reachable
        //    silently.
        let Some(config) = req
            .app_data::<actix_web::web::Data<AuthConfig>>()
            .and_then(|deployment| deployment.for_tenant_path(tenant_id))
        else {
            return refuse(req, HttpResponse::NotFound().finish());
        };

        req.extensions_mut().insert(TenantPathBinding {
            tenant_id,
            auth_config: Arc::new(config),
        });

        // 4. Hand the tenant to the handlers where they already look for it.
        let Some(rewritten) = uri_with_tenant(req.uri(), tenant_id) else {
            return refuse(
                req,
                invalid_request("the request URI could not be scoped to its tenant"),
            );
        };
        req.head_mut().uri = rewritten;

        let fut = self.inner.call(req);
        Box::pin(async move { Ok(fut.await?.map_into_left_body()) })
    }
}

#[cfg(test)]
mod tests {
    use super::uri_with_tenant;
    use actix_web::http::uri::Uri;
    use uuid::Uuid;

    const TENANT: &str = "11111111-2222-3333-4444-555555555555";

    #[test]
    fn a_bare_path_gains_the_tenant_as_its_only_parameter() {
        let uri: Uri = "/t/x/oauth2/token".parse().unwrap();
        let out = uri_with_tenant(&uri, Uuid::parse_str(TENANT).unwrap()).unwrap();
        assert_eq!(out.path(), "/t/x/oauth2/token");
        assert_eq!(out.query(), Some(format!("tenant_id={TENANT}").as_str()));
    }

    #[test]
    fn an_existing_query_is_preserved_and_the_tenant_appended() {
        let uri: Uri = "/t/x/oauth2/authorize?client_id=oa_1&state=abc"
            .parse()
            .unwrap();
        let out = uri_with_tenant(&uri, Uuid::parse_str(TENANT).unwrap()).unwrap();
        assert_eq!(
            out.query(),
            Some(format!("client_id=oa_1&state=abc&tenant_id={TENANT}").as_str())
        );
    }

    /// The path is what `req.path()` reports and therefore what the DPoP `htu`
    /// is built from (RFC 9449 §4.3). Rewriting it here would make a proof
    /// signed for the URL the client called fail against the URL the server
    /// thinks it served.
    #[test]
    fn the_path_is_never_rewritten() {
        let uri: Uri = "/t/x/oauth2/par?a=1".parse().unwrap();
        let out = uri_with_tenant(&uri, Uuid::parse_str(TENANT).unwrap()).unwrap();
        assert_eq!(out.path(), uri.path());
    }
}

//! TokenService gRPC implementation.

use axiam_auth::config::AuthConfig;
use axiam_auth::error::AuthError;
use axiam_auth::token::validate_access_token;
use tonic::{Request, Response, Status};

use axiam_auth::token::ValidatedClaims;

use crate::proto::token_service_server::TokenService;
use crate::proto::{
    CnfClaim, IntrospectTokenRequest, IntrospectTokenResponse, RptPermission, ValidateTokenRequest,
    ValidateTokenResponse,
};

/// Project a decoded `cnf` claim onto the wire message (X5.1).
///
/// `None` for an unbound token, so the field is simply absent — which is what
/// every pre-X5.1 token produces and what keeps this response byte-compatible
/// for a consumer that has never heard of sender-constraining.
fn wire_cnf(claims: &axiam_auth::token::AccessTokenClaims) -> Option<CnfClaim> {
    claims.cnf.as_ref().map(|c| CnfClaim {
        x5t_s256: c.x5t_s256.clone().unwrap_or_default(),
        jkt: c.jkt.clone().unwrap_or_default(),
    })
}

/// RFC 6749 §7.1 / RFC 9449 §5 token type for a set of claims.
///
/// A DPoP-bound token is announced as `DPoP`; everything else — including a
/// certificate-bound token, which RFC 8705 leaves a bearer token at the HTTP
/// layer — is `Bearer`.
fn wire_token_type(claims: &axiam_auth::token::AccessTokenClaims) -> String {
    match claims.cnf.as_ref().and_then(|c| c.jkt.as_deref()) {
        Some(_) => "DPoP".to_owned(),
        None => "Bearer".to_owned(),
    }
}

pub struct TokenServiceImpl {
    config: AuthConfig,
}

impl TokenServiceImpl {
    pub fn new(config: AuthConfig) -> Self {
        Self { config }
    }
}

#[tonic::async_trait]
impl TokenService for TokenServiceImpl {
    async fn validate_token(
        &self,
        request: Request<ValidateTokenRequest>,
    ) -> Result<Response<ValidateTokenResponse>, Status> {
        // SEC-068: the caller's tenant comes from the interceptor-verified JWT.
        let caller_tenant = request
            .extensions()
            .get::<ValidatedClaims>()
            .ok_or_else(|| Status::unauthenticated("missing validated claims"))?
            .0
            .tenant_id
            .clone();
        let req = request.into_inner();

        match validate_access_token(&req.access_token, &self.config) {
            // SEC-068: refuse to introspect a token belonging to a different
            // tenant — report it as invalid (not merely denied) so a mesh peer
            // in tenant A cannot read a tenant-B token's claims by observing the
            // difference between "denied" and "invalid".
            Ok(validated) if validated.0.tenant_id == caller_tenant => {
                let claims = validated.0;
                let cnf = wire_cnf(&claims);
                let token_type = wire_token_type(&claims);
                if cnf.is_some() {
                    // Worth a line in the log rather than silence: the caller
                    // is about to receive `valid: true` for a token that is
                    // NOT usable as a bearer credential, and whether they act
                    // on that is beyond this service's reach.
                    tracing::debug!(
                        token_jti = %claims.jti,
                        "grpc: validated a sender-constrained token; the caller must prove \
                         possession of the confirmed key or refuse the request"
                    );
                }
                Ok(Response::new(ValidateTokenResponse {
                    valid: true,
                    subject_id: claims.sub,
                    tenant_id: claims.tenant_id,
                    org_id: claims.org_id,
                    exp: claims.exp,
                    cnf,
                    token_type,
                }))
            }
            Err(AuthError::Crypto(msg)) => {
                Err(Status::internal(format!("token validation error: {msg}")))
            }
            // Invalid token OR a cross-tenant token (guard above failed) — both
            // report inactive so the two are indistinguishable to the caller.
            _ => Ok(Response::new(ValidateTokenResponse {
                valid: false,
                subject_id: String::new(),
                tenant_id: String::new(),
                org_id: String::new(),
                exp: 0,
                // An inactive answer discloses nothing, including whether the
                // token that failed was bound.
                cnf: None,
                token_type: String::new(),
            })),
        }
    }

    async fn introspect_token(
        &self,
        request: Request<IntrospectTokenRequest>,
    ) -> Result<Response<IntrospectTokenResponse>, Status> {
        // SEC-068: the caller's tenant comes from the interceptor-verified JWT.
        let caller_tenant = request
            .extensions()
            .get::<ValidatedClaims>()
            .ok_or_else(|| Status::unauthenticated("missing validated claims"))?
            .0
            .tenant_id
            .clone();
        let req = request.into_inner();

        match validate_access_token(&req.access_token, &self.config) {
            // SEC-068: only introspect a token from the caller's own tenant; a
            // cross-tenant token reports inactive (indistinguishable from an
            // invalid one) so its sub/org/jti claims are not disclosed.
            Ok(validated) if validated.0.tenant_id == caller_tenant => {
                let claims = validated.0;
                let cnf = wire_cnf(&claims);
                let token_type = wire_token_type(&claims);
                let permissions = claims
                    .permissions
                    .as_ref()
                    .map(|ps| {
                        ps.iter()
                            .map(|p| RptPermission {
                                resource_id: p.resource_id.to_string(),
                                resource_scopes: p.resource_scopes.clone(),
                                exp: p.exp,
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let ext_exchange_iss = claims
                    .ext_exchange
                    .as_ref()
                    .map(|e| e.iss.clone())
                    .unwrap_or_default();
                // The client id lives in `sub` for a client-credentials token,
                // where `sub_kind` says so. Reading it off `sub_kind` rather
                // than pattern-matching the string is what keeps this from
                // guessing: an `oa_`-prefixed user id would otherwise be
                // reported as a client.
                let client_id = match claims.sub_kind {
                    axiam_auth::token::SubjectKind::OAuth2Client
                    | axiam_auth::token::SubjectKind::ServiceAccount => claims.sub.clone(),
                    _ => String::new(),
                };
                Ok(Response::new(IntrospectTokenResponse {
                    active: true,
                    sub: claims.sub,
                    tenant_id: claims.tenant_id,
                    org_id: claims.org_id,
                    iss: claims.iss,
                    iat: claims.iat,
                    exp: claims.exp,
                    jti: claims.jti,
                    scope: claims.scope.unwrap_or_default(),
                    client_id,
                    token_type,
                    cnf,
                    permissions,
                    ext_exchange_iss,
                }))
            }
            Err(AuthError::Crypto(msg)) => {
                Err(Status::internal(format!("token validation error: {msg}")))
            }
            _ => Ok(Response::new(IntrospectTokenResponse {
                active: false,
                sub: String::new(),
                tenant_id: String::new(),
                org_id: String::new(),
                iss: String::new(),
                iat: 0,
                exp: 0,
                jti: String::new(),
                // RFC 7662 §2.2: an inactive response carries `active: false`
                // and nothing else. Every field below stays empty on purpose —
                // leaking a `cnf` or a scope for a token the caller may not
                // introspect would undo the SEC-068 guard above.
                scope: String::new(),
                client_id: String::new(),
                token_type: String::new(),
                cnf: None,
                permissions: Vec::new(),
                ext_exchange_iss: String::new(),
            })),
        }
    }
}

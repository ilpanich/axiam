//! OAuth2 Token Exchange (RFC 8693) — B3.
//!
//! Design and rationale: `claude_dev/token-exchange-design.md`. The short
//! version, because it governs every function below:
//!
//! > **An exchange may only ever narrow.** There is no input, no
//! > configuration and no client grant that causes the issued token to permit
//! > something the subject token did not already permit.
//!
//! Each check here is that rule restated for one dimension — scopes,
//! audience, lifetime, actor identity — and each has a test named after the
//! thing it stops.
//!
//! Like the device grant, this is a **separate service** rather than another
//! arm of [`crate::token::TokenService`]: it needs different collaborators,
//! and the REST layer keeps the seam at one `match` on `grant_type`.

use axiam_auth::config::AuthConfig;
use axiam_auth::token::{
    AUD_M2M, AUD_USER, ActClaim, MAX_ACT_CHAIN_DEPTH, SubjectKind, decode_access_token,
    issue_exchanged_token,
};
use axiam_core::models::oauth2_client::OAuth2Client;
use axiam_core::repository::TenantRepository;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::OAuth2Error;

/// The grant type this service handles.
pub const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// The only subject/actor token type accepted in v1.
///
/// Refusing everything else is deliberate rather than unfinished: accepting a
/// token means accepting whatever its issuer asserts about the subject, and
/// the trust configuration that makes an *external* issuer safe is a feature
/// of its own (X4). Hard-wiring "us" keeps this grant small enough to review.
pub const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";

/// Grant-list entry that permits impersonation.
///
/// Encoded as a grant-type entry rather than a new column: the client
/// registration already carries a list of what a client may do, adding to it
/// needs no migration, and an operator reading `grant_types` sees this
/// capability in the same place as every other one.
pub const MAY_IMPERSONATE_GRANT: &str = "urn:axiam:params:oauth:grant-type:may-impersonate";

/// `POST /oauth2/token` with `grant_type=…:token-exchange` (RFC 8693 §2.1).
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct TokenExchangeRequest {
    pub subject_token: String,
    pub subject_token_type: String,
    /// RFC 8693 §2.1. Optional, and the AS picks the default — but a client
    /// that *names* a type it does not get must be told, not handed an
    /// access token and left to discover the difference. v1 issues access
    /// tokens only, so any other explicit value is refused.
    pub requested_token_type: Option<String>,
    /// Presence of an actor token selects **delegation**; absence selects
    /// **impersonation**, which is off unless the client is granted it.
    pub actor_token: Option<String>,
    pub actor_token_type: Option<String>,
    /// Space-separated. Absent means "the subject's own scopes".
    pub scope: Option<String>,
    pub audience: Option<String>,
    /// RFC 8707. Treated as a synonym of `audience`; if both are given they
    /// must agree, because silently preferring one would make the request
    /// mean something the caller did not write.
    pub resource: Option<String>,
}

/// RFC 8693 §2.2.1 response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TokenExchangeResponse {
    pub access_token: String,
    /// Mandatory per §2.2.1, and not decoration: a client that asked for one
    /// token type and got another must be able to tell.
    pub issued_token_type: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// What an exchange did, for the audit record.
///
/// Impersonation is the reason this type exists. A delegated token carries an
/// `act` claim naming who acted; an impersonated one deliberately does not, so
/// the audit entry is the *only* surviving evidence that the acting party was
/// not the subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeKind {
    Delegation,
    Impersonation,
}

impl ExchangeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Delegation => "delegation",
            Self::Impersonation => "impersonation",
        }
    }
}

/// The outcome the caller audits and returns.
pub struct ExchangeOutcome {
    pub response: TokenExchangeResponse,
    pub kind: ExchangeKind,
    pub subject: String,
    pub actor: Option<String>,
    pub granted_scopes: Vec<String>,
    pub audience: String,
}

/// Intersect the three scope sets, preserving the caller's requested order.
///
/// A free function, not a method, because it is the single most important
/// thing in the feature and should be testable without a datastore, a client
/// or a token. `requested` is already defaulted to the subject's scopes by the
/// caller when the parameter was absent.
///
/// Returns `Err` naming the first requested scope that fails. **Refusing
/// rather than silently dropping** is deliberate: a quietly-narrowed token
/// works for some calls and not others, and the caller discovers that at the
/// second service with no idea why. An error at the exchange is actionable.
pub fn narrow_scopes(
    requested: &[String],
    subject_scopes: &[String],
    client_scopes: &[String],
) -> Result<Vec<String>, OAuth2Error> {
    let mut granted: Vec<String> = Vec::with_capacity(requested.len());
    for scope in requested {
        if !subject_scopes.contains(scope) {
            return Err(OAuth2Error::InvalidScope(format!(
                "the subject token does not hold scope '{scope}'"
            )));
        }
        // The client's own registration bounds the result even when the
        // subject token is broader. This is what stops a compromised
        // low-privilege service that has captured an admin's token from
        // minting an admin token: it can only ever reach its own ceiling.
        if !client_scopes.contains(scope) {
            return Err(OAuth2Error::InvalidScope(format!(
                "the exchanging client is not registered for scope '{scope}'"
            )));
        }
        if !granted.contains(scope) {
            granted.push(scope.clone());
        }
    }
    if granted.is_empty() {
        return Err(OAuth2Error::InvalidScope(
            "the exchange would grant no scopes at all".into(),
        ));
    }
    Ok(granted)
}

/// Whether a client may impersonate.
pub fn client_may_impersonate(client: &OAuth2Client) -> bool {
    client
        .grant_types
        .iter()
        .any(|g| g == MAY_IMPERSONATE_GRANT)
}

/// AXIAM's own two audiences are always addressable — they are not
/// third-party systems, and refusing them would make the common "narrow a
/// user token to an M2M token" case impossible to express.
fn is_builtin_audience(target: &str) -> bool {
    target == AUD_USER || target == AUD_M2M
}

fn parse_scopes(raw: Option<&str>) -> Option<Vec<String>> {
    raw.map(|s| s.split_whitespace().map(str::to_owned).collect())
}

/// Token-exchange service.
#[derive(Clone)]
pub struct TokenExchangeService<TR> {
    tenant_repo: TR,
    auth_config: AuthConfig,
    /// Independent ceiling on an exchanged token's lifetime, applied on top of
    /// "never outlives its subject".
    max_lifetime_secs: i64,
}

impl<TR> TokenExchangeService<TR>
where
    TR: TenantRepository,
{
    pub fn new(tenant_repo: TR, auth_config: AuthConfig, max_lifetime_secs: i64) -> Self {
        Self {
            tenant_repo,
            auth_config,
            max_lifetime_secs,
        }
    }

    /// Perform an exchange.
    ///
    /// The exchanging client is assumed already authenticated by the caller —
    /// the token endpoint does that for every grant — and `client` is the row
    /// that authentication produced.
    pub async fn exchange(
        &self,
        tenant_id: Uuid,
        client: &OAuth2Client,
        req: TokenExchangeRequest,
    ) -> Result<ExchangeOutcome, OAuth2Error> {
        if !client
            .grant_types
            .iter()
            .any(|g| g == TOKEN_EXCHANGE_GRANT_TYPE)
        {
            return Err(OAuth2Error::UnauthorizedClient(
                "client is not registered for the token-exchange grant".into(),
            ));
        }

        // Checked before anything is decoded: a client asking for a refresh
        // token wants a different thing entirely, and answering it with an
        // access token would satisfy the request shape while defeating the
        // lifetime cap the whole grant is built around.
        if let Some(want) = req.requested_token_type.as_deref()
            && want != TOKEN_TYPE_ACCESS_TOKEN
        {
            return Err(OAuth2Error::InvalidRequest(format!(
                "unsupported requested_token_type '{want}'; \
                 v1 issues only {TOKEN_TYPE_ACCESS_TOKEN}"
            )));
        }

        if req.subject_token_type != TOKEN_TYPE_ACCESS_TOKEN {
            return Err(OAuth2Error::InvalidRequest(format!(
                "unsupported subject_token_type '{}'; v1 accepts only {TOKEN_TYPE_ACCESS_TOKEN}",
                req.subject_token_type
            )));
        }

        // --- the subject ---------------------------------------------------
        let subject = decode_access_token(&req.subject_token, &self.auth_config)
            .map_err(|_| OAuth2Error::InvalidGrant("subject token is not valid".into()))?;

        // Cross-tenant is `invalid_grant`, not a distinct error: a caller
        // learning that their token is valid SOMEWHERE ELSE is a
        // tenant-enumeration signal.
        if subject.tenant_id != tenant_id.to_string() {
            return Err(OAuth2Error::InvalidGrant(
                "subject token is not valid".into(),
            ));
        }

        // No unbounded re-exchange. A token already carrying a full `act`
        // chain cannot be exchanged again — otherwise the chain, and the
        // token, grows one re-exchange at a time.
        if let Some(act) = subject.act.as_ref()
            && act.depth() >= MAX_ACT_CHAIN_DEPTH
        {
            return Err(OAuth2Error::InvalidRequest(format!(
                "subject token already names {MAX_ACT_CHAIN_DEPTH} actors; \
                 it cannot be exchanged again"
            )));
        }

        // --- delegation or impersonation ------------------------------------
        let (kind, actor_sub) = match req.actor_token.as_deref() {
            Some(actor_token) => {
                match req.actor_token_type.as_deref() {
                    Some(t) if t == TOKEN_TYPE_ACCESS_TOKEN => {}
                    _ => {
                        return Err(OAuth2Error::InvalidRequest(
                            "actor_token_type must be supplied and must be an access token".into(),
                        ));
                    }
                }
                let actor = decode_access_token(actor_token, &self.auth_config)
                    .map_err(|_| OAuth2Error::InvalidGrant("actor token is not valid".into()))?;
                if actor.tenant_id != tenant_id.to_string() {
                    return Err(OAuth2Error::InvalidGrant("actor token is not valid".into()));
                }
                (ExchangeKind::Delegation, Some(actor.sub))
            }
            None => {
                // Impersonation. The resulting token is indistinguishable from
                // one the subject obtained directly, so it is off unless the
                // client was explicitly granted it — and a client without the
                // grant is REFUSED rather than silently downgraded to
                // delegation, which would hand back a token that is not the
                // one they asked for.
                if !client_may_impersonate(client) {
                    return Err(OAuth2Error::UnauthorizedClient(
                        "impersonation requires the may_impersonate grant; \
                         supply an actor_token to delegate instead"
                            .into(),
                    ));
                }
                (ExchangeKind::Impersonation, None)
            }
        };

        // --- scopes ----------------------------------------------------------
        let subject_scopes: Vec<String> = subject
            .scope
            .as_deref()
            .map(|s| s.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default();
        let requested =
            parse_scopes(req.scope.as_deref()).unwrap_or_else(|| subject_scopes.clone());
        let granted = narrow_scopes(&requested, &subject_scopes, &client.scopes)?;

        // --- audience ---------------------------------------------------------
        let target = match (req.audience.as_deref(), req.resource.as_deref()) {
            (Some(a), Some(r)) if a != r => {
                return Err(OAuth2Error::InvalidRequest(
                    "audience and resource disagree; supply one or make them equal".into(),
                ));
            }
            (Some(a), _) => Some(a),
            (None, Some(r)) => Some(r),
            (None, None) => None,
        };
        let audience = match target {
            Some(t) => {
                // An unconstrained `aud` would let a service mint tokens
                // addressed at systems it has no relationship with — the mesh
                // equivalent of an open redirect. The client's registered URIs
                // are its declared relationships.
                if !is_builtin_audience(t) && !client.redirect_uris.iter().any(|u| u == t) {
                    return Err(OAuth2Error::InvalidTarget(format!(
                        "'{t}' is not a registered target for this client"
                    )));
                }
                t.to_owned()
            }
            // Inherit. `aud` is optional on pre-Phase-4 tokens, which
            // `decode_access_token` treats as user tokens.
            None => subject.aud.clone().unwrap_or_else(|| AUD_USER.to_string()),
        };

        // --- lifetime ----------------------------------------------------------
        let now = Utc::now().timestamp();
        let subject_remaining = subject.exp - now;
        if subject_remaining <= 0 {
            return Err(OAuth2Error::InvalidGrant(
                "subject token has expired".into(),
            ));
        }
        // Never outlives its subject. Without this an exchange launders
        // lifetime: hold a token for thirty seconds, exchange it, hold the
        // result for the full access-token lifetime.
        let lifetime = subject_remaining.min(self.max_lifetime_secs);
        let expires_at = now + lifetime;

        // --- issue --------------------------------------------------------------
        let tenant = self
            .tenant_repo
            .get_by_id(tenant_id)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        let act = actor_sub.as_ref().map(|actor| ActClaim {
            sub: actor.clone(),
            act: subject.act.clone().map(Box::new),
        });

        let sub_kind = if audience == AUD_M2M {
            SubjectKind::OAuth2Client
        } else {
            subject.sub_kind
        };

        let access_token = issue_exchanged_token(
            &subject.sub,
            sub_kind,
            tenant_id,
            tenant.organization_id,
            &granted,
            &self.auth_config,
            Uuid::new_v4().to_string(),
            &audience,
            expires_at,
            act,
        )
        .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        Ok(ExchangeOutcome {
            response: TokenExchangeResponse {
                access_token,
                issued_token_type: TOKEN_TYPE_ACCESS_TOKEN.to_string(),
                token_type: "Bearer".into(),
                expires_in: lifetime as u64,
                scope: Some(granted.join(" ")),
                // No refresh token, ever. One would let the holder outlive the
                // subject token indefinitely — the lifetime cap above,
                // defeated. Re-run the exchange.
            },
            kind,
            subject: subject.sub,
            actor: actor_sub,
            granted_scopes: granted,
            audience,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn narrowing_keeps_only_what_all_three_sets_hold() {
        let granted = narrow_scopes(
            &v(&["read", "write"]),
            &v(&["read", "write", "admin"]),
            &v(&["read", "write", "delete"]),
        )
        .unwrap();
        assert_eq!(granted, v(&["read", "write"]));
    }

    #[test]
    fn a_scope_the_subject_lacks_is_refused_not_dropped() {
        let err = narrow_scopes(
            &v(&["read", "admin"]),
            &v(&["read"]),
            &v(&["read", "admin"]),
        )
        .unwrap_err();
        assert_eq!(err.error_code(), "invalid_scope");
        assert!(
            err.error_description().contains("admin"),
            "the error should name the offending scope: {err}"
        );
    }

    #[test]
    fn the_clients_own_ceiling_bounds_a_broader_subject_token() {
        // The headline case: a low-privilege service holding an admin's token
        // must not be able to mint an admin token.
        let err = narrow_scopes(&v(&["admin"]), &v(&["admin", "read"]), &v(&["read"])).unwrap_err();
        assert_eq!(err.error_code(), "invalid_scope");
        assert!(err.error_description().contains("client"));
    }

    #[test]
    fn an_empty_result_is_an_error_rather_than_a_scopeless_token() {
        let err = narrow_scopes(&[], &v(&["read"]), &v(&["read"])).unwrap_err();
        assert_eq!(err.error_code(), "invalid_scope");
    }

    #[test]
    fn duplicate_requested_scopes_collapse() {
        let granted = narrow_scopes(&v(&["read", "read"]), &v(&["read"]), &v(&["read"])).unwrap();
        assert_eq!(granted, v(&["read"]));
    }

    /// The property the whole feature exists to preserve, over every
    /// combination of three scope sets: whatever comes out is a subset of all
    /// three inputs. Exhaustive rather than randomised — the universe is four
    /// scopes, so every case can simply be enumerated.
    #[test]
    fn granted_is_always_a_subset_of_all_three_inputs() {
        let universe = ["a", "b", "c", "d"];
        let subsets: Vec<Vec<String>> = (0u8..16)
            .map(|mask| {
                universe
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| mask & (1 << i) != 0)
                    .map(|(_, s)| (*s).to_string())
                    .collect()
            })
            .collect();

        for requested in &subsets {
            for subject in &subsets {
                for client in &subsets {
                    match narrow_scopes(requested, subject, client) {
                        Ok(granted) => {
                            assert!(!granted.is_empty(), "an Ok result is never empty");
                            for s in &granted {
                                assert!(requested.contains(s), "widened past requested");
                                assert!(subject.contains(s), "widened past the subject token");
                                assert!(client.contains(s), "widened past the client");
                            }
                        }
                        Err(e) => assert_eq!(e.error_code(), "invalid_scope"),
                    }
                }
            }
        }
    }

    #[test]
    fn act_chain_depth_counts_every_actor() {
        let one = ActClaim {
            sub: "a".into(),
            act: None,
        };
        assert_eq!(one.depth(), 1);
        let two = ActClaim {
            sub: "b".into(),
            act: Some(Box::new(one)),
        };
        assert_eq!(two.depth(), 2);
        let three = ActClaim {
            sub: "c".into(),
            act: Some(Box::new(two)),
        };
        assert_eq!(three.depth(), MAX_ACT_CHAIN_DEPTH);
    }

    #[test]
    fn impersonation_is_off_unless_the_grant_is_present() {
        let mut client = OAuth2Client {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            client_id: "oa_x".into(),
            client_secret_hash: String::new(),
            name: "svc".into(),
            redirect_uris: vec![],
            grant_types: vec![TOKEN_EXCHANGE_GRANT_TYPE.into()],
            scopes: v(&["read"]),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(
            !client_may_impersonate(&client),
            "a client registered only for the exchange grant must not impersonate"
        );
        client.grant_types.push(MAY_IMPERSONATE_GRANT.into());
        assert!(client_may_impersonate(&client));
    }
}

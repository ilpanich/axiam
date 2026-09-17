//! Pushed Authorization Requests (RFC 9126) — B5.
//!
//! The client POSTs its authorization parameters to `/oauth2/par`, where it
//! **authenticates**, and gets back an opaque `request_uri` to put in the
//! browser redirect instead of the parameters themselves.
//!
//! # What this actually buys
//!
//! In a plain authorization-code redirect, every parameter travels through the
//! user agent: it lands in browser history, in `Referer` headers, in any proxy
//! access log along the way, and — the part that matters — it is trivially
//! modifiable by whoever controls the browser. PKCE closes the code-injection
//! half of that, but nothing stops a tampered `scope` or `redirect_uri` from
//! reaching the authorization endpoint attributable to nobody.
//!
//! With PAR the parameters arrive over a direct, client-authenticated,
//! server-to-server POST. What travels through the browser is a random string
//! that means nothing to anyone who intercepts it and cannot be edited into
//! meaning something else. This is why FAPI 2.0 requires it, and why X5 needs
//! it before a conformance run is possible.
//!
//! # The two rules that carry the security
//!
//! 1. **Single-use.** Enforced in the repository's `consume`, in one
//!    statement. A replayable `request_uri` is a replayable authorization
//!    request.
//! 2. **Parameters do not mix.** An authorize request carrying both a
//!    `request_uri` and inline parameters is refused rather than merged.
//!    Merging is exactly where parameter confusion lives: the attacker
//!    supplies the inline value they want and lets the pushed one satisfy
//!    whatever check reads the other copy.

use axiam_core::error::AxiamError;
use axiam_core::models::oauth2_client::{ClientProfile, CreatePushedAuthRequest, PushedAuthParams};
use axiam_core::repository::{OAuth2ClientRepository, PushedAuthRequestRepository};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use rand::RngExt;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::OAuth2Error;

/// The `request_uri` scheme RFC 9126 §2.2 mandates.
pub const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// How long a pushed request stays usable.
///
/// RFC 9126 §2.2 suggests "in the order of seconds to a few minutes", and the
/// window only has to cover one browser redirect. There is deliberately no
/// configuration knob in v1: every value an operator might pick is either this
/// or worse, and a tunable that only trends longer is a tunable that only
/// widens a replay window.
pub const REQUEST_URI_LIFETIME_SECS: i64 = 60;

/// The longest `state` or `nonce` a **fapi2** client may push.
///
/// 256 characters, which is six times what a 32-byte random value needs once
/// base64url-encoded (43) and comfortably above anything that carries entropy
/// rather than payload. It is not a guess at what clients send: the OpenID
/// Foundation's FAPI 2.0 suite probes this boundary directly with a
/// 1000-character `state` and a 384-character `nonce`, and requires both to be
/// refused, so any cap that admits either is not conformant.
///
/// Characters, not bytes — [`str::len`] would make the limit depend on how
/// many non-ASCII code points the value happens to contain, and the value is
/// opaque, so the count the client can reason about is the one to bound.
pub const MAX_FAPI_OPAQUE_PARAM_CHARS: usize = 256;

/// Generate a `request_uri`: 256 bits of CSPRNG behind the RFC's URN prefix.
pub fn generate_request_uri() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 32] = rng.random();
    format!("{REQUEST_URI_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// SHA-256 of a `request_uri`'s random component, hex-encoded — what is stored.
///
/// Hashed at rest for the same reason device codes are: for the 60 s it lives,
/// the `request_uri` is a bearer credential, and a database read should not
/// hand an attacker a usable one. SHA-256 rather than a KDF because the value
/// is a 256-bit CSPRNG string with no offline-guessing threat to defend
/// against.
pub fn hash_request_uri(raw: &str) -> String {
    let component = raw.strip_prefix(REQUEST_URI_PREFIX).unwrap_or(raw);
    let mut hasher = Sha256::new();
    hasher.update(component.as_bytes());
    hex::encode(hasher.finalize())
}

/// What a client pushes.
///
/// X7.1 — the nine OIDC authentication-request parameters are pushed
/// alongside the original seven. PAR and the inline query string are two
/// carriers of one request, and for a `require_par` client PAR is the only
/// carrier there is: a parameter added to only one of them is silently lost by
/// exactly the clients the FAPI profile insists on.
#[derive(Debug, Clone, Default)]
pub struct PushedRequest {
    pub tenant_id: Uuid,
    pub client_id: String,
    pub response_type: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub prompt: Option<String>,
    pub max_age: Option<String>,
    pub acr_values: Option<String>,
    pub claims: Option<String>,
    pub id_token_hint: Option<String>,
    pub login_hint: Option<String>,
    pub display: Option<String>,
    pub ui_locales: Option<String>,
    pub claims_locales: Option<String>,
    /// RFC 9449 §10 — the DPoP key this request binds its authorization to.
    ///
    /// Already *resolved* by the caller: the handler is where both inputs
    /// exist (the `dpop_jkt` form parameter and the `DPoP` header's verified
    /// thumbprint), and §10.1's rule that the two must agree is a refusal the
    /// endpoint owes the client before anything is stored. What arrives here
    /// is the single key the authorization is bound to, or `None`.
    pub dpop_jkt: Option<String>,
}

/// What `/oauth2/par` answers with (RFC 9126 §2.2).
#[derive(Debug, Clone)]
pub struct PushedAuthResponse {
    pub request_uri: String,
    pub expires_in: i64,
}

/// The PAR endpoint's logic.
#[derive(Clone)]
pub struct ParService<OC, PR> {
    client_repo: OC,
    par_repo: PR,
}

impl<OC, PR> ParService<OC, PR>
where
    OC: OAuth2ClientRepository,
    PR: PushedAuthRequestRepository,
{
    pub fn new(client_repo: OC, par_repo: PR) -> Self {
        Self {
            client_repo,
            par_repo,
        }
    }

    /// Store a pushed authorization request and mint its `request_uri`.
    ///
    /// The caller must already have authenticated the client — that is the
    /// point of the endpoint, and doing it here as well would duplicate the
    /// one secret-verification path the token endpoint shares.
    pub async fn push(&self, req: PushedRequest) -> Result<PushedAuthResponse, OAuth2Error> {
        let client = self
            .client_repo
            .get_by_client_id(req.tenant_id, &req.client_id)
            .await
            .map_err(|e| match e {
                // Same QUAL-03/D-11 discipline as the authorize endpoint: only
                // a genuinely-unknown client is `invalid_client`. A DB outage
                // must not masquerade as bad client credentials.
                AxiamError::NotFound { .. } => {
                    OAuth2Error::InvalidClient("client not found".into())
                }
                other => OAuth2Error::ServerError(other.to_string()),
            })?;

        // The redirect_uri is validated here, not deferred to the authorize
        // step. Validating at push time is the whole benefit: the client is
        // authenticated *now*, so a rejection is attributable, and the browser
        // never gets a request_uri standing for a request that was going to
        // fail anyway.
        // T21.2: the same matcher the authorization endpoint uses, so the two
        // cannot come to disagree about what this client registered — a PAR
        // request accepted here and refused at `/oauth2/authorize` would hand
        // the user agent a `request_uri` standing for a request that cannot
        // complete, which is the failure this check exists to prevent.
        if !crate::redirect_uri::any_redirect_uri_matches(&client.redirect_uris, &req.redirect_uri)
        {
            return Err(OAuth2Error::InvalidRedirectUri(
                "redirect_uri is not registered for this client".into(),
            ));
        }

        if req.response_type != "code" {
            return Err(OAuth2Error::UnsupportedResponseType);
        }

        // `state` and `nonce` are bounded, on the FAPI 2.0 profile only.
        //
        // Both are opaque values the client chooses and the server only ever
        // echoes, so a client has no legitimate need for a long one: 32 bytes
        // of entropy is 43 characters base64url, and the cap below is six
        // times that. What an unbounded value buys instead is a way to push
        // kilobytes of attacker-chosen text through the authorization request
        // and back out of the `redirect_uri` — stored in the datastore in the
        // meantime, and reflected into whatever the client does with `state`.
        //
        // Gated on [`ClientProfile::Fapi2`] deliberately, and not applied to
        // `Standard`. A cap is a breaking change for any client that packs
        // data into `state` — a bad practice, but a widespread one, and one a
        // deployment upgrading AXIAM has not agreed to. The FAPI profile is
        // the place where a client HAS agreed to the stricter bundle, and the
        // OpenID Foundation's own conformance suite requires the refusal
        // (`ensure-authorization-request-with-long-state` pushes 1000
        // characters, `-with-long-nonce` pushes 384, and both expect
        // `invalid_request`).
        //
        // Checked here rather than at `/oauth2/authorize` for the same reason
        // the `redirect_uri` above is: the client is authenticated *now*, so
        // the refusal is attributable and reaches the client as a protocol
        // error — instead of surfacing in a browser after a sign-in the user
        // should never have been asked for.
        if client.profile == ClientProfile::Fapi2 {
            for (name, value) in [
                ("state", req.state.as_deref()),
                ("nonce", req.nonce.as_deref()),
            ] {
                if let Some(v) = value
                    && v.chars().count() > MAX_FAPI_OPAQUE_PARAM_CHARS
                {
                    return Err(OAuth2Error::InvalidRequest(format!(
                        "{name} exceeds the {MAX_FAPI_OPAQUE_PARAM_CHARS}-character limit this \
                         client's fapi2 profile imposes"
                    )));
                }
            }
        }

        // RFC 9126 §2.1: `request_uri` is not a parameter a client may push.
        // Accepting one would let a client chain pushed requests, and the
        // second would inherit the first's authentication.
        let request_uri = generate_request_uri();
        let expires_at = Utc::now() + Duration::seconds(REQUEST_URI_LIFETIME_SECS);

        self.par_repo
            .create(CreatePushedAuthRequest {
                tenant_id: req.tenant_id,
                client_id: req.client_id,
                request_uri_hash: hash_request_uri(&request_uri),
                params: PushedAuthParams {
                    response_type: req.response_type,
                    redirect_uri: req.redirect_uri,
                    scope: req.scope,
                    state: req.state,
                    code_challenge: req.code_challenge,
                    code_challenge_method: req.code_challenge_method,
                    nonce: req.nonce,
                    prompt: req.prompt,
                    max_age: req.max_age,
                    acr_values: req.acr_values,
                    claims: req.claims,
                    id_token_hint: req.id_token_hint,
                    login_hint: req.login_hint,
                    display: req.display,
                    ui_locales: req.ui_locales,
                    claims_locales: req.claims_locales,
                    dpop_jkt: req.dpop_jkt,
                },
                expires_at,
            })
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        Ok(PushedAuthResponse {
            request_uri,
            expires_in: REQUEST_URI_LIFETIME_SECS,
        })
    }

    /// Resolve and consume a `request_uri` on the authorize path.
    ///
    /// The returned parameters are the ones the client pushed; the caller must
    /// use them *instead of* anything on the authorize query string, never
    /// merged with it.
    pub async fn consume(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        request_uri: &str,
    ) -> Result<PushedAuthParams, OAuth2Error> {
        if !request_uri.starts_with(REQUEST_URI_PREFIX) {
            return Err(OAuth2Error::InvalidRequest(
                "request_uri is not a pushed authorization request URI".into(),
            ));
        }

        let stored = self
            .par_repo
            .consume(tenant_id, &hash_request_uri(request_uri))
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?
            .ok_or_else(|| {
                // Unknown, expired and already-consumed all answer identically,
                // deliberately: distinguishing them tells an attacker holding a
                // stolen request_uri whether it is worth racing for, and none of
                // the three is recoverable by the client anyway.
                OAuth2Error::InvalidRequest(REQUEST_URI_GONE.into())
            })?;

        // The pushed request belongs to the client that pushed it. Without
        // this, a second client could spend another client's request_uri and
        // receive a code minted against the first client's registration.
        if stored.client_id != client_id {
            return Err(OAuth2Error::InvalidRequest(
                "request_uri was not issued to this client".into(),
            ));
        }

        Ok(stored.params)
    }

    /// Ask whether a `request_uri` is still spendable, **without** spending it.
    ///
    /// Answers the three questions [`consume`](Self::consume) answers — is this
    /// a pushed-request handle at all, does an unexpired and unconsumed row
    /// exist for it, and does that row belong to this client — with the same
    /// refusals, in the same order, and nothing else.
    ///
    /// # Why this exists, and why it returns nothing
    ///
    /// `/oauth2/authorize` sends an anonymous browser to a sign-in page before
    /// it can consume anything: the handle is single-use and is spent in the
    /// handler, after a principal exists. So a request presenting a
    /// `request_uri` that was already used, expired, or issued to a different
    /// client took a person through a full sign-in for a request that was dead
    /// before they started, and refused it afterwards. This lets the endpoint
    /// refuse first.
    ///
    /// It returns `()` rather than the pushed parameters **deliberately**. A
    /// caller holding them could authorize from a handle it never consumed, and
    /// the single-use guarantee is exactly the property that would lose. The
    /// authoritative decision stays in `consume`, inside the handler: a
    /// `request_uri` that passes here has not been authorized, has not been
    /// spent, and may still lose the race to a concurrent authorize request —
    /// which is the correct outcome, and the reason nothing here is cached,
    /// marked or carried forward.
    ///
    /// **This is an early refusal, never an authorization.**
    pub async fn peek(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        request_uri: &str,
    ) -> Result<(), OAuth2Error> {
        if !request_uri.starts_with(REQUEST_URI_PREFIX) {
            return Err(OAuth2Error::InvalidRequest(
                "request_uri is not a pushed authorization request URI".into(),
            ));
        }

        let stored = self
            .par_repo
            .find_unconsumed(tenant_id, &hash_request_uri(request_uri))
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?
            // Unknown, expired and already-consumed answer identically here for
            // the same reason they do in `consume`, and the wording is the same
            // constant so the two cannot come to describe the same state
            // differently depending on how far the request got.
            .ok_or_else(|| OAuth2Error::InvalidRequest(REQUEST_URI_GONE.into()))?;

        if stored.client_id != client_id {
            return Err(OAuth2Error::InvalidRequest(
                "request_uri was not issued to this client".into(),
            ));
        }

        Ok(())
    }
}

/// The single answer given for a `request_uri` that is unknown, expired or
/// already consumed.
///
/// A constant because two places need to agree on it: [`ParService::consume`]
/// produces it, and the authorization endpoint recognises it to tell a
/// **login-hop return leg** whose 60-second window closed (W3, plan §4.0 and
/// F10) apart from a client that sent nonsense. See [`is_request_uri_gone`].
pub const REQUEST_URI_GONE: &str = "request_uri is unknown, expired, or used";

/// Is this the "the pushed request is gone" refusal?
///
/// The recogniser lives here, next to the producer, so the two cannot drift:
/// a caller matching on the message itself would keep compiling after the
/// wording changed and would silently stop recognising the case.
///
/// Deliberately narrow. `request_uri was not issued to this client` is a
/// different failure — a client spending someone else's handle — and must keep
/// its own answer even on a return leg.
pub fn is_request_uri_gone(e: &OAuth2Error) -> bool {
    matches!(e, OAuth2Error::InvalidRequest(msg) if msg == REQUEST_URI_GONE)
}

// `has_inline_params` used to live here: it reported whether an authorize
// request carried `response_type`/`redirect_uri`/`scope`/`code_challenge`
// alongside a `request_uri`, and the authorization endpoint refused such a
// request as "the two forms do not mix".
//
// It is gone rather than merely unused, because the rule it encoded is not the
// one the specifications state. RFC 9126 §4 delegates the shape of the
// authorization request to RFC 9101, whose §5 says a client MAY duplicate the
// pushed parameters in the query string and whose §6.3 says the authorization
// server MUST only *use* the ones from the pushed request. Ignore, not refuse
// — and the endpoint reads every field from the pushed copy already, so
// ignoring is what it now does. See the comment at the `request_uri` branch in
// `axiam_api_rest::handlers::oauth2`.

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Doubles for `peek`
    // -----------------------------------------------------------------------
    //
    // `peek` asks the pushed-request repository one question and the CLIENT
    // repository none at all, and the doubles are shaped to prove it: every
    // method of `NoClients` panics, so a `peek` that grew a registration lookup
    // would fail these tests loudly rather than quietly doing a second read on
    // a refusal path.
    //
    // `OneRow` answers `find_unconsumed` from a single optional row and records
    // that `consume` was never called. That second half is the whole point —
    // the refusal this method exists for must not spend the handle it is
    // refusing, or the "present it again before the first authorization
    // completes" case stops working.
    mod doubles {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use axiam_core::error::{AxiamError, AxiamResult};
        use axiam_core::models::oauth2_client::{
            CreateOAuth2Client, CreatePushedAuthRequest, OAuth2Client, PushedAuthParams,
            PushedAuthRequest, UpdateOAuth2Client,
        };
        use axiam_core::repository::{
            OAuth2ClientRepository, PaginatedResult, Pagination, PushedAuthRequestRepository,
        };
        use chrono::{Duration, Utc};
        use uuid::Uuid;

        pub struct NoClients;

        impl OAuth2ClientRepository for NoClients {
            async fn create(&self, _: CreateOAuth2Client) -> AxiamResult<(OAuth2Client, String)> {
                unreachable!("peek must not touch the client registration")
            }
            async fn get_by_id(&self, _: Uuid, _: Uuid) -> AxiamResult<OAuth2Client> {
                unreachable!("peek must not touch the client registration")
            }
            async fn get_by_client_id(&self, _: Uuid, _: &str) -> AxiamResult<OAuth2Client> {
                unreachable!("peek must not touch the client registration")
            }
            async fn update(
                &self,
                _: Uuid,
                _: Uuid,
                _: UpdateOAuth2Client,
            ) -> AxiamResult<OAuth2Client> {
                unreachable!("peek must not touch the client registration")
            }
            async fn delete(&self, _: Uuid, _: Uuid) -> AxiamResult<()> {
                unreachable!("peek must not touch the client registration")
            }
            async fn list(
                &self,
                _: Uuid,
                _: Pagination,
            ) -> AxiamResult<PaginatedResult<OAuth2Client>> {
                unreachable!("peek must not touch the client registration")
            }
            async fn upgrade_client_secret_hash(
                &self,
                _: Uuid,
                _: &str,
                _: &str,
                _: &str,
            ) -> AxiamResult<bool> {
                unreachable!("peek must not touch the client registration")
            }
        }

        #[derive(Default)]
        pub struct OneRow {
            pub row: Option<PushedAuthRequest>,
            pub consumes: AtomicUsize,
            pub reads: AtomicUsize,
        }

        impl OneRow {
            /// A live, unconsumed, unexpired row for `client_id`.
            pub fn live(tenant_id: Uuid, client_id: &str) -> Self {
                Self {
                    row: Some(PushedAuthRequest {
                        id: Uuid::now_v7(),
                        tenant_id,
                        client_id: client_id.to_owned(),
                        request_uri_hash: String::new(),
                        params: PushedAuthParams {
                            response_type: "code".into(),
                            redirect_uri: "https://rp.example.test/cb".into(),
                            ..Default::default()
                        },
                        consumed: false,
                        expires_at: Utc::now() + Duration::seconds(60),
                        created_at: Utc::now(),
                    }),
                    ..Default::default()
                }
            }

            /// Nothing matched: unknown, expired, or already consumed. The
            /// repository cannot tell them apart and neither may the caller.
            pub fn gone() -> Self {
                Self::default()
            }
        }

        impl PushedAuthRequestRepository for OneRow {
            async fn create(&self, _: CreatePushedAuthRequest) -> AxiamResult<PushedAuthRequest> {
                unreachable!("peek does not create")
            }
            async fn consume(&self, _: Uuid, _: &str) -> AxiamResult<Option<PushedAuthRequest>> {
                self.consumes.fetch_add(1, Ordering::SeqCst);
                Err(AxiamError::Internal(
                    "peek must never consume the handle it is asked about".into(),
                ))
            }
            async fn find_unconsumed(
                &self,
                _: Uuid,
                _: &str,
            ) -> AxiamResult<Option<PushedAuthRequest>> {
                self.reads.fetch_add(1, Ordering::SeqCst);
                Ok(self.row.clone())
            }
            async fn cleanup_expired(&self, _: Uuid) -> AxiamResult<u64> {
                unreachable!("peek does not clean up")
            }
        }
    }

    use std::sync::atomic::Ordering;

    use doubles::{NoClients, OneRow};

    fn service(repo: OneRow) -> ParService<NoClients, OneRow> {
        ParService::new(NoClients, repo)
    }

    /// A live handle is spendable, and **stays** spendable.
    ///
    /// The second assertion is the one that matters. `peek` exists so that a
    /// dead `request_uri` can be refused before a person is asked to sign in
    /// for it; if it spent the handle on the way past, it would break the
    /// opposite case — the OIDF module
    /// `par-ensure-reused-request-uri-prior-to-auth-completion-succeeds`
    /// presents one `request_uri` twice before any authorization completes and
    /// requires the login page both times.
    #[tokio::test]
    async fn a_live_handle_passes_and_is_not_spent() {
        let tenant = Uuid::now_v7();
        let svc = service(OneRow::live(tenant, "client-a"));
        let uri = generate_request_uri();

        assert!(svc.peek(tenant, "client-a", &uri).await.is_ok());
        assert_eq!(
            svc.par_repo.consumes.load(Ordering::SeqCst),
            0,
            "peek must never call consume — the single-use decision belongs in \
             the handler, after a principal exists"
        );
        assert_eq!(svc.par_repo.reads.load(Ordering::SeqCst), 1);
    }

    /// Unknown, expired and already-used are one answer, and it is the same
    /// sentence `consume` produces — so a refusal does not change its wording
    /// depending on how far the request got.
    #[tokio::test]
    async fn a_gone_handle_is_refused_with_the_shared_sentence() {
        let tenant = Uuid::now_v7();
        let svc = service(OneRow::gone());
        let err = svc
            .peek(tenant, "client-a", &generate_request_uri())
            .await
            .expect_err("a handle that matched nothing must be refused");
        assert!(
            is_request_uri_gone(&err),
            "the recogniser the authorization endpoint matches on must accept \
             this refusal: {err}"
        );
        assert_eq!(svc.par_repo.consumes.load(Ordering::SeqCst), 0);
    }

    /// A handle belongs to the client that pushed it, and this is a **different**
    /// refusal from "gone" — deliberately, and the recogniser says so.
    #[tokio::test]
    async fn another_clients_handle_is_refused_by_name() {
        let tenant = Uuid::now_v7();
        let svc = service(OneRow::live(tenant, "client-a"));
        let err = svc
            .peek(tenant, "client-b", &generate_request_uri())
            .await
            .expect_err("a handle issued to another client must be refused");
        assert!(
            !is_request_uri_gone(&err),
            "a wrong-client refusal must keep its own answer: {err}"
        );
        assert!(
            err.to_string().contains("not issued to this client"),
            "{err}"
        );
        assert_eq!(svc.par_repo.consumes.load(Ordering::SeqCst), 0);
    }

    /// A value that is not a PAR handle is refused before the datastore is
    /// asked, exactly as `consume` refuses it — the authorization endpoint
    /// classifies a request object by reference separately and must keep the
    /// OIDC code that goes with it.
    #[tokio::test]
    async fn a_value_without_the_urn_prefix_never_reaches_the_datastore() {
        let tenant = Uuid::now_v7();
        let svc = service(OneRow::live(tenant, "client-a"));
        let err = svc
            .peek(tenant, "client-a", "https://attacker.example/request.jwt")
            .await
            .expect_err("a non-PAR request_uri is not a handle");
        assert!(
            err.to_string()
                .contains("not a pushed authorization request URI"),
            "{err}"
        );
        assert_eq!(
            svc.par_repo.reads.load(Ordering::SeqCst),
            0,
            "the prefix check must come first, as it does in consume"
        );
    }

    #[test]
    fn generated_request_uri_carries_the_rfc_prefix() {
        assert!(generate_request_uri().starts_with(REQUEST_URI_PREFIX));
    }

    #[test]
    fn generated_request_uris_are_distinct() {
        let a = generate_request_uri();
        let b = generate_request_uri();
        assert_ne!(a, b, "request_uri must be CSPRNG, not a counter");
    }

    #[test]
    fn hash_ignores_the_prefix() {
        // The prefix is constant, so hashing it adds nothing; what matters is
        // that a caller passing the full URI and one passing the bare
        // component resolve to the same stored row.
        let uri = generate_request_uri();
        let bare = uri.strip_prefix(REQUEST_URI_PREFIX).unwrap();
        assert_eq!(hash_request_uri(&uri), hash_request_uri(bare));
    }

    #[test]
    fn hash_is_not_the_plaintext() {
        let uri = generate_request_uri();
        let h = hash_request_uri(&uri);
        assert!(!uri.contains(&h));
        assert_eq!(h.len(), 64, "hex-encoded SHA-256");
    }

    #[test]
    fn the_fapi_opaque_cap_admits_entropy_and_refuses_the_suite_probes() {
        // The boundary is not a taste question, so it is asserted rather than
        // commented. Below: what a conformant client actually sends — 32 bytes
        // base64url is 43 characters, and doubling the entropy is still 86.
        // Above: the two values the OpenID Foundation's FAPI 2.0 suite pushes
        // and requires to be refused. A future edit that "relaxes" the cap
        // past either of them breaks certification, and this fails to compile
        // rather than waiting for a 56-module plan to say so.
        const {
            assert!(MAX_FAPI_OPAQUE_PARAM_CHARS >= 86);
            assert!(MAX_FAPI_OPAQUE_PARAM_CHARS < 384); // -with-long-nonce
            assert!(MAX_FAPI_OPAQUE_PARAM_CHARS < 1000); // -with-long-state
        }
    }

    #[test]
    fn lifetime_is_short_enough_to_bound_replay() {
        // Guards the constant against a well-meaning future edit: RFC 9126
        // §2.2 wants seconds-to-minutes, and the window only has to cover one
        // browser redirect. In a `const` block so a bad edit fails to compile
        // rather than waiting for someone to run the suite.
        const {
            assert!(REQUEST_URI_LIFETIME_SECS <= 120);
            assert!(REQUEST_URI_LIFETIME_SECS >= 30);
        }
    }
}

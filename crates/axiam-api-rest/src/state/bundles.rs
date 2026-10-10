//! `AppState`'s cohesive sub-states (F3).
//!
//! # Why these exist
//!
//! `AppState` carried **75 public fields**, nearly all concrete
//! `Surreal*Repository<C>` values, and every handler received all of them
//! regardless of what it used. That is a god object by the usual definition,
//! and it had the usual consequences: `state.rs` referenced `axiam_db` in
//! nineteen places, `C: Connection + Clone` propagated through every handler
//! signature in the crate, and twenty-five `#[allow(clippy::too_many_arguments)]`
//! sites sat downstream of the same pressure.
//!
//! Forty-six of those fields are used by **one** handler module each. Grouping
//! them by what they are *for* takes the root from 75 members to 36 and gives
//! each group a name, a docstring and a boundary.
//!
//! # Why not `Arc<dyn Repository>`
//!
//! The obvious "fix" for a struct full of concrete types is to box them behind
//! trait objects. That would put vtable dispatch on the authorization hot path,
//! which is the one place this system cannot afford it -- `check_access` is
//! what a service mesh calls on every request.
//!
//! This is a **field-grouping change, not a dispatch change**. Every type is
//! what it was, monomorphisation is what it was, and the generated code is what
//! it was. What changes is who can see what.
//!
//! # `use super::*`
//!
//! Deliberate. These structs and [`super::AppState`] are two halves of one
//! dependency-injection container and name the same forty-odd types; a
//! duplicated import list would be a second place to update every time a
//! repository is added, for no reader's benefit.

use super::*;

/// Certificate authority, X.509 issuance, PGP and device certificate auth.
///
/// Everything behind `/api/v1/ca-certificates`, `/api/v1/certificates`,
/// `/api/v1/pgp-keys`, the revocation lists under `/pki/v1` and the mTLS
/// device-auth path. Grouped because they share
/// one subject -- key material this deployment issues or verifies -- and because
/// nothing outside those four handlers has any business reaching a signing
/// service.
#[derive(Clone)]
pub struct PkiState<C: Connection + Clone> {
    pub ca_service: CaServiceT<C>,
    pub cert_service: CertServiceT<C>,
    /// Each issuing CA's certificate revocation list, signed on request and
    /// cached (#565). Behind the unauthenticated `GET /pki/v1/…/crl`.
    pub crl_service: CrlServiceT<C>,
    pub cert_repo: SurrealCertificateRepository<C>,
    /// The CA rows themselves, for the handful of operations that are about a
    /// CA record rather than about signing with it — today, toggling
    /// `mtls_trust_anchor`. `CaService` owns issuance; a flag that changes what
    /// the TLS listener trusts is not issuance and does not belong behind it.
    pub ca_cert_repo: axiam_db::SurrealCaCertificateRepository<C>,
    pub pgp_service: PgpServiceT<C>,
    pub device_auth_service: DeviceAuthServiceT<C>,
    /// Applies the current mTLS trust anchor set to the live TLS listener.
    ///
    /// `None` when nothing registered one: a plaintext deployment, or a test
    /// harness. Toggling an anchor then updates the row and reports that a
    /// restart is needed, which is exactly what it used to do.
    ///
    /// The implementation lives in `axiam-server` because it is the crate that
    /// owns the listener; this is the seam that lets a handler reach it without
    /// the layering pointing outward.
    pub trust_anchor_reloader: Option<std::sync::Arc<dyn crate::TrustAnchorReloader>>,
}

/// WebAuthn ceremonies, attestation policy and FIDO MDS metadata.
///
/// The registration/authentication ceremonies, the tenant attestation policy
/// they are evaluated against, and the FIDO MDS3 metadata that policy reads.
/// `attestation_ca_cache` and `attestation_metadata_source` sit here rather than
/// in [`PkiState`] because they exist to answer "is this authenticator's
/// attestation acceptable", which is a WebAuthn question, not a PKI one.
#[derive(Clone)]
pub struct WebauthnState<C: Connection + Clone> {
    pub webauthn_service: WebauthnServiceT<C>,
    /// X3 wave 3: direct access to WebAuthn credentials for the tenant-wide
    /// compliance report (D9) — `webauthn_service` only exposes per-user
    /// ceremony operations, not a tenant-wide listing.
    pub webauthn_credential_repo: SurrealWebauthnCredentialRepository<C>,
    /// X3 (D5): tenant WebAuthn attestation policy. Resolved by REST
    /// handlers on every registration ceremony start/finish (an absent row
    /// means `WebauthnAttestationPolicy::default()`, i.e. today's `mode:
    /// none` behavior) and by the policy admin/compliance-report endpoints.
    pub webauthn_attestation_policy_repo: SurrealWebauthnAttestationPolicyRepository<C>,
    /// X3 (D10): server-global FIDO MDS3 metadata storage, read by the
    /// `GET /api/v1/mds/status` / `POST /api/v1/mds/refresh` admin endpoints.
    pub mds_repo: SurrealMdsRepository<C>,
    /// X3 (W2-D4): the small, data-only view over `mds_repo` that
    /// `axiam-auth`'s attestation enforcement and compliance evaluation
    /// consume, keeping `axiam-auth` free of a hard `axiam-db` dependency.
    pub attestation_metadata_source: MdsAttestationMetadataSource<SurrealMdsRepository<C>>,
    /// X3 (W2-D3): process-wide cache of built `AttestationCaList`s.
    /// `Arc`-shared (mirrors `tenant_org_cache`) so every worker/request
    /// sees the same cache, and so it can be invalidated from the MDS
    /// refresh and attestation-policy-update endpoints (and the background
    /// MDS refresh job in `axiam-server`) without threading a second
    /// `web::Data` registration through every call site.
    pub attestation_ca_cache: Arc<AttestationCaCache>,
    /// X3 (D10): FIDO MDS3 ingestion configuration (`mds_enabled`,
    /// `mds_blob_url`/`mds_blob_path`, `mds_leaf_dns`). `POST
    /// /api/v1/mds/refresh` reads this to decide whether ingestion is
    /// enabled at all and which source to fetch from — `encryption_key`
    /// here is unused by the REST layer (PKI-service construction in
    /// `axiam-server` keeps its own copy for that).
    pub pki_config: PkiConfig,
}

/// Consent records, account deletion, data export and erasure proofs.
///
/// The Art. 7 / Art. 17 / Art. 20 surfaces. A tight, self-contained group:
/// these four repositories are read by `handlers/gdpr.rs` and the cleanup job and
/// by nothing else, which is exactly the property that makes them a bundle rather
/// than four more fields on the root.
#[derive(Clone)]
pub struct GdprState<C: Connection + Clone> {
    pub consent_repo: SurrealConsentRepository<C>,
    pub account_deletion_repo: SurrealAccountDeletionRepository<C>,
    pub export_job_repo: SurrealExportJobRepository<C>,
    pub erasure_proof_repo: SurrealErasureProofRepository<C>,
}

/// Outbound mail, provider configuration and the two token-mail services.
///
/// `email_encryption_key` is `None` when `AXIAM__AUTH__EMAIL_ENCRYPTION_KEY` is
/// unset, and that absence is what makes the email-config routes fail closed. It
/// lives beside the repository it protects rather than several screens away from
/// it, so the pairing is visible at the point of use.
#[derive(Clone)]
pub struct MailState<C: Connection + Clone> {
    pub mail_outbound_publisher: Arc<dyn DynMailPublisher>,
    /// D-02: `None` when `AXIAM__AUTH__EMAIL_ENCRYPTION_KEY` is unset — the six
    /// email-config routes fail closed rather than silently using a
    /// constant/zero key.
    pub email_config_repo: Option<SurrealEmailConfigRepository<C>>,
    /// D-17: AES-256-GCM key for email-provider secrets. Absent (`None`)
    /// means email-config admin endpoints and mail delivery stay disabled
    /// (fail-closed) — mirrors the pre-existing behavior exactly.
    pub email_encryption_key: Option<[u8; 32]>,
    pub email_verification_service: EmailVerificationServiceT<C>,

    // -- QUAL-07: hoisted per-request service constructions (13 call sites) --
    pub password_reset_service: PasswordResetServiceT<C>,
}

/// Reactors, webhooks and notification rules — everything AXIAM emits outward.
///
/// The three outbound-notification mechanisms share a lifecycle: a domain
/// event happens, a routing table decides who hears about it, and delivery is
/// best-effort and must never fail the request that produced it. Keeping them
/// together keeps that shared property in one place.
#[derive(Clone)]
pub struct EventsState<C: Connection + Clone> {
    pub reactor_repo: SurrealReactorRepository<C>,
    /// X1 — the interceptor chain the `user.pre_create`, `user.pre_update` and
    /// `grant.pre_assign` handlers call.
    ///
    /// `axiam-auth` and `axiam-oauth2` hold their own clone of the same gate
    /// (they own the `login.post_auth` and `token.pre_issue` sites), so all
    /// five hooks share one routing table, one per-tenant concurrency bound and
    /// one audit sink. A deployment without AMQP holds
    /// [`axiam_core::models::reactor::NoopReactorGate`] here — never `None`,
    /// because a call site that branches on the feature is a call site where
    /// the two builds can drift.
    pub reactor_gate: axiam_core::models::reactor::SharedReactorGate,
    /// X1 — invalidates the gate's routing table when a reactor registration
    /// changes, so the change is live on this replica immediately rather than
    /// at the end of the TTL.
    ///
    /// A closure rather than the routing table itself because the table is
    /// generic over its source, and `AppState<C>` is already generic over one
    /// parameter too many. `None` when no gate is composed.
    pub reactor_routing_invalidator: Option<Arc<dyn Fn(uuid::Uuid) + Send + Sync>>,
    pub webhook_repo: SurrealWebhookRepository<C>,
    pub webhook_delivery: WebhookDeliveryServiceT<C>,
    /// The publisher [`AppState::emit_webhook`] dispatches domain events
    /// through (CQ-B22): the core `OutboundPublisher` port, so the durable AMQP
    /// queue in the full profile and the in-process dispatcher in the minimal
    /// one (G-8, D-59) are interchangeable here. `None` in tests —
    /// `emit_webhook` becomes a no-op rather than failing the originating
    /// request (webhook delivery is a best-effort side effect).
    pub webhook_publisher: Option<Arc<dyn axiam_core::outbound::OutboundPublisher>>,
    pub notification_rule_repo: SurrealNotificationRuleRepository<C>,
}

/// The OAuth2 authorization server and OIDC provider.
///
/// The widest bundle, and the one that most justifies the split: twelve
/// fields that only `handlers/oauth2.rs`, `uma.rs`, `token_exchange.rs` and
/// `backchannel_logout.rs` touch, previously visible to all twenty-nine handler
/// modules.
#[derive(Clone)]
pub struct OAuth2State<C: Connection + Clone> {
    pub authorize_service: AuthorizeServiceT<C>,
    pub token_service: TokenServiceT<C>,
    /// B2 — device authorization grant (RFC 8628).
    pub device_authorization_service: DeviceAuthorizationServiceT<C>,
    /// G-7 — CIBA: `bc-authorize`, the pending-request store and the approval
    /// API.
    pub ciba_service: CibaServiceT<C>,
    /// G-7 — where a stored CIBA request reaches its user (T23.7.2 wires
    /// e-mail; until then, nobody is notified and the request waits on the
    /// identity pages). Called detached, after the request is stored.
    pub ciba_notifier: Arc<dyn axiam_core::models::ciba::CibaUserNotifier>,
    /// B3 — token exchange (RFC 8693).
    pub token_exchange_service: TokenExchangeServiceT<C>,
    /// B5 — pushed authorization requests (RFC 9126).
    pub par_service: ParServiceT<C>,
    /// X2 — UMA 2.0 permission tickets.
    ///
    /// The repository rather than an assembled `UmaService`, because the
    /// service also needs the [`crate::authz::AuthzChecker`], which is a
    /// separate `web::Data` and not part of this state. Handlers assemble the
    /// service with [`AppState::uma_service`].
    pub permission_ticket_repo: SurrealPermissionTicketRepository<C>,
    /// X2 — deployment ceiling on RPT lifetime, in seconds. The effective
    /// lifetime is the minimum of this, the protocol default (300 s), and the
    /// subject token's own remaining life.
    pub rpt_max_lifetime_secs: i64,
    /// B5 — which clients joined which session, for the back-channel logout
    /// fan-out.
    pub session_client_repo: SurrealSessionClientRepository<C>,
    pub device_grant_repo: SurrealDeviceGrantRepository<C>,
    /// X5.1 — single-use `jti` store for RFC 7523 client assertions and
    /// RFC 9449 DPoP proofs. Decides replay by a `UNIQUE` index violation
    /// rather than by reading first; see the repository's module docs.
    pub proof_replay_repo: SurrealProofReplayRepository<C>,
    /// B3: in-process cache + ETag for AXIAM's OWN `GET /oauth2/jwks`
    /// response (the signing keys AXIAM serves to relying parties).
    /// Constructed once at startup and shared via this `Arc` so all workers
    /// hit the same cache instead of each maintaining its own.
    pub oauth2_jwks_cache: Arc<Oauth2JwksCache>,
    /// B3: `Cache-Control` max-age (and header rendering) for the
    /// `GET /oauth2/jwks` response. Configured via
    /// `AXIAM__OAUTH2__JWKS_CACHE_MAX_AGE_SECS` (default 300s).
    pub oauth2_jwks_cache_config: Oauth2JwksCacheConfig,
    /// T21.5: the client-metadata-document cache — REMOTE documents fetched
    /// because a `client_id` was a URL. Unrelated to either JWKS cache above,
    /// and a third distinct thing: `jwks_cache` holds an identity provider's
    /// keys, `oauth2_jwks_cache` holds AXIAM's own, and this holds a client's
    /// *registration*.
    ///
    /// **One instance per process**, cloned (an `Arc` clone) into every actix
    /// worker, for the reason `shared_rate_limit` states: N per-worker caches
    /// would be N times the outbound fetches for the same document, which is
    /// the amplification `cimd.min_cache_secs` exists to bound.
    pub cimd_cache: ClientMetadataCache,
}

/// Inbound SAML and OIDC federation.
///
/// Where AXIAM is the *relying party* rather than the provider --
/// `OAuth2State` is the other direction. `assertion_replay_repo` belongs here and
/// not with the other replay guards because what it guards is a SAML assertion,
/// and the handler that consumes one is the only caller.
#[derive(Clone)]
pub struct FederationState<C: Connection + Clone> {
    pub federation_config_repo: SurrealFederationConfigRepository<C>,
    pub federation_link_repo: SurrealFederationLinkRepository<C>,
    pub federation_login_state_repo: SurrealFederationLoginStateRepository<C>,
    /// Single-use, 60-second codes that turn a cross-site SSO return (SAML,
    /// Apple's `response_mode=form_post`) into a same-site session issuance
    /// without weakening `SameSite=Strict` on the session cookies. Here rather
    /// than with the session repositories because the only thing that mints or
    /// redeems one is a federation callback.
    pub sso_handoff_code_repo: SurrealSsoHandoffCodeRepository<C>,
    pub assertion_replay_repo: SurrealAssertionReplayRepository<C>,
    /// `None` when `AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY` is unset — the
    /// OIDC federation encryption key is baked into `OidcFederationService`
    /// at construction, so absence is resolved once at startup rather than
    /// per-request (identical fail-closed error at the 4 call sites).
    pub oidc_federation_service: Option<OidcFederationServiceT<C>>,
    /// Constructed unconditionally (SamlFederationService::new needs no
    /// encryption key) — but the FIELD itself stays `#[cfg(feature = "saml")]`
    /// gated. Why: `axiam_federation::saml` only exists when
    /// axiam-federation's OWN `saml` Cargo feature is on, and
    /// axiam-api-rest's `saml` feature intentionally forwards to it so
    /// `cargo build -p axiam-server --no-default-features` can still build
    /// without the `samael`/`libxml2` dependency chain (documented escape
    /// hatch for hosts with an incompatible system libxml2 — see
    /// `axiam-server/src/main.rs`'s `--dump-openapi` doc comment and
    /// `axiam-api-rest/Cargo.toml`). Un-gating this field would force
    /// `axiam-federation/saml` on unconditionally and break that hatch.
    #[cfg(feature = "saml")]
    pub saml_federation_service: SamlFederationServiceT<C>,
}

/// The LDAP / Active Directory identity source's management surface (G-3,
/// T23.3.8): the per-tenant configuration, the sync job's state row, and the
/// connector's address guard.
///
/// The configuration repository carries the optional `directory_encryption_key`
/// (D-15): without it a write that carries a bind secret is `503`, while reads,
/// `DELETE` and the sync status still answer. The client is the **one** the
/// sign-in path and the sync job use (the composition root shares it), so the
/// address policy a write is checked against is the policy every connection is
/// checked against.
#[derive(Clone)]
pub struct DirectoryState<C: Connection + Clone> {
    /// One row per tenant; the bind secret sealed in it.
    pub config_repo: axiam_db::SurrealDirectoryConfigRepository<C>,
    /// What the sync job remembers about a tenant (deleted with the config).
    pub sync_state_repo: axiam_db::SurrealDirectorySyncStateRepository<C>,
    /// The connector, for its address guard: `client.guard(url)` resolves the
    /// host and judges every address under the deployment's policy.
    pub client: Arc<axiam_directory::DirectoryClient>,
}

/// The SAML 2.0 identity provider (G-2, T23.2.3, T23.2.5): the service-provider
/// registry, the pending `AuthnRequest`s held across the login hop, the
/// tenant's signing credential, and the issuer.
///
/// **Not behind `saml`** — contract §29's registry and credential routes are
/// compiled into every build (D-42), and they need only the plain-data pieces
/// below. The one member that exists only in a SAML build is the **issuer**, which
/// is `axiam_federation::saml_idp` (see [`FederationState::saml_federation_service`]
/// for why that gate is load-bearing): a build without `saml` mounts none of the
/// browser routes that read it.
#[derive(Clone)]
pub struct SamlIdpState<C: Connection + Clone> {
    /// The tenant's registered service providers (T23.2.1).
    pub sp_repo: axiam_db::SurrealSamlServiceProviderRepository<C>,
    /// `AuthnRequest`s between the SSO endpoint's two legs (schema v73).
    pub pending_repo: axiam_db::SurrealPendingSamlRequestRepository<C>,
    /// Which service providers hold which session, with the `NameID` and the
    /// per-SP `SessionIndex` each was given (schema v76, D-37). Written by the
    /// SSO endpoint's second leg before it signs; read by single logout.
    pub participant_repo: axiam_db::SurrealSamlSpSessionRepository<C>,
    /// Logout runs: the replay guard of a `LogoutRequest` and the state of the
    /// front-channel chain (schema v76, D-38, D-39).
    pub logout_run_repo: axiam_db::SurrealSamlLogoutRunRepository<C>,
    /// The tenant's signing credential, unsealed per issuance (D-21).
    pub credential_service: SamlIdpCredentialServiceT<C>,
    /// The deployment's issuer: the root issuer every IdP entity id is built
    /// on, and the pairwise-identifier key (D-22). One per process. Behind
    /// `saml`, like the routes that issue with it.
    #[cfg(feature = "saml")]
    pub issuer: Arc<axiam_federation::saml_idp::SamlIdpIssuer>,
}

/// The Shared Signals Framework transmitter (G-5, T23.5.2, T23.5.3): the
/// stream registry, the poll buffer, the outbox events go to, and the emitter
/// the change sites call.
///
/// In every build; it reads nothing behind a feature.
#[derive(Clone)]
pub struct SsfState<C: Connection + Clone> {
    /// The tenant's registered streams; seals the push `Authorization` header
    /// under `pki_encryption_key`.
    pub stream_repo: axiam_db::SurrealSsfStreamRepository<C>,
    /// The per-stream bounded buffer: what a poll stream's receiver reads and a
    /// paused stream holds (D-48).
    pub buffer_repo: axiam_db::SurrealSsfEventBufferRepository<C>,
    /// What the honour lane remembers about a step-up it sent a user to perform
    /// (D-53 (1)): written at the Interact leg, consumed once by the return leg.
    pub step_up_repo: axiam_db::SurrealSsfStepUpRepository<C>,
    /// Where produced events go (D-48): push enqueue, the poll buffer, or
    /// nothing for a disabled stream. `None` when delivery is not wired (a
    /// harness that does not test it) — the verification endpoint then answers
    /// `503`. Set through [`SsfState::bind_outbox`], which also wires the
    /// emitter.
    pub outbox: Option<Arc<dyn axiam_core::models::ssf::SsfOutbox>>,
    /// The one emitter every change site calls (D-52). A no-op until an outbox
    /// is bound.
    pub emitter: crate::ssf_emitter::SsfEmitter<C>,
    /// The session repository's `session-revoked` port, bound to [`Self::emitter`]
    /// (D-52). A `Late` handle because the repository is built first.
    pub session_sink:
        Arc<axiam_core::models::ssf::Late<dyn axiam_core::models::ssf::SessionRevocationSink>>,
    /// The directory sync's `account-disabled` port, bound to [`Self::emitter`].
    pub account_sink:
        Arc<axiam_core::models::ssf::Late<dyn axiam_core::models::ssf::SsfSystemAccountSink>>,
    /// The long polls currently waiting, one per stream (D-53 (11)).
    pub poll_waiters: Arc<PollWaiters>,
    /// D-55: SSF requires per-tenant issuers in a deployment of more than one
    /// tenant. Asked where events are produced, where a SET is signed and at
    /// discovery; shared with the emitter and the push deliverer.
    pub gate: Arc<axiam_oauth2::ssf::SsfIssuerGate>,
}

/// The streams that have a long poll waiting **on this instance**.
///
/// A long poll holds a request open for up to thirty seconds; a receiver that
/// opens many on one stream (a retry loop with no backoff, a bug) would hold as
/// many connections for no benefit, since RFC 8936 has one receiver draining one
/// stream in order. At most one waits per stream; a second answers at once.
/// Per instance on purpose: an exact cross-instance count would need shared
/// state for a bound that only has to be small.
#[derive(Debug, Default)]
pub struct PollWaiters {
    waiting: std::sync::Mutex<std::collections::HashSet<uuid::Uuid>>,
}

/// Holds a stream's wait slot; releases it when dropped — including when the
/// request is cancelled because the receiver hung up.
#[derive(Debug)]
pub struct PollWaitGuard {
    owner: Arc<PollWaiters>,
    stream_id: uuid::Uuid,
}

impl PollWaiters {
    /// Take `stream_id`'s wait slot, or `None` when a long poll already holds it.
    #[must_use]
    pub fn try_enter(self: &Arc<Self>, stream_id: uuid::Uuid) -> Option<PollWaitGuard> {
        let mut waiting = self.waiting.lock().unwrap_or_else(|e| e.into_inner());
        waiting.insert(stream_id).then(|| PollWaitGuard {
            owner: Arc::clone(self),
            stream_id,
        })
    }

    /// How many streams have a long poll waiting.
    #[must_use]
    pub fn waiting(&self) -> usize {
        self.waiting.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl Drop for PollWaitGuard {
    fn drop(&mut self) {
        self.owner
            .waiting
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.stream_id);
    }
}

impl<C: Connection + Clone> SsfState<C> {
    /// Wire the outbox: producers (verification, a status change) and the
    /// emitter — and through it both ports — send events to it. The emitter
    /// keeps the first outbox it is given.
    pub fn bind_outbox(&mut self, outbox: Arc<dyn axiam_core::models::ssf::SsfOutbox>) {
        self.emitter.bind_outbox(outbox.clone());
        self.outbox = Some(outbox);
    }
}

#[cfg(test)]
mod poll_waiter_tests {
    use super::*;

    #[test]
    fn one_slot_per_stream_released_on_drop() {
        let waiters = Arc::new(PollWaiters::default());
        let (a, b) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let first = waiters.try_enter(a).expect("the first takes the slot");
        assert!(waiters.try_enter(a).is_none(), "the second finds it taken");
        assert!(waiters.try_enter(b).is_some(), "another stream is free");
        assert_eq!(waiters.waiting(), 1, "b's guard was a temporary");
        drop(first);
        assert!(waiters.try_enter(a).is_some(), "released on drop");
        assert_eq!(waiters.waiting(), 0);
    }
}

/// What starting an on-demand SCIM reconciliation came to (G-6, T23.6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScimReconcileStart {
    /// The caller took the claim and the run is under way (`202`).
    Started,
    /// A run holds the claim, or ran within the on-demand window (`409`).
    AlreadyClaimed,
    /// The target is disabled: it receives nothing, so there is nothing to
    /// reconcile and no claim was taken (`409`).
    TargetDisabled,
}

/// The management API's way to start a reconciliation. A port, because the
/// deliverer that makes the run lives in `axiam-scim`, which sits **above**
/// this crate (layer 7) and so cannot be named here; `axiam-scim` implements
/// it (`ReconcileLauncher`) and the composition root binds it.
pub trait ScimReconcileTrigger: Send + Sync {
    /// Take the target's reconciliation claim and, when it is taken, make the
    /// run in the background. Answers as soon as the claim is decided.
    ///
    /// # Errors
    ///
    /// `NotFound` when the target does not exist in the tenant; any other
    /// failure of the datastore while claiming.
    fn start<'a>(
        &'a self,
        tenant_id: uuid::Uuid,
        target_id: uuid::Uuid,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<ScimReconcileStart, axiam_core::error::AxiamError>,
                > + Send
                + 'a,
        >,
    >;
}

/// The outbound SCIM target registry (G-6, T23.6.4): the repository the
/// management routes write — which seals the credential under
/// `pki_encryption_key` — the delivery state they project, and the
/// reconciliation trigger.
///
/// In every build; it reads nothing behind a feature.
#[derive(Clone)]
pub struct ScimTargetsState<C: Connection + Clone> {
    /// The tenant's registered targets; seals the credential.
    pub target_repo: axiam_db::SurrealScimTargetRepository<C>,
    /// Per-target delivery state, projected by `GET`.
    pub state_repo: axiam_db::SurrealScimTargetStateRepository<C>,
    /// Starts an on-demand reconciliation, and the one a newly enabled target
    /// begins with. `None` when delivery is not wired (a harness that does not
    /// test it): *reconcile now* then answers `503`, and enabling a target
    /// starts nothing.
    pub reconcile: Option<Arc<dyn ScimReconcileTrigger>>,
}

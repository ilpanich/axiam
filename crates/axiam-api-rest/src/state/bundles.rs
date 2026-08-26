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
/// `/api/v1/pgp-keys` and the mTLS device-auth path. Grouped because they share
/// one subject -- key material this deployment issues or verifies -- and because
/// nothing outside those four handlers has any business reaching a signing
/// service.
#[derive(Clone)]
pub struct PkiState<C: Connection + Clone> {
    pub ca_service: CaServiceT<C>,
    pub cert_service: CertServiceT<C>,
    pub cert_repo: SurrealCertificateRepository<C>,
    /// The CA rows themselves, for the handful of operations that are about a
    /// CA record rather than about signing with it — today, toggling
    /// `mtls_trust_anchor`. `CaService` owns issuance; a flag that changes what
    /// the TLS listener trusts is not issuance and does not belong behind it.
    pub ca_cert_repo: axiam_db::SurrealCaCertificateRepository<C>,
    pub pgp_service: PgpServiceT<C>,
    pub device_auth_service: DeviceAuthServiceT<C>,
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
/// `email_encryption_key` is `None` when `AXIAM__EMAIL_ENCRYPTION_KEY` is
/// unset, and that absence is what makes the email-config routes fail closed. It
/// lives beside the repository it protects rather than several screens away from
/// it, so the pairing is visible at the point of use.
#[derive(Clone)]
pub struct MailState<C: Connection + Clone> {
    pub mail_outbound_publisher: Arc<dyn DynMailPublisher>,
    /// D-02: `None` when `AXIAM__EMAIL_ENCRYPTION_KEY` is unset — the six
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
    /// AMQP publisher used by [`AppState::emit_webhook`] to dispatch domain
    /// events onto the durable webhook queue (CQ-B22). `None` in tests and when
    /// AMQP is unavailable — `emit_webhook` becomes a no-op rather than failing
    /// the originating request (webhook delivery is a best-effort side effect).
    pub webhook_publisher: Option<Arc<axiam_amqp::WebhookPublisher>>,
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

//! Reactor domain model (X1) — AMQP-native extension actors.
//!
//! A **Reactor** is an external process, written in any SDK language, that
//! subscribes to well-defined hook events on the AMQP bus and answers back
//! (veto / mutate / observe) under a signed, timeout-bounded,
//! field-allow-listed protocol.
//!
//! # Why this shape
//!
//! Zitadel Actions embed user JavaScript in the IAM process; Keycloak SPIs
//! load user JARs into the JVM. Both put third-party code inside the security
//! kernel — a bug in an extension is a bug in the authorization server. AXIAM
//! keeps the kernel closed: a reactor is a *separate process* that can only
//! influence the server through a narrow, signed, allow-listed reply schema,
//! and whose failure (timeout, crash, bad signature) is a case the server
//! already has a policy for.
//!
//! # The registry is here, not in `axiam-amqp`
//!
//! [`EVENT_REGISTRY`] is pure data: which hooks exist, what each may mutate,
//! and what happens when its reactor does not answer. Three crates need it and
//! none of them should need the broker — the REST layer validates a
//! registration's `events` against it, the dispatcher validates a reply's
//! `patch` against it, and `axiam-auth`/`axiam-oauth2` call through
//! [`ReactorGate`] without knowing AMQP exists at all. Putting the registry in
//! the broker crate would make the trait's whole reason for existing moot.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Hook class and the event registry
// ---------------------------------------------------------------------------

/// How a reactor participates in an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ReactorMode {
    /// Synchronous request/response: the server waits, and the reply can veto
    /// or mutate the operation within the event's allow-list.
    Intercept,
    /// Asynchronous fire-and-forget observation. The server never waits and
    /// never reads a reply, so a listener cannot affect any outcome.
    Listen,
}

impl ReactorMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Intercept => "intercept",
            Self::Listen => "listen",
        }
    }

    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "intercept" => Some(Self::Intercept),
            "listen" => Some(Self::Listen),
            _ => None,
        }
    }
}

/// What the server does when an interceptor does not produce a usable reply —
/// timeout, transport failure, bad signature, stale nonce, or a patch the
/// allow-list rejects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FailurePolicy {
    /// Deny the underlying operation. The safe default for veto-capable
    /// security hooks: a fraud check that cannot be reached has not passed.
    FailClosed,
    /// Proceed as if the reactor had replied `allow`. Appropriate only where
    /// the reactor *adds* something optional — an enrichment claim whose
    /// absence degrades a feature rather than weakening a decision.
    FailOpen,
}

impl FailurePolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::FailOpen => "fail_open",
        }
    }

    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "fail_closed" => Some(Self::FailClosed),
            "fail_open" => Some(Self::FailOpen),
            _ => None,
        }
    }
}

/// One hookable event: its name, what a reactor may change, and what happens
/// when the reactor does not answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReactorEventSpec {
    /// Wire name, and the second half of the routing key
    /// (`<tenant_id>.<event>`).
    pub name: &'static str,
    /// Whether an interceptor may register for this event at all. `false`
    /// means listen-only.
    pub interceptable: bool,
    /// Whether an interceptor's reply may carry a `patch`. A veto-only hook
    /// (`grant.pre_assign`) can refuse but cannot rewrite.
    pub mutable: bool,
    /// Exact field names a `patch` may set, or the single-element prefix form
    /// documented on [`ReactorEventSpec::patch_field_allowed`].
    pub mutable_fields: &'static [&'static str],
    /// The `failure_policy` a registration gets when it does not pick one.
    pub default_failure_policy: FailurePolicy,
    /// One line, surfaced in the admin UI and the generated docs.
    pub description: &'static str,
}

impl ReactorEventSpec {
    /// Whether `field` may appear in a `patch` for this event.
    ///
    /// An entry ending in `.` is a **namespace prefix**: `"ext."` admits
    /// `ext.department` and `ext.a.b`, and admits nothing else. That is the
    /// whole of the `token.pre_issue` rule — a reactor writes into the `ext.`
    /// namespace and can never reach `sub`, `aud`, `exp` or a scope claim,
    /// because none of them start with `ext.`.
    ///
    /// A bare `"ext."` itself is refused: it names the namespace, not a claim,
    /// and accepting it would let a reactor set a claim literally called
    /// `ext.`.
    pub fn patch_field_allowed(&self, field: &str) -> bool {
        if !self.mutable {
            return false;
        }
        self.mutable_fields.iter().any(|allowed| {
            if let Some(prefix) = allowed.strip_suffix('.') {
                field.len() > prefix.len() + 1 && field.starts_with(allowed)
            } else {
                field == *allowed
            }
        })
    }
}

/// Every hookable event. **The single source of truth** — the REST validator,
/// the dispatcher's patch check, the SDK contract chapter and the admin UI all
/// read this list rather than restating it.
///
/// # What is deliberately absent
///
/// `authz.check` and every other hot-path decision. A reactor round-trip is
/// milliseconds; the check path's budget is microseconds, and the benchmark
/// matrix runs it at 1 000–12 000 req/s. Hooking it would not be a slower
/// check, it would be a different product. Anyone who needs per-request
/// external input there should write a deny grant, not a reactor.
pub const EVENT_REGISTRY: &[ReactorEventSpec] = &[
    ReactorEventSpec {
        name: "token.pre_issue",
        interceptable: true,
        mutable: true,
        // Custom claims only. The standard set (iss, sub, aud, exp, iat, nbf,
        // jti, scope) is immutable to reactors: a hook that can rewrite `sub`
        // is a hook that can mint a token for anyone.
        mutable_fields: &["ext."],
        // The mutation is optional enrichment, so its absence degrades a
        // feature rather than a decision. A veto reactor registered on the
        // same event overrides this by setting fail_closed explicitly.
        default_failure_policy: FailurePolicy::FailOpen,
        description: "Enrich or veto token issuance. May add claims under `ext.` only.",
    },
    ReactorEventSpec {
        name: "login.post_auth",
        interceptable: true,
        mutable: false,
        mutable_fields: &[],
        // Veto-capable security hook: a fraud or geo check that times out has
        // not passed.
        default_failure_policy: FailurePolicy::FailClosed,
        description: "After credentials verify, before session issuance: veto or require step-up MFA.",
    },
    ReactorEventSpec {
        name: "user.pre_create",
        interceptable: true,
        mutable: true,
        // Profile attributes only — never credentials, tenant or role fields.
        mutable_fields: &["username", "email", "metadata."],
        default_failure_policy: FailurePolicy::FailClosed,
        description: "Validate or normalize a new user's profile fields.",
    },
    ReactorEventSpec {
        name: "user.pre_update",
        interceptable: true,
        mutable: true,
        mutable_fields: &["username", "email", "metadata."],
        default_failure_policy: FailurePolicy::FailClosed,
        description: "Validate or normalize a profile update.",
    },
    ReactorEventSpec {
        name: "grant.pre_assign",
        interceptable: true,
        mutable: false,
        mutable_fields: &[],
        // Four-eyes workflows live here. An unreachable approver is not an
        // approval.
        default_failure_policy: FailurePolicy::FailClosed,
        description: "Veto a role or permission assignment (four-eyes workflows). Veto-only.",
    },
];

/// Look an event up by wire name.
pub fn event_spec(name: &str) -> Option<&'static ReactorEventSpec> {
    EVENT_REGISTRY.iter().find(|spec| spec.name == name)
}

// ---------------------------------------------------------------------------
// The gate the rest of the server calls through
// ---------------------------------------------------------------------------

/// What a reactor decided about one operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReactorOutcome {
    /// Proceed unchanged. Also what a `fail_open` failure resolves to.
    Allow,
    /// Refuse, with a reason that is audited and (in redacted form) returned
    /// to the caller.
    Deny { reason: String },
    /// Proceed, applying `patch` — already validated against the event's
    /// allow-list by the time it reaches a caller.
    Mutate { patch: BTreeMap<String, String> },
    /// Proceed only after step-up authentication. `login.post_auth` only.
    RequireMfa,
}

impl ReactorOutcome {
    /// Whether the operation may continue.
    pub fn permits(&self) -> bool {
        !matches!(self, Self::Deny { .. })
    }
}

/// The seam between the security-critical crates and the broker.
///
/// `axiam-auth` and `axiam-oauth2` call this and stay broker-agnostic: the
/// AMQP dispatcher implements it, and so does the no-op used when reactors are
/// disabled. That the trait is here rather than in `axiam-amqp` is the whole
/// point — those crates must not gain a dependency on the message bus to ask
/// whether an extension vetoed something.
pub trait ReactorGate: Send + Sync {
    /// Run every interceptor registered for `event` in this tenant, in
    /// priority order, and return the composed outcome.
    ///
    /// Implementations MUST return [`ReactorOutcome::Allow`] when no reactor is
    /// registered, so a deployment with the feature off behaves identically to
    /// one built without it.
    fn intercept(
        &self,
        tenant_id: Uuid,
        event: &'static str,
        payload: serde_json::Value,
    ) -> impl std::future::Future<Output = ReactorOutcome> + Send;

    /// Whether a registration made now could ever be dispatched to (SEC-101).
    ///
    /// The REST layer refuses `POST`/`PUT /api/v1/reactors` while this is
    /// `false`, because a registration that cannot be reached resolves through
    /// its own `failure_policy` on every dispatch — and `login.post_auth`,
    /// `user.pre_create`, `user.pre_update` and `grant.pre_assign` all default
    /// to `fail_closed`. Accepting the registration therefore hands a tenant
    /// admin a complete, self-inflicted login outage through a supported admin
    /// action, with the only warning emitted at boot, hours earlier, in a log
    /// nobody is reading at the time.
    ///
    /// The fail-closed *posture* is right and is not what this changes: a
    /// registered fail-closed check that silently does nothing is worse. What
    /// changes is that the refusal now happens at the moment of the action
    /// that causes the consequence, where it can be explained.
    ///
    /// Defaults to `true`. [`NoopReactorGate`] keeps that default deliberately:
    /// it runs no reactors at all, so a registration under it is inert rather
    /// than dangerous, and refusing would break every deployment and test that
    /// composes it.
    fn can_dispatch(&self) -> bool {
        true
    }
}

/// The object-safe half of [`ReactorGate`].
///
/// [`ReactorGate`] returns `impl Future`, which is what keeps the no-op gate
/// allocation-free — and which also makes it impossible to store behind a
/// `dyn`. Every call site that needs one is reached through a struct that is
/// *already* generic over half a dozen repositories (`AuthService`,
/// `TokenService`, `AppState<C>`), so adding one more type parameter to each of
/// them would push the broker choice into the signature of code that must not
/// know a broker exists. This trait is the seam instead: one boxed allocation
/// per *intercepted* event — never on the path where no reactor is registered,
/// because that decision is made inside the implementation, after the call.
///
/// Implemented **blanket** for every [`ReactorGate`], so a gate author writes
/// the ergonomic trait and gets this one for free.
pub trait DynReactorGate: Send + Sync {
    /// Object-safe [`ReactorGate::intercept`].
    fn intercept_dyn<'a>(
        &'a self,
        tenant_id: Uuid,
        event: &'static str,
        payload: serde_json::Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ReactorOutcome> + Send + 'a>>;

    /// Object-safe [`ReactorGate::can_dispatch`] (SEC-101).
    fn can_dispatch_dyn(&self) -> bool;
}

impl<G: ReactorGate> DynReactorGate for G {
    fn intercept_dyn<'a>(
        &'a self,
        tenant_id: Uuid,
        event: &'static str,
        payload: serde_json::Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ReactorOutcome> + Send + 'a>> {
        Box::pin(self.intercept(tenant_id, event, payload))
    }

    fn can_dispatch_dyn(&self) -> bool {
        self.can_dispatch()
    }
}

/// What the security-critical crates actually hold: a shared, type-erased gate.
pub type SharedReactorGate = std::sync::Arc<dyn DynReactorGate>;

/// So a call site can keep writing `gate.intercept(..)` whether it holds a
/// concrete gate or the erased one. Without this, every hook would read
/// `intercept_dyn` and a reader would have to know which of the two traits was
/// in play to know whether the call was doing anything different (it is not).
impl ReactorGate for SharedReactorGate {
    async fn intercept(
        &self,
        tenant_id: Uuid,
        event: &'static str,
        payload: serde_json::Value,
    ) -> ReactorOutcome {
        (**self).intercept_dyn(tenant_id, event, payload).await
    }

    fn can_dispatch(&self) -> bool {
        (**self).can_dispatch_dyn()
    }
}

/// A gate that runs no reactors — what a deployment without AMQP composes, and
/// the default every service is constructed with.
///
/// Exists so `axiam-auth`, `axiam-oauth2` and the REST handlers have exactly
/// **one** code path whether or not reactors are configured. A call site that
/// branches on `Option<Gate>` is a call site where the disabled build and the
/// enabled build can drift, and the drift would be invisible until a reactor
/// was registered in production.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopReactorGate;

impl ReactorGate for NoopReactorGate {
    async fn intercept(
        &self,
        _tenant_id: Uuid,
        _event: &'static str,
        _payload: serde_json::Value,
    ) -> ReactorOutcome {
        ReactorOutcome::Allow
    }
}

/// The gate a service is built with until something hands it a real one.
pub fn noop_reactor_gate() -> SharedReactorGate {
    std::sync::Arc::new(NoopReactorGate)
}

/// The five v1 interceptor event names, as the `&'static str`s the gate takes.
///
/// Call sites use these rather than string literals so a typo is a compile
/// error rather than an event that silently dispatches to nothing (which is
/// exactly what [`crate::models::reactor::event_spec`] does with an unknown
/// name, and correctly so — see the dispatcher's `run_chain`).
pub mod events {
    /// Before an access token is minted. Mutable: the `ext.` claim namespace.
    pub const TOKEN_PRE_ISSUE: &str = "token.pre_issue";
    /// After credentials verify, before a session is issued. Veto or step-up.
    pub const LOGIN_POST_AUTH: &str = "login.post_auth";
    /// Before a user row is written. Mutable: `username`, `email`, `metadata.`.
    pub const USER_PRE_CREATE: &str = "user.pre_create";
    /// Before a user row is updated. Mutable: `username`, `email`, `metadata.`.
    pub const USER_PRE_UPDATE: &str = "user.pre_update";
    /// Before a role is assigned to a user or a group. Veto only.
    pub const GRANT_PRE_ASSIGN: &str = "grant.pre_assign";
}

// ---------------------------------------------------------------------------
// Persistence model
// ---------------------------------------------------------------------------

/// Hard ceiling on a registration's `timeout_ms`. A reactor that needs longer
/// than five seconds to answer is not an interceptor, it is an outage.
pub const MAX_TIMEOUT_MS: u32 = 5_000;

/// Default `timeout_ms` when a registration does not name one.
pub const DEFAULT_TIMEOUT_MS: u32 = 500;

/// A registered reactor.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Reactor {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: String,
    /// Event names from [`EVENT_REGISTRY`]. Validated on write; an unknown
    /// name is refused rather than stored and silently never fired.
    pub events: Vec<String>,
    pub mode: ReactorMode,
    /// Interceptor ordering, ascending. Ties break by `id` so the order is
    /// total and stable across restarts.
    pub priority: i32,
    pub timeout_ms: u32,
    pub failure_policy: FailurePolicy,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// When this reactor last consumed from its queue. `None` means it has
    /// never connected — which the admin UI shows differently from "connected
    /// once, silent since".
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// Input for creating a reactor. `timeout_ms` and `failure_policy` are
/// optional: omitting them takes the per-event default from the registry,
/// which is how a caller gets `fail_closed` on a security hook without having
/// to know that it should.
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct CreateReactor {
    pub tenant_id: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub events: Vec<String>,
    pub mode: ReactorMode,
    #[serde(default)]
    pub priority: i32,
    pub timeout_ms: Option<u32>,
    pub failure_policy: Option<FailurePolicy>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Input for updating a reactor. Every field is optional; `None` leaves it.
#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
pub struct UpdateReactor {
    pub name: Option<String>,
    pub description: Option<String>,
    pub events: Option<Vec<String>>,
    pub mode: Option<ReactorMode>,
    pub priority: Option<i32>,
    pub timeout_ms: Option<u32>,
    pub failure_policy: Option<FailurePolicy>,
    pub enabled: Option<bool>,
}

/// Why a registration was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReactorValidationError {
    /// `events` was empty. A reactor subscribed to nothing is a queue nobody
    /// writes to.
    NoEvents,
    /// An event name that is not in [`EVENT_REGISTRY`].
    UnknownEvent(String),
    /// An `intercept` registration naming a listen-only event.
    NotInterceptable(String),
    /// `timeout_ms` above [`MAX_TIMEOUT_MS`], or zero.
    TimeoutOutOfRange(u32),
    /// `name` was blank.
    BlankName,
}

impl std::fmt::Display for ReactorValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoEvents => write!(f, "a reactor must subscribe to at least one event"),
            Self::UnknownEvent(e) => write!(f, "unknown reactor event '{e}'"),
            Self::NotInterceptable(e) => {
                write!(
                    f,
                    "event '{e}' cannot be intercepted; register it with mode 'listen'"
                )
            }
            Self::TimeoutOutOfRange(ms) => {
                write!(f, "timeout_ms {ms} is outside 1..={MAX_TIMEOUT_MS}")
            }
            Self::BlankName => write!(f, "a reactor must have a non-blank name"),
        }
    }
}

impl std::error::Error for ReactorValidationError {}

/// Validate a registration's events, mode and timeout against the registry.
///
/// Deliberately a free function over the parts rather than a method on
/// [`CreateReactor`], so the update path can validate the *merged* result
/// rather than only the fields the request happened to carry.
pub fn validate_registration(
    name: &str,
    events: &[String],
    mode: ReactorMode,
    timeout_ms: u32,
) -> Result<(), ReactorValidationError> {
    if name.trim().is_empty() {
        return Err(ReactorValidationError::BlankName);
    }
    if events.is_empty() {
        return Err(ReactorValidationError::NoEvents);
    }
    if timeout_ms == 0 || timeout_ms > MAX_TIMEOUT_MS {
        return Err(ReactorValidationError::TimeoutOutOfRange(timeout_ms));
    }
    for event in events {
        let spec =
            event_spec(event).ok_or_else(|| ReactorValidationError::UnknownEvent(event.clone()))?;
        if mode == ReactorMode::Intercept && !spec.interceptable {
            return Err(ReactorValidationError::NotInterceptable(event.clone()));
        }
    }
    Ok(())
}

/// The `failure_policy` a registration should get when it names none: the
/// strictest default among the events it subscribes to.
///
/// Strictest-wins is the only safe composition. A reactor registered for both
/// `token.pre_issue` (default `fail_open`) and `login.post_auth` (default
/// `fail_closed`) is a reactor that can veto a login, so it inherits
/// `fail_closed`. Taking the first event's default, or the loosest, would let
/// the order of a JSON array decide whether an unreachable fraud check passes.
pub fn default_failure_policy_for(events: &[String]) -> FailurePolicy {
    if events
        .iter()
        .filter_map(|e| event_spec(e))
        .any(|spec| spec.default_failure_policy == FailurePolicy::FailClosed)
    {
        FailurePolicy::FailClosed
    } else {
        FailurePolicy::FailOpen
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_registry_entry_is_self_consistent() {
        for spec in EVENT_REGISTRY {
            assert!(!spec.name.is_empty());
            assert!(
                !spec.description.is_empty(),
                "{} needs a description — it is surfaced in the admin UI",
                spec.name
            );
            if spec.mutable {
                assert!(
                    !spec.mutable_fields.is_empty(),
                    "{} claims to be mutable but allows no fields",
                    spec.name
                );
            } else {
                assert!(
                    spec.mutable_fields.is_empty(),
                    "{} is veto-only but lists mutable fields — one of the two is a lie",
                    spec.name
                );
            }
        }
    }

    #[test]
    fn event_names_are_unique() {
        let mut names: Vec<_> = EVENT_REGISTRY.iter().map(|s| s.name).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate event name in the registry");
    }

    /// The claim the `token.pre_issue` allow-list exists to make: a reactor
    /// cannot reach any standard claim.
    #[test]
    fn token_pre_issue_admits_only_the_ext_namespace() {
        let spec = event_spec("token.pre_issue").unwrap();

        assert!(spec.patch_field_allowed("ext.department"));
        assert!(spec.patch_field_allowed("ext.a.b.c"));

        for claim in [
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "nbf",
            "jti",
            "scope",
            "scp",
            "azp",
            "act",
            "sub_kind",
            "client_id",
        ] {
            assert!(
                !spec.patch_field_allowed(claim),
                "a reactor must not be able to set the standard claim '{claim}'"
            );
        }
    }

    /// Prefix matching must not be defeatable by a name that merely *starts
    /// like* the namespace.
    #[test]
    fn the_namespace_prefix_is_not_a_substring_match() {
        let spec = event_spec("token.pre_issue").unwrap();

        // Bare namespace, and a claim called `ext` — neither is inside it.
        assert!(!spec.patch_field_allowed("ext."));
        assert!(!spec.patch_field_allowed("ext"));
        // `extra` starts with "ext" but is not in the "ext." namespace.
        assert!(!spec.patch_field_allowed("extra"));
        assert!(!spec.patch_field_allowed("external_id"));
        // Not a suffix match either.
        assert!(!spec.patch_field_allowed("evil.ext.department"));
    }

    #[test]
    fn a_veto_only_event_admits_no_patch_at_all() {
        for name in ["login.post_auth", "grant.pre_assign"] {
            let spec = event_spec(name).unwrap();
            for field in ["anything", "ext.x", "reason", ""] {
                assert!(
                    !spec.patch_field_allowed(field),
                    "{name} is veto-only and must reject the field '{field}'"
                );
            }
        }
    }

    /// The profile hooks admit profile fields and nothing that could escalate.
    #[test]
    fn the_user_hooks_cannot_touch_credentials_tenant_or_roles() {
        for name in ["user.pre_create", "user.pre_update"] {
            let spec = event_spec(name).unwrap();
            assert!(spec.patch_field_allowed("email"));
            assert!(spec.patch_field_allowed("metadata.source"));

            for field in [
                "password",
                "password_hash",
                "tenant_id",
                "id",
                "roles",
                "metadata",
                "is_admin",
            ] {
                assert!(
                    !spec.patch_field_allowed(field),
                    "{name} must not be able to set '{field}'"
                );
            }
        }
    }

    /// The hot path is not hookable, and this is the test that says so out
    /// loud. Adding it to the registry should be a decision someone makes
    /// while looking at this assertion, not a line someone appends.
    #[test]
    fn the_authorization_hot_path_is_not_hookable() {
        for name in ["authz.check", "authz.check_batch", "token.introspect"] {
            assert!(
                event_spec(name).is_none(),
                "{name} is a hot path (1k–12k req/s); a reactor round-trip is milliseconds"
            );
        }
    }

    #[test]
    fn validation_refuses_an_unknown_event() {
        let events = vec!["token.pre_issue".into(), "not.an.event".into()];
        assert_eq!(
            validate_registration("r", &events, ReactorMode::Intercept, 500),
            Err(ReactorValidationError::UnknownEvent("not.an.event".into()))
        );
    }

    #[test]
    fn validation_refuses_an_out_of_range_timeout() {
        let events = vec!["token.pre_issue".into()];
        assert!(matches!(
            validate_registration("r", &events, ReactorMode::Intercept, MAX_TIMEOUT_MS + 1),
            Err(ReactorValidationError::TimeoutOutOfRange(_))
        ));
        assert!(matches!(
            validate_registration("r", &events, ReactorMode::Intercept, 0),
            Err(ReactorValidationError::TimeoutOutOfRange(0))
        ));
        assert!(
            validate_registration("r", &events, ReactorMode::Intercept, MAX_TIMEOUT_MS).is_ok()
        );
    }

    #[test]
    fn validation_refuses_an_empty_event_list_and_a_blank_name() {
        assert_eq!(
            validate_registration("r", &[], ReactorMode::Intercept, 500),
            Err(ReactorValidationError::NoEvents)
        );
        assert_eq!(
            validate_registration("  ", &["token.pre_issue".into()], ReactorMode::Listen, 500),
            Err(ReactorValidationError::BlankName)
        );
    }

    /// Listen mode may subscribe to anything in the registry — a listener
    /// cannot affect an outcome, so interceptability does not constrain it.
    #[test]
    fn listen_mode_may_subscribe_to_every_registered_event() {
        let events: Vec<String> = EVENT_REGISTRY.iter().map(|s| s.name.to_string()).collect();
        assert!(validate_registration("r", &events, ReactorMode::Listen, 500).is_ok());
    }

    /// The composition rule that decides whether an unreachable reactor
    /// passes or fails.
    #[test]
    fn the_strictest_default_failure_policy_wins() {
        assert_eq!(
            default_failure_policy_for(&["token.pre_issue".into()]),
            FailurePolicy::FailOpen
        );
        assert_eq!(
            default_failure_policy_for(&["login.post_auth".into()]),
            FailurePolicy::FailClosed
        );
        // Mixed, in both array orders — a JSON array's order must not decide
        // whether an unreachable fraud check passes.
        assert_eq!(
            default_failure_policy_for(&["token.pre_issue".into(), "login.post_auth".into()]),
            FailurePolicy::FailClosed
        );
        assert_eq!(
            default_failure_policy_for(&["login.post_auth".into(), "token.pre_issue".into()]),
            FailurePolicy::FailClosed
        );
    }

    /// An unknown event contributes nothing to the default — it is refused by
    /// `validate_registration` anyway, and guessing on its behalf would be the
    /// wrong kind of helpful.
    #[test]
    fn an_unknown_event_does_not_influence_the_default_policy() {
        assert_eq!(
            default_failure_policy_for(&["nonsense".into()]),
            FailurePolicy::FailOpen
        );
    }

    #[test]
    fn wire_forms_round_trip() {
        for mode in [ReactorMode::Intercept, ReactorMode::Listen] {
            assert_eq!(ReactorMode::from_wire(mode.as_str()), Some(mode));
        }
        for policy in [FailurePolicy::FailClosed, FailurePolicy::FailOpen] {
            assert_eq!(FailurePolicy::from_wire(policy.as_str()), Some(policy));
        }
        assert_eq!(
            ReactorMode::from_wire("INTERCEPT"),
            Some(ReactorMode::Intercept)
        );
        assert_eq!(
            FailurePolicy::from_wire(" fail_open "),
            Some(FailurePolicy::FailOpen)
        );
        assert_eq!(ReactorMode::from_wire("observe"), None);
        assert_eq!(FailurePolicy::from_wire("fail_sometimes"), None);
    }

    /// The constants the five call sites pass must be registry names. A
    /// constant that drifted out of the registry would make its hook dispatch
    /// to nothing — a security control that silently stopped running.
    #[test]
    fn every_call_site_constant_names_a_registered_event() {
        for name in [
            events::TOKEN_PRE_ISSUE,
            events::LOGIN_POST_AUTH,
            events::USER_PRE_CREATE,
            events::USER_PRE_UPDATE,
            events::GRANT_PRE_ASSIGN,
        ] {
            assert!(
                event_spec(name).is_some(),
                "call-site constant '{name}' is not in EVENT_REGISTRY"
            );
        }
        assert_eq!(
            EVENT_REGISTRY.len(),
            5,
            "a sixth event needs a call-site constant and a wired hook, or it \
             is a registration nothing will ever fire"
        );
    }

    /// The erased gate is constructible and `Send + Sync` — the property that
    /// lets every service hold one field instead of a type parameter. Its
    /// *behavioural* equivalence to the concrete gate is asserted in
    /// `axiam-amqp` (`reactor::gate` tests), which has an async runtime.
    #[test]
    fn the_erased_gate_is_a_shareable_object() {
        fn assert_send_sync<T: Send + Sync>(_: &T) {}
        let erased: SharedReactorGate = noop_reactor_gate();
        assert_send_sync(&erased);
        let _cloned = erased.clone();
    }

    #[test]
    fn an_outcome_permits_unless_it_denies() {
        assert!(ReactorOutcome::Allow.permits());
        assert!(ReactorOutcome::RequireMfa.permits());
        assert!(
            ReactorOutcome::Mutate {
                patch: BTreeMap::new()
            }
            .permits()
        );
        assert!(
            !ReactorOutcome::Deny {
                reason: "no".into()
            }
            .permits()
        );
    }
}

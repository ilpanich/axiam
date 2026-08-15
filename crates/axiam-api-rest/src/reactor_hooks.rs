//! The three REST-side reactor hooks (X1 / R2.2).
//!
//! `login.post_auth` lives in `axiam-auth` and `token.pre_issue` in
//! `axiam-oauth2`, because those are the crates that own the operation. The
//! other three — `user.pre_create`, `user.pre_update` and `grant.pre_assign` —
//! have no service layer between the handler and the repository, so the handler
//! *is* the operation and this module is where they run.
//!
//! # What these functions are, and what they are deliberately not
//!
//! Each is "call the gate, then apply the answer". They are **not** a second
//! allow-list. A patch key is checked against the event's `mutable_fields`
//! three times before it reaches [`apply_user_patch`] — by the reply validator
//! (`ReactorReply::into_outcome`), by the gate's own re-check
//! (`DispatchingReactorGate::enforce_allow_list`), and by the exhaustive
//! `match` here that has no arm for anything else. The third is the one that
//! makes the property structural: adding a field to the allow-list without
//! deciding what it *means* here does not silently start writing it, because
//! there is nowhere for it to go.

use axiam_core::error::AxiamError;
use axiam_core::models::reactor::{
    ReactorGate, ReactorOutcome, SharedReactorGate, events as reactor_events,
};
use axiam_core::models::user::{CreateUser, UpdateUser};
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::error::AxiamApiError;

/// The metadata namespace a `user.pre_create` / `user.pre_update` patch may
/// write into, matching the registry's `metadata.` allow-list entry.
const METADATA_PREFIX: &str = "metadata.";

/// Turn a reactor veto into the error the handler returns.
///
/// `403`, not `400`: the request was well-formed and the caller was
/// authenticated and permitted — an external policy refused it. The reactor's
/// own text **is** surfaced here, unlike on the login and token paths, because
/// this caller has already proven a `users:create`-class permission and is an
/// administrator who needs to know why their write was refused. The audit
/// record carries the same string plus the reactor's id.
fn veto(action: &str, reason: String) -> AxiamApiError {
    AxiamApiError(AxiamError::AuthorizationDenied {
        reason: format!("refused by a reactor: {reason}"),
        action: Some(action.to_string()),
        resource_id: None,
    })
}

/// A mutation on a veto-only event, or an outcome the site cannot honour.
fn impossible(action: &str, what: &str) -> AxiamApiError {
    tracing::error!(
        target: "axiam::reactor",
        action,
        outcome = what,
        "a reactor outcome reached a call site that cannot honour it — refusing \
         the operation rather than proceeding as if it had not happened"
    );
    AxiamApiError(AxiamError::AuthorizationDenied {
        reason: "refused by a reactor".into(),
        action: Some(action.to_string()),
        resource_id: None,
    })
}

/// Apply an allow-listed `user.pre_*` patch.
///
/// Returns the merged metadata object, or `None` when the patch touched no
/// metadata key. The caller decides whether a `None` means "leave it alone"
/// (update) or "use what the request supplied" (create), because those differ.
fn apply_user_patch(
    patch: &BTreeMap<String, String>,
    username: &mut Option<String>,
    email: &mut Option<String>,
    metadata: &mut Option<serde_json::Value>,
) {
    for (key, value) in patch {
        match key.as_str() {
            "username" => *username = Some(value.clone()),
            "email" => *email = Some(value.clone()),
            other => {
                let Some(field) = other
                    .strip_prefix(METADATA_PREFIX)
                    .filter(|f| !f.is_empty())
                else {
                    // Unreachable: three checks upstream refuse it. Logged at
                    // ERROR rather than ignored, because reaching this line
                    // means one of them has a hole.
                    tracing::error!(
                        target: "axiam::reactor",
                        field = %other,
                        "a user patch field outside the allow-list reached the handler; \
                         dropping it"
                    );
                    continue;
                };
                let object =
                    metadata.get_or_insert_with(|| serde_json::Value::Object(Default::default()));
                if !object.is_object() {
                    // The request supplied a non-object `metadata`. The patch
                    // namespace is defined in terms of object keys, so replace
                    // rather than guess at a merge.
                    *object = serde_json::Value::Object(Default::default());
                }
                if let Some(map) = object.as_object_mut() {
                    map.insert(field.to_string(), serde_json::Value::String(value.clone()));
                }
            }
        }
    }
}

/// Run `user.pre_create`, applying any allow-listed mutation to `input`.
pub async fn user_pre_create(
    gate: &SharedReactorGate,
    tenant_id: Uuid,
    input: &mut CreateUser,
) -> Result<(), AxiamApiError> {
    let outcome = gate
        .intercept(
            tenant_id,
            reactor_events::USER_PRE_CREATE,
            serde_json::json!({
                // Never the password (§22.3): a reactor validates a profile,
                // it is not handed a credential.
                "username": input.username,
                "email": input.email,
                "metadata": input.metadata,
                "tenant_id": tenant_id,
            }),
        )
        .await;

    match outcome {
        ReactorOutcome::Allow => Ok(()),
        ReactorOutcome::Deny { reason } => Err(veto("users:create", reason)),
        ReactorOutcome::Mutate { patch } => {
            let mut username = None;
            let mut email = None;
            let mut metadata = input.metadata.clone();
            apply_user_patch(&patch, &mut username, &mut email, &mut metadata);
            if let Some(username) = username {
                input.username = username;
            }
            if let Some(email) = email {
                input.email = email;
            }
            input.metadata = metadata;
            Ok(())
        }
        ReactorOutcome::RequireMfa => Err(impossible("users:create", "require_mfa")),
    }
}

/// Run `user.pre_update`, applying any allow-listed mutation to `input`.
pub async fn user_pre_update(
    gate: &SharedReactorGate,
    tenant_id: Uuid,
    target_id: Uuid,
    input: &mut UpdateUser,
) -> Result<(), AxiamApiError> {
    let outcome = gate
        .intercept(
            tenant_id,
            reactor_events::USER_PRE_UPDATE,
            serde_json::json!({
                "user_id": target_id,
                // The *proposed* change, which is what is being decided. Fields
                // the request did not touch are absent rather than null, so a
                // reactor can tell "unchanged" from "cleared".
                "username": input.username,
                "email": input.email,
                "metadata": input.metadata,
                "tenant_id": tenant_id,
            }),
        )
        .await;

    match outcome {
        ReactorOutcome::Allow => Ok(()),
        ReactorOutcome::Deny { reason } => Err(veto("users:update", reason)),
        ReactorOutcome::Mutate { patch } => {
            let mut metadata = input.metadata.clone();
            apply_user_patch(&patch, &mut input.username, &mut input.email, &mut metadata);
            input.metadata = metadata;
            Ok(())
        }
        ReactorOutcome::RequireMfa => Err(impossible("users:update", "require_mfa")),
    }
}

/// Run `grant.pre_assign` — the four-eyes hook. Veto only.
pub async fn grant_pre_assign(
    gate: &SharedReactorGate,
    tenant_id: Uuid,
    payload: serde_json::Value,
) -> Result<(), AxiamApiError> {
    match gate
        .intercept(tenant_id, reactor_events::GRANT_PRE_ASSIGN, payload)
        .await
    {
        ReactorOutcome::Allow => Ok(()),
        ReactorOutcome::Deny { reason } => Err(veto("roles:assign", reason)),
        // The registry marks this event `mutable: false` and carries no
        // step-up notion; both are refused by the reply validator and again by
        // the gate. Refusing here too means the assignment cannot proceed on an
        // answer nobody can apply.
        ReactorOutcome::Mutate { .. } => Err(impossible("roles:assign", "mutate")),
        ReactorOutcome::RequireMfa => Err(impossible("roles:assign", "require_mfa")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::reactor::{DynReactorGate, noop_reactor_gate};
    use std::sync::Arc;

    /// A gate that always answers the same thing — enough to prove each site
    /// reads the outcome it is given. The per-site allow/deny/mutate/timeout
    /// matrix against a *real* chain lives in `axiam-amqp::reactor::gate`.
    struct Fixed(ReactorOutcome);

    impl DynReactorGate for Fixed {
        fn intercept_dyn<'a>(
            &'a self,
            _tenant_id: Uuid,
            _event: &'static str,
            _payload: serde_json::Value,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ReactorOutcome> + Send + 'a>>
        {
            let outcome = self.0.clone();
            Box::pin(std::future::ready(outcome))
        }
    }

    fn gate(outcome: ReactorOutcome) -> SharedReactorGate {
        Arc::new(Fixed(outcome))
    }

    fn patch(pairs: &[(&str, &str)]) -> ReactorOutcome {
        ReactorOutcome::Mutate {
            patch: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    fn create_input() -> CreateUser {
        CreateUser {
            tenant_id: Uuid::new_v4(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            // Generated, never a literal: a username/password pair sitting in
            // source trips secret scanners, and this test only cares that the
            // value survives untouched — not what it is.
            password: format!("pw-{}", Uuid::new_v4()),
            metadata: None,
        }
    }

    #[tokio::test]
    async fn the_noop_gate_leaves_a_create_untouched() {
        let mut input = create_input();
        let before = (input.username.clone(), input.email.clone());
        user_pre_create(&noop_reactor_gate(), input.tenant_id, &mut input)
            .await
            .expect("the no-op gate allows");
        assert_eq!((input.username.clone(), input.email.clone()), before);
        assert!(input.metadata.is_none());
    }

    #[tokio::test]
    async fn a_veto_refuses_a_create() {
        let mut input = create_input();
        let err = user_pre_create(
            &gate(ReactorOutcome::Deny {
                reason: "domain not allow-listed".into(),
            }),
            input.tenant_id,
            &mut input,
        )
        .await
        .expect_err("a veto must refuse the write");
        assert!(err.0.to_string().contains("domain not allow-listed"));
    }

    #[tokio::test]
    async fn a_create_mutation_normalizes_the_allow_listed_fields() {
        let mut input = create_input();
        let password_before = input.password.clone();
        user_pre_create(
            &gate(patch(&[
                ("username", "alice.normalized"),
                ("email", "alice@corp.example.com"),
                ("metadata.source", "hr-sync"),
                ("metadata.cost_center", "42"),
            ])),
            input.tenant_id,
            &mut input,
        )
        .await
        .expect("an allow-listed mutation applies");

        assert_eq!(input.username, "alice.normalized");
        assert_eq!(input.email, "alice@corp.example.com");
        let metadata = input.metadata.expect("metadata written");
        assert_eq!(metadata["source"], "hr-sync");
        assert_eq!(metadata["cost_center"], "42");
        assert_eq!(
            input.password, password_before,
            "the password is not a mutable field and must be untouched"
        );
    }

    /// The wiring-layer half of the allow-list guarantee: a field outside the
    /// event's list has nowhere to go, so it cannot be written even if it
    /// arrives.
    #[tokio::test]
    async fn a_field_outside_the_allow_list_cannot_be_written_by_the_handler() {
        let mut input = create_input();
        let original_password = input.password.clone();
        let original_tenant = input.tenant_id;

        // These are exactly the keys `EVENT_REGISTRY` refuses for
        // `user.pre_create`. Reaching `apply_user_patch` with them is
        // impossible through the wire path; the point of the test is that the
        // handler is not the layer that would let them through.
        user_pre_create(
            &gate(patch(&[
                ("password", "hunter2"),
                ("password_hash", "$argon2id$xxx"),
                ("tenant_id", &Uuid::new_v4().to_string()),
                ("roles", "admin"),
                ("is_admin", "true"),
                ("metadata", "not-a-namespace"),
            ])),
            input.tenant_id,
            &mut input,
        )
        .await
        .expect("the outcome is applied, minus everything it may not touch");

        assert_eq!(input.password, original_password);
        assert_eq!(input.tenant_id, original_tenant);
        assert_eq!(input.username, "alice");
        assert_eq!(input.email, "alice@example.com");
        assert!(
            input.metadata.is_none(),
            "bare `metadata` is not the `metadata.` namespace"
        );
    }

    #[tokio::test]
    async fn an_update_mutation_merges_into_the_requested_metadata() {
        let mut input = UpdateUser {
            email: Some("bob@example.com".into()),
            metadata: Some(serde_json::json!({ "keep": "me" })),
            ..Default::default()
        };
        user_pre_update(
            &gate(patch(&[("metadata.source", "scim")])),
            Uuid::new_v4(),
            Uuid::new_v4(),
            &mut input,
        )
        .await
        .expect("mutation applies");

        let metadata = input.metadata.expect("metadata present");
        assert_eq!(metadata["keep"], "me", "the caller's own keys survive");
        assert_eq!(metadata["source"], "scim");
        assert_eq!(input.email.as_deref(), Some("bob@example.com"));
    }

    #[tokio::test]
    async fn an_update_veto_refuses_the_write() {
        let mut input = UpdateUser {
            username: Some("mallory".into()),
            ..Default::default()
        };
        assert!(
            user_pre_update(
                &gate(ReactorOutcome::Deny {
                    reason: "reserved name".into()
                }),
                Uuid::new_v4(),
                Uuid::new_v4(),
                &mut input,
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn a_grant_veto_refuses_the_assignment_and_an_allow_permits_it() {
        let tenant = Uuid::new_v4();
        grant_pre_assign(&noop_reactor_gate(), tenant, serde_json::json!({}))
            .await
            .expect("the no-op gate allows");

        assert!(
            grant_pre_assign(
                &gate(ReactorOutcome::Deny {
                    reason: "four-eyes approval pending".into()
                }),
                tenant,
                serde_json::json!({}),
            )
            .await
            .is_err()
        );
    }

    /// `grant.pre_assign` is veto-only. An answer it cannot honour must refuse
    /// the assignment rather than be discarded.
    #[tokio::test]
    async fn a_mutation_on_the_veto_only_grant_event_refuses_the_assignment() {
        assert!(
            grant_pre_assign(
                &gate(patch(&[("anything", "x")])),
                Uuid::new_v4(),
                serde_json::json!({}),
            )
            .await
            .is_err()
        );
        assert!(
            grant_pre_assign(
                &gate(ReactorOutcome::RequireMfa),
                Uuid::new_v4(),
                serde_json::json!({}),
            )
            .await
            .is_err()
        );
    }
}

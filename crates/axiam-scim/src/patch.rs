//! RFC 7644 §3.5.2 PATCH operation parsing and application — **restricted to
//! the op subset Okta and Entra actually send** (B4's own words): `add` /
//! `replace` / `remove` on a fixed set of standard attribute paths. No
//! attribute-path filters other than the one Okta/Entra both rely on for
//! single-member group removal (`members[value eq "<uuid>"]`), no nested
//! boolean filter expressions, no `path`-less multi-attribute `replace`
//! beyond a flat top-level object.
//!
//! This module only *parses* a `PatchRequest` into a delta
//! ([`UserPatchDelta`] / [`GroupPatchDelta`]) — applying that delta to a
//! fetched resource and persisting it is `users.rs`/`groups.rs`'s job. That
//! split is what makes the PATCH-op unit matrix (`tests/contract_test.rs`)
//! cheap: it exercises this module directly, with no database.

use serde::Deserialize;
use uuid::Uuid;

use crate::error::ScimError;

pub const PATCH_OP_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

#[derive(Debug, Deserialize)]
pub struct PatchRequest {
    #[serde(default, rename = "Operations")]
    pub operations: Vec<PatchOp>,
}

#[derive(Debug, Deserialize)]
pub struct PatchOp {
    pub op: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub value: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Add,
    Replace,
    Remove,
}

fn parse_op(raw: &str) -> Result<Op, ScimError> {
    match raw.to_ascii_lowercase().as_str() {
        "add" => Ok(Op::Add),
        "replace" => Ok(Op::Replace),
        "remove" => Ok(Op::Remove),
        other => Err(ScimError::invalid_value(format!(
            "unsupported PATCH op {other:?} — only add, replace, remove are supported"
        ))),
    }
}

/// Strip a leading schema URN qualifier from a path
/// (`urn:ietf:params:scim:schemas:core:2.0:User:active` -> `active`) and
/// lower-case the rest for case-insensitive attribute-name comparison
/// (RFC 7643 §2.1).
fn normalize_path(path: &str) -> String {
    let unqualified = path.rsplit(':').next().unwrap_or(path);
    unqualified.to_ascii_lowercase()
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

/// Accumulated, not-yet-applied change set from a User PATCH request.
///
/// Each field is `Option<Option<T>>`-shaped where the attribute is
/// nullable: outer `None` = "not touched by any operation", `Some(None)` =
/// "explicitly cleared", `Some(Some(v))` = "set to v". Plain `Option<T>` is
/// used where the attribute has no clear/remove semantics we support
/// (required attributes reject `remove` outright — see below).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct UserPatchDelta {
    pub username: Option<String>,
    /// From `emails` add/replace — the (first) primary email value.
    pub email: Option<String>,
    pub active: Option<bool>,
    pub external_id: Option<Option<String>>,
    pub given_name: Option<Option<String>>,
    pub family_name: Option<Option<String>>,
    pub formatted: Option<Option<String>>,
    pub password: Option<String>,
}

/// The exact set of top-level User attribute paths this crate accepts in a
/// PATCH `path`, plus `name.*` sub-paths. Kept as a function (not a const
/// slice of the enum) so the "unsupported path" error can echo it.
const USER_PATCHABLE_PATHS: &[&str] = &[
    "active",
    "username",
    "externalid",
    "name.givenname",
    "name.familyname",
    "name.formatted",
    "emails",
    "password",
];

pub fn parse_user_patch(body: &PatchRequest) -> Result<UserPatchDelta, ScimError> {
    let mut delta = UserPatchDelta::default();
    for raw_op in &body.operations {
        let op = parse_op(&raw_op.op)?;
        match &raw_op.path {
            Some(path) => {
                apply_user_op(&mut delta, op, &normalize_path(path), raw_op.value.as_ref())?
            }
            // No `path`: Entra's shape for a multi-attribute replace —
            // `{"op":"replace","value":{"active":false,...}}`. Only valid
            // for `replace`; recurse once per top-level key in `value`.
            None => {
                if op != Op::Replace {
                    return Err(ScimError::invalid_path(
                        "a PATCH operation without \"path\" must be \"replace\" with an object value",
                    ));
                }
                let obj = raw_op
                    .value
                    .as_ref()
                    .and_then(|v| v.as_object())
                    .ok_or_else(|| {
                        ScimError::invalid_value(
                            "a path-less \"replace\" requires an object \"value\"",
                        )
                    })?;
                for (key, val) in obj {
                    apply_user_op(&mut delta, Op::Replace, &normalize_path(key), Some(val))?;
                }
            }
        }
    }
    Ok(delta)
}

fn apply_user_op(
    delta: &mut UserPatchDelta,
    op: Op,
    path: &str,
    value: Option<&serde_json::Value>,
) -> Result<(), ScimError> {
    match path {
        "active" => {
            if op == Op::Remove {
                // RFC 7643 §4.1.2: "active"'s default is true — removing it
                // reverts to that default rather than leaving it undefined.
                delta.active = Some(true);
                return Ok(());
            }
            let b = value
                .and_then(|v| v.as_bool())
                .ok_or_else(|| ScimError::invalid_value("\"active\" requires a boolean value"))?;
            delta.active = Some(b);
        }
        "username" => {
            if op == Op::Remove {
                return Err(ScimError::mutability(
                    "\"userName\" is required and cannot be removed",
                ));
            }
            delta.username = Some(string_value(value, "userName")?);
        }
        "externalid" => {
            delta.external_id = Some(if op == Op::Remove {
                None
            } else {
                Some(string_value(value, "externalId")?)
            });
        }
        "name.givenname" => {
            delta.given_name = Some(non_remove_string(op, value, "name.givenName")?);
        }
        "name.familyname" => {
            delta.family_name = Some(non_remove_string(op, value, "name.familyName")?);
        }
        "name.formatted" => {
            delta.formatted = Some(non_remove_string(op, value, "name.formatted")?);
        }
        "emails" => {
            if op == Op::Remove {
                return Err(ScimError::mutability(
                    "\"emails\" cannot be removed — AXIAM users require an email address",
                ));
            }
            delta.email = Some(primary_email(value)?);
        }
        "password" => {
            if op == Op::Remove {
                return Err(ScimError::invalid_path("\"password\" cannot be removed"));
            }
            delta.password = Some(string_value(value, "password")?);
        }
        other => {
            return Err(ScimError::invalid_path(format!(
                "unsupported PATCH path {other:?} — supported: {USER_PATCHABLE_PATHS:?}"
            )));
        }
    }
    Ok(())
}

fn string_value(value: Option<&serde_json::Value>, attr: &str) -> Result<String, ScimError> {
    value
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| ScimError::invalid_value(format!("{attr:?} requires a string value")))
}

fn non_remove_string(
    op: Op,
    value: Option<&serde_json::Value>,
    attr: &str,
) -> Result<Option<String>, ScimError> {
    if op == Op::Remove {
        return Ok(None);
    }
    Ok(Some(string_value(value, attr)?))
}

/// Extract the primary (or first, if none is marked `primary`) email address
/// from a SCIM `emails` array value: `[{"value":"...", "primary": true}]`.
fn primary_email(value: Option<&serde_json::Value>) -> Result<String, ScimError> {
    let arr = value
        .and_then(|v| v.as_array())
        .filter(|a| !a.is_empty())
        .ok_or_else(|| {
            ScimError::invalid_value("\"emails\" requires a non-empty array of {value, primary}")
        })?;

    let entry = arr
        .iter()
        .find(|e| e.get("primary").and_then(|p| p.as_bool()) == Some(true))
        .or_else(|| arr.first())
        .ok_or_else(|| ScimError::invalid_value("\"emails\" entries must have a \"value\""))?;

    entry
        .get("value")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| ScimError::invalid_value("\"emails\" entries must have a \"value\""))
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberAction {
    Add(Uuid),
    Remove(Uuid),
    /// `remove` on the whole `members` attribute with no value filter —
    /// RFC 7644 §3.5.2.2: clears every value of a multi-valued attribute.
    RemoveAll,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct GroupPatchDelta {
    pub display_name: Option<String>,
    pub external_id: Option<Option<String>>,
    pub member_actions: Vec<MemberAction>,
}

const GROUP_PATCHABLE_PATHS: &[&str] = &["displayname", "externalid", "members"];

pub fn parse_group_patch(body: &PatchRequest) -> Result<GroupPatchDelta, ScimError> {
    let mut delta = GroupPatchDelta::default();
    for raw_op in &body.operations {
        let op = parse_op(&raw_op.op)?;
        let path = raw_op
            .path
            .as_deref()
            .ok_or_else(|| ScimError::invalid_path("Group PATCH operations require a \"path\""))?;

        if let Some(member_id) = parse_member_filter_path(path) {
            // `members[value eq "<uuid>"]` — the Okta/Entra single-member
            // removal shape. Only meaningful for `remove`.
            if op != Op::Remove {
                return Err(ScimError::invalid_path(
                    "a filtered \"members[value eq ...]\" path is only supported for \"remove\"",
                ));
            }
            delta.member_actions.push(MemberAction::Remove(member_id));
            continue;
        }

        match normalize_path(path).as_str() {
            "displayname" => {
                if op == Op::Remove {
                    return Err(ScimError::mutability(
                        "\"displayName\" is required and cannot be removed",
                    ));
                }
                delta.display_name = Some(string_value(raw_op.value.as_ref(), "displayName")?);
            }
            "externalid" => {
                delta.external_id = Some(if op == Op::Remove {
                    None
                } else {
                    Some(string_value(raw_op.value.as_ref(), "externalId")?)
                });
            }
            "members" => match op {
                Op::Add => {
                    for id in member_id_list(raw_op.value.as_ref())? {
                        delta.member_actions.push(MemberAction::Add(id));
                    }
                }
                Op::Replace => {
                    // Treated as "the target membership set is exactly this
                    // list" — expressed as clear-then-add, applied in order.
                    delta.member_actions.push(MemberAction::RemoveAll);
                    for id in member_id_list(raw_op.value.as_ref())? {
                        delta.member_actions.push(MemberAction::Add(id));
                    }
                }
                Op::Remove => {
                    if raw_op.value.is_none() {
                        delta.member_actions.push(MemberAction::RemoveAll);
                    } else {
                        for id in member_id_list(raw_op.value.as_ref())? {
                            delta.member_actions.push(MemberAction::Remove(id));
                        }
                    }
                }
            },
            other => {
                return Err(ScimError::invalid_path(format!(
                    "unsupported PATCH path {other:?} — supported: {GROUP_PATCHABLE_PATHS:?}"
                )));
            }
        }
    }
    Ok(delta)
}

/// Match exactly `members[value eq "<uuid>"]` (whitespace-tolerant around
/// `eq`), returning the parsed member id. Any other bracketed path —
/// multiple predicates, a different attribute, `and`/`or` — returns `None`
/// so the caller falls through to the generic path handling (and, for
/// anything under `members[...]` that isn't this exact shape, an
/// `invalidPath` error) rather than being silently misread.
fn parse_member_filter_path(path: &str) -> Option<Uuid> {
    let lower = path.to_ascii_lowercase();
    let inner = lower.strip_prefix("members[")?.strip_suffix(']')?;
    let mut parts = inner.splitn(3, char::is_whitespace);
    let attr = parts.next()?.trim();
    let op = parts.next()?.trim();
    let value = parts.next()?.trim();
    if attr != "value" || !op.eq_ignore_ascii_case("eq") {
        return None;
    }
    let unquoted = value.strip_prefix('"')?.strip_suffix('"')?;
    Uuid::parse_str(unquoted).ok()
}

/// Parse a SCIM `members` value array (`[{"value":"<uuid>"}, ...]`) into
/// member UUIDs.
fn member_id_list(value: Option<&serde_json::Value>) -> Result<Vec<Uuid>, ScimError> {
    let arr = value.and_then(|v| v.as_array()).ok_or_else(|| {
        ScimError::invalid_value("\"members\" requires an array of {value} objects")
    })?;
    arr.iter()
        .map(|entry| {
            let raw = entry.get("value").and_then(|v| v.as_str()).ok_or_else(|| {
                ScimError::invalid_value("each member entry requires a \"value\"")
            })?;
            Uuid::parse_str(raw)
                .map_err(|_| ScimError::invalid_value(format!("invalid member id: {raw:?}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn op(o: &str, path: Option<&str>, value: Option<serde_json::Value>) -> PatchOp {
        PatchOp {
            op: o.to_string(),
            path: path.map(str::to_owned),
            value,
        }
    }

    fn req(ops: Vec<PatchOp>) -> PatchRequest {
        PatchRequest { operations: ops }
    }

    // -----------------------------------------------------------------
    // User PATCH-op matrix: add/replace/remove × every supported path.
    // -----------------------------------------------------------------

    #[test]
    fn user_active_add_and_replace_set_bool() {
        for verb in ["add", "replace"] {
            let d =
                parse_user_patch(&req(vec![op(verb, Some("active"), Some(json!(false)))])).unwrap();
            assert_eq!(d.active, Some(false), "verb={verb}");
        }
    }

    #[test]
    fn user_active_remove_reverts_to_default_true() {
        let d = parse_user_patch(&req(vec![op("remove", Some("active"), None)])).unwrap();
        assert_eq!(d.active, Some(true));
    }

    #[test]
    fn user_username_add_and_replace_set_value() {
        for verb in ["add", "replace"] {
            let d = parse_user_patch(&req(vec![op(
                verb,
                Some("userName"),
                Some(json!("alice2")),
            )]))
            .unwrap();
            assert_eq!(d.username, Some("alice2".to_string()), "verb={verb}");
        }
    }

    #[test]
    fn user_username_remove_is_rejected() {
        let err = parse_user_patch(&req(vec![op("remove", Some("userName"), None)])).unwrap_err();
        assert_eq!(err.scim_type, Some("mutability"));
    }

    #[test]
    fn user_externalid_add_replace_remove() {
        let d = parse_user_patch(&req(vec![op(
            "add",
            Some("externalId"),
            Some(json!("ext-1")),
        )]))
        .unwrap();
        assert_eq!(d.external_id, Some(Some("ext-1".to_string())));

        let d = parse_user_patch(&req(vec![op(
            "replace",
            Some("externalId"),
            Some(json!("ext-2")),
        )]))
        .unwrap();
        assert_eq!(d.external_id, Some(Some("ext-2".to_string())));

        let d = parse_user_patch(&req(vec![op("remove", Some("externalId"), None)])).unwrap();
        assert_eq!(d.external_id, Some(None));
    }

    #[test]
    fn user_name_subpaths_add_replace_remove() {
        for path in ["name.givenName", "name.familyName", "name.formatted"] {
            let d = parse_user_patch(&req(vec![op("add", Some(path), Some(json!("X")))])).unwrap();
            let d2 =
                parse_user_patch(&req(vec![op("replace", Some(path), Some(json!("Y")))])).unwrap();
            let d3 = parse_user_patch(&req(vec![op("remove", Some(path), None)])).unwrap();
            match path {
                "name.givenName" => {
                    assert_eq!(d.given_name, Some(Some("X".into())));
                    assert_eq!(d2.given_name, Some(Some("Y".into())));
                    assert_eq!(d3.given_name, Some(None));
                }
                "name.familyName" => {
                    assert_eq!(d.family_name, Some(Some("X".into())));
                    assert_eq!(d2.family_name, Some(Some("Y".into())));
                    assert_eq!(d3.family_name, Some(None));
                }
                _ => {
                    assert_eq!(d.formatted, Some(Some("X".into())));
                    assert_eq!(d2.formatted, Some(Some("Y".into())));
                    assert_eq!(d3.formatted, Some(None));
                }
            }
        }
    }

    #[test]
    fn user_emails_add_and_replace_extract_primary() {
        let value = json!([
            {"value": "old@x.com", "primary": false},
            {"value": "new@x.com", "primary": true}
        ]);
        for verb in ["add", "replace"] {
            let d = parse_user_patch(&req(vec![op(verb, Some("emails"), Some(value.clone()))]))
                .unwrap();
            assert_eq!(d.email, Some("new@x.com".to_string()), "verb={verb}");
        }
    }

    #[test]
    fn user_emails_remove_is_rejected() {
        let err = parse_user_patch(&req(vec![op("remove", Some("emails"), None)])).unwrap_err();
        assert_eq!(err.scim_type, Some("mutability"));
    }

    #[test]
    fn user_password_add_and_replace_set_value() {
        for verb in ["add", "replace"] {
            let d = parse_user_patch(&req(vec![op(
                verb,
                Some("password"),
                Some(json!("N3wPassw0rd!")),
            )]))
            .unwrap();
            assert_eq!(d.password, Some("N3wPassw0rd!".to_string()), "verb={verb}");
        }
    }

    #[test]
    fn user_password_remove_is_rejected() {
        let err = parse_user_patch(&req(vec![op("remove", Some("password"), None)])).unwrap_err();
        assert_eq!(err.scim_type, Some("invalidPath"));
    }

    #[test]
    fn user_unsupported_path_is_invalid_path() {
        let err = parse_user_patch(&req(vec![op(
            "replace",
            Some("nickname"),
            Some(json!("x")),
        )]))
        .unwrap_err();
        assert_eq!(err.scim_type, Some("invalidPath"));
    }

    #[test]
    fn user_unknown_op_is_invalid_value() {
        let err = parse_user_patch(&req(vec![op("move", Some("active"), Some(json!(true)))]))
            .unwrap_err();
        assert_eq!(err.scim_type, Some("invalidValue"));
    }

    #[test]
    fn user_pathless_replace_recurses_into_object_keys() {
        // Entra's shape: {"op":"replace","value":{"active":false}}
        let d = parse_user_patch(&req(vec![op(
            "replace",
            None,
            Some(json!({"active": false})),
        )]))
        .unwrap();
        assert_eq!(d.active, Some(false));
    }

    #[test]
    fn user_pathless_add_is_rejected() {
        let err = parse_user_patch(&req(vec![op("add", None, Some(json!({"active": false})))]))
            .unwrap_err();
        assert_eq!(err.scim_type, Some("invalidPath"));
    }

    // -----------------------------------------------------------------
    // Group PATCH-op matrix.
    // -----------------------------------------------------------------

    #[test]
    fn group_displayname_add_and_replace() {
        for verb in ["add", "replace"] {
            let d = parse_group_patch(&req(vec![op(
                verb,
                Some("displayName"),
                Some(json!("Eng")),
            )]))
            .unwrap();
            assert_eq!(d.display_name, Some("Eng".to_string()), "verb={verb}");
        }
    }

    #[test]
    fn group_displayname_remove_is_rejected() {
        let err =
            parse_group_patch(&req(vec![op("remove", Some("displayName"), None)])).unwrap_err();
        assert_eq!(err.scim_type, Some("mutability"));
    }

    #[test]
    fn group_externalid_add_replace_remove() {
        let d = parse_group_patch(&req(vec![op(
            "add",
            Some("externalId"),
            Some(json!("g-1")),
        )]))
        .unwrap();
        assert_eq!(d.external_id, Some(Some("g-1".to_string())));
        let d = parse_group_patch(&req(vec![op("remove", Some("externalId"), None)])).unwrap();
        assert_eq!(d.external_id, Some(None));
    }

    #[test]
    fn group_members_add() {
        let id = Uuid::new_v4();
        let d = parse_group_patch(&req(vec![op(
            "add",
            Some("members"),
            Some(json!([{"value": id.to_string()}])),
        )]))
        .unwrap();
        assert_eq!(d.member_actions, vec![MemberAction::Add(id)]);
    }

    #[test]
    fn group_members_replace_clears_then_adds() {
        let id = Uuid::new_v4();
        let d = parse_group_patch(&req(vec![op(
            "replace",
            Some("members"),
            Some(json!([{"value": id.to_string()}])),
        )]))
        .unwrap();
        assert_eq!(
            d.member_actions,
            vec![MemberAction::RemoveAll, MemberAction::Add(id)]
        );
    }

    #[test]
    fn group_members_remove_with_value_removes_listed() {
        let id = Uuid::new_v4();
        let d = parse_group_patch(&req(vec![op(
            "remove",
            Some("members"),
            Some(json!([{"value": id.to_string()}])),
        )]))
        .unwrap();
        assert_eq!(d.member_actions, vec![MemberAction::Remove(id)]);
    }

    #[test]
    fn group_members_remove_without_value_removes_all() {
        let d = parse_group_patch(&req(vec![op("remove", Some("members"), None)])).unwrap();
        assert_eq!(d.member_actions, vec![MemberAction::RemoveAll]);
    }

    #[test]
    fn group_members_filtered_remove_single_member_okta_shape() {
        let id = Uuid::new_v4();
        let path = format!("members[value eq \"{id}\"]");
        let d = parse_group_patch(&req(vec![op("remove", Some(&path), None)])).unwrap();
        assert_eq!(d.member_actions, vec![MemberAction::Remove(id)]);
    }

    #[test]
    fn group_members_filtered_add_is_rejected() {
        let id = Uuid::new_v4();
        let path = format!("members[value eq \"{id}\"]");
        let err = parse_group_patch(&req(vec![op("add", Some(&path), None)])).unwrap_err();
        assert_eq!(err.scim_type, Some("invalidPath"));
    }

    #[test]
    fn group_unsupported_path_is_invalid_path() {
        let err = parse_group_patch(&req(vec![op("replace", Some("owner"), Some(json!("x")))]))
            .unwrap_err();
        assert_eq!(err.scim_type, Some("invalidPath"));
    }

    #[test]
    fn group_patch_without_path_is_rejected() {
        let err = parse_group_patch(&req(vec![op(
            "replace",
            None,
            Some(json!({"displayName": "x"})),
        )]))
        .unwrap_err();
        assert_eq!(err.scim_type, Some("invalidPath"));
    }
}

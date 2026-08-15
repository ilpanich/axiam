//! Storage for SCIM-only fields (`externalId`, `name.*`) inside the existing
//! generic `metadata: serde_json::Value` column AXIAM's `User`/`Group`
//! models already carry, instead of adding new schema (B4: "map onto the
//! EXISTING user/group repositories — do not create parallel storage").
//!
//! Everything SCIM writes lives under a single top-level `"scim"` key so it
//! can never collide with metadata some other feature (or the admin UI)
//! writes into the same column, and a PUT/PATCH that touches only SCIM
//! fields never disturbs those other keys.

use serde_json::{Map, Value};

const SCIM_KEY: &str = "scim";

/// Read `metadata.scim.<field>` as a string, or `None` if absent/not a string.
pub fn get_str(metadata: &Value, field: &str) -> Option<String> {
    metadata
        .get(SCIM_KEY)?
        .get(field)?
        .as_str()
        .map(str::to_owned)
}

/// Set (`Some`) or remove (`None`) `metadata.scim.<field>`, leaving every
/// other key — under `"scim"` or at the top level — untouched. Creates the
/// `"scim"` sub-object (and, if `metadata` wasn't already a JSON object, the
/// object itself) on demand.
pub fn set_str(metadata: &mut Value, field: &str, value: Option<String>) {
    if !metadata.is_object() {
        *metadata = Value::Object(Map::new());
    }
    let obj = metadata.as_object_mut().expect("just ensured object above");
    let scim = obj
        .entry(SCIM_KEY)
        .or_insert_with(|| Value::Object(Map::new()));
    if !scim.is_object() {
        *scim = Value::Object(Map::new());
    }
    let scim_obj = scim.as_object_mut().expect("just ensured object above");
    match value {
        Some(v) => {
            scim_obj.insert(field.to_string(), Value::String(v));
        }
        None => {
            scim_obj.remove(field);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn set_then_get_round_trips() {
        let mut meta = json!({});
        set_str(&mut meta, "externalId", Some("ext-1".into()));
        assert_eq!(get_str(&meta, "externalId"), Some("ext-1".to_string()));
    }

    #[test]
    fn set_none_removes_field() {
        let mut meta = json!({"scim": {"externalId": "ext-1"}});
        set_str(&mut meta, "externalId", None);
        assert_eq!(get_str(&meta, "externalId"), None);
        // The (now-empty) "scim" object stays — harmless, and simpler than
        // pruning it back out.
        assert!(meta.get("scim").is_some());
    }

    #[test]
    fn preserves_unrelated_top_level_and_scim_keys() {
        let mut meta = json!({"app_note": "keep me", "scim": {"givenName": "Alice"}});
        set_str(&mut meta, "externalId", Some("ext-1".into()));
        assert_eq!(meta["app_note"], "keep me");
        assert_eq!(get_str(&meta, "givenName"), Some("Alice".to_string()));
        assert_eq!(get_str(&meta, "externalId"), Some("ext-1".to_string()));
    }

    #[test]
    fn non_object_metadata_is_replaced_not_panicked_on() {
        let mut meta = Value::Null;
        set_str(&mut meta, "externalId", Some("ext-1".into()));
        assert_eq!(get_str(&meta, "externalId"), Some("ext-1".to_string()));
    }
}

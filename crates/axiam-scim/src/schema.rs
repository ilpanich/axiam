//! SCIM service-discovery endpoints (RFC 7643 §5, §7, §8):
//! `GET /Schemas`, `GET /ServiceProviderConfig`, `GET /ResourceTypes`.
//!
//! Every SCIM client Okta/Entra ship fetches these before provisioning
//! anything, to learn which attributes exist and which operations are
//! supported. The bodies below are hand-authored, static JSON — they are not
//! derived from `axiam-core`'s `User`/`Group` structs (those carry AXIAM
//! fields like `password_hash` that must never appear here) but they DO
//! reflect exactly the attribute subset `users.rs`/`groups.rs` actually
//! read/write, and the filter/PATCH subset `filter.rs`/`patch.rs` actually
//! implement. If that subset changes, these bodies must change with it.

use actix_web::{HttpResponse, ResponseError, web};
use serde_json::json;

pub const SCIM_LIST_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

/// `GET /scim/v2/ServiceProviderConfig` (RFC 7643 §5).
///
/// Advertises exactly what this crate implements: no bulk, no PATCH-less
/// mode, filter support (so clients know `filter=` is honored, even though
/// only the `eq` subset works), and ETag as documented-not-implemented
/// (`etag.supported = false` — see `users.rs`/`groups.rs` module docs for
/// the weak-ETag-emission TODO).
pub async fn service_provider_config() -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://github.com/emanuele/axiam/blob/main/docs/api/scim-provisioning.md",
        "patch": { "supported": true },
        "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter": { "supported": true, "maxResults": 200 },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": false },
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "AXIAM Bearer Token",
            "description": "Authenticate with an AXIAM access token (Authorization: Bearer <token>) belonging to a principal granted the scim:provision permission for this tenant.",
            "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
            "primary": true
        }],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": "/scim/v2/ServiceProviderConfig"
        }
    }))
}

/// `GET /scim/v2/ResourceTypes` (RFC 7643 §6).
pub async fn resource_types() -> HttpResponse {
    HttpResponse::Ok().json(resource_types_list())
}

/// `GET /scim/v2/ResourceTypes/{name}` — single-resource lookup variant.
pub async fn resource_type(path: web::Path<String>) -> HttpResponse {
    let name = path.into_inner();
    match resource_types_list()["Resources"]
        .as_array()
        .and_then(|items| items.iter().find(|r| r["id"] == name))
    {
        Some(item) => HttpResponse::Ok().json(item),
        None => crate::error::ScimError::not_found("ResourceType", &name).error_response(),
    }
}

fn resource_types_list() -> serde_json::Value {
    let resources = [
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "description": "AXIAM tenant user account",
            "schema": USER_SCHEMA,
            "meta": { "resourceType": "ResourceType", "location": "/scim/v2/ResourceTypes/User" }
        }),
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "description": "AXIAM tenant group",
            "schema": GROUP_SCHEMA,
            "meta": { "resourceType": "ResourceType", "location": "/scim/v2/ResourceTypes/Group" }
        }),
    ];
    json!({
        "schemas": [SCIM_LIST_RESPONSE_SCHEMA],
        "totalResults": resources.len(),
        "itemsPerPage": resources.len(),
        "startIndex": 1,
        "Resources": resources
    })
}

/// `GET /scim/v2/Schemas` (RFC 7643 §7). Lists the two core schemas this
/// service provider supports, each with its supported-attribute subset.
pub async fn schemas() -> HttpResponse {
    HttpResponse::Ok().json(schemas_list())
}

/// `GET /scim/v2/Schemas/{id}` — single-schema lookup variant.
pub async fn schema_by_id(path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    match schemas_list()["Resources"]
        .as_array()
        .and_then(|items| items.iter().find(|r| r["id"] == id))
    {
        Some(item) => HttpResponse::Ok().json(item),
        None => crate::error::ScimError::not_found("Schema", &id).error_response(),
    }
}

fn attr(
    name: &str,
    attr_type: &str,
    multi_valued: bool,
    required: bool,
    mutability: &str,
) -> serde_json::Value {
    json!({
        "name": name,
        "type": attr_type,
        "multiValued": multi_valued,
        "required": required,
        "caseExact": false,
        "mutability": mutability,
        "returned": "default",
        "uniqueness": "none"
    })
}

fn schemas_list() -> serde_json::Value {
    let user_schema = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
        "id": USER_SCHEMA,
        "name": "User",
        "description": "AXIAM user account — see docs/api/scim-provisioning.md for the field mapping (username <-> userName, status <-> active, metadata carries externalId/name).",
        "attributes": [
            attr("userName", "string", false, true, "readWrite"),
            attr("externalId", "string", false, false, "readWrite"),
            json!({
                "name": "name", "type": "complex", "multiValued": false, "required": false,
                "mutability": "readWrite", "returned": "default", "uniqueness": "none",
                "subAttributes": [
                    attr("givenName", "string", false, false, "readWrite"),
                    attr("familyName", "string", false, false, "readWrite"),
                    attr("formatted", "string", false, false, "readWrite")
                ]
            }),
            json!({
                "name": "emails", "type": "complex", "multiValued": true, "required": false,
                "mutability": "readWrite", "returned": "default", "uniqueness": "none",
                "subAttributes": [
                    attr("value", "string", false, false, "readWrite"),
                    attr("primary", "boolean", false, false, "readWrite")
                ]
            }),
            attr("active", "boolean", false, false, "readWrite"),
            attr("password", "string", false, false, "writeOnly"),
            json!({
                "name": "meta", "type": "complex", "multiValued": false, "required": false,
                "mutability": "readOnly", "returned": "default", "uniqueness": "none",
                "subAttributes": [
                    attr("resourceType", "string", false, false, "readOnly"),
                    attr("created", "dateTime", false, false, "readOnly"),
                    attr("lastModified", "dateTime", false, false, "readOnly"),
                    attr("location", "string", false, false, "readOnly")
                ]
            })
        ],
        "meta": { "resourceType": "Schema", "location": format!("/scim/v2/Schemas/{USER_SCHEMA}") }
    });

    let group_schema = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
        "id": GROUP_SCHEMA,
        "name": "Group",
        "description": "AXIAM group — see docs/api/scim-provisioning.md.",
        "attributes": [
            attr("displayName", "string", false, true, "readWrite"),
            attr("externalId", "string", false, false, "readWrite"),
            json!({
                "name": "members", "type": "complex", "multiValued": true, "required": false,
                "mutability": "readWrite", "returned": "default", "uniqueness": "none",
                "subAttributes": [
                    attr("value", "string", false, true, "immutable"),
                    attr("display", "string", false, false, "readOnly"),
                    attr("type", "string", false, false, "readOnly")
                ]
            }),
            json!({
                "name": "meta", "type": "complex", "multiValued": false, "required": false,
                "mutability": "readOnly", "returned": "default", "uniqueness": "none",
                "subAttributes": [
                    attr("resourceType", "string", false, false, "readOnly"),
                    attr("created", "dateTime", false, false, "readOnly"),
                    attr("lastModified", "dateTime", false, false, "readOnly"),
                    attr("location", "string", false, false, "readOnly")
                ]
            })
        ],
        "meta": { "resourceType": "Schema", "location": format!("/scim/v2/Schemas/{GROUP_SCHEMA}") }
    });

    let resources = [user_schema, group_schema];
    json!({
        "schemas": [SCIM_LIST_RESPONSE_SCHEMA],
        "totalResults": resources.len(),
        "itemsPerPage": resources.len(),
        "startIndex": 1,
        "Resources": resources
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn body_json(resp: HttpResponse) -> serde_json::Value {
        let bytes = actix_web::body::to_bytes(resp.into_body()).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[actix_web::test]
    async fn service_provider_config_disables_bulk_and_advertises_patch() {
        let resp = service_provider_config().await;
        let json = body_json(resp).await;
        assert_eq!(json["bulk"]["supported"], false);
        assert_eq!(json["patch"]["supported"], true);
        assert_eq!(json["filter"]["supported"], true);
    }

    #[actix_web::test]
    async fn resource_types_lists_user_and_group() {
        let resp = resource_types().await;
        let json = body_json(resp).await;
        let ids: Vec<&str> = json["Resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["User", "Group"]);
    }

    #[actix_web::test]
    async fn resource_type_lookup_by_name() {
        let resp = resource_type(web::Path::from("User".to_string())).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["endpoint"], "/Users");
    }

    #[actix_web::test]
    async fn resource_type_lookup_unknown_is_404() {
        let resp = resource_type(web::Path::from("Widget".to_string())).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::NOT_FOUND);
    }

    #[actix_web::test]
    async fn schemas_lists_user_and_group_core_schemas() {
        let resp = schemas().await;
        let json = body_json(resp).await;
        let ids: Vec<&str> = json["Resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec![USER_SCHEMA, GROUP_SCHEMA]);
    }

    #[actix_web::test]
    async fn schema_by_id_lookup_unknown_is_404() {
        let resp = schema_by_id(web::Path::from("urn:nope".to_string())).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::NOT_FOUND);
    }
}

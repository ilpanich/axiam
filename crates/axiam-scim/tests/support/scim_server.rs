//! A loopback SCIM 2.0 service provider: the oracle of the outbound tests
//! (G-6, T23.6.2).
//!
//! It stores Users and Groups, honours `?filter=externalId eq "…"` (and
//! `userName eq`), applies RFC 7644 §3.5.2 `replace` operations, can be told to
//! answer a given status for the next *n* requests, and **records every request**:
//! method, path, query, which headers were present (the *scheme* of the
//! `Authorization` header, never its value) and the JSON body.
//!
//! No credential value is ever recorded or exposed by an accessor. The server
//! checks credentials internally: [`TestScimServer::accept_token`] tells it
//! which bearer value is good, and its token endpoint issues generated ones.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use actix_web::dev::ServerHandle;
use actix_web::http::StatusCode;
use actix_web::{App, HttpRequest, HttpResponse, HttpServer, web};
use serde_json::{Value, json};
use uuid::Uuid;

/// One request the server received.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub query: String,
    /// The scheme of the `Authorization` header (`Bearer`, `Basic`), or `None`
    /// when the header was absent. Never the credential.
    pub authorization_scheme: Option<String>,
    pub content_type: Option<String>,
    pub accept: Option<String>,
    /// The JSON body, or `Null`. A token request's form body is recorded as a
    /// string.
    pub body: Value,
}

struct Forced {
    method: Option<String>,
    path_prefix: String,
    remaining: usize,
    status: u16,
    location: Option<String>,
}

#[derive(Default)]
struct Inner {
    users: Vec<Value>,
    groups: Vec<Value>,
    requests: Vec<Recorded>,
    forced: Vec<Forced>,
    accepted: HashSet<String>,
    issued: usize,
    require_auth: bool,
    token_expires_in: u64,
    /// A list that never ends: every page is full and `totalResults` is huge.
    endless_lists: bool,
}

/// The server. Dropping it stops it.
pub struct TestScimServer {
    pub port: u16,
    inner: Arc<Mutex<Inner>>,
    handle: ServerHandle,
}

impl Drop for TestScimServer {
    fn drop(&mut self) {
        // Stop accepting; the System of the test ends with it.
        let handle = self.handle.clone();
        actix_web::rt::spawn(async move {
            handle.stop(false).await;
        });
    }
}

impl TestScimServer {
    /// Start on `127.0.0.1:0`. Must be called inside an actix runtime.
    pub fn start() -> Self {
        let inner = Arc::new(Mutex::new(Inner {
            token_expires_in: 3600,
            ..Inner::default()
        }));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let port = listener.local_addr().expect("a local address").port();
        let shared = inner.clone();
        let server = HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(shared.clone()))
                .default_service(web::to(handle))
        })
        .workers(1)
        .listen(listener)
        .expect("listen")
        .run();
        let handle = server.handle();
        actix_web::rt::spawn(server);
        Self {
            port,
            inner,
            handle,
        }
    }

    /// The SCIM service root a target is registered with.
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}/scim/v2", self.port)
    }

    pub fn token_url(&self) -> String {
        format!("http://127.0.0.1:{}/oauth/token", self.port)
    }

    /// From now on a request to `/scim/v2` must carry `Authorization: Bearer`
    /// with an accepted value, else it is a `401`.
    pub fn require_auth(&self) {
        self.inner.lock().unwrap().require_auth = true;
    }

    /// Accept this bearer value.
    pub fn accept_token(&self, value: &str) {
        self.inner.lock().unwrap().accepted.insert(value.to_owned());
    }

    /// Forget every accepted and issued token: the next use is a `401`.
    pub fn revoke_all_tokens(&self) {
        self.inner.lock().unwrap().accepted.clear();
    }

    /// From now on every `GET /Users` and `/Groups` answers a full page of
    /// resources that are nobody's and reports a huge `totalResults`: a
    /// downstream a reconciliation run must stop reading by its own budget.
    pub fn set_endless_lists(&self) {
        self.inner.lock().unwrap().endless_lists = true;
    }

    /// The `expires_in` the token endpoint reports.
    pub fn set_token_expires_in(&self, seconds: u64) {
        self.inner.lock().unwrap().token_expires_in = seconds;
    }

    /// Answer `status` to the next `n` SCIM requests of any method.
    pub fn fail_next(&self, n: usize, status: u16) {
        self.force(None, "/scim/v2", n, status, None);
    }

    /// Answer `status` to the next `n` requests of `method` whose path starts
    /// with `prefix`.
    pub fn fail_next_on(&self, method: &str, prefix: &str, n: usize, status: u16) {
        self.force(Some(method), prefix, n, status, None);
    }

    /// Answer a redirect to `location` to the next `n` SCIM requests.
    pub fn redirect_next(&self, n: usize, status: u16, location: &str) {
        self.force(None, "/scim/v2", n, status, Some(location.to_owned()));
    }

    fn force(
        &self,
        method: Option<&str>,
        prefix: &str,
        n: usize,
        status: u16,
        location: Option<String>,
    ) {
        self.inner.lock().unwrap().forced.push(Forced {
            method: method.map(str::to_owned),
            path_prefix: prefix.to_owned(),
            remaining: n,
            status,
            location,
        });
    }

    /// Put a user in the store as if the downstream's own application had made
    /// it. Returns its id.
    pub fn seed_user(&self, resource: Value) -> String {
        Self::seed(&mut self.inner.lock().unwrap().users, resource)
    }

    pub fn seed_group(&self, resource: Value) -> String {
        Self::seed(&mut self.inner.lock().unwrap().groups, resource)
    }

    fn seed(store: &mut Vec<Value>, mut resource: Value) -> String {
        let id = Uuid::new_v4().to_string();
        resource["id"] = json!(id);
        store.push(resource);
        id
    }

    /// Remove a resource behind AXIAM's back.
    pub fn forget_user(&self, id: &str) {
        self.inner
            .lock()
            .unwrap()
            .users
            .retain(|u| u["id"] != json!(id));
    }

    /// Edit a user behind AXIAM's back: set `path` (dotted, as in a `replace`
    /// operation) to `value`, the way a downstream administrator would.
    pub fn edit_user(&self, id: &str, path: &str, value: Value) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(user) = inner.users.iter_mut().find(|u| u["id"] == json!(id)) {
            set_path(user, path, value);
        }
    }

    /// As [`Self::edit_user`], for a group.
    pub fn edit_group(&self, id: &str, path: &str, value: Value) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(group) = inner.groups.iter_mut().find(|g| g["id"] == json!(id)) {
            set_path(group, path, value);
        }
    }

    pub fn user(&self, id: &str) -> Option<Value> {
        self.users().into_iter().find(|u| u["id"] == json!(id))
    }

    pub fn users(&self) -> Vec<Value> {
        self.inner.lock().unwrap().users.clone()
    }

    pub fn groups(&self) -> Vec<Value> {
        self.inner.lock().unwrap().groups.clone()
    }

    pub fn user_by_external_id(&self, external_id: &str) -> Option<Value> {
        self.users()
            .into_iter()
            .find(|u| u["externalId"] == json!(external_id))
    }

    pub fn group_by_external_id(&self, external_id: &str) -> Option<Value> {
        self.groups()
            .into_iter()
            .find(|g| g["externalId"] == json!(external_id))
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.inner.lock().unwrap().requests.clone()
    }

    /// The requests of `method` (upper case) whose path starts with `prefix`.
    pub fn requests_of(&self, method: &str, prefix: &str) -> Vec<Recorded> {
        self.requests()
            .into_iter()
            .filter(|r| r.method == method && r.path.starts_with(prefix))
            .collect()
    }

    pub fn clear_requests(&self) {
        self.inner.lock().unwrap().requests.clear();
    }

    /// How many access tokens the token endpoint has issued.
    pub fn tokens_issued(&self) -> usize {
        self.inner.lock().unwrap().issued
    }
}

// ---------------------------------------------------------------------------
// The handler
// ---------------------------------------------------------------------------

fn scim_error(status: u16, scim_type: Option<&str>) -> HttpResponse {
    let mut body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "status": status.to_string(),
    });
    if let Some(kind) = scim_type {
        body["scimType"] = json!(kind);
    }
    HttpResponse::build(StatusCode::from_u16(status).expect("a status"))
        .content_type("application/scim+json")
        .json(body)
}

fn resource_response(status: u16, resource: &Value) -> HttpResponse {
    HttpResponse::build(StatusCode::from_u16(status).expect("a status"))
        .content_type("application/scim+json")
        .json(resource)
}

async fn handle(
    req: HttpRequest,
    body: web::Bytes,
    state: web::Data<Arc<Mutex<Inner>>>,
) -> HttpResponse {
    let header = |name: &str| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let authorization = header("authorization");
    let parsed: Value = serde_json::from_slice(&body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).into_owned()));
    let method = req.method().as_str().to_owned();
    let path = req.path().to_owned();

    let mut inner = state.lock().unwrap();
    inner.requests.push(Recorded {
        method: method.clone(),
        path: path.clone(),
        query: req.query_string().to_owned(),
        authorization_scheme: authorization
            .as_deref()
            .and_then(|v| v.split_once(' '))
            .map(|(scheme, _)| scheme.to_owned()),
        content_type: header("content-type"),
        accept: header("accept"),
        body: if body.is_empty() {
            Value::Null
        } else {
            parsed.clone()
        },
    });

    if path == "/oauth/token" {
        return token_endpoint(&mut inner, authorization.as_deref());
    }

    if inner.require_auth {
        let good = authorization
            .as_deref()
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|token| inner.accepted.contains(token));
        if !good {
            return scim_error(401, None);
        }
    }

    if let Some(forced) = inner.forced.iter_mut().find(|f| {
        f.remaining > 0
            && path.starts_with(&f.path_prefix)
            && f.method.as_deref().is_none_or(|m| m == method)
    }) {
        forced.remaining -= 1;
        let mut response =
            HttpResponse::build(StatusCode::from_u16(forced.status).expect("a status"));
        if let Some(location) = &forced.location {
            response.insert_header(("Location", location.clone()));
        }
        return response.finish();
    }

    let Some(rest) = path.strip_prefix("/scim/v2/") else {
        return scim_error(404, None);
    };
    let mut segments = rest.split('/');
    let collection = segments.next().unwrap_or_default();
    let id = segments.next().map(str::to_owned);
    let query = req.query_string().to_owned();
    let endless = inner.endless_lists;
    let store = match collection {
        "Users" => &mut inner.users,
        "Groups" => &mut inner.groups,
        _ => return scim_error(404, None),
    };
    let is_user = collection == "Users";

    match (method.as_str(), id) {
        ("POST", None) => {
            let duplicate = store.iter().any(|existing| {
                existing["externalId"] == parsed["externalId"]
                    || (is_user && existing["userName"] == parsed["userName"])
            });
            if duplicate {
                return scim_error(409, Some("uniqueness"));
            }
            let mut created = parsed.clone();
            created["id"] = json!(Uuid::new_v4().to_string());
            store.push(created.clone());
            resource_response(201, &created)
        }
        ("GET", None) => {
            let (start_index, count) = paging(&query);
            if endless {
                let page: Vec<Value> = (0..count)
                    .map(|n| {
                        json!({
                            "id": Uuid::new_v4().to_string(),
                            "externalId": format!("downstream-own-{}", start_index + n as u64),
                            "userName": format!("own-{}", start_index + n as u64),
                        })
                    })
                    .collect();
                return HttpResponse::Ok()
                    .content_type("application/scim+json")
                    .json(json!({
                        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                        "totalResults": 1_000_000,
                        "startIndex": start_index,
                        "itemsPerPage": page.len(),
                        "Resources": page,
                    }));
            }
            let wanted = filter_value(&query);
            let matching: Vec<Value> = store
                .iter()
                .filter(|r| match &wanted {
                    Some((attribute, value)) => r[attribute.as_str()] == json!(value),
                    None => true,
                })
                .cloned()
                .collect();
            // RFC 7644 §3.4.2.4: `startIndex` is 1-based; a server may return
            // fewer than `count`.
            let resources: Vec<Value> = matching
                .iter()
                .skip((start_index as usize).saturating_sub(1))
                .take(count)
                .cloned()
                .collect();
            HttpResponse::Ok()
                .content_type("application/scim+json")
                .json(json!({
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                    "totalResults": matching.len(),
                    "startIndex": start_index,
                    "itemsPerPage": resources.len(),
                    "Resources": resources,
                }))
        }
        ("PATCH", Some(id)) => match store.iter_mut().find(|r| r["id"] == json!(id)) {
            None => scim_error(404, None),
            Some(resource) => {
                for operation in parsed["Operations"].as_array().into_iter().flatten() {
                    if operation["op"] == "replace"
                        && let Some(path) = operation["path"].as_str()
                    {
                        set_path(resource, path, operation["value"].clone());
                    }
                }
                resource_response(200, resource)
            }
        },
        ("DELETE", Some(id)) => {
            let before = store.len();
            store.retain(|r| r["id"] != json!(id));
            if store.len() == before {
                scim_error(404, None)
            } else {
                HttpResponse::NoContent().finish()
            }
        }
        ("GET", Some(id)) => match store.iter().find(|r| r["id"] == json!(id)) {
            Some(resource) => resource_response(200, resource),
            None => scim_error(404, None),
        },
        _ => scim_error(405, None),
    }
}

fn token_endpoint(inner: &mut Inner, authorization: Option<&str>) -> HttpResponse {
    if !authorization.is_some_and(|v| v.starts_with("Basic ")) {
        return HttpResponse::Unauthorized().json(json!({"error": "invalid_client"}));
    }
    inner.issued += 1;
    let token = format!("at-{}", Uuid::new_v4().simple());
    inner.accepted.insert(token.clone());
    HttpResponse::Ok().json(json!({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": inner.token_expires_in,
    }))
}

/// `startIndex` (1-based, default 1) and `count` (default: everything).
fn paging(query: &str) -> (u64, usize) {
    let value = |name: &str| {
        url::form_urlencoded::parse(query.as_bytes())
            .find(|(key, _)| key == name)
            .and_then(|(_, v)| v.parse::<u64>().ok())
    };
    (
        value("startIndex").unwrap_or(1).max(1),
        value("count").map_or(usize::MAX, |c| c as usize),
    )
}

/// `filter=externalId eq "x"` → `("externalId", "x")`.
fn filter_value(query: &str) -> Option<(String, String)> {
    let filter = url::form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == "filter")?
        .1
        .into_owned();
    let (attribute, rest) = filter.split_once(" eq ")?;
    Some((
        attribute.to_owned(),
        rest.trim().trim_matches('"').to_owned(),
    ))
}

/// Apply a `replace` to a simple or dotted path.
fn set_path(resource: &mut Value, path: &str, value: Value) {
    let mut parts = path.split('.').peekable();
    let mut cursor = resource;
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            cursor[part] = value;
            return;
        }
        if !cursor[part].is_object() {
            cursor[part] = json!({});
        }
        cursor = &mut cursor[part];
    }
}

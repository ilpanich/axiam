//! B3 — mesh-delegation end-to-end example.
//!
//! A "storefront" user authenticates through a normal authorization-code +
//! PKCE login and ends up holding an access token scoped to `orders:read`.
//! An "orders-mesh-gateway" service receives that token on an inbound
//! request (simulated here — see step 5 below) and, per
//! `docs/api/token-exchange.md`, exchanges it for a *narrower*,
//! actor-annotated token via OAuth2 Token Exchange (RFC 8693) **delegation**
//! (an `actor_token` is present, so the issued token keeps `sub` = the user
//! and gains an `act` claim naming the gateway) before using that token to
//! call the low-latency `axiam.v1.AuthorizationService/CheckAccess` gRPC
//! endpoint — the service-mesh authz check surface `docs/api/grpc.md`
//! describes and the one `docs/api/token-exchange.md` names as the reason
//! Track B's token exchange exists at all.
//!
//! See README.md for prerequisites and what is proven at the end (and its
//! "History" section for a registration gap this example's construction
//! found and that has since been fixed upstream).
//!
//! Run: `cargo run` from this directory, against a running, bootstrapped
//! AXIAM instance (`AXIAM_URL`, `AXIAM_GRPC_URL` env vars; see README.md).

use base64::Engine;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub mod axiam_v1 {
    tonic::include_proto!("axiam.v1");
}

use axiam_v1::CheckAccessRequest;
use axiam_v1::authorization_service_client::AuthorizationServiceClient;

// ---------------------------------------------------------------------------
// Small helpers — deliberately not a framework. Each one is a single HTTP
// call plus the one piece of bookkeeping (CSRF token / status check) every
// caller needs, mirroring the same non-browser pattern
// `examples/b1-deny-override/walkthrough.sh` and `sdks/CONTRACT.md` §3 use.
// ---------------------------------------------------------------------------

/// A fresh 32-byte CSPRNG PKCE pair, per RFC 7636 §4.1 / `sdks/CONTRACT.md`
/// §12.1 rule 2-3 (43-character base64url verifier, S256 challenge).
fn pkce_pair() -> (String, String) {
    let mut raw = [0u8; 32];
    raw[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    raw[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

async fn post_json(
    client: &reqwest::Client,
    url: &str,
    csrf: Option<&str>,
    body: &Value,
) -> anyhow::Result<(reqwest::StatusCode, Value)> {
    let mut req = client.post(url).json(body);
    if let Some(t) = csrf {
        req = req.header("X-CSRF-Token", t);
    }
    let resp = req.send().await?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    Ok((status, body))
}

fn expect_ok(label: &str, status: reqwest::StatusCode, body: &Value) -> anyhow::Result<()> {
    if !status.is_success() {
        anyhow::bail!("{label} -> {status}: {body}");
    }
    Ok(())
}

/// Login (cookie session) and return the `X-CSRF-Token` response header
/// value (`sdks/CONTRACT.md` §3's non-browser pattern) plus the parsed
/// response body.
async fn login(
    client: &reqwest::Client,
    base: &str,
    org_slug: &str,
    tenant_slug: &str,
    username: &str,
    password: &str,
) -> anyhow::Result<(String, Value)> {
    let resp = client
        .post(format!("{base}/api/v1/auth/login"))
        .json(&json!({
            "org_slug": org_slug,
            "tenant_slug": tenant_slug,
            "username_or_email": username,
            "password": password,
        }))
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("login as {username} -> {}", resp.status());
    }
    let csrf = resp
        .headers()
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("login response carried no X-CSRF-Token header"))?;
    let body: Value = resp.json().await?;
    Ok((csrf, body))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let axiam_url = std::env::var("AXIAM_URL").unwrap_or_else(|_| "http://localhost:8090".into());
    let grpc_url =
        std::env::var("AXIAM_GRPC_URL").unwrap_or_else(|_| "http://127.0.0.1:50051".into());
    let org_slug = std::env::var("E2E_ORG_SLUG").unwrap_or_else(|_| "test-org".into());
    let tenant_slug = std::env::var("E2E_TENANT_SLUG").unwrap_or_else(|_| "default".into());
    let admin_email = std::env::var("E2E_ADMIN_EMAIL").unwrap_or_else(|_| "admin@axiam.dev".into());
    // Required, with no baked-in default: a credential literal in source is a
    // hard-coded-secret finding, and examples get copied. The compose stack's
    // value is documented in this example's README instead.
    let admin_password = std::env::var("E2E_ADMIN_PASSWORD").map_err(|_| {
        anyhow::anyhow!(
            "E2E_ADMIN_PASSWORD must be set (see this example's README for the \
             docker-compose.e2e.yml default)"
        )
    })?;

    let run_id = format!(
        "{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        std::process::id()
    );

    // Two independent cookie jars: the admin doing the setup, and the
    // end-user whose browser session mints the inbound token. Real HTTP
    // clients must persist cookies per session (`sdks/CONTRACT.md` §4) —
    // sharing one jar between the two identities would be exactly the bug
    // that requirement exists to prevent.
    let admin = reqwest::Client::builder().cookie_store(true).build()?;
    let user_agent_client = reqwest::Client::builder()
        .cookie_store(true)
        // Do NOT follow the /oauth2/authorize redirect — we need the
        // Location header's `code`, not whatever it points to.
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    println!("== B3 mesh-delegation-grpc ==");
    println!("[1/8] logging in as {admin_email} (admin)");
    let (admin_csrf, admin_login) = login(
        &admin,
        &axiam_url,
        &org_slug,
        &tenant_slug,
        &admin_email,
        &admin_password,
    )
    .await?;
    let tenant_id = admin_login["user"]["tenant_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("login response missing user.tenant_id"))?
        .to_owned();
    println!("      tenant_id={tenant_id}");

    // -----------------------------------------------------------------
    // 2. Fixtures: a resource + permission + role, an end user, and the
    //    two OAuth2 clients this scenario needs.
    // -----------------------------------------------------------------
    println!("[2/8] creating fixtures (resource, permission, role, user, clients)");

    // permission.action and role.name are UNIQUE per tenant (schema.rs), so
    // both carry run_id — otherwise a second run against a persistent stack
    // would 500 on a name collision. This is a distinct namespace from the
    // OAuth2 "orders:read" *scope* string used below (client registration,
    // PKCE, token exchange) — scopes are plain strings on a client row, not
    // a unique-constrained table, so they need no such suffix and are kept
    // stable/readable. resource.name also has no uniqueness constraint.
    let action = format!("orders:read:{run_id}");

    let (status, resource) = post_json(
        &admin,
        &format!("{axiam_url}/api/v1/resources"),
        Some(&admin_csrf),
        &json!({"name": "orders-service", "resource_type": "service", "parent_id": null}),
    )
    .await?;
    expect_ok("create resource", status, &resource)?;
    let resource_id = resource["id"].as_str().unwrap().to_owned();

    let (status, permission) = post_json(
        &admin,
        &format!("{axiam_url}/api/v1/permissions"),
        Some(&admin_csrf),
        &json!({"action": action.clone(), "description": "Read order records"}),
    )
    .await?;
    expect_ok("create permission", status, &permission)?;
    let permission_id = permission["id"].as_str().unwrap().to_owned();

    let (status, role) = post_json(
        &admin,
        &format!("{axiam_url}/api/v1/roles"),
        Some(&admin_csrf),
        &json!({"name": format!("orders-reader-{run_id}"), "description": "Read access to orders-service", "is_global": false}),
    )
    .await?;
    expect_ok("create role", status, &role)?;
    let role_id = role["id"].as_str().unwrap().to_owned();

    let (status, grant) = post_json(
        &admin,
        &format!("{axiam_url}/api/v1/roles/{role_id}/permissions"),
        Some(&admin_csrf),
        &json!({"permission_id": permission_id, "scope_ids": [], "effect": "allow"}),
    )
    .await?;
    expect_ok("grant permission to role", status, &grant)?;

    let user_username = format!("orders-caller-{run_id}");
    let user_email = format!("orders-caller-{run_id}@example.invalid");
    // This example creates the user itself, so nothing needs to know the
    // password ahead of time — generate one per run rather than carrying a
    // literal in source.
    let user_password = format!(
        "Ax{}!aA1",
        uuid::Uuid::new_v4().simple().to_string()[..20].to_uppercase()
    );
    let user_password = user_password.as_str();
    let (status, user) = post_json(
        &admin,
        &format!("{axiam_url}/api/v1/users"),
        Some(&admin_csrf),
        &json!({"username": user_username, "email": user_email, "password": user_password}),
    )
    .await?;
    expect_ok("create user", status, &user)?;
    let user_id = user["id"].as_str().unwrap().to_owned();

    let (status, assignment) = post_json(
        &admin,
        &format!("{axiam_url}/api/v1/roles/{role_id}/users"),
        Some(&admin_csrf),
        &json!({"user_id": user_id, "resource_id": resource_id}),
    )
    .await?;
    expect_ok("assign role to user", status, &assignment)?;

    // The user-facing app the caller logs into (a normal confidential
    // authorization_code client — nothing about it is mesh-specific).
    let redirect_uri = "http://127.0.0.1:9999/callback";
    let (status, storefront) = post_json(
        &admin,
        &format!("{axiam_url}/api/v1/oauth2-clients"),
        Some(&admin_csrf),
        &json!({
            "name": format!("storefront-app-{run_id}"),
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "scopes": ["openid", "orders:read"],
        }),
    )
    .await?;
    expect_ok("register storefront-app client", status, &storefront)?;
    let storefront_client_id = storefront["client_id"].as_str().unwrap().to_owned();
    let storefront_client_secret = storefront["client_secret"].as_str().unwrap().to_owned();

    // The mesh service itself: client_credentials (to authenticate as
    // itself as the actor) + the token-exchange grant (to perform the
    // delegation). Registering a client for
    // "urn:ietf:params:oauth:grant-type:token-exchange" through this REST
    // endpoint requires `KNOWN_GRANT_TYPES` in
    // `crates/axiam-api-rest/src/handlers/oauth2_clients.rs` to include it
    // — it does as of the fix landed alongside this example.
    let (status, gateway) = post_json(
        &admin,
        &format!("{axiam_url}/api/v1/oauth2-clients"),
        Some(&admin_csrf),
        &json!({
            "name": format!("orders-mesh-gateway-{run_id}"),
            "redirect_uris": [],
            "grant_types": [
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ],
            "scopes": ["orders:read"],
        }),
    )
    .await?;
    expect_ok("register orders-mesh-gateway client", status, &gateway)?;
    let gateway_client_id = gateway["client_id"].as_str().unwrap().to_owned();
    let gateway_client_secret = gateway["client_secret"].as_str().unwrap().to_owned();

    // -----------------------------------------------------------------
    // 3. The user logs in (browser-equivalent: a cookie session) and
    //    completes authorization_code + PKCE against storefront-app,
    //    ending up with an access token scoped to orders:read. This is
    //    the "inbound request carrying a user's access token" that
    //    docs/api/token-exchange.md's opening paragraph describes.
    // -----------------------------------------------------------------
    println!("[3/8] user login (browser-equivalent cookie session)");
    login(
        &user_agent_client,
        &axiam_url,
        &org_slug,
        &tenant_slug,
        &user_username,
        user_password,
    )
    .await?;

    println!("[4/8] authorization_code + PKCE against storefront-app");
    let (code_verifier, code_challenge) = pkce_pair();
    let state_param = uuid::Uuid::new_v4().to_string();
    let authorize_url = format!(
        "{axiam_url}/oauth2/authorize?response_type=code&client_id={storefront_client_id}\
         &redirect_uri={redirect_uri}&scope=openid%20orders:read&state={state_param}\
         &code_challenge={code_challenge}&code_challenge_method=S256"
    );
    let authorize_resp = user_agent_client.get(&authorize_url).send().await?;
    if !authorize_resp.status().is_redirection() {
        anyhow::bail!(
            "GET /oauth2/authorize -> {} (expected a redirect)",
            authorize_resp.status()
        );
    }
    let location = authorize_resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("authorize redirect carried no Location header"))?
        .to_owned();
    let redirected = url::Url::parse(&location).unwrap_or_else(|_| {
        // A relative Location (scheme-relative) — anchor it at redirect_uri's origin.
        url::Url::parse(redirect_uri)
            .unwrap()
            .join(&location)
            .unwrap()
    });
    let code = redirected
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .ok_or_else(|| anyhow::anyhow!("no ?code= in the authorize redirect: {location}"))?;

    let token_resp = user_agent_client
        .post(format!("{axiam_url}/oauth2/token?tenant_id={tenant_id}"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("code_verifier", &code_verifier),
            ("redirect_uri", redirect_uri),
            ("client_id", &storefront_client_id),
            ("client_secret", &storefront_client_secret),
        ])
        .send()
        .await?;
    let token_status = token_resp.status();
    let token_body: Value = token_resp.json().await?;
    expect_ok("exchange authorization code", token_status, &token_body)?;
    let subject_token = token_body["access_token"].as_str().unwrap().to_owned();
    println!(
        "      subject token acquired (scope={:?})",
        token_body["scope"]
    );

    // -----------------------------------------------------------------
    // 5. The mesh gateway's own identity: a plain client_credentials
    //    token, used as the `actor_token` below. This is the "request
    //    arrives at the gateway carrying the user's token" moment,
    //    simulated by simply having both tokens in hand in one process —
    //    a real gateway would have the subject_token from the inbound
    //    request and mint this actor_token from its own stored
    //    credentials ahead of time (or cache it).
    // -----------------------------------------------------------------
    println!("[5/8] mesh gateway mints its own actor token (client_credentials)");
    let actor_resp = admin
        .post(format!("{axiam_url}/oauth2/token?tenant_id={tenant_id}"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", gateway_client_id.as_str()),
            ("client_secret", gateway_client_secret.as_str()),
            ("scope", "orders:read"),
        ])
        .send()
        .await?;
    let actor_status = actor_resp.status();
    let actor_body: Value = actor_resp.json().await?;
    expect_ok("mint actor token", actor_status, &actor_body)?;
    let actor_token = actor_body["access_token"].as_str().unwrap().to_owned();

    // -----------------------------------------------------------------
    // 6. The exchange itself — delegation (actor_token present), scope
    //    narrowed to exactly what the downstream check needs.
    // -----------------------------------------------------------------
    println!("[6/8] POST /oauth2/token grant_type=token-exchange (delegation)");
    let exchange_resp = admin
        .post(format!("{axiam_url}/oauth2/token?tenant_id={tenant_id}"))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", subject_token.as_str()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("actor_token", actor_token.as_str()),
            (
                "actor_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("scope", "orders:read"),
            ("client_id", gateway_client_id.as_str()),
            ("client_secret", gateway_client_secret.as_str()),
        ])
        .send()
        .await?;
    let exchange_status = exchange_resp.status();
    let exchange_body: Value = exchange_resp.json().await?;
    expect_ok("token exchange", exchange_status, &exchange_body)?;
    let exchanged_token = exchange_body["access_token"].as_str().unwrap().to_owned();
    println!(
        "      exchanged token acquired (issued_token_type={:?}, scope={:?})",
        exchange_body["issued_token_type"], exchange_body["scope"]
    );

    // -----------------------------------------------------------------
    // 7/8. Use the exchanged (narrower, actor-annotated) token to call
    //    the gRPC AuthorizationService — the mesh data-plane check this
    //    whole example exists to demonstrate. Delegation keeps `sub` =
    //    the original user, so `subject_id` below is the user's UUID,
    //    not the gateway's.
    // -----------------------------------------------------------------
    println!("[7/8] connecting to gRPC AuthorizationService at {grpc_url}");
    let mut grpc = AuthorizationServiceClient::connect(grpc_url).await?;

    let mut request = tonic::Request::new(CheckAccessRequest {
        tenant_id: tenant_id.clone(),
        subject_id: user_id.clone(),
        action: action.clone(),
        resource_id: resource_id.clone(),
        scope: None,
    });
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {exchanged_token}").parse()?,
    );

    println!("[8/8] AuthorizationService/CheckAccess");
    let response = grpc.check_access(request).await?.into_inner();
    println!(
        "      allowed={} reason_code={:?} deny_reason={:?}",
        response.allowed, response.reason_code, response.deny_reason
    );

    if !response.allowed || response.reason_code != "allowed" {
        anyhow::bail!(
            "expected allowed=true reason_code=\"allowed\", got allowed={} reason_code={:?}",
            response.allowed,
            response.reason_code
        );
    }

    println!("\nmesh delegation proved: the gateway never held the user's original token,");
    println!("only a narrower, actor-annotated one — and the gRPC check still resolved");
    println!("access for the original user (sub unchanged, act names the gateway).");
    Ok(())
}

//! 802.1X with an AXIAM-issued `Device` certificate, against a real FreeRADIUS
//! and a real `eapol_test` (W6.2, D3 of the RADIUS spike).
//!
//! The recipe in `docs/pki/freeradius.md` makes claims about a configuration
//! AXIAM does not run and cannot unit-test. This file is the oracle for them:
//! the same AXIAM routes an operator calls issue the certificates, the CA and
//! the revocation list they export go into the shipped FreeRADIUS configuration
//! (`docker/radius/raddb/`, `docker/docker-compose.radius.yml`), and a
//! supplicant implementation somebody else wrote (`eapol_test`, from
//! `wpa_supplicant`) authenticates against it over EAP-TLS.
//!
//! # What is real
//!
//! * FreeRADIUS 3.2.8, the upstream image pinned by digest, with the recipe's
//!   configuration mounted over it and no other change;
//! * `eapol_test` (Ubuntu package `eapoltest`), the supplicant;
//! * the routes: `POST .../ca-certificates`, `POST .../signing-cas`,
//!   `GET .../ca-certificates/{id}` (the export), `POST /certificates`,
//!   `POST /service-accounts/{id}/bind-certificate`, `GET /certificates`,
//!   `POST /certificates/{id}/revoke` and the unauthenticated
//!   `GET /pki/v1/{org}/ca/{ca}/crl`, mounted by the production
//!   `register_api_v1_routes` over an in-memory database, as in
//!   `directory_e2e.rs`.
//!
//! # The cases
//!
//! 1. **issue** — an organization CA, a tenant signing CA and a `Device`
//!    certificate (clientAuth, the CRL distribution point of its issuer);
//! 2. **bind** — the certificate bound to a service account, and listed as such;
//! 3. **accept** — the bound device is admitted, with the VLAN attributes of
//!    RFC 3580 and a bounded `Session-Timeout`;
//! 4. **wrong CA** — a device of another organization, and a device of another
//!    tenant of the same organization, whose signing CA chains to the **same**
//!    organization CA, are refused; the latter also when it presents its signing
//!    CA, and its whole chain up to that shared root, while the tenant's own
//!    device presenting its whole chain is admitted;
//! 5. **revoked after the CRL refresh** — a revoked device keeps being admitted
//!    while FreeRADIUS holds the old list, which is the revocation lag; once the
//!    list AXIAM publishes is in FreeRADIUS's `ca_path` and FreeRADIUS has
//!    re-read it, the device is refused and the others are not;
//!
//! the revocation list reaches FreeRADIUS through `docker/radius/fetch-crl.sh`,
//! the file the guide sends an operator to, run here on the host against a
//! local stand-in for the CRL route (#643, R101W6-04). Beside the refresh the
//! test shows what the script refuses: a list re-signed under **another key
//! with the CA's name** (which `openssl crl -verify` waves through with exit
//! status 0), a **lower-numbered** list that the CA did sign (a replay of the
//! empty list the run started with), and, on a `304`, that the installed list
//! is left alone;
//!
//! and the settings the guide stands behind: a valid certificate that is not in
//! the placement table is refused — also when the table holds a bound
//! certificate whose subject is `DEFAULT`, because the table is keyed on the
//! certificate serial and never on a subject (R101W6-02) — TLS 1.2 is refused,
//! EAP-MD5 is refused, and an Access-Request without a `Message-Authenticator`
//! is discarded.
//!
//! # Gating
//!
//! `cargo test` needs no container, no `eapol_test` and no `docker`: without
//! `AXIAM_E2E_RADIUS=1` the test prints `SKIPPED` and returns. With it set the
//! test is **not** allowed to skip: a missing `docker`, `eapol_test` or
//! `openssl`, or a FreeRADIUS that does not come up, is a failure with the
//! command that fixes it.
//!
//! `AXIAM_E2E_RADIUS_REFRESH=restart` refreshes FreeRADIUS's revocation lists by
//! restarting the container instead of waiting for `ca_path_reload_interval`
//! (300 seconds, the smallest value FreeRADIUS accepts); it is for iterating
//! locally and is not what CI runs. `AXIAM_E2E_RADIUS_KEEP=1` leaves the stack up.
//!
//! # Credentials
//!
//! None is written in this file. The shared secret is random per run; the
//! server certificate, every device key and the CA are minted per run into
//! `docker/.secrets/radius/` (gitignored).

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use actix_web::{App, test, web};
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::state::AppState;
use axiam_api_rest::{RateLimitConfig, register_api_v1_routes};
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_test_support::test_password;
use serde_json::{Value, json};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const CONTAINER: &str = "axiam-radius-e2e-freeradius";
const CSRF_TOKEN: &str = "radius-e2e-csrf-token";
/// The CRL route is metered per IP; the test says which one it is.
const CRL_PEER: &str = "203.0.113.30:4000";
/// The VLAN the placement table puts every device on.
const VLAN: &str = "20";

// ===========================================================================
// The gate, and the commands the test shells out to
// ===========================================================================

fn gate() -> bool {
    if std::env::var("AXIAM_E2E_RADIUS").as_deref() != Ok("1") {
        eprintln!(
            "SKIPPED: set AXIAM_E2E_RADIUS=1 (with docker, `eapol_test` and `openssl` installed) \
             to run the FreeRADIUS e2e; see docker/radius/README.md"
        );
        return false;
    }
    for (program, probe, hint) in [
        (
            "docker",
            vec!["compose", "version"],
            "install Docker with the compose plugin",
        ),
        (
            "openssl",
            vec!["version"],
            "install openssl (sudo apt-get install -y openssl)",
        ),
        (
            "curl",
            vec!["--version"],
            "install curl (the CRL fetch script, docker/radius/fetch-crl.sh, needs it)",
        ),
        (
            "eapol_test",
            // `eapol_test` has no version flag; an unknown one prints usage.
            vec!["-h"],
            "install it with `sudo apt-get install -y eapoltest` (wpa_supplicant's test tool)",
        ),
    ] {
        assert!(
            Command::new(program)
                .args(&probe)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok(),
            "AXIAM_E2E_RADIUS is set but `{program}` cannot be run: {hint}"
        );
    }
    true
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Where the run's material goes: `docker/.secrets/radius` unless
/// `AXIAM_E2E_RADIUS_DIR` says otherwise. Wiped at the start of a run, so the
/// last path component must say what it is.
fn work_dir() -> PathBuf {
    let dir = std::env::var_os("AXIAM_E2E_RADIUS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root().join("docker/.secrets/radius"));
    assert!(
        dir.file_name().is_some_and(|n| n == "radius"),
        "AXIAM_E2E_RADIUS_DIR must end in `radius`: the test deletes and recreates it"
    );
    dir
}

/// Run a command to completion and require success; on failure the panic
/// carries the command's own stderr and stdout.
fn run_ok(program: &str, args: &[&str]) -> String {
    let out = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("`{program}` could not be run: {e}"));
    assert!(
        out.status.success(),
        "`{program} {}` failed ({}):\n{}\n{}",
        args.join(" "),
        out.status,
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("a UTF-8 path")
}

fn openssl_in(args: &[&str], stdin: &[u8]) -> Vec<u8> {
    let mut child = Command::new("openssl")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("openssl can be run");
    {
        use std::io::Write as _;
        child
            .stdin
            .take()
            .expect("a piped stdin")
            .write_all(stdin)
            .expect("openssl takes its input");
    }
    let out = child.wait_with_output().expect("openssl finishes");
    assert!(
        out.status.success(),
        "`openssl {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs()
}

// ===========================================================================
// The FreeRADIUS stack
// ===========================================================================

struct Stack {
    compose: PathBuf,
    env_file: PathBuf,
}

impl Stack {
    fn new(work: &Path) -> Self {
        Self {
            compose: repo_root().join("docker/docker-compose.radius.yml"),
            env_file: work.join("env"),
        }
    }

    fn compose(&self, args: &[&str]) -> std::process::Output {
        Command::new("docker")
            .args(["compose", "-f", path_str(&self.compose), "--env-file"])
            .arg(&self.env_file)
            .args(args)
            .output()
            .expect("`docker compose` can be run")
    }

    fn up(&self) {
        // A stack left by an aborted run would keep the fixed address.
        let _ = self.compose(&["down", "-v"]);
        let out = self.compose(&["up", "-d", "--wait"]);
        assert!(
            out.status.success(),
            "FreeRADIUS did not come up (docker compose up -d --wait -f \
             docker/docker-compose.radius.yml):\n{}\n{}\n--- container log ---\n{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout),
            self.log_tail()
        );
    }

    fn restart(&self) {
        let out = self.compose(&["restart", "--no-deps", "freeradius"]);
        assert!(
            out.status.success(),
            "restarting FreeRADIUS failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        // `restart` does not wait for the healthcheck.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let health = Command::new("docker")
                .args(["inspect", "--format", "{{.State.Health.Status}}", CONTAINER])
                .output()
                .expect("docker inspect");
            if String::from_utf8_lossy(&health.stdout).trim() == "healthy" {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "FreeRADIUS did not become healthy after the restart"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// The server's log since `epoch` (Unix seconds), stdout and stderr.
    fn log_since(&self, epoch: u64) -> String {
        let out = Command::new("docker")
            .args(["logs", "--since", &epoch.to_string(), CONTAINER])
            .output()
            .expect("docker logs");
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }

    fn log_tail(&self) -> String {
        let out = Command::new("docker")
            .args(["logs", "--tail", "200", CONTAINER])
            .output()
            .expect("docker logs");
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "--- FreeRADIUS log (last 200 lines) ---\n{}",
                self.log_tail()
            );
        }
        if std::env::var("AXIAM_E2E_RADIUS_KEEP").as_deref() == Ok("1") {
            eprintln!("AXIAM_E2E_RADIUS_KEEP=1: the stack is left up (docker/radius/README.md)");
            return;
        }
        let _ = self.compose(&["down", "-v"]);
    }
}

/// What one `eapol_test` run said.
struct Attempt {
    accepted: bool,
    /// `eapol_test`'s own output, for the RADIUS attributes of an Accept.
    output: String,
    /// FreeRADIUS's log from the moment the attempt started.
    log: String,
}

impl Attempt {
    /// What to print when an assertion about this attempt fails: the end of
    /// `eapol_test`'s output (the supplicant's side) and the server's log.
    fn report(&self) -> String {
        let lines: Vec<&str> = self.output.lines().collect();
        let tail = lines[lines.len().saturating_sub(40)..].join("\n");
        format!(
            "--- eapol_test (last 40 lines) ---\n{tail}\n--- FreeRADIUS ---\n{}",
            self.log
        )
    }
}

struct Radius<'a> {
    stack: &'a Stack,
    work: PathBuf,
    ip: String,
    secret: String,
}

impl Radius<'_> {
    /// Authenticate with EAP-TLS and the given device files.
    fn eap_tls(&self, name: &str, cert: &str, key: &str, tls13: bool) -> Attempt {
        let conf = self.work.join(format!("supplicant-{name}.conf"));
        std::fs::write(
            &conf,
            format!(
                "network={{\n\tssid=\"axiam-e2e\"\n\tkey_mgmt=WPA-EAP\n\teap=TLS\n\
                 \tidentity=\"{name}\"\n\tca_cert=\"{ca}\"\n\tclient_cert=\"{cert}\"\n\
                 \tprivate_key=\"{key}\"\n\tphase1=\"tls_disable_tlsv1_3={disable}\"\n}}\n",
                ca = path_str(&self.work.join("server-ca.pem")),
                disable = if tls13 { 0 } else { 1 },
            ),
        )
        .expect("the supplicant configuration can be written");
        self.run_eapol(&conf)
    }

    /// Authenticate with EAP-MD5 (a method this server does not offer).
    fn eap_md5(&self) -> Attempt {
        let conf = self.work.join("supplicant-md5.conf");
        std::fs::write(
            &conf,
            "network={\n\tssid=\"axiam-e2e\"\n\tkey_mgmt=WPA-EAP\n\teap=MD5\n\
             \tidentity=\"md5-device\"\n\tpassword=\"not-a-real-password\"\n}\n",
        )
        .expect("the supplicant configuration can be written");
        self.run_eapol(&conf)
    }

    fn run_eapol(&self, conf: &Path) -> Attempt {
        // FreeRADIUS logs with one-second resolution: start each attempt in a
        // second of its own so a reason read from the log is this attempt's.
        std::thread::sleep(Duration::from_millis(1100));
        let since = unix_now();
        let out = Command::new("eapol_test")
            .args(["-c", path_str(conf), "-a", &self.ip, "-p", "1812", "-s"])
            .arg(&self.secret)
            .args(["-t", "20"])
            .output()
            .expect("eapol_test can be run");
        let output = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        // Let the server finish writing the decision.
        std::thread::sleep(Duration::from_millis(300));
        let accepted = output
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .is_some_and(|l| l.trim() == "SUCCESS");
        Attempt {
            accepted,
            output,
            log: self.stack.log_since(since),
        }
    }

    /// An Access-Request that carries a `User-Name` and nothing else, in
    /// particular no `Message-Authenticator`, from the host's address on the
    /// compose network (which `clients.conf` lists). Returns whether anything
    /// answered within three seconds.
    fn bare_access_request(&self) -> (bool, String) {
        std::thread::sleep(Duration::from_millis(1100));
        let since = unix_now();
        let socket = UdpSocket::bind("0.0.0.0:0").expect("a UDP socket");
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("a read timeout");
        let user = b"no-message-authenticator";
        let mut packet = vec![1u8, 7u8]; // Access-Request, Identifier 7
        let length = 20 + 2 + user.len();
        packet.extend_from_slice(&(length as u16).to_be_bytes());
        packet.extend_from_slice(&Uuid::new_v4().into_bytes()); // Request Authenticator
        packet.push(1); // User-Name
        packet.push((2 + user.len()) as u8);
        packet.extend_from_slice(user);
        let to: SocketAddr = format!("{}:1812", self.ip).parse().expect("an address");
        socket.send_to(&packet, to).expect("the request is sent");
        let mut buf = [0u8; 4096];
        let answered = socket.recv_from(&mut buf).is_ok();
        std::thread::sleep(Duration::from_millis(300));
        (answered, self.stack.log_since(since))
    }
}

// ===========================================================================
// The AXIAM side: the production route table, in process
// ===========================================================================

type Reply = (u16, Vec<u8>);
type ReplyFuture = Pin<Box<dyn Future<Output = Reply>>>;

/// A reply with the `ETag` header: the CRL route's status, body and tag.
type TaggedReply = (u16, Vec<u8>, Option<String>);
type TaggedFuture = Pin<Box<dyn Future<Output = TaggedReply>>>;

struct Api {
    call: Box<dyn Fn(test::TestRequest) -> ReplyFuture>,
    call_tagged: Box<dyn Fn(test::TestRequest) -> TaggedFuture>,
}

impl Api {
    async fn new(state: AppState<TestDb>, auth: AuthConfig, authz: Arc<dyn AuthzChecker>) -> Self {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(auth))
                .app_data(web::Data::new(authz))
                .app_data(web::Data::new(state))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await;
        let app = Rc::new(app);
        let tagged = Rc::clone(&app);
        Self {
            call: Box::new(move |req| {
                let app = Rc::clone(&app);
                Box::pin(async move {
                    let resp = test::call_service(&*app, req.to_request()).await;
                    let status = resp.status().as_u16();
                    let body = test::read_body(resp).await.to_vec();
                    (status, body)
                })
            }),
            call_tagged: Box::new(move |req| {
                let app = Rc::clone(&tagged);
                Box::pin(async move {
                    let resp = test::call_service(&*app, req.to_request()).await;
                    let status = resp.status().as_u16();
                    let etag = resp
                        .headers()
                        .get(actix_web::http::header::ETAG)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string);
                    let body = test::read_body(resp).await.to_vec();
                    (status, body, etag)
                })
            }),
        }
    }

    async fn send(&self, req: test::TestRequest) -> Reply {
        (self.call)(req).await
    }

    /// A bearer-token request carrying the CSRF pair the middleware checks.
    async fn json(
        &self,
        method: actix_web::http::Method,
        uri: &str,
        token: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let mut req = test::TestRequest::default()
            .method(method)
            .uri(uri)
            .insert_header(("Authorization", format!("Bearer {token}")))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN));
        if let Some(body) = body {
            req = req.set_json(body);
        }
        let (status, bytes) = self.send(req).await;
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn post(&self, uri: &str, token: &str, body: Value) -> (u16, Value) {
        self.json(actix_web::http::Method::POST, uri, token, Some(body))
            .await
    }

    async fn get(&self, uri: &str, token: &str) -> (u16, Value) {
        self.json(actix_web::http::Method::GET, uri, token, None)
            .await
    }

    /// `GET /pki/v1/{org}/ca/{ca}/crl`, with no credential, as a relying party
    /// calls it. Returns the DER list.
    /// `GET /pki/v1/{org}/ca/{ca}/crl`, optionally conditional: the status, the
    /// body and the `ETag` the route answered with.
    async fn crl_tagged(&self, org: Uuid, ca: &str, if_none_match: Option<&str>) -> TaggedReply {
        let mut req = test::TestRequest::get()
            .uri(&format!("/pki/v1/{org}/ca/{ca}/crl"))
            .peer_addr(CRL_PEER.parse().expect("a peer address"));
        if let Some(tag) = if_none_match {
            req = req.insert_header((actix_web::http::header::IF_NONE_MATCH, tag));
        }
        (self.call_tagged)(req).await
    }

    async fn crl(&self, org: Uuid, ca: &str) -> Vec<u8> {
        let (status, body, _) = self.crl_tagged(org, ca, None).await;
        assert_eq!(status, 200, "the CRL route answers a relying party");
        body
    }
}

fn auth_config() -> AuthConfig {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair");
    AuthConfig {
        jwt_private_key_pem: key.serialize_pem(),
        jwt_public_key_pem: key.public_key_pem(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        // Names the CRL distribution point of every certificate issued.
        oauth2_issuer_url: "https://id.radius.example".into(),
        ..AuthConfig::default()
    }
}

/// An organization with two tenants, an organization-level administrator for
/// the CA calls and a tenant administrator for each tenant.
struct Org {
    id: Uuid,
    ca_admin: String,
    tenants: Vec<(Uuid, String)>,
}

async fn mint(
    db: &Surreal<TestDb>,
    auth: &AuthConfig,
    org: Uuid,
    tenant: Uuid,
    name: &str,
) -> String {
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant,
            username: name.into(),
            email: format!("{name}@example.test"),
            password: test_password(),
            metadata: None,
        })
        .await
        .expect("an administrator");
    issue_access_token(
        user.id,
        tenant,
        org,
        &[],
        auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .expect("a token")
}

async fn organization(
    db: &Surreal<TestDb>,
    auth: &AuthConfig,
    slug: &str,
    tenant_slugs: &[&str],
) -> Org {
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: format!("RADIUS e2e {slug}"),
            slug: slug.into(),
            metadata: None,
        })
        .await
        .expect("an organization");
    // CA operations are organization-level: they need a principal that lives in
    // the organization's reserved scope.
    let scope = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant::organization_scope(org.id))
        .await
        .expect("the organization scope");
    let ca_admin = mint(db, auth, org.id, scope.id, "org-admin").await;
    let mut tenants = Vec::new();
    for slug in tenant_slugs {
        let tenant = SurrealTenantRepository::new(db.clone())
            .create(CreateTenant {
                organization_id: org.id,
                kind: TenantKind::Standard,
                name: (*slug).into(),
                slug: (*slug).into(),
                metadata: None,
            })
            .await
            .expect("a tenant");
        let admin = mint(db, auth, org.id, tenant.id, "tenant-admin").await;
        tenants.push((tenant.id, admin));
    }
    Org {
        id: org.id,
        ca_admin,
        tenants,
    }
}

/// An organization CA (the root), issued once per organization, as the guide
/// says: every tenant signing CA of the organization is issued beneath it.
struct OrgRoot {
    id: String,
    pem: String,
}

async fn org_root(api: &Api, org: &Org, subject: &str) -> OrgRoot {
    let (status, root) = api
        .post(
            &format!("/api/v1/organizations/{}/ca-certificates", org.id),
            &org.ca_admin,
            json!({
                "subject": subject,
                "key_algorithm": "Ed25519",
                "validity_days": 365,
            }),
        )
        .await;
    assert_eq!(status, 201, "issue: the organization CA: {root}");
    OrgRoot {
        id: root["id"].as_str().expect("the CA id").to_string(),
        pem: root["public_cert_pem"]
            .as_str()
            .expect("the root certificate")
            .to_string(),
    }
}

/// One tenant signing CA, issued the way an operator issues it: beneath the
/// organization's CA, for the tenant.
struct SigningCa {
    id: String,
    pem: String,
}

async fn signing_ca(
    api: &Api,
    org: &Org,
    root: &OrgRoot,
    tenant: usize,
    subject: &str,
) -> SigningCa {
    let root_id = &root.id;
    let tenant_id = org.tenants[tenant].0;
    let (status, ca) = api
        .post(
            &format!(
                "/api/v1/organizations/{}/tenants/{tenant_id}/signing-cas",
                org.id
            ),
            &org.ca_admin,
            json!({
                "parent_ca_id": root_id,
                "subject": subject,
                "key_algorithm": "Ed25519",
                // A signing CA may not outlive its parent.
                "validity_days": 364,
            }),
        )
        .await;
    assert_eq!(status, 201, "issue: the tenant signing CA: {ca}");
    let id = ca["id"].as_str().expect("the CA id").to_string();

    // The export: the CA certificate an operator copies to FreeRADIUS.
    let (status, exported) = api
        .get(
            &format!("/api/v1/organizations/{}/ca-certificates/{id}", org.id),
            &org.ca_admin,
        )
        .await;
    assert_eq!(
        status, 200,
        "issue: the export of the signing CA: {exported}"
    );
    let pem = exported["public_cert_pem"]
        .as_str()
        .expect("the exported certificate")
        .to_string();
    assert_eq!(
        ca["public_cert_pem"].as_str(),
        Some(pem.as_str()),
        "the export is the certificate that was issued"
    );
    SigningCa { id, pem }
}

/// AXIAM returns an Ed25519 private key as PKCS#8 **version 2** (RFC 5958): the
/// 32-byte seed followed by the public key. OpenSSL 3.0 — the library behind
/// Ubuntu 24.04's `wpa_supplicant` and so `eapol_test` — refuses that encoding
/// ("DECODER routines::unsupported") and reads only version 1, which is the same
/// seed without the public key. This re-encodes the key the way an operator has
/// to for such a supplicant (docs/pki/freeradius.md, "Issue and bind"); it
/// changes no key material. A key that is not in the expected shape is returned
/// as it is, and the supplicant says why it cannot read it.
fn supplicant_readable_key(pem: &str) -> String {
    use base64::Engine as _;
    const V2_PREFIX: [u8; 16] = [
        0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    const V1_PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let Ok(der) = base64::engine::general_purpose::STANDARD.decode(body.trim()) else {
        return pem.to_string();
    };
    if der.len() != 83 || der[..16] != V2_PREFIX {
        return pem.to_string();
    }
    let mut v1 = V1_PREFIX.to_vec();
    v1.extend_from_slice(&der[16..48]);
    let encoded = base64::engine::general_purpose::STANDARD.encode(v1);
    let mut out = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END PRIVATE KEY-----\n");
    out
}

/// A device certificate and its key, written where `eapol_test` reads them.
struct Device {
    /// The subject with everything but `[A-Za-z0-9-]` replaced, for file and
    /// service-account names.
    name: String,
    id: String,
    cert: PathBuf,
    key: PathBuf,
    pem: String,
}

async fn issue_device(
    api: &Api,
    org: &Org,
    tenant: usize,
    ca: &SigningCa,
    subject: &str,
    dir: &Path,
) -> Device {
    let (status, leaf) = try_issue_device(api, org, tenant, ca, subject).await;
    assert_eq!(
        status, 201,
        "issue: the device certificate {subject:?}: {leaf}"
    );
    write_device(&leaf, subject, dir)
}

async fn try_issue_device(
    api: &Api,
    org: &Org,
    tenant: usize,
    ca: &SigningCa,
    subject: &str,
) -> (u16, Value) {
    api.post(
        "/api/v1/certificates",
        &org.tenants[tenant].1,
        json!({
            "issuer_ca_id": ca.id,
            "subject": subject,
            "cert_type": "Device",
            "key_algorithm": "Ed25519",
            "validity_days": 30,
        }),
    )
    .await
}

fn write_device(leaf: &Value, subject: &str, dir: &Path) -> Device {
    let name: String = subject
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let pem = leaf["public_cert_pem"]
        .as_str()
        .expect("the certificate")
        .to_string();
    let key = supplicant_readable_key(
        leaf["private_key_pem"]
            .as_str()
            .expect("the key is returned once, at issuance"),
    );
    let cert_path = dir.join(format!("{name}.pem"));
    let key_path = dir.join(format!("{name}.key"));
    std::fs::write(&cert_path, &pem).expect("the certificate can be written");
    std::fs::write(&key_path, key).expect("the key can be written");
    Device {
        name,
        id: leaf["id"].as_str().expect("the certificate id").to_string(),
        cert: cert_path,
        key: key_path,
        pem,
    }
}

async fn bind(api: &Api, org: &Org, tenant: usize, device: &Device) -> String {
    let token = &org.tenants[tenant].1;
    let (status, sa) = api
        .post(
            "/api/v1/service-accounts",
            token,
            json!({ "name": format!("sa-{}", device.name) }),
        )
        .await;
    assert_eq!(status, 201, "bind: the service account: {sa}");
    let sa_id = sa["id"]
        .as_str()
        .expect("the service account id")
        .to_string();
    let (status, bound) = api
        .post(
            &format!("/api/v1/service-accounts/{sa_id}/bind-certificate"),
            token,
            json!({ "certificate_id": device.id }),
        )
        .await;
    assert_eq!(status, 200, "bind: {bound}");
    assert_eq!(bound["status"], "bound");
    sa_id
}

/// Whether `key` is a placement-table key the generator may write: the
/// certificate serial as FreeRADIUS spells `TLS-Client-Cert-Serial` (lowercase
/// hex, two digits per byte, at most the 20 bytes RFC 5280 allows). Nothing else
/// is ever written as a key — in particular not `DEFAULT`, which `rlm_files`
/// matches for every key, nor `NONE`, which it looks a missing key up as, and
/// neither can be spelt in hex.
fn is_placement_key(key: &str) -> bool {
    (2..=40).contains(&key.len())
        && key.len().is_multiple_of(2)
        && key.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// What an operator's script would do (docs/pki/freeradius.md, "the placement
/// table"): the placement table is the tenant's active `Device` certificates
/// that are bound to a service account, each keyed on its **serial**, which
/// AXIAM assigns, and never on its subject, which whoever requests the
/// certificate chooses (R101W6-02). A key that is not a serial stops the
/// generator before anything is written. Returns the table, the subjects it
/// placed (for the assertion that exactly the bound devices are in it) and the
/// keys it wrote.
async fn placement_from_axiam(
    api: &Api,
    org: &Org,
    tenant: usize,
) -> (String, Vec<String>, Vec<String>) {
    let (status, list) = api
        .get(
            "/api/v1/certificates?offset=0&limit=200",
            &org.tenants[tenant].1,
        )
        .await;
    assert_eq!(status, 200, "bind: the certificate list: {list}");
    let items = list["items"].as_array().expect("an item list");
    assert_eq!(
        list["total"].as_u64(),
        Some(items.len() as u64),
        "the generator reads the whole list, not its first page"
    );
    let mut table = String::new();
    let mut placed = Vec::new();
    let mut keys = Vec::new();
    for item in items {
        let bound = !item["bound_service_account_id"].is_null();
        if item["cert_type"] == "Device" && item["status"] == "Active" && bound {
            let id: Uuid = item["id"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .expect("a certificate id");
            let serial = certificate_serial(item["public_cert_pem"].as_str().expect("a PEM"));
            assert!(
                is_placement_key(&serial),
                "the generator refuses certificate {id}: its serial {serial:?} is not a placement \
                 key, and nothing is written"
            );
            // The comment names the certificate by AXIAM's id, never by its
            // subject: a subject may hold a newline, which would end the comment.
            table.push_str(&format!(
                "# certificate {id}\n{serial}\n\tTunnel-Type:0 = VLAN,\n\
                 \tTunnel-Medium-Type:0 = IEEE-802,\n\tTunnel-Private-Group-Id:0 = \"{VLAN}\",\n\
                 \tSession-Timeout = 3600,\n\tTermination-Action = RADIUS-Request\n\n"
            ));
            placed.push(item["subject"].as_str().expect("a subject").to_string());
            keys.push(serial);
        }
    }
    (table, placed, keys)
}

// ---------------------------------------------------------------------------
// The fetch job: docker/radius/fetch-crl.sh, and the server it fetches from
// ---------------------------------------------------------------------------

/// What the stand-in for the CRL route serves, and the `If-None-Match` of every
/// request it has answered.
struct Served {
    der: Vec<u8>,
    etag: Option<String>,
    seen: Vec<Option<String>>,
}

/// A plain-HTTP server on a loopback port, standing in for the CRL route on the
/// fetch script's side of the wire: the script is a `curl` client, and the
/// route lives in the in-process test service, so the test hands this server
/// the bytes and the `ETag` the route answered with, and it answers as the
/// route does: `200` with the list, or `304` when `If-None-Match` is the tag
/// it holds. It also serves what the route never would (a forged list, an older
/// one), which is the point.
struct Mirror {
    port: u16,
    served: Arc<Mutex<Served>>,
}

impl Mirror {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let port = listener.local_addr().expect("its address").port();
        let served = Arc::new(Mutex::new(Served {
            der: Vec::new(),
            etag: None,
            seen: Vec::new(),
        }));
        let shared = Arc::clone(&served);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                Self::answer(stream, &shared);
            }
        });
        Self { port, served }
    }

    fn answer(mut stream: TcpStream, served: &Mutex<Served>) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => request.extend_from_slice(&buf[..n]),
            }
            if request.len() > 16 * 1024 {
                return;
            }
        }
        let request = String::from_utf8_lossy(&request);
        let if_none_match = request.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("if-none-match")
                .then(|| value.trim().to_string())
        });
        let mut served = served.lock().expect("the stand-in's state");
        served.seen.push(if_none_match.clone());
        let tag = served
            .etag
            .as_ref()
            .map(|t| format!("ETag: {t}\r\n"))
            .unwrap_or_default();
        let reply = if served.etag.is_some() && if_none_match == served.etag {
            format!("HTTP/1.1 304 Not Modified\r\n{tag}Connection: close\r\n\r\n").into_bytes()
        } else {
            let mut reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/pkix-crl\r\n{tag}\
                 Content-Length: {}\r\nConnection: close\r\n\r\n",
                served.der.len()
            )
            .into_bytes();
            reply.extend_from_slice(&served.der);
            reply
        };
        let _ = stream.write_all(&reply);
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/crl", self.port)
    }

    fn serve(&self, der: &[u8], etag: Option<&str>) {
        let mut served = self.served.lock().expect("the stand-in's state");
        served.der = der.to_vec();
        served.etag = etag.map(str::to_string);
    }

    /// The `If-None-Match` of the most recent request, `None` if it sent none.
    fn last_if_none_match(&self) -> Option<String> {
        self.served
            .lock()
            .expect("the stand-in's state")
            .seen
            .last()
            .cloned()
            .expect("the stand-in has been asked for a list")
    }
}

/// What one run of `docker/radius/fetch-crl.sh` did.
struct Fetch {
    ok: bool,
    stdout: String,
    stderr: String,
}

impl Fetch {
    fn report(&self) -> String {
        format!(
            "exit ok: {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.ok, self.stdout, self.stderr
        )
    }
}

/// Run the fetch script the guide ships, as an operator's cron job would:
/// `fetch-crl.sh <url> <ca.pem> <capath>`, under the host's `sh`. The stand-in
/// for the route is plain HTTP on a loopback port, which the script refuses
/// unless `FETCH_CRL_ALLOW_HTTP=1` is in its environment (R110W5-03): `allow_http`
/// says whether this run sets it.
fn fetch_crl_with(mirror: &Mirror, ca_file: &Path, capath: &Path, allow_http: bool) -> Fetch {
    let script = repo_root().join("docker/radius/fetch-crl.sh");
    let mut command = Command::new("sh");
    command
        .arg(&script)
        .arg(mirror.url())
        .arg(ca_file)
        .arg(capath)
        .env_remove("FETCH_CRL_ALLOW_HTTP");
    if allow_http {
        command.env("FETCH_CRL_ALLOW_HTTP", "1");
    }
    let out = command.output().expect("`sh` can run the fetch script");
    Fetch {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// [`fetch_crl_with`] as the end-to-end runs it: the plain-HTTP stand-in allowed.
fn fetch_crl(mirror: &Mirror, ca_file: &Path, capath: &Path) -> Fetch {
    fetch_crl_with(mirror, ca_file, capath, true)
}

/// One field of a DER list, as `openssl crl -noout <flag>` prints it.
fn crl_field(der: &[u8], flag: &str) -> String {
    String::from_utf8(openssl_in(&["crl", "-inform", "DER", "-noout", flag], der))
        .expect("openssl prints text")
        .trim()
        .to_string()
}

/// The CRL number of a DER list.
fn crl_number(der: &[u8]) -> u128 {
    let field = crl_field(der, "-crlnumber");
    let hex = field
        .strip_prefix("crlNumber=0x")
        .unwrap_or_else(|| panic!("a CRL number, got `{field}`"));
    u128::from_str_radix(hex, 16).expect("a hexadecimal CRL number")
}

/// A list AXIAM answered with, as the run installed it.
struct Refreshed {
    /// `openssl crl -text` of the installed list.
    text: String,
    der: Vec<u8>,
    etag: String,
    /// `capath/<hash>.r0`.
    installed: PathBuf,
}

/// Fetch the signing CA's list from AXIAM and put it where FreeRADIUS reads it,
/// the way the guide does it: `docker/radius/fetch-crl.sh` fetches (here from the
/// stand-in, serving what the route answered with), checks the CA's signature
/// and the CRL number, and moves the list into `capath` as `<hash>.r0`.
async fn refresh_crl(
    api: &Api,
    org: Uuid,
    ca: &SigningCa,
    ca_file: &Path,
    capath: &Path,
    mirror: &Mirror,
) -> Refreshed {
    let (status, der, etag) = api.crl_tagged(org, &ca.id, None).await;
    assert_eq!(status, 200, "the CRL route answers a relying party");
    let etag = etag.expect("the CRL route names its list with an ETag");
    mirror.serve(&der, Some(&etag));
    let run = fetch_crl(mirror, ca_file, capath);
    assert!(
        run.ok && run.stdout.contains("installed"),
        "the fetch script installs the list:\n{}",
        run.report()
    );
    let hash = crl_field(&der, "-hash");
    let installed = capath.join(format!("{hash}.r0"));
    let pem = std::fs::read(&installed).expect("the list is in ca_path");
    Refreshed {
        text: String::from_utf8(openssl_in(&["crl", "-noout", "-text"], &pem)).expect("CRL text"),
        der,
        etag,
        installed,
    }
}

/// A DER list that names the CA and was signed by another key, with a CRL
/// number above `above` and no entries: whoever can answer the fetch (a
/// TLS-intercepting proxy, a compromised mirror) can serve it, and it would
/// un-revoke everything. `openssl crl -verify` prints `verify failure` for it
/// and, on OpenSSL 3.0, still exits 0 (R101W6-04): the case the script's text
/// check exists for.
fn forged_list(work: &Path, ca_pem: &str, above: u128) -> Vec<u8> {
    let dir = work.join("forged");
    std::fs::create_dir_all(&dir).expect("a directory for the forgery");
    let genuine = dir.join("genuine-ca.pem");
    let key = dir.join("key.pem");
    let request = dir.join("ca.csr");
    let cert = dir.join("ca.pem");
    let pem_list = dir.join("crl.pem");
    std::fs::write(&genuine, ca_pem).expect("the CA can be written");
    run_ok(
        "openssl",
        &["genpkey", "-algorithm", "ed25519", "-out", path_str(&key)],
    );
    // A certificate over another key with the CA's own subject: the same name,
    // so the list's issuer matches the trusted CA's and OpenSSL goes on to check
    // the signature, which is the step that fails.
    run_ok(
        "openssl",
        &[
            "x509",
            "-in",
            path_str(&genuine),
            "-x509toreq",
            "-signkey",
            path_str(&key),
            "-out",
            path_str(&request),
        ],
    );
    run_ok(
        "openssl",
        &[
            "x509",
            "-req",
            "-in",
            path_str(&request),
            "-signkey",
            path_str(&key),
            "-days",
            "2",
            "-out",
            path_str(&cert),
        ],
    );
    std::fs::write(dir.join("index.txt"), "").expect("an empty database");
    std::fs::write(dir.join("crlnumber"), format!("{:032X}\n", above + 1))
        .expect("a CRL number file");
    let config = dir.join("ca.cnf");
    std::fs::write(
        &config,
        format!(
            "[ca]\ndefault_ca = forged\n[forged]\ndatabase = {0}/index.txt\n\
             crlnumber = {0}/crlnumber\ndefault_md = default\ndefault_crl_days = 1\n",
            dir.display()
        ),
    )
    .expect("a CA configuration");
    run_ok(
        "openssl",
        &[
            "ca",
            "-config",
            path_str(&config),
            "-cert",
            path_str(&cert),
            "-keyfile",
            path_str(&key),
            "-gencrl",
            "-out",
            path_str(&pem_list),
        ],
    );
    let pem = std::fs::read(&pem_list).expect("the forged list");
    openssl_in(&["crl", "-inform", "PEM", "-outform", "DER"], &pem)
}

/// A `client_cert` file holding a leaf and the certificates above it, in order.
fn write_chain(dir: &Path, name: &str, pems: &[&str]) -> PathBuf {
    let path = dir.join(format!("{name}.pem"));
    let mut chain = String::new();
    for pem in pems {
        chain.push_str(pem.trim_end());
        chain.push('\n');
    }
    std::fs::write(&path, chain).expect("the chain can be written");
    path
}

/// Whether the supplicant loaded its `client_cert` as a chain, which is what
/// makes it send the certificates above the leaf.
fn sent_chain(attempt: &Attempt) -> bool {
    attempt
        .output
        .contains("SSL_use_certificate_chain_file --> OK")
}

/// OpenSSL's refusal when the peer's chain ends at a self-signed root the
/// server does not trust.
const FULL_CHAIN_REFUSAL: &str = "self-signed certificate in certificate chain";

fn set_readable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
        .expect("permissions can be set");
}

/// The octets of one RADIUS attribute as `eapol_test` dumps an Access-Accept
/// (`Attribute 81 (Tunnel-Private-Group-Id) length=4` and, below it,
/// `Value: 3230`), as lowercase hex. `None` when the attribute is not there.
fn attribute_octets(output: &str, number: u8, name: &str) -> Option<String> {
    let header = format!("Attribute {number} ({name})");
    let mut lines = output.lines();
    lines.find(|l| l.trim_start().starts_with(&header))?;
    let value = lines.next()?.trim().strip_prefix("Value:")?;
    Some(value.trim().to_ascii_lowercase())
}

fn certificate_serial(pem: &str) -> String {
    let out = openssl_in(&["x509", "-noout", "-serial"], pem.as_bytes());
    String::from_utf8(out)
        .expect("serial output")
        .trim()
        .trim_start_matches("serial=")
        .to_ascii_lowercase()
}

fn certificate_text(pem: &str) -> String {
    String::from_utf8(openssl_in(&["x509", "-noout", "-text"], pem.as_bytes())).expect("text")
}

/// What the fetch script refuses, with the list in `ca_path` the one AXIAM
/// published after the revocation (`current`): each refusal leaves that file as
/// it was, byte for byte, and each of them is a case the guide's earlier snippet
/// failed (R101W6-04, #643).
#[allow(clippy::too_many_arguments)]
async fn fetch_script_cases(
    api: &Api,
    org: Uuid,
    ca: &SigningCa,
    work: &Path,
    ca_file: &Path,
    capath: &Path,
    mirror: &Mirror,
    initial: &Refreshed,
    current: &Refreshed,
) {
    let held = std::fs::read(&current.installed).expect("the installed list");
    let unchanged = |what: &str| {
        assert_eq!(
            std::fs::read(&current.installed).expect("the installed list"),
            held,
            "{what}: the installed list is as it was"
        );
    };

    // The script sent the tag of the list it held, and the list it fetched
    // after the revocation is the new one: the tags differ, so a 200.
    assert_eq!(
        mirror.last_if_none_match().as_deref(),
        Some(initial.etag.as_str()),
        "the script sends the ETag of the list it installed as If-None-Match"
    );

    // ---- a 304 keeps the installed list --------------------------------
    // AXIAM's own route answers the current tag with 304 and no body ...
    let (status, body, _) = api.crl_tagged(org, &ca.id, Some(&current.etag)).await;
    assert_eq!(status, 304, "the CRL route answers its own tag with 304");
    assert!(body.is_empty(), "a 304 has no body");
    // ... and the script, which holds that tag, sends it and reads the 304 as
    // "unchanged".
    mirror.serve(&current.der, Some(&current.etag));
    let run = fetch_crl(mirror, ca_file, capath);
    assert!(
        run.ok && run.stdout.contains("unchanged (304)"),
        "a 304 is \"unchanged\":\n{}",
        run.report()
    );
    assert_eq!(
        mirror.last_if_none_match().as_deref(),
        Some(current.etag.as_str()),
        "the script revalidates with the ETag it stored"
    );
    unchanged("304");
    say("fetch script", "304: unchanged, the installed list stays");

    // ---- plain HTTP is refused unless the operator allows it -------------
    // The script's default is HTTPS only (R110W5-03): the stand-in's `http://`
    // URL is refused before curl runs, and nothing is touched.
    let run = fetch_crl_with(mirror, ca_file, capath, false);
    assert!(
        !run.ok && run.stderr.contains("plain HTTP"),
        "an http:// URL without FETCH_CRL_ALLOW_HTTP=1 is refused:\n{}",
        run.report()
    );
    unchanged("plain HTTP without the opt-in");
    say(
        "fetch script",
        "http:// without FETCH_CRL_ALLOW_HTTP=1 is refused; the installed list stays",
    );

    // ---- a list another key signed, under the CA's name -----------------
    let forged = forged_list(work, &ca.pem, crl_number(&current.der));
    assert_eq!(
        crl_field(&forged, "-hash"),
        crl_field(&current.der, "-hash"),
        "the forged list names the CA: the same issuer name, so the same file name"
    );
    assert!(
        crl_number(&forged) > crl_number(&current.der),
        "the forged list's number is higher: only its signature can stop it"
    );
    mirror.serve(&forged, Some("\"forged\""));
    let run = fetch_crl(mirror, ca_file, capath);
    assert!(
        !run.ok && run.stderr.contains("not signed by"),
        "a list another key signed is refused:\n{}",
        run.report()
    );
    unchanged("forged");
    // What the guide's earlier snippet relied on, for the record: OpenSSL's own
    // verdict and exit status on the same file.
    let forged_file = work.join("forged/crl.der");
    std::fs::write(&forged_file, &forged).expect("the forged list can be written");
    let naive = Command::new("openssl")
        .args(["crl", "-inform", "DER", "-in", path_str(&forged_file)])
        .args(["-CAfile", path_str(ca_file), "-noout", "-verify"])
        .output()
        .expect("openssl can be run");
    say(
        "fetch script",
        &format!(
            "forged list refused; `openssl crl -verify` says {:?}, exit {}",
            String::from_utf8_lossy(&naive.stderr).trim(),
            naive.status.code().unwrap_or(-1)
        ),
    );

    // ---- a list the CA signed, but older than the one installed ---------
    assert!(
        crl_number(&initial.der) < crl_number(&current.der),
        "the list the run started with is numbered below the one after the revocation"
    );
    mirror.serve(&initial.der, Some(&initial.etag));
    let run = fetch_crl(mirror, ca_file, capath);
    assert!(
        !run.ok && run.stderr.contains("lower than the installed"),
        "a lower-numbered list is refused:\n{}",
        run.report()
    );
    unchanged("lower number");
    say(
        "fetch script",
        "an older list the CA signed is refused; the installed list stays",
    );

    // Back to what AXIAM serves now.
    mirror.serve(&current.der, Some(&current.etag));
}

// ===========================================================================
// The test
// ===========================================================================

fn say(step: &str, what: &str) {
    eprintln!("[radius-e2e] {step:<22} {what}");
}

#[actix_web::test]
async fn eap_tls_with_an_axiam_issued_device_certificate() {
    if !gate() {
        return;
    }

    // ---- the run's directory, the server's own certificate, the secret ----
    let work = work_dir();
    let _ = std::fs::remove_dir_all(&work);
    let trust = work.join("trust");
    let capath = trust.join("capath");
    std::fs::create_dir_all(&capath).expect("the run directory can be created");
    let secret = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    std::fs::write(
        work.join("env"),
        format!("RADIUS_E2E_SHARED_SECRET={secret}\n"),
    )
    .expect("the env file can be written");
    let ip = std::env::var("RADIUS_E2E_IP").unwrap_or_else(|_| "172.28.78.10".into());

    // The certificate FreeRADIUS shows the supplicant. It has nothing to do
    // with AXIAM's CA: the supplicant validates the server against this one.
    let server_ca_key = work.join("server-ca.key");
    let server_ca = work.join("server-ca.pem");
    run_ok(
        "openssl",
        &[
            "req",
            "-x509",
            "-newkey",
            "ed25519",
            "-nodes",
            "-days",
            "2",
            "-subj",
            "/CN=AXIAM e2e RADIUS server CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign",
            "-keyout",
            path_str(&server_ca_key),
            "-out",
            path_str(&server_ca),
        ],
    );
    let server_csr = work.join("server.csr");
    run_ok(
        "openssl",
        &[
            "req",
            "-newkey",
            "ed25519",
            "-nodes",
            "-subj",
            "/CN=radius.example.test",
            "-keyout",
            path_str(&trust.join("server.key")),
            "-out",
            path_str(&server_csr),
        ],
    );
    let server_ext = work.join("server.ext");
    std::fs::write(
        &server_ext,
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n\
         extendedKeyUsage=serverAuth\nsubjectAltName=DNS:radius.example.test\n",
    )
    .expect("the extension file can be written");
    run_ok(
        "openssl",
        &[
            "x509",
            "-req",
            "-in",
            path_str(&server_csr),
            "-CA",
            path_str(&server_ca),
            "-CAkey",
            path_str(&server_ca_key),
            "-CAcreateserial",
            "-days",
            "2",
            "-extfile",
            path_str(&server_ext),
            "-out",
            path_str(&trust.join("server.pem")),
        ],
    );
    set_readable(&trust.join("server.key"));
    set_readable(&trust.join("server.pem"));

    // ---- AXIAM -----------------------------------------------------------
    let db = Surreal::new::<Mem>(())
        .await
        .expect("an in-memory database");
    db.use_ns("test").use_db("test").await.expect("a namespace");
    axiam_db::run_migrations(&db).await.expect("migrations");
    let auth = auth_config();
    let authz: Arc<dyn AuthzChecker> = Arc::new(AllowAllAuthzChecker);
    let api = Api::new(
        AppState::for_test(db.clone(), auth.clone()),
        auth.clone(),
        authz,
    )
    .await;

    // Plant A has the line FreeRADIUS serves and a second line; Plant B is
    // another organization altogether.
    let plant_a = organization(&db, &auth, "plant-a", &["line-1", "line-2"]).await;
    let plant_b = organization(&db, &auth, "plant-b", &["line-1"]).await;

    // ---- 1. issue ---------------------------------------------------------
    // One organization CA per organization, and both of Plant A's tenant
    // signing CAs beneath the same one: the case the tenant boundary has to hold
    // in is the one where a chain check alone would not separate the tenants
    // (spike R9, T-459, R101W6-01).
    let plant_a_root = org_root(&api, &plant_a, "Plant A root").await;
    let plant_b_root = org_root(&api, &plant_b, "Plant B root").await;
    let line1 = signing_ca(&api, &plant_a, &plant_a_root, 0, "Plant A line 1 devices").await;
    let line2 = signing_ca(&api, &plant_a, &plant_a_root, 1, "Plant A line 2 devices").await;
    let other_org = signing_ca(&api, &plant_b, &plant_b_root, 0, "Plant B line 1 devices").await;
    let root_file = work.join("plant-a-root.pem");
    std::fs::write(&root_file, &plant_a_root.pem).expect("the root can be written");
    for (ca, name) in [(&line1, "line 1"), (&line2, "line 2")] {
        // openssl verify trusts only the file given as -CAfile: each signing CA
        // verifies against Plant A's one root, so both chain to it.
        let out = openssl_in(
            &["verify", "-CAfile", path_str(&root_file)],
            ca.pem.as_bytes(),
        );
        assert!(
            String::from_utf8_lossy(&out).contains("OK"),
            "issue: the {name} signing CA chains to Plant A's organization CA"
        );
    }

    let press07 = issue_device(&api, &plant_a, 0, &line1, "press-07", &work).await;
    let press07_full = write_chain(
        &work,
        "press-07-full-chain",
        &[&press07.pem, &line1.pem, &plant_a_root.pem],
    );
    let press08 = issue_device(&api, &plant_a, 0, &line1, "press-08", &work).await;
    let press09 = issue_device(&api, &plant_a, 0, &line1, "press-09", &work).await;
    let gate03 = issue_device(&api, &plant_a, 1, &line2, "gate-03", &work).await;
    // What a supplicant of the other tenant would send: its leaf and the chain
    // above it, as a real deployment configures one (wpa_supplicant loads a
    // client_cert file as a chain). The root is sent once without and once with.
    let gate03_chain = write_chain(&work, "gate-03-chain", &[&gate03.pem, &line2.pem]);
    let gate03_full = write_chain(
        &work,
        "gate-03-full-chain",
        &[&gate03.pem, &line2.pem, &plant_a_root.pem],
    );
    let crane01 = issue_device(&api, &plant_b, 0, &other_org, "crane-01", &work).await;
    // Two subjects a tenant certificate administrator may choose, and that a
    // table keyed on the subject would read as something else (R101W6-02):
    // `DEFAULT`, which `rlm_files` matches for every key, and a subject that
    // carries a newline and a second entry. AXIAM issues the first. The second
    // it issues today (R101W6-12); if a later release refuses it, there is
    // nothing to inject and the case still holds.
    let default_named = issue_device(&api, &plant_a, 0, &line1, "DEFAULT", &work).await;
    let injected_subject = "lamp-04\nDEFAULT";
    let (status, injected) = try_issue_device(&api, &plant_a, 0, &line1, injected_subject).await;
    let injected = match status {
        201 => Some(write_device(&injected, injected_subject, &work)),
        400 => None,
        other => {
            panic!("issue: a subject with a newline is issued or refused, not {other}: {injected}")
        }
    };

    let text = certificate_text(&press07.pem);
    assert!(
        text.contains("TLS Web Client Authentication"),
        "issue: a Device certificate carries clientAuth:\n{text}"
    );
    assert!(
        text.contains(&format!("/pki/v1/{}/ca/{}/crl", plant_a.id, line1.id)),
        "issue: the certificate names its issuer's revocation list:\n{text}"
    );
    say(
        "issue",
        &format!(
            "one organization CA per organization, both Plant A signing CAs under one, {} Device \
             certificates (one named DEFAULT{})",
            6 + usize::from(injected.is_some()),
            if injected.is_some() {
                ", one with a newline in its subject"
            } else {
                "; a subject with a newline is refused"
            }
        ),
    );

    // ---- 2. bind ----------------------------------------------------------
    bind(&api, &plant_a, 0, &press07).await;
    bind(&api, &plant_a, 0, &press09).await;
    bind(&api, &plant_a, 1, &gate03).await;
    bind(&api, &plant_b, 0, &crane01).await;
    bind(&api, &plant_a, 0, &default_named).await;
    if let Some(injected) = &injected {
        bind(&api, &plant_a, 0, injected).await;
    }
    // press-08 is issued and valid, and bound to nothing.
    let (table, placed, keys) = placement_from_axiam(&api, &plant_a, 0).await;
    let mut placed = placed;
    placed.sort();
    let mut expected = vec!["DEFAULT", "press-07", "press-09"];
    if injected.is_some() {
        expected.push(injected_subject);
    }
    expected.sort();
    assert_eq!(
        placed, expected,
        "bind: exactly the bound devices of the tenant are listed as bound"
    );
    // The table's keys are the bound certificates' serials and nothing else:
    // no entry is named after a subject, so none is `DEFAULT` or `NONE`, and no
    // subject's newline has started an entry of its own.
    let entry_names: Vec<&str> = table
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('\t'))
        .collect();
    assert_eq!(
        entry_names, keys,
        "placement: every entry is keyed on a bound certificate's serial:\n{table}"
    );
    assert!(
        entry_names.iter().all(|k| is_placement_key(k)),
        "placement: no entry is keyed on anything but a serial:\n{table}"
    );
    assert!(
        !keys.contains(&certificate_serial(&press08.pem)),
        "placement: the unbound press-08 has no entry"
    );
    say(
        "bind",
        "press-07, press-09 and DEFAULT bound; press-08 left unbound; the table is keyed on serials",
    );

    // ---- the trust material, and the stack -------------------------------
    std::fs::write(trust.join("ca.pem"), &line1.pem).expect("the CA can be written");
    std::fs::write(trust.join("placement"), table).expect("the placement table can be written");
    set_readable(&trust.join("ca.pem"));
    set_readable(&trust.join("placement"));
    // The list reaches `ca_path` the way the guide says: through the fetch
    // script, from a stand-in for the CRL route.
    let mirror = Mirror::start();
    let ca_file = trust.join("ca.pem");
    let initial = refresh_crl(&api, plant_a.id, &line1, &ca_file, &capath, &mirror).await;
    assert!(
        initial.text.contains("No Revoked Certificates"),
        "the list starts empty:\n{}",
        initial.text
    );
    assert_eq!(
        mirror.last_if_none_match(),
        None,
        "the first fetch holds no ETag to send"
    );
    std::fs::set_permissions(&capath, {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::Permissions::from_mode(0o755)
    })
    .expect("permissions");

    let stack = Stack::new(&work);
    stack.up();
    let radius = Radius {
        stack: &stack,
        work: work.clone(),
        ip,
        secret,
    };
    say(
        "stack",
        "FreeRADIUS 3.2.8 up, trusting only the line 1 signing CA",
    );

    // ---- 3. accept --------------------------------------------------------
    let accept = radius.eap_tls(
        "press-07",
        path_str(&press07.cert),
        path_str(&press07.key),
        true,
    );
    assert!(
        accept.accepted,
        "accept: press-07 is admitted:\n{}",
        accept.report()
    );
    assert!(
        accept.log.contains("Sent Access-Accept"),
        "accept: the server says it admitted the device"
    );
    for (number, name) in [
        (64, "Tunnel-Type"),
        (65, "Tunnel-Medium-Type"),
        (81, "Tunnel-Private-Group-Id"),
        (27, "Session-Timeout"),
        (29, "Termination-Action"),
    ] {
        assert!(
            accept
                .output
                .contains(&format!("Attribute {number} ({name})")),
            "accept: the Access-Accept carries {name} (RFC 3580): {}",
            accept.output
        );
    }
    // The wire encoding, read from the attribute's own octets: RFC 2868 puts a
    // tag octet before a tagged integer's value, and FreeRADIUS 3.2.8 writes the
    // placement's `:0` as 0x00 there; a tagged string with tag 0 carries no tag
    // octet at all (its first octet, a digit, is above 0x1F, which RFC 2868 §3.6
    // reads as the start of the string). A tag other than 0 would show as one
    // more octet in front of the VLAN, and a NAS would read it as another tunnel.
    let vlan_hex: String = VLAN.bytes().map(|b| format!("{b:02x}")).collect();
    for (number, name, expected, what) in [
        (
            64,
            "Tunnel-Type",
            "0000000d".to_string(),
            "tag 0x00, VLAN (13)",
        ),
        (
            65,
            "Tunnel-Medium-Type",
            "00000006".to_string(),
            "tag 0x00, IEEE-802 (6)",
        ),
        (
            81,
            "Tunnel-Private-Group-Id",
            vlan_hex,
            "the VLAN string and no tag octet",
        ),
    ] {
        assert_eq!(
            attribute_octets(&accept.output, number, name).as_deref(),
            Some(expected.as_str()),
            "accept: {name} is encoded as {what}: {}",
            accept.output
        );
    }
    say("accept", "press-07 admitted onto VLAN 20, session bounded");

    // ---- 4. wrong CA ------------------------------------------------------
    // gate-03 belongs to line 2, another tenant of the same organization, and
    // its signing CA chains to the same organization CA as line 1's. The server
    // holds line 1's signing CA and nothing above it, so neither the leaf
    // alone, nor the leaf with its signing CA, nor the whole chain up to the
    // shared root reaches a CA it trusts.
    let wrong_tenant = radius.eap_tls(
        "gate-03",
        path_str(&gate03.cert),
        path_str(&gate03.key),
        true,
    );
    assert!(
        !wrong_tenant.accepted
            && wrong_tenant
                .log
                .contains("unable to get local issuer certificate"),
        "wrong CA: another tenant of the same organization is refused:\n{}",
        wrong_tenant.log
    );
    let wrong_tenant_chain = radius.eap_tls(
        "gate-03",
        path_str(&gate03_chain),
        path_str(&gate03.key),
        true,
    );
    assert!(
        sent_chain(&wrong_tenant_chain)
            && wrong_tenant_chain
                .log
                .contains("TLS-Cert-Subject := \"/CN=Plant A line 2 devices\"")
            && !wrong_tenant_chain.accepted
            && wrong_tenant_chain
                .log
                .contains("unable to get local issuer certificate"),
        "wrong CA: another tenant's device presenting its signing CA is refused:\n{}",
        wrong_tenant_chain.report()
    );
    let wrong_tenant_full = radius.eap_tls(
        "gate-03",
        path_str(&gate03_full),
        path_str(&gate03.key),
        true,
    );
    assert!(
        sent_chain(&wrong_tenant_full)
            && wrong_tenant_full
                .log
                .contains("TLS-Cert-Subject := \"/CN=Plant A root\"")
            && !wrong_tenant_full.accepted
            && wrong_tenant_full.log.contains(FULL_CHAIN_REFUSAL),
        "wrong CA: another tenant's device presenting its whole chain, up to the organization \
         CA both tenants share, is refused:\n{}",
        wrong_tenant_full.report()
    );
    // The control: the tenant's own device presenting the same shape of chain,
    // to the same root, is admitted, so the refusals above are the anchor's.
    let own_full = radius.eap_tls(
        "press-07",
        path_str(&press07_full),
        path_str(&press07.key),
        true,
    );
    assert!(
        sent_chain(&own_full) && own_full.accepted,
        "wrong CA (control): press-07 presenting its whole chain is admitted:\n{}",
        own_full.report()
    );
    let wrong_org = radius.eap_tls(
        "crane-01",
        path_str(&crane01.cert),
        path_str(&crane01.key),
        true,
    );
    assert!(
        !wrong_org.accepted
            && wrong_org
                .log
                .contains("unable to get local issuer certificate"),
        "wrong CA: another organization's device is refused:\n{}",
        wrong_org.log
    );
    say(
        "wrong CA",
        "gate-03 (other tenant, same organization CA; leaf, leaf + signing CA, whole chain) and \
         crane-01 (other organization) refused; press-07 with its whole chain admitted",
    );

    // ---- placement: a valid certificate that is not in the table ----------
    // The table holds a bound certificate whose subject is `DEFAULT`. Keyed on
    // the subject, that entry would match every certificate this CA issued;
    // keyed on the serial it places that one certificate and nothing else.
    let default_device = radius.eap_tls(
        &default_named.name,
        path_str(&default_named.cert),
        path_str(&default_named.key),
        true,
    );
    assert!(
        default_device.accepted,
        "placement: the bound certificate named DEFAULT is placed as itself:\n{}",
        default_device.report()
    );
    let unplaced = radius.eap_tls(
        "press-08",
        path_str(&press08.cert),
        path_str(&press08.key),
        true,
    );
    assert!(
        !unplaced.accepted
            && unplaced
                .log
                .contains("Certificate rejected by the virtual server"),
        "unplaced: a valid but unbound device is refused, not admitted onto a default, although \
         a bound certificate named DEFAULT is in the table:\n{}",
        unplaced.log
    );
    say(
        "unplaced",
        "press-08 (valid, unbound) refused; the certificate named DEFAULT places only itself",
    );

    // ---- the settings the guide stands behind -----------------------------
    let tls12 = radius.eap_tls(
        "press-07",
        path_str(&press07.cert),
        path_str(&press07.key),
        false,
    );
    assert!(
        !tls12.accepted && tls12.log.contains("protocol_version"),
        "TLS 1.3 only: a TLS 1.2 supplicant is refused:\n{}",
        tls12.log
    );
    let md5 = radius.eap_md5();
    assert!(
        !md5.accepted && md5.output.contains("EAP-Failure"),
        "EAP allow-list: EAP-MD5 is refused:\n{}",
        md5.output
    );
    let (answered, log) = radius.bare_access_request();
    assert!(
        !answered && log.contains("does not contain required Message-Authenticator"),
        "Message-Authenticator: a request without one is discarded, unanswered:\n{log}"
    );
    say(
        "settings",
        "TLS 1.2, EAP-MD5 and a request without Message-Authenticator refused",
    );

    // ---- 5. revoked after the CRL refresh ----------------------------------
    let before = radius.eap_tls(
        "press-09",
        path_str(&press09.cert),
        path_str(&press09.key),
        true,
    );
    assert!(
        before.accepted,
        "revoked: press-09 is admitted before it is revoked"
    );

    let (status, _) = api
        .post(
            &format!("/api/v1/certificates/{}/revoke", press09.id),
            &plant_a.tenants[0].1,
            json!({}),
        )
        .await;
    assert_eq!(status, 200, "revoked: AXIAM revokes press-09");
    let revoked_at = Instant::now();

    // AXIAM publishes it at once: the next response from the CRL route names it.
    let der = api.crl(plant_a.id, &line1.id).await;
    let published = String::from_utf8(openssl_in(
        &["crl", "-inform", "DER", "-noout", "-text"],
        &der,
    ))
    .expect("CRL text")
    .to_ascii_lowercase();
    assert!(
        published.contains(&certificate_serial(&press09.pem)),
        "revoked: the list AXIAM serves names press-09 at once:\n{published}"
    );

    // The revocation lag: FreeRADIUS still holds the old list.
    let lagging = radius.eap_tls(
        "press-09",
        path_str(&press09.cert),
        path_str(&press09.key),
        true,
    );
    assert!(
        lagging.accepted,
        "revoked: until FreeRADIUS reads the new list, a revoked device is still admitted \
         (the lag the guide states):\n{}",
        lagging.log
    );
    say(
        "revocation lag",
        &format!(
            "revoked in AXIAM {}s ago, still admitted: FreeRADIUS holds the old list",
            revoked_at.elapsed().as_secs()
        ),
    );

    // The refresh: fetch the list from AXIAM into ca_path ...
    let current = refresh_crl(&api, plant_a.id, &line1, &ca_file, &capath, &mirror).await;
    assert!(
        current
            .text
            .to_ascii_lowercase()
            .contains(&certificate_serial(&press09.pem))
    );
    say(
        "refresh",
        "list fetched from AXIAM into ca_path by fetch-crl.sh",
    );
    fetch_script_cases(
        &api, plant_a.id, &line1, &work, &ca_file, &capath, &mirror, &initial, &current,
    )
    .await;

    // ... and FreeRADIUS reads it: by its own ca_path_reload_interval, or, for
    // a quick local run, by a restart.
    if std::env::var("AXIAM_E2E_RADIUS_REFRESH").as_deref() == Ok("restart") {
        stack.restart();
    }
    let deadline = Instant::now() + Duration::from_secs(420);
    let refused = loop {
        let attempt = radius.eap_tls(
            "press-09",
            path_str(&press09.cert),
            path_str(&press09.key),
            true,
        );
        if !attempt.accepted {
            break attempt;
        }
        assert!(
            Instant::now() < deadline,
            "revoked: FreeRADIUS still admits press-09 {}s after the list was revoked and \
             fetched",
            revoked_at.elapsed().as_secs()
        );
        std::thread::sleep(Duration::from_secs(15));
    };
    assert!(
        refused.log.contains("certificate revoked"),
        "revoked: press-09 is refused because it is revoked:\n{}",
        refused.log
    );
    say(
        "revoked",
        &format!(
            "press-09 refused {}s after the revocation; the lag is the fetch interval plus \
             ca_path_reload_interval",
            revoked_at.elapsed().as_secs()
        ),
    );

    // Revoking one device does not touch the others.
    let still = radius.eap_tls(
        "press-07",
        path_str(&press07.cert),
        path_str(&press07.key),
        true,
    );
    assert!(
        still.accepted,
        "revoked: press-07 is still admitted:\n{}",
        still.log
    );
    say("done", "press-07 still admitted");
}

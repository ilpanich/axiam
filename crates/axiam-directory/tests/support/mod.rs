//! An in-process, scriptable LDAP server: the oracle for the client tests
//! until T23.3.6 brings containerised OpenLDAP and Samba AD.
//!
//! It speaks real LDAP (the `ldap3_proto` server codec) over real TLS
//! (`tokio-rustls`, certificates minted by `rcgen` per test), and it records
//! what it was sent — connections, StartTLS, every bind (with whether it
//! arrived encrypted, and **never** the password), every search with its
//! *parsed* filter — so a test can assert on what reached the wire rather than
//! on what the client says it did.
//!
//! It also behaves like the servers the client must survive: it accepts an
//! empty-password bind as an "unauthenticated" success (RFC 4513 §5.1.2, the
//! behaviour that makes an empty password dangerous), it answers `(attr=*)` and
//! substring filters, so an unescaped injection would genuinely widen the match,
//! and it can be told to refuse StartTLS, send referrals and search references,
//! stall, or answer with an Active Directory diagnostic.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use ldap3_proto::LdapCodec;
use ldap3_proto::proto::{
    LdapBindCred, LdapBindResponse, LdapDerefAliases, LdapExtendedResponse, LdapFilter, LdapMsg,
    LdapOp, LdapPartialAttribute, LdapResult, LdapResultCode, LdapSearchRequest,
    LdapSearchResultEntry, LdapSearchResultReference, LdapSearchScope,
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::Framed;

pub const STARTTLS_OID: &str = "1.3.6.1.4.1.1466.20037";
pub const BASE_DN: &str = "dc=example,dc=com";
pub const SERVICE_DN: &str = "cn=axiam-reader,dc=example,dc=com";

/// The service account's bind secret: minted per process, stable within one,
/// never a literal in the source.
pub fn service_secret() -> String {
    static VALUE: OnceLock<String> = OnceLock::new();
    VALUE
        .get_or_init(axiam_test_support::other_password)
        .clone()
}

/// The fixture user "alice"'s directory password: minted per process, stable
/// within one, never a literal in the source.
pub fn alice_password() -> String {
    static VALUE: OnceLock<String> = OnceLock::new();
    VALUE
        .get_or_init(axiam_test_support::other_password)
        .clone()
}

/// A throwaway certificate authority.
pub struct TestCa {
    pub pem: String,
    params: CertificateParams,
    key: KeyPair,
}

impl TestCa {
    pub fn new() -> Self {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let pem = params.self_signed(&key).unwrap().pem();
        Self { pem, params, key }
    }

    /// A server leaf for `names`, signed by this CA.
    fn leaf(&self, names: &[&str]) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let key = KeyPair::generate().unwrap();
        let params =
            CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        let issuer = Issuer::from_params(&self.params, &self.key);
        let cert = params.signed_by(&key, &issuer).unwrap();
        (
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
    }
}

/// A directory entry the server holds.
#[derive(Clone)]
pub struct Entry {
    pub dn: String,
    pub password: String,
    pub attrs: Vec<(String, Vec<Vec<u8>>)>,
}

impl Entry {
    /// An OpenLDAP-shaped person.
    pub fn person(uid: &str, password: &str, entry_uuid: &str) -> Self {
        Self {
            dn: format!("uid={uid},ou=people,{BASE_DN}"),
            password: password.into(),
            attrs: vec![
                ("objectClass".into(), vec![b"person".to_vec()]),
                ("uid".into(), vec![uid.as_bytes().to_vec()]),
                (
                    "mail".into(),
                    vec![format!("{uid}@example.com").into_bytes()],
                ),
                (
                    "displayName".into(),
                    vec![format!("Test {uid}").into_bytes()],
                ),
                ("entryUUID".into(), vec![entry_uuid.as_bytes().to_vec()]),
            ],
        }
    }
}

impl Entry {
    /// A group (`groupOfNames`) under `ou=groups`, with `member` values.
    pub fn group(cn: &str, members: &[&str]) -> Self {
        Self {
            dn: group_dn(cn),
            password: String::new(),
            attrs: vec![
                ("objectClass".into(), vec![b"groupOfNames".to_vec()]),
                ("cn".into(), vec![cn.as_bytes().to_vec()]),
                (
                    "member".into(),
                    members.iter().map(|m| m.as_bytes().to_vec()).collect(),
                ),
            ],
        }
    }

    /// An Active Directory-shaped group: no `member` list that matters here,
    /// `memberOf` naming the groups that contain it.
    pub fn ad_group(cn: &str, member_of: &[&str]) -> Self {
        Self {
            dn: group_dn(cn),
            password: String::new(),
            attrs: vec![
                ("objectClass".into(), vec![b"group".to_vec()]),
                ("cn".into(), vec![cn.as_bytes().to_vec()]),
                (
                    "memberOf".into(),
                    member_of.iter().map(|m| m.as_bytes().to_vec()).collect(),
                ),
            ],
        }
    }

    /// This entry with `attribute` set to `values` (replacing any earlier one).
    pub fn with_values(mut self, attribute: &str, values: &[&str]) -> Self {
        self.attrs
            .retain(|(name, _)| !name.eq_ignore_ascii_case(attribute));
        self.attrs.push((
            attribute.into(),
            values.iter().map(|v| v.as_bytes().to_vec()).collect(),
        ));
        self
    }
}

pub const GROUP_BASE_DN: &str = "ou=groups,dc=example,dc=com";

/// The DN of a fixture group.
pub fn group_dn(cn: &str) -> String {
    format!("cn={cn},{GROUP_BASE_DN}")
}

/// How the server's transport behaves.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// TLS from the first byte.
    Ldaps,
    /// Plain LDAP that upgrades on StartTLS.
    StartTls,
    /// Plain LDAP that refuses StartTLS — and would then accept a bind in the
    /// clear, which is what makes the client's refusal observable.
    StartTlsRefused,
    /// Accepts the TCP connection and never says anything.
    Silent,
}

/// What the server does, scripted per test.
#[derive(Clone)]
pub struct Script {
    pub transport: Transport,
    /// Names on the server certificate.
    pub cert_names: Vec<String>,
    /// Offer TLS 1.2 only.
    pub tls12_only: bool,
    pub entries: Vec<Entry>,
    /// Sent before the matching entries of every search.
    pub search_references: Vec<String>,
    /// The search's final result code and referral list (default: success).
    pub search_done: Option<(LdapResultCode, Vec<String>)>,
    /// Replaces the result of a *correct* user bind (e.g. AD's `data 533`).
    pub user_bind_result: Option<(LdapResultCode, String)>,
    /// Delay before answering any bind.
    pub bind_delay: Option<Duration>,
    /// Replaces the final result of every **group** search (a base-object read
    /// or a search under a base other than [`BASE_DN`]), e.g. a referral.
    pub group_search_done: Option<(LdapResultCode, Vec<String>)>,
    /// Delay before answering a group search.
    pub group_search_delay: Option<Duration>,
    /// From this (zero-based) group search on, on one connection, answer
    /// `busy`: level 0 of a lookup works and a later level fails.
    pub fail_group_searches_from: Option<usize>,
    /// Honour the request's size limit the way a real server does: stop and say
    /// `sizeLimitExceeded` once it is reached. Off by default, so the older
    /// tests keep the server that does not.
    pub enforce_sizelimit: bool,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            transport: Transport::Ldaps,
            cert_names: vec!["localhost".into()],
            tls12_only: false,
            entries: vec![],
            search_references: vec![],
            search_done: None,
            user_bind_result: None,
            bind_delay: None,
            group_search_done: None,
            group_search_delay: None,
            fail_group_searches_from: None,
            enforce_sizelimit: false,
        }
    }
}

/// What the server observed.
#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    Connected,
    StartTlsRequested,
    TlsEstablished,
    /// A bind. The password is never recorded — only whether it was empty.
    Bind {
        dn: String,
        encrypted: bool,
        empty_password: bool,
    },
    Search {
        base: String,
        scope: LdapSearchScope,
        filter: LdapFilter,
        sizelimit: i32,
        deref: LdapDerefAliases,
        attrs: Vec<String>,
        encrypted: bool,
    },
    Unbind,
}

/// What a test can change while the server runs: the directory's contents and
/// the scripted outcome of group searches. Everything else is fixed at start.
struct Live {
    entries: Mutex<Vec<Entry>>,
    group_search_done: Mutex<Option<(LdapResultCode, Vec<String>)>>,
}

pub struct TestServer {
    pub addr: SocketAddr,
    pub ca: Arc<TestCa>,
    live: Arc<Live>,
    events: Arc<Mutex<Vec<Event>>>,
    open_now: Arc<AtomicUsize>,
    open_max: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestServer {
    pub async fn start(script: Script) -> Self {
        Self::start_with_ca(script, Arc::new(TestCa::new())).await
    }

    pub async fn start_with_ca(script: Script, ca: Arc<TestCa>) -> Self {
        let names: Vec<&str> = script.cert_names.iter().map(String::as_str).collect();
        let (chain, key) = ca.leaf(&names);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let versions: &[&rustls::SupportedProtocolVersion] = if script.tls12_only {
            &[&rustls::version::TLS12]
        } else {
            &[&rustls::version::TLS13, &rustls::version::TLS12]
        };
        let config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let open_now = Arc::new(AtomicUsize::new(0));
        let open_max = Arc::new(AtomicUsize::new(0));
        let live = Arc::new(Live {
            entries: Mutex::new(script.entries.clone()),
            group_search_done: Mutex::new(script.group_search_done.clone()),
        });
        let script = Arc::new(script);

        let task = {
            let live = Arc::clone(&live);
            let events = Arc::clone(&events);
            let open_now = Arc::clone(&open_now);
            let open_max = Arc::clone(&open_max);
            tokio::spawn(async move {
                loop {
                    let Ok((tcp, _)) = listener.accept().await else {
                        return;
                    };
                    let session = Session {
                        script: Arc::clone(&script),
                        live: Arc::clone(&live),
                        events: Arc::clone(&events),
                        bound: None,
                        group_searches: 0,
                        _gauge: Gauge::open(&open_now, &open_max),
                    };
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        session.run(tcp, acceptor).await;
                    });
                }
            })
        };
        Self {
            addr,
            ca,
            live,
            events,
            open_now,
            open_max,
            task,
        }
    }

    /// Replace the directory's contents: what the next bind and search see.
    pub fn set_entries(&self, entries: Vec<Entry>) {
        *self.live.entries.lock().unwrap() = entries;
    }

    /// Change the scripted final result of group searches (`None`: success).
    pub fn set_group_search_done(&self, done: Option<(LdapResultCode, Vec<String>)>) {
        *self.live.group_search_done.lock().unwrap() = done;
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }

    pub fn connections(&self) -> usize {
        self.events()
            .iter()
            .filter(|e| matches!(e, Event::Connected))
            .count()
    }

    pub fn binds(&self) -> Vec<(String, bool, bool)> {
        self.events()
            .into_iter()
            .filter_map(|e| match e {
                Event::Bind {
                    dn,
                    encrypted,
                    empty_password,
                } => Some((dn, encrypted, empty_password)),
                _ => None,
            })
            .collect()
    }

    pub fn service_binds(&self) -> usize {
        self.binds()
            .iter()
            .filter(|(dn, ..)| dn == SERVICE_DN)
            .count()
    }

    pub fn user_binds(&self) -> usize {
        self.binds()
            .iter()
            .filter(|(dn, ..)| dn != SERVICE_DN)
            .count()
    }

    pub fn search_filters(&self) -> Vec<LdapFilter> {
        self.events()
            .into_iter()
            .filter_map(|e| match e {
                Event::Search { filter, .. } => Some(filter),
                _ => None,
            })
            .collect()
    }

    /// Most connections that were open at the same moment.
    pub fn max_concurrent_connections(&self) -> usize {
        self.open_max.load(Ordering::SeqCst)
    }
}

/// Counts open connections, and the high-water mark.
struct Gauge {
    open_now: Arc<AtomicUsize>,
}

impl Gauge {
    fn open(open_now: &Arc<AtomicUsize>, open_max: &Arc<AtomicUsize>) -> Self {
        let now = open_now.fetch_add(1, Ordering::SeqCst) + 1;
        open_max.fetch_max(now, Ordering::SeqCst);
        Self {
            open_now: Arc::clone(open_now),
        }
    }
}

impl Drop for Gauge {
    fn drop(&mut self) {
        self.open_now.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Session {
    script: Arc<Script>,
    live: Arc<Live>,
    events: Arc<Mutex<Vec<Event>>>,
    bound: Option<String>,
    /// Group searches answered so far on this connection.
    group_searches: usize,
    _gauge: Gauge,
}

enum Next {
    Close,
    Upgrade,
}

impl Session {
    fn record(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }

    async fn run(mut self, tcp: TcpStream, acceptor: TlsAcceptor) {
        self.record(Event::Connected);
        match self.script.transport {
            Transport::Silent => {
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
            Transport::Ldaps => {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                self.record(Event::TlsEstablished);
                let mut framed = Framed::new(tls, LdapCodec::default());
                self.serve(&mut framed, true, false).await;
            }
            Transport::StartTls | Transport::StartTlsRefused => {
                let mut framed = Framed::new(tcp, LdapCodec::default());
                let allow = self.script.transport == Transport::StartTls;
                if let Next::Upgrade = self.serve(&mut framed, false, allow).await {
                    let tcp = framed.into_inner();
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    self.record(Event::TlsEstablished);
                    let mut framed = Framed::new(tls, LdapCodec::default());
                    self.serve(&mut framed, true, false).await;
                }
            }
        }
    }

    async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        framed: &mut Framed<S, LdapCodec>,
        encrypted: bool,
        allow_starttls: bool,
    ) -> Next {
        while let Some(Ok(msg)) = framed.next().await {
            let msgid = msg.msgid;
            let replies: Vec<LdapOp> = match msg.op {
                LdapOp::ExtendedRequest(req) if req.name == STARTTLS_OID => {
                    self.record(Event::StartTlsRequested);
                    if allow_starttls {
                        let ok = reply(
                            msgid,
                            LdapOp::ExtendedResponse(extended(LdapResultCode::Success)),
                        );
                        if framed.send(ok).await.is_err() {
                            return Next::Close;
                        }
                        return Next::Upgrade;
                    }
                    vec![LdapOp::ExtendedResponse(extended(
                        LdapResultCode::Unavailable,
                    ))]
                }
                LdapOp::ExtendedRequest(_) => vec![LdapOp::ExtendedResponse(extended(
                    LdapResultCode::ProtocolError,
                ))],
                LdapOp::BindRequest(req) => {
                    let password = match req.cred {
                        LdapBindCred::Simple(pw) => pw,
                        // A SASL bind carries no simple password. Give it a value no
                        // entry or service secret can equal, so it is never accepted.
                        LdapBindCred::SASL(_) => uuid::Uuid::new_v4().to_string(),
                    };
                    self.record(Event::Bind {
                        dn: req.dn.clone(),
                        encrypted,
                        empty_password: password.is_empty(),
                    });
                    if let Some(delay) = self.script.bind_delay {
                        tokio::time::sleep(delay).await;
                    }
                    let (code, message) = self.bind(&req.dn, &password);
                    vec![LdapOp::BindResponse(LdapBindResponse {
                        res: result(code, &message, vec![]),
                        saslcreds: None,
                    })]
                }
                LdapOp::SearchRequest(req) => {
                    self.record(Event::Search {
                        base: req.base.clone(),
                        scope: req.scope.clone(),
                        filter: req.filter.clone(),
                        sizelimit: req.sizelimit,
                        deref: req.aliases.clone(),
                        attrs: req.attrs.clone(),
                        encrypted,
                    });
                    if is_group_search(&req)
                        && let Some(delay) = self.script.group_search_delay
                    {
                        tokio::time::sleep(delay).await;
                    }
                    if is_group_search(&req) {
                        let index = self.group_searches;
                        self.group_searches += 1;
                        if self
                            .script
                            .fail_group_searches_from
                            .is_some_and(|n| index >= n)
                        {
                            vec![LdapOp::SearchResultDone(result(
                                LdapResultCode::Busy,
                                "scripted failure",
                                vec![],
                            ))]
                        } else {
                            self.search(&req)
                        }
                    } else {
                        self.search(&req)
                    }
                }
                LdapOp::UnbindRequest => {
                    self.record(Event::Unbind);
                    return Next::Close;
                }
                _ => return Next::Close,
            };
            for op in replies {
                if framed.send(reply(msgid, op)).await.is_err() {
                    return Next::Close;
                }
            }
        }
        Next::Close
    }

    fn bind(&mut self, dn: &str, password: &str) -> (LdapResultCode, String) {
        // RFC 4513 §5.1.2: a name with an empty password is an
        // "unauthenticated" bind, and servers that allow it report success.
        // That is exactly why the client must never send one.
        if password.is_empty() {
            self.bound = None;
            return (LdapResultCode::Success, String::new());
        }
        if dn == SERVICE_DN && password == service_secret() {
            self.bound = Some(dn.to_string());
            return (LdapResultCode::Success, String::new());
        }
        let found = self
            .live
            .entries
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.dn == dn)
            .cloned();
        if let Some(entry) = found
            && entry.password == password
        {
            if let Some((code, message)) = &self.script.user_bind_result {
                return (code.clone(), message.clone());
            }
            self.bound = Some(dn.to_string());
            return (LdapResultCode::Success, String::new());
        }
        self.bound = None;
        (
            LdapResultCode::InvalidCredentials,
            "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e, v4563"
                .into(),
        )
    }

    fn search(&self, req: &LdapSearchRequest) -> Vec<LdapOp> {
        let (filter, attrs) = (&req.filter, &req.attrs);
        if self.bound.as_deref() != Some(SERVICE_DN) {
            return vec![LdapOp::SearchResultDone(result(
                LdapResultCode::InsufficentAccessRights,
                "search requires the service account",
                vec![],
            ))];
        }
        let group_search = is_group_search(req);
        let mut out = Vec::new();
        for uri in &self.script.search_references {
            out.push(LdapOp::SearchResultReference(LdapSearchResultReference {
                uris: vec![uri.clone()],
            }));
        }
        let base_object = matches!(req.scope, LdapSearchScope::Base);
        let mut found_base = false;
        let mut limited = false;
        let entries = self.live.entries.lock().unwrap().clone();
        for (sent, entry) in entries
            .iter()
            .filter(|e| {
                if base_object {
                    // A base-object read: the one entry whose DN is the base.
                    e.dn.eq_ignore_ascii_case(&req.base) && matches(filter, e)
                } else {
                    matches(filter, e)
                }
            })
            .enumerate()
        {
            found_base = true;
            if self.script.enforce_sizelimit
                && req.sizelimit > 0
                && sent >= usize::try_from(req.sizelimit).unwrap_or(usize::MAX)
            {
                limited = true;
                break;
            }
            out.push(LdapOp::SearchResultEntry(LdapSearchResultEntry {
                dn: entry.dn.clone(),
                attributes: entry
                    .attrs
                    .iter()
                    .filter(|(name, _)| {
                        // A ranged attribute (`memberOf;range=0-1499`) answers a
                        // request for `memberOf`, as Active Directory's does.
                        let plain = name.split(';').next().unwrap_or(name);
                        attrs.iter().any(|a| a.eq_ignore_ascii_case(plain))
                    })
                    .map(|(name, vals)| LdapPartialAttribute {
                        atype: name.clone(),
                        vals: vals.clone(),
                    })
                    .collect(),
            }));
        }
        let scripted = if group_search {
            self.live.group_search_done.lock().unwrap().clone()
        } else {
            None
        };
        let (code, referral) = if let Some(done) = scripted {
            done
        } else if limited {
            (LdapResultCode::SizeLimitExceeded, vec![])
        } else if base_object && !found_base {
            (LdapResultCode::NoSuchObject, vec![])
        } else {
            self.script
                .search_done
                .clone()
                .unwrap_or((LdapResultCode::Success, vec![]))
        };
        out.push(LdapOp::SearchResultDone(result(code, "", referral)));
        out
    }
}

/// A group lookup rather than the user search: a base-object read, or a search
/// under any base but the user base.
fn is_group_search(req: &LdapSearchRequest) -> bool {
    matches!(req.scope, LdapSearchScope::Base) || !req.base.eq_ignore_ascii_case(BASE_DN)
}

fn values(entry: &Entry, attr: &str) -> Vec<String> {
    entry
        .attrs
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(attr))
        .flat_map(|(_, vals)| vals.iter())
        .filter_map(|v| String::from_utf8(v.clone()).ok())
        .collect()
}

/// A small filter evaluator — enough for `(attr=*)` and substrings to widen a
/// match, which is the hazard an unescaped login name would create.
fn matches(filter: &LdapFilter, entry: &Entry) -> bool {
    match filter {
        LdapFilter::And(parts) => parts.iter().all(|f| matches(f, entry)),
        LdapFilter::Or(parts) => parts.iter().any(|f| matches(f, entry)),
        LdapFilter::Not(inner) => !matches(inner, entry),
        LdapFilter::Equality(attr, value) => values(entry, attr)
            .iter()
            .any(|v| v.eq_ignore_ascii_case(value)),
        LdapFilter::Present(attr) => !values(entry, attr).is_empty(),
        LdapFilter::Substring(attr, sub) => values(entry, attr).iter().any(|v| {
            let v = v.to_ascii_lowercase();
            sub.initial
                .as_ref()
                .is_none_or(|i| v.starts_with(&i.to_ascii_lowercase()))
                && sub
                    .final_
                    .as_ref()
                    .is_none_or(|f| v.ends_with(&f.to_ascii_lowercase()))
                && sub.any.iter().all(|a| v.contains(&a.to_ascii_lowercase()))
        }),
        _ => false,
    }
}

fn reply(msgid: i32, op: LdapOp) -> LdapMsg {
    LdapMsg {
        msgid,
        op,
        ctrl: vec![],
    }
}

fn result(code: LdapResultCode, message: &str, referral: Vec<String>) -> LdapResult {
    LdapResult {
        code,
        matcheddn: String::new(),
        message: message.into(),
        referral,
    }
}

fn extended(code: LdapResultCode) -> LdapExtendedResponse {
    LdapExtendedResponse {
        res: result(code, "", vec![]),
        name: None,
        value: None,
    }
}

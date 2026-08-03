//! AXIAM Rust SDK benchmark (wired to `axiam-sdk`).
//!
//! Times `axiam_sdk::client::AxiamClient`'s canonical CONTRACT.md §1
//! operations — `login`, `refresh`, `check_access`, `batch_check` — against a
//! running, seeded AXIAM target. `oauth2_token`/`introspect`/`userinfo` are
//! protocol-level ops with no SDK wrapper (see ../HARNESS-SPEC.md) and are not
//! measured here. The stdout JSON contract (`axiam.sdk-bench/v1`) must stay
//! intact — the aggregator (`sdk/collect.py`) depends on `schema`, `sdk`,
//! `status`, and `ops.*`.
//!
//! This mirrors the reference harnesses `../python/bench.py` and
//! `../typescript/bench.mjs` (timing loop, percentile math, warm-up, graceful
//! pending/error handling, JSON shape).
//!
//! Run: cargo run --release   (or: cd benchmarks && just sdk=rust sdk-bench)

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use axiam_sdk::AxiamError;
use axiam_sdk::client::AxiamClient;
use axiam_sdk::rest::authz::AccessCheckRequest;
use uuid::Uuid;

const OP_KEYS: [&str; 4] = ["login", "refresh", "check_access", "batch_check"];

/// Read an env var, falling back to `default`.
fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Parsed configuration + tuning knobs, read once from the environment
/// (identical keys/defaults to the Python and TypeScript reference harnesses).
struct Cfg {
    base_url: String,
    tenant_slug: String,
    org_slug: String,
    username: String,
    password: String,
    action: String,
    resource_id: Uuid,
    iterations: usize,
    warmup: usize,
    concurrency: usize,
    target: String,
    profile: String,
    /// H8 fix: HARNESS-SPEC.md documents BENCH_CA_CERT (a PEM file path) as
    /// an input every SDK bench should honor under the TLS profiles (p2),
    /// but this bench never read it before — every p2 run failed at the
    /// first HTTPS call with a certificate-verification error against the
    /// profile's throwaway CA. `None` under p0/plaintext (unset).
    custom_ca_pem: Option<Vec<u8>>,
    /// p3-mtls client identity as `(cert_pem, key_pem)` — CONTRACT.md §6.1.
    /// Read from BENCH_CLIENT_CERT/BENCH_CLIENT_KEY (file PATHS, the same
    /// pair k6 hands to `tlsAuth` and seed.sh to `curl --cert`). `None` on
    /// p0/p1/p2, where no builder call is made and the SDK's default
    /// bearer-cookie behavior is untouched (§6.1 rule 5: mTLS is opt-in).
    client_identity_pem: Option<(Vec<u8>, Vec<u8>)>,
}

impl Cfg {
    fn from_env() -> Result<Self, String> {
        let base_url = format!(
            "{}://{}:{}",
            env("BENCH_SCHEME", "http"),
            env("BENCH_HOST", "localhost"),
            env("BENCH_PORT", "8090"),
        );

        // `check_access`/`batch_check` require a real resource UUID — the
        // server rejects non-UUID resource ids. Unlike the loosely-typed
        // reference harnesses, the Rust SDK takes a `uuid::Uuid`, so parse it
        // up front and treat a missing/invalid value as a setup error.
        let resource_id_raw = env("BENCH_RESOURCE_ID", "");
        let resource_id = Uuid::parse_str(resource_id_raw.trim()).map_err(|_| {
            format!(
                "BENCH_RESOURCE_ID must be a valid UUID (got {resource_id_raw:?}); \
                 the AXIAM authz endpoints reject non-UUID resource ids"
            )
        })?;

        let parse_usize = |key: &str, default: &str| -> usize {
            env(key, default).parse().unwrap_or_else(|_| {
                default.parse().expect("literal default parses")
            })
        };

        let ca_path = env("BENCH_CA_CERT", "");
        let custom_ca_pem = if ca_path.is_empty() {
            None
        } else {
            Some(std::fs::read(&ca_path).map_err(|e| {
                format!("BENCH_CA_CERT={ca_path:?} could not be read: {e}")
            })?)
        };

        // p3-mtls client identity (CONTRACT.md §6.1). The pair is
        // all-or-nothing: the SDK's builder rejects a half-configured
        // identity too (§6.1 rule 1), but failing here names the env var the
        // operator actually got wrong.
        let cert_path = env("BENCH_CLIENT_CERT", "");
        let key_path = env("BENCH_CLIENT_KEY", "");
        if cert_path.is_empty() != key_path.is_empty() {
            return Err(format!(
                "BENCH_CLIENT_CERT={cert_path:?} and BENCH_CLIENT_KEY={key_path:?} must be \
                 set together — mTLS needs both (CONTRACT.md §6.1 rule 1)"
            ));
        }
        let client_identity_pem = if cert_path.is_empty() {
            None
        } else {
            let cert = std::fs::read(&cert_path).map_err(|e| {
                format!("BENCH_CLIENT_CERT={cert_path:?} could not be read: {e}")
            })?;
            let key = std::fs::read(&key_path).map_err(|e| {
                format!("BENCH_CLIENT_KEY={key_path:?} could not be read: {e}")
            })?;
            Some((cert, key))
        };

        Ok(Cfg {
            base_url,
            tenant_slug: env("BENCH_TENANT_SLUG", "default"),
            org_slug: env("BENCH_ORG_SLUG", "bench-org"),
            username: env("BENCH_USERNAME", "benchuser"),
            password: env("BENCH_PASSWORD", "Bench@User123!"),
            action: env("BENCH_ACTION", "read"),
            resource_id,
            iterations: parse_usize("SDK_BENCH_ITERATIONS", "2000"),
            warmup: parse_usize("SDK_BENCH_WARMUP", "200"),
            concurrency: parse_usize("SDK_BENCH_CONCURRENCY", "16"),
            target: env("BENCH_TARGET", "axiam"),
            profile: env("BENCH_PROFILE", "p0-plaintext"),
            custom_ca_pem,
            client_identity_pem,
        })
    }
}

/// The four canonical ops. `Login` builds and discards a fresh, unauthenticated
/// client per call (mirroring what the op measures); the other three share one
/// already-authenticated client (`refresh` is routed through the SDK's
/// single-flight guard, so serial timing measures real wire cost).
#[derive(Clone, Copy)]
enum Op {
    Login,
    Refresh,
    CheckAccess,
    BatchCheck,
}

/// Build a tenant-scoped client. `base_url()` validates the scheme (https, or
/// http on loopback) and returns a `Result`; the tenant slug is required, and
/// the org slug is required for login/refresh (CONTRACT.md §5.1).
fn build_client(cfg: &Cfg) -> Result<AxiamClient, AxiamError> {
    let mut builder = AxiamClient::builder()
        .base_url(cfg.base_url.as_str())?
        .tenant_slug(cfg.tenant_slug.as_str())
        .org_slug(cfg.org_slug.as_str());
    // H8 fix: trust BENCH_CA_CERT (the p2 profile's throwaway CA) when set.
    if let Some(pem) = &cfg.custom_ca_pem {
        builder = builder.with_custom_ca(pem)?;
    }
    // p3-mtls: present the client identity (CONTRACT.md §6.1). Doing it here,
    // in the single shared constructor, means the identity cannot drift
    // between the long-lived client and the fresh one `Op::Login` builds per
    // iteration — a login client without it would fail the handshake while
    // the other three ops succeeded.
    if let Some((cert_pem, key_pem)) = &cfg.client_identity_pem {
        builder = builder.with_client_cert(cert_pem, key_pem)?;
    }
    builder.build()
}

/// Execute one op invocation, discarding the success payload. `shared` is the
/// pre-authenticated client used by refresh/check_access/batch_check; `Login`
/// ignores it and builds its own throwaway client.
async fn run_one(op: Op, shared: &AxiamClient, cfg: &Cfg) -> Result<(), AxiamError> {
    match op {
        Op::Login => {
            let fresh = build_client(cfg)?;
            fresh.login(&cfg.username, &cfg.password).await?;
            // `fresh` is dropped here — a fresh, short-lived session per call.
            Ok(())
        }
        Op::Refresh => shared.refresh().await,
        Op::CheckAccess => shared
            .check_access(&cfg.action, cfg.resource_id, None)
            .await
            .map(|_| ()),
        Op::BatchCheck => {
            // Three checks, all against the SAME real resource UUID (no
            // -0/-1/-2 suffixes — the server needs valid UUIDs).
            let checks = vec![
                AccessCheckRequest::new(cfg.action.clone(), cfg.resource_id),
                AccessCheckRequest::new(cfg.action.clone(), cfg.resource_id),
                AccessCheckRequest::new(cfg.action.clone(), cfg.resource_id),
            ];
            shared.batch_check(checks).await.map(|_| ())
        }
    }
}

/// Percentile via linear interpolation between closest ranks — identical method
/// to the Python/TypeScript reference harnesses.
fn pct(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let k = (sorted.len() - 1) as f64 * (p / 100.0);
    let lo = k.floor() as usize;
    let hi = (lo + 1).min(sorted.len() - 1);
    sorted[lo] + (sorted[hi] - sorted[lo]) * (k - lo as f64)
}

/// Warm up, then run `iterations` timed invocations across `concurrency`
/// workers, returning the per-op contract record. Warm-up errors are counted
/// (matching the reference harnesses).
async fn time_op(
    op: Op,
    shared: &AxiamClient,
    cfg: &Arc<Cfg>,
    iterations: usize,
    warmup: usize,
    concurrency: usize,
) -> serde_json::Value {
    let mut errors: u64 = 0;

    // Warm-up (uncounted latency, counted errors), run serially.
    for _ in 0..warmup {
        if run_one(op, shared, cfg).await.is_err() {
            errors += 1;
        }
    }

    let counter = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..concurrency.max(1) {
        let shared = shared.clone();
        let cfg = Arc::clone(cfg);
        let counter = Arc::clone(&counter);
        set.spawn(async move {
            let mut lat: Vec<f64> = Vec::new();
            let mut errs: u64 = 0;
            loop {
                let i = counter.fetch_add(1, Ordering::Relaxed);
                if i >= iterations {
                    break;
                }
                let t0 = Instant::now();
                match run_one(op, &shared, &cfg).await {
                    Ok(()) => lat.push(t0.elapsed().as_secs_f64() * 1000.0),
                    Err(_) => errs += 1,
                }
            }
            (lat, errs)
        });
    }

    let mut lat: Vec<f64> = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok((mut l, e)) = res {
            lat.append(&mut l);
            errors += e;
        }
    }

    let secs = start.elapsed().as_secs_f64();
    lat.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let throughput = if secs > 0.0 {
        lat.len() as f64 / secs
    } else {
        0.0
    };

    serde_json::json!({
        "p50_ms": pct(&lat, 50.0),
        "p95_ms": pct(&lat, 95.0),
        "p99_ms": pct(&lat, 99.0),
        "throughput_rps": throughput,
        "errors": errors,
    })
}

/// The `ops` object with every op zeroed — used for `pending`/`error` records.
fn zero_ops() -> serde_json::Value {
    let mut ops = serde_json::Map::new();
    for k in OP_KEYS {
        ops.insert(
            k.to_string(),
            serde_json::json!({
                "p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "throughput_rps": 0, "errors": 0
            }),
        );
    }
    serde_json::Value::Object(ops)
}

/// I13 (improvement-after-run4-benchmark.md §C): `client_cpu_ms_total`/
/// `client_rss_mib_peak` recorded 0.0 for every SDK bench — the sampler was
/// never wired. Reads `/proc/self/status` (`VmHWM`, already a lifetime
/// high-water mark, not a snapshot) for peak RSS and `/proc/self/stat`
/// (fields 14/15: utime/stime in clock ticks) for cumulative CPU time —
/// stdlib-only (`std::fs`), no new crate dependency. Linux-only (matches
/// this harness' Docker/K8s deployment target per CLAUDE.md); returns
/// `(0.0, 0.0)` if `/proc` is unavailable rather than failing the bench.
/// The kernel clock-tick rate is assumed to be the near-universal Linux
/// default of 100 Hz (`sysconf(_SC_CLK_TCK)`) rather than queried, since
/// querying it portably needs an FFI call this file otherwise has no reason
/// to make; this makes `client_cpu_ms_total` an approximation on the rare
/// kernel built with a different `USER_HZ`.
fn client_resource_usage() -> (f64, f64) {
    const CLK_TCK_HZ: f64 = 100.0;

    let rss_mib_peak = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("VmHWM:").map(|rest| {
                    rest.trim()
                        .split_whitespace()
                        .next()
                        .and_then(|kb| kb.parse::<f64>().ok())
                        .unwrap_or(0.0)
                        / 1024.0 // kB -> MiB
                })
            })
        })
        .unwrap_or(0.0);

    let parse_field = |fields: &[&str], idx: usize| -> Option<f64> {
        fields.get(idx).and_then(|s| s.parse::<f64>().ok())
    };
    let cpu_ms_total = std::fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|stat| {
            // Field 2 (comm) may itself contain spaces/parens, so split on
            // the LAST ')' before splitting the remaining fields by
            // whitespace (the same trick ps/top use).
            let after_comm = stat.rsplit_once(')')?.1;
            let fields: Vec<&str> = after_comm.split_whitespace().collect();
            // Fields after `comm` are 1-indexed from `state` (field 3 overall):
            // utime is overall field 14 -> fields[11]; stime is field 15 -> fields[12].
            let utime = parse_field(&fields, 11)?;
            let stime = parse_field(&fields, 12)?;
            Some((utime + stime) / CLK_TCK_HZ * 1000.0)
        })
        .unwrap_or(0.0);

    (cpu_ms_total, rss_mib_peak)
}

/// Print exactly one `axiam.sdk-bench/v1` JSON object to stdout.
fn emit(
    status: &str,
    ops: serde_json::Value,
    iterations: usize,
    concurrency: usize,
    target: &str,
    profile: &str,
    notes: &str,
) {
    let (cpu_ms_total, rss_mib_peak) = client_resource_usage();
    let record = serde_json::json!({
        "schema": "axiam.sdk-bench/v1",
        "sdk": "rust",
        "sdk_version": "1.0.0-alpha7",
        "language_runtime": "rust (cargo)",
        "target": target,
        "profile": profile,
        "status": status,
        "iterations": iterations,
        "concurrency": concurrency,
        "ops": ops,
        "client_cpu_ms_total": cpu_ms_total,
        "client_rss_mib_peak": rss_mib_peak,
        "notes": notes,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&record).expect("record serializes")
    );
}

/// I9 (improvement-after-run4-benchmark.md §C): a floor below which a
/// measured `refresh` latency is not plausibly a real HTTP round trip. The
/// C# bench recorded p50 1.2 microseconds ("752 k rps") because its SDK's
/// RefreshGuard cached a completed token result on a shared client for up
/// to ~15 minutes (wall-clock freshness, no observed-token check), so only
/// the FIRST refresh in a ~2200-call run ever touched the wire. This SDK's
/// `token::refresh_guard::TokenManager::refresh_if_needed` keys on the
/// caller's currently observed access token instead, which this bench's
/// `shared.refresh()` call updates after every real refresh — so a
/// same-client loop keeps hitting the wire — but this floor is kept as a
/// language-agnostic regression guard against that class of bug reappearing
/// here too (a cache hit completes in low single-digit microseconds; every
/// genuine wire call recorded across this harness' 11 languages averages
/// ~17 ms, so 0.2 ms leaves a wide margin).
const MIN_PLAUSIBLE_REFRESH_MS: f64 = 0.2;

/// I9 shared-driver-style regression guard: fail loudly (non-zero exit)
/// instead of silently publishing a fake number if `refresh` looks like it
/// never left the process.
fn assert_refresh_hit_the_wire(refresh: &serde_json::Value, iterations: usize) {
    let errors = refresh["errors"].as_u64().unwrap_or(0) as usize;
    let p50 = refresh["p50_ms"].as_f64().unwrap_or(0.0);
    let had_samples = errors < iterations;
    if had_samples && p50 < MIN_PLAUSIBLE_REFRESH_MS {
        eprintln!(
            "[rust] I9 guard: refresh p50={p50:.4}ms is below the {MIN_PLAUSIBLE_REFRESH_MS}ms \
             plausible-wire-call floor despite successful samples — this looks like a cached \
             no-op (CONTRACT.md §9 guard reuse), not a real HTTP round trip. Failing the bench \
             run instead of publishing a fake number (see improvement-after-run4-benchmark.md I9)."
        );
        std::process::exit(1);
    }
}

#[tokio::main]
async fn main() {
    // Config / env parsing failures (e.g. a non-UUID BENCH_RESOURCE_ID) are a
    // setup error, not a crash: emit a zeroed `error` record and exit 0.
    let cfg = match Cfg::from_env() {
        Ok(cfg) => cfg,
        Err(note) => {
            emit("error", zero_ops(), 0, 0, "axiam", "p0-plaintext", &note);
            return;
        }
    };

    // Build one authenticated client shared by refresh/check_access/batch_check.
    // A failure here (server down, seed missing, bad credentials) is graceful:
    // emit a zeroed `error` record and exit 0.
    let shared = match build_client(&cfg) {
        Ok(client) => match client.login(&cfg.username, &cfg.password).await {
            Ok(_) => client,
            Err(e) => {
                emit(
                    "error",
                    zero_ops(),
                    0,
                    0,
                    &cfg.target,
                    &cfg.profile,
                    &format!("server unreachable or setup failed: {e}"),
                );
                return;
            }
        },
        Err(e) => {
            emit(
                "error",
                zero_ops(),
                0,
                0,
                &cfg.target,
                &cfg.profile,
                &format!("server unreachable or setup failed: {e}"),
            );
            return;
        }
    };

    let iterations = cfg.iterations;
    let warmup = cfg.warmup;
    let conc = cfg.concurrency;
    let target = cfg.target.clone();
    let profile = cfg.profile.clone();
    let cfg = Arc::new(cfg);

    // login/check_access/batch_check run at SDK_BENCH_CONCURRENCY. `refresh`
    // runs SERIALLY (concurrency 1): the SDK single-flight-guards refresh, so
    // concurrent callers would coalesce into one wire call and under-report the
    // real cost.
    let login = time_op(Op::Login, &shared, &cfg, iterations, warmup, conc).await;
    let refresh = time_op(Op::Refresh, &shared, &cfg, iterations, warmup, 1).await;
    let check_access = time_op(Op::CheckAccess, &shared, &cfg, iterations, warmup, conc).await;
    let batch_check = time_op(Op::BatchCheck, &shared, &cfg, iterations, warmup, conc).await;

    let ops = serde_json::json!({
        "login": login,
        "refresh": refresh,
        "check_access": check_access,
        "batch_check": batch_check,
    });

    emit("ok", ops.clone(), iterations, conc, &target, &profile, "");
    assert_refresh_hit_the_wire(&ops["refresh"], iterations);
}

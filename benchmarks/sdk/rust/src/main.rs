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
    username: String,
    password: String,
    action: String,
    resource_id: Uuid,
    iterations: usize,
    warmup: usize,
    concurrency: usize,
    target: String,
    profile: String,
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

        Ok(Cfg {
            base_url,
            tenant_slug: env("BENCH_TENANT_SLUG", "default"),
            username: env("BENCH_USERNAME", "benchuser"),
            password: env("BENCH_PASSWORD", "Bench@User123!"),
            action: env("BENCH_ACTION", "read"),
            resource_id,
            iterations: parse_usize("SDK_BENCH_ITERATIONS", "2000"),
            warmup: parse_usize("SDK_BENCH_WARMUP", "200"),
            concurrency: parse_usize("SDK_BENCH_CONCURRENCY", "16"),
            target: env("BENCH_TARGET", "axiam"),
            profile: env("BENCH_PROFILE", "p0-plaintext"),
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
/// http on loopback) and returns a `Result`; the tenant slug is required.
fn build_client(cfg: &Cfg) -> Result<AxiamClient, AxiamError> {
    AxiamClient::builder()
        .base_url(cfg.base_url.as_str())?
        .tenant_slug(cfg.tenant_slug.as_str())
        .build()
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
        "client_cpu_ms_total": 0,
        "client_rss_mib_peak": 0,
        "notes": notes,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&record).expect("record serializes")
    );
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

    emit("ok", ops, iterations, conc, &target, &profile, "");
}

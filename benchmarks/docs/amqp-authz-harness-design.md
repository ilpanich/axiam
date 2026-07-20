# AMQP Async-Authz Load Harness — Design (E2)

**Status:** DESIGN (the plan's mandated "design doc first" deliverable for E2).
Implementation is scaffolded per §5 but its acceptance is a **measured run
against a live RabbitMQ + AXIAM authz consumer** and is therefore pending the
benchmark environment — no throughput/latency numbers appear here until that
run exists.

## 1. Why a separate tool

The k6-based matrix cannot exercise the AMQP path — k6 speaks HTTP/gRPC, not
AMQP, and the async-authz flow is request/response over two queues with
HMAC-signed, replay-protected messages. `benchmarks/README.md` lists AMQP as
explicitly out of scope for the first matrix. E2 closes that gap with a
dedicated publisher/consumer load tool that measures the metric that matters
for deferred authz: **end-to-end decision latency** (publish → correlated
response) and **consumer throughput** (decisions/s the AXIAM consumer
sustains).

## 2. The contract being measured (from `crates/axiam-amqp`)

- **Request queue:** `axiam.authz.request` (`connection::queues::AUTHZ_REQUEST`).
- **Response queue:** `axiam.authz.response` (`AUTHZ_RESPONSE`).
- **Request message** (`messages::AuthzRequest`): `correlation_id`,
  `tenant_id`, `subject_id`, `action`, `resource_id`, `scope?`, `key_version`
  (currently `2`), `nonce` (unique per message), `issued_at`, and an
  `hmac_signature` over the canonical payload.
- **Signing:** HMAC-SHA256 with a **per-tenant subkey** derived as
  `derive_tenant_key(master_key, tenant_id, key_version)`. The harness must
  hold the same tenant master key the AXIAM consumer verifies against (a bench
  secret, sourced from `.seed/` like every other bench credential — never
  committed).
- **Replay/freshness gates the harness must satisfy:** `key_version >= 2`,
  `issued_at` within `DEFAULT_FRESHNESS_SKEW_SECS` (300 s), and a **unique
  `nonce` per message** (the consumer records consumed nonces in the durable
  `amqp_nonce_replay` store and rejects duplicates — so the load tool must
  generate a fresh nonce every publish or it will measure rejections, not
  decisions).
- **Response** (`messages::AuthzResponse`): carries the same `correlation_id`
  so the harness can pair a response to its request and compute latency.

## 3. Metrics

Per run, over a measured window (after warm-up):

- **Decision latency** end-to-end: `t(response received) − t(request
  published)`, correlated by `correlation_id`. Report p50/p95/p99 + max.
- **Consumer throughput:** responses/s sustained at steady state.
- **Publish rate vs. drain rate:** offered load vs. responses/s, to find the
  saturation knee (where latency diverges = the consumer's ceiling).
- **In-flight depth:** outstanding (published-not-yet-answered) count over
  time — a proxy for queue backlog.
- **Rejections:** responses that are errors, plus publishes with no response
  within a timeout (surfaced separately — a silent timeout is a failure, not a
  slow success).

Emit one JSON record per run mirroring the k6 harness's shape
(`bench_ok`/`bench_failed`/latency percentiles) so `runner/report.py` /
`sdk/collect.py` can fold AMQP cells into the same report with a clear
`protocol: amqp` label (not comparable head-to-head with REST/gRPC single
checks — it measures a *deferred* decision, a different logical op).

## 4. Load model

- **Open model, fixed arrival rate** (like k6's `constant-arrival-rate`):
  publish at R req/s regardless of in-flight depth, so latency reflects the
  consumer's true service time under offered load rather than a closed loop
  that self-throttles. Sweep R across a few points to trace the latency knee.
- **Bounded in-flight cap** as a safety valve (stop publishing if outstanding
  exceeds a ceiling) to avoid unbounded memory on a saturated consumer —
  logged as a saturation event, never silently.
- **Request shape** matches the k6 authz scenario's seeded subject/resource so
  the AMQP number is comparable *within AXIAM* to the REST/gRPC authz cells
  (same evaluation cost, different transport/dispatch).

## 5. Implementation plan (scaffold; build behind a live broker)

Two viable implementations; **prefer (a)** for signature fidelity:

- **(a) Rust bench binary** under `benchmarks/amqp/` (its own tiny crate,
  *not* in the server workspace to keep server build times unaffected) that
  depends on `axiam-amqp` for `AuthzRequest`/`AuthzResponse`,
  `derive_tenant_key`, and canonical signing — guaranteeing byte-identical
  signatures/nonce handling with the server. Uses `lapin` (already a
  server dep) for publish/consume. A publisher task fans out at rate R; a
  consumer task drains `axiam.authz.response`, matches `correlation_id` in a
  `DashMap`/`HashMap`, timestamps, and records latencies into an `hdrhistogram`.
- **(b) Python + `pika`** — faster to iterate but must re-implement the exact
  `derive_tenant_key` HKDF + canonical JSON signing, which risks drift from
  the Rust canonicalization. Only if (a)'s build cost is prohibitive.

Wire-up: a `just bench-amqp target=axiam rate=<R> duration=<s>` recipe that
brings up the AXIAM stack (which already starts the authz consumer),
sources the tenant master key from `.seed/`, runs the tool, and drops a JSON
record into `results/<target>/amqp/`.

## 6. Acceptance (to verify on the benchmark environment)

1. A short run against a seeded AXIAM stack produces a valid record with real
   correlated end-to-end latency percentiles and a steady-state responses/s.
2. Every published request either gets a correlated response or is counted as
   a timeout — no silent drops.
3. Signatures/nonces are accepted by the live consumer (zero rejections on the
   happy path), proving contract fidelity.
4. The latency-vs-rate sweep shows a saturation knee, locating the consumer
   ceiling.

## 7. Out of scope

- Multi-tenant fan-out and DLQ/retry-storm behavior (a follow-up).
- Comparing AMQP decisions/s head-to-head with REST/gRPC — different logical
  op (deferred vs. synchronous); the report labels it, never ranks it against
  them.

---

*Design grounded in `crates/axiam-amqp/{messages,authz_consumer,connection}.rs`
at branch `claude/benchmark-improvement-plan-9yxx7g`. Implementation to land as
its own PR with measured numbers once a live broker run is available.*

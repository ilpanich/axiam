# New-feature benchmark cells (E4)

> Companion to [`run5-runbook.md`](run5-runbook.md) and §E4 of
> [`improvement-after-run5-benchmark.md`](improvement-after-run5-benchmark.md).
> Every feature this improvement round adds to the server changes something a
> reader of the benchmark can ask about, and the project's rule is that a
> feature ships with its measured cost rather than with an assurance. This
> file is the list of labeled cells that obligation turns into, and the exact
> commands for each.
>
> Cells are **labeled**: each one is a deliberate, non-default configuration,
> and its numbers are not interchangeable with the default matrix's. Every
> cell below records its distinguishing configuration in `meta.json`
> (`axiam_env`, `seed_scale`, `connection_model`), so a labeled result can
> never be read as a default one.

## Status

| Cell | Feature | State |
|---|---|---|
| `authz-deny-present` | B1 deny-override | **ready** — run it |
| `grpc-strict-revocation` | A4 opt-in strict mode | **ready** — run it |
| `seed-scale` | E3 bulk fixture | **ready** — run it |
| `device-flow-poll` | B2 device authorization grant | unblocked, scenario unwritten — REST surface mounted in `ffaaed1` (`POST /oauth2/device_authorization`, the `device_code` arm of `POST /oauth2/token`, `GET /api/v1/device/verify`, `POST /api/v1/device/decide`); the k6 scenario itself still needs authoring |
| `token-exchange` | B3 RFC 8693 | unblocked, scenario unwritten — grant implemented and wired into the server in `4dbd832` (`handle_token_exchange` in `crates/axiam-api-rest/src/handlers/oauth2.rs`, dispatched from `POST /oauth2/token`); the k6 scenario itself still needs authoring |
| `amqp-tls` | A6 broker TLS | optional; see A6 step 6 |

A blocked cell has no scenario file on purpose. Writing a k6 script against
endpoints that do not exist produces a scenario that fails for the wrong
reason and quietly rots; the cell lands with its feature. `device-flow-poll`
and `token-exchange` have graduated out of that state — the endpoints exist
and are reachable in a real deployment (verified against `ffaaed1` and
`4dbd832` respectively) — but neither k6 scenario has been written yet, so
neither cell has ever been run. That authoring work is tracked in the
remediation plan's Wave R7 (the E4 row: "author the two missing k6 scenarios
first").

---

## `authz-deny-present` — what deny-override costs when denies exist

**The question.** B1's evaluation short-circuits: the second, deny-matching
indexed query only runs for tenants that hold at least one deny rule, so the
common case stays one indexed query and the run-5 numbers should be
reproducible to within noise. Two things need publishing — that the
no-denies path really is unchanged, and what the with-denies path costs.

**Both arms, same fixture, same scenario.** The only difference is whether
the tenant holds deny rules, which is what `--deny-ratio` controls.

```bash
cd benchmarks

# ---- Arm A: control. No deny rules anywhere in the tenant. ----
just target=axiam profile=p2-tls13 bench-up
just target=axiam bench-seed
BENCH_SEED_DENY_RATIO=0 just scale=10 bench-bulk-seed
BENCH_RESULTS_DIR=$PWD/results/e4-deny-none \
  just target=axiam profile=p2-tls13 scenario=authz_check_rest bench-run
just target=axiam bench-down

# ---- Arm B: 5% of grants carry effect: deny. ----
just target=axiam profile=p2-tls13 bench-up
just target=axiam bench-seed
BENCH_SEED_DENY_RATIO=0.05 just scale=10 bench-bulk-seed
BENCH_RESULTS_DIR=$PWD/results/e4-deny-present \
  just target=axiam profile=p2-tls13 scenario=authz_check_rest bench-run
just target=axiam bench-down
```

Tear down between arms: the fixture differs, and a re-seed over a live stack
would leave the first arm's rows in place.

**Reading it.** Arm A against the run-5 headline is the ±2% gate the plan
sets for B1 — a regression there means the short-circuit is not
short-circuiting. Arm B is published as its own labeled row, honestly, with
the deny ratio named; it is a new capability's cost, not a regression.

`meta.json` carries `seed_fixture.deny_ratio` for both arms, so the two are
distinguishable from the artifacts alone.

## `grpc-strict-revocation` — what the stricter posture costs

**The question.** Part of gRPC's read advantage over REST is that its
interceptor validates the token and stops, so a revoked session stays usable
until the token expires (15 minutes). A4 added an opt-in mode that adds the
revocation read, served from the session-validation cache. The posture is
documented; the cost is not yet measured.

```bash
cd benchmarks

# ---- Arm A: shipped default (JWT lifetime is the revocation bound). ----
just target=axiam profile=p2-tls13 bench-up
just target=axiam bench-seed
BENCH_RESULTS_DIR=$PWD/results/e4-grpc-default \
  just target=axiam profile=p2-tls13 scenario=authz_check_grpc bench-run
just target=axiam bench-down

# ---- Arm B: strict mode, with the session cache the mode is designed for. ----
AXIAM__GRPC__STRICT_REVOCATION=true \
AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS=5 \
  just target=axiam profile=p2-tls13 bench-up
just target=axiam bench-seed
BENCH_REQUIRE_ENV="AXIAM__GRPC__STRICT_REVOCATION" \
BENCH_RESULTS_DIR=$PWD/results/e4-grpc-strict \
  just target=axiam profile=p2-tls13 scenario=authz_check_grpc bench-run
just target=axiam bench-down
```

Note the two things that make this reproducible rather than hopeful:

- the knob is set on **`bench-up`**, because a container's environment is
  fixed when it is created. This is the J9 rule, and the pass that ignored it
  cost run 5 an entire investigation.
- `BENCH_REQUIRE_ENV` asserts the knob actually reached the container, off
  `docker inspect`, before any k6 time is spent. Arm B without the flag would
  otherwise be a second copy of arm A wearing arm B's directory name — the
  single most expensive mistake this cell can make.

**Reading it.** The expectation is that strict mode approaches REST's
revocation-checked profile, and the honest framing is "here is what the
stricter bound costs", not "gRPC is slower than we said". Publish both rows
adjacent, with the revocation bound stated for each.

## `seed-scale` — does the check path hold at 10× and 100×?

See [`benchmarks/README.md`](../benchmarks/README.md#seed-size-sensitivity-bench-bulk-seed)
for the mechanism. The cell itself:

```bash
cd benchmarks
just target=axiam profile=p2-tls13 bench-up
just target=axiam bench-seed
for S in 1 10 100; do
  [ "$S" = 1 ] || just scale=$S bench-bulk-seed
  BENCH_RESULTS_DIR=$PWD/results/e4-seed-$S \
    just target=axiam profile=p2-tls13 scenario=authz_check_rest bench-run
done
just target=axiam bench-down
```

The scales are cumulative on one fixture (the seeder upserts, so `scale=100`
after `scale=10` adds rather than replaces), which is deliberate: the same
seeded `benchuser`/`bench-resource` fixture is measured against a growing
index, so the three rows differ in exactly one variable.

`meta.json` carries `seed_scale` and the full `seed_fixture` block per cell.

---

## Cells still waiting on their k6 scenarios

### `device-flow-poll` (B2)

The RFC 8628 polling loop is the interesting shape: an input-constrained
device polls the token endpoint every `interval` seconds until the user
approves, which is a sustained low-rate request stream from many devices at
once — a different load profile from anything currently in the matrix, and
one whose rate-limiting posture (A1's family for polling, distinct from the
generic token bucket) is what the cell exists to validate.

The feature is no longer the blocker: `ffaaed1` mounted
`POST /oauth2/device_authorization`, the `device_code` arm of
`POST /oauth2/token`, and `GET /api/v1/device/verify` /
`POST /api/v1/device/decide`, each with its own rate-limit bucket
(`device_authorization` 12/min, `device_verify` 10/min). What is still owed
is the scenario file itself — nobody has written the k6 script that drives
the polling loop against these routes, so the cell has never been run.

### `token-exchange` (B3)

One exchange per request against the token endpoint, measuring the
scope-narrowing and audience-restriction work on the hot path, plus its own
rate-limit bucket under flood.

The feature is no longer the blocker: `4dbd832` finished the exchange
service, wired it into the server's `AppState`, and dispatches it from
`POST /oauth2/token` (`handle_token_exchange` in
`crates/axiam-api-rest/src/handlers/oauth2.rs`) ahead of its own rate-limit
bucket (`token_exchange_per_min`). What is still owed is the scenario file
itself — nobody has written the k6 script exercising one exchange per
request, so the cell has never been run.

### `amqp-tls` (A6, optional)

A6 ships `amqps://` support; step 6 of that task asks for one labeled cell
comparing the AMQP async-authz path over TLS against plaintext. The expected
result is ~nil steady-state difference, because long-lived connections
amortize the handshake — which is exactly the kind of claim this project
measures rather than asserts. The bench compose deliberately keeps the broker
hop plaintext (`AXIAM__AMQP__ALLOW_PLAINTEXT: "true"`) so the standing matrix
stays comparable to run 5; this cell is the deliberate exception, not a
change of that default.

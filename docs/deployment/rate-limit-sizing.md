# Sizing your rate limits

AXIAM ships with rate limits **on by default**. That is deliberate — most
IAM servers ship with none — but it means the shipped numbers are a
*posture choice*, and the right posture depends on who is calling you.

This page tells you which posture you are in, what the measured hardware
envelope is, and how to move the limits without quietly turning the
anti-abuse controls off.

- Mechanism, layering and the `AXIAM__RATE_LIMIT__KEY` semantics:
  [Deployment Guide § Rate limiting](README.md#rate-limiting).
- Source of truth for the shipped values:
  [`crates/axiam-api-rest/src/config/rate_limit.rs`](../../crates/axiam-api-rest/src/config/rate_limit.rs).
  The table below is checked against that file by a unit test
  (`cargo test -p axiam-api-rest --lib rate_limit`), so it cannot silently
  drift from the code.

---

## 1. The one-line summary

| You are… | Use | Why |
|---|---|---|
| A small internet-facing deployment; humans log in from many IPs | the shipped defaults (`internet`) | The defaults are sized to stop single-source credential-stuffing and token-probing floods. |
| An M2M / microservice / IoT fleet reaching AXIAM through a shared NAT or egress gateway | `AXIAM__RATE_LIMIT__PROFILE=gateway` | Many distinct OAuth2 clients share one source IP; per-IP buckets collide and the fleet throttles itself. |
| Reachable only on a private network / service mesh | `AXIAM__RATE_LIMIT__PROFILE=mesh` | Ceilings become runaway-loop guards; abuse control lives at the network edge. |

Presets are **opt-in**. Setting no profile keeps the shipped defaults
byte-for-byte. **No profile ever changes the human endpoints**
(`login`, `register`, `password_reset`, `mfa`) — those stay strict and
per-IP in every posture. Raise them only deliberately, one env var at a
time, and read §5 first.

---

## 2. The evidence (why this page exists)

From benchmark run 3 (2026-07-25/26, `1.0.0-alpha19`,
[`benchmarks/PUBLIC_BENCH_ANALYSIS.md`](../../benchmarks/PUBLIC_BENCH_ANALYSIS.md)
§4/§6):

- With the **then-shipped defaults** (token 20/min, introspect 10/min,
  revoke 10/min, authz 300/min), a 50-VU load generator on a **single
  source IP** was flattened to ~0–14 req/s on every limited endpoint at
  ~100% `429` (client-credentials 0.9/s, introspection 0.4/s). Unlimited
  paths in the same pass were untouched — JWKS served 27 700/s. The limits
  work exactly as designed.
- The **same 2-core server** sustains ~1 800 token issuances/s and
  ~740–2 300 authz checks/s when unthrottled.

### The run-4 revision of the machine-endpoint defaults

Run 4 re-measured the same envelope on a clean build and put the shipped
machine defaults next to the capacity actually behind them: token 20/min
against ~163 000/min, introspect 10/min against ~263 000/min, authz
300/min against ~45 000/min. Those numbers did not protect anything the
raised ones fail to protect — they broke the first healthy integration
behind a NAT while sitting four to five orders of magnitude below the
machine's ceiling. The `internet` machine defaults were therefore revised:

| Knob | Was | Now | Margin to measured capacity |
|---|---:|---:|---|
| `AXIAM__RATE_LIMIT__TOKEN_PER_MIN` | 20 | **120** | ~1 358x below |
| `AXIAM__RATE_LIMIT__INTROSPECT_PER_MIN` | 10 | **600** | ~438x below |
| `AXIAM__RATE_LIMIT__AUTHZ_CHECK_PER_MIN` | 300 | **1 800** | ~25x below (4% of a 2-core envelope) |
| `AXIAM__RATE_LIMIT__REVOKE_PER_MIN` | 10 | **60** | ~2 716x below |
| login / register / password-reset / MFA | 10 / 5 / 3 / 5 | **unchanged** | not sized from capacity — see §4 rule 6 |

The posture did not change: still strict, still per-IP, still opt-in to
anything else. Only the numbers moved, and only on the four machine
endpoints. If you had pinned any of these with an env var, nothing about
your deployment changes.

Both facts are true at once. A single IP producing 10 token requests per
second is an attacker on a small public deployment and a perfectly normal
Tuesday for a NAT'd device fleet. The defaults cannot serve both, so AXIAM
keeps the strict posture as the default and makes the machine-scale
posture an explicit, logged choice.

### Measured envelope (what the hardware did)

Reproduced from the public analysis §6. **These are laptop-class
measurements** (Docker containers pinned to 2 cores / 1 GiB each, on a
developer machine) and are **explicitly temporary** — they exist to give
you a starting order of magnitude, not an SLA. Re-measure on your own
hardware before committing to a number.

| Envelope (server / DB) | Token issuance | Introspection | Authz checks (cache off / on) | Userinfo | Logins (Argon2id, OWASP params) |
|---|---|---|---|---|---|
| 2 cores / 2 cores | ~1 800/s | ~2 200/s | ~740 / ~2 300/s | ~5 000/s | ~69/s |
| 2 cores / 4 cores | ~1 800/s | ~2 200/s | ~1 000 / higher | ~7 500/s (server-bound) | ~69/s |

Two shape facts that matter more than the absolute numbers:

1. **Authz checks and userinfo scale with database CPU**; token issuance
   does not (it is server-CPU bound until ~1 800/s per 2 cores).
2. **Logins are Argon2id-bound** at ~69/s per 2 cores. Login limits are a
   password-guessing control, but they are also the one place where a
   flood costs you real CPU — another reason not to raise them casually.

---

## 3. The postures

`AXIAM__RATE_LIMIT__PROFILE` = `internet` (default) | `gateway` | `mesh`.
It sets the whole machine-traffic family — key mode, token, introspect,
revoke, REST authz, and the gRPC authz ceiling — coherently, so you cannot
half-apply it.

**Precedence: an explicit env var always beats the preset, which always
beats the shipped default.** If you set `AXIAM__RATE_LIMIT__TOKEN_PER_MIN`
yourself, the profile leaves it alone (and the startup log names it in
`operator_overrides`).

<!-- rate-limit-posture-table:begin -->
| Env var | `internet` (shipped default) | `gateway` | `mesh` |
|---|---|---|---|
| `AXIAM__RATE_LIMIT__KEY` | `ip` | `client_id` | `client_id` |
| `AXIAM__RATE_LIMIT__LOGIN_PER_MIN` | 10 | 10 | 10 |
| `AXIAM__RATE_LIMIT__REGISTER_PER_MIN` | 5 | 5 | 5 |
| `AXIAM__RATE_LIMIT__PASSWORD_RESET_PER_MIN` | 3 | 3 | 3 |
| `AXIAM__RATE_LIMIT__MFA_PER_MIN` | 5 | 5 | 5 |
| `AXIAM__RATE_LIMIT__TOKEN_PER_MIN` | 120 | 600 | 6000 |
| `AXIAM__RATE_LIMIT__INTROSPECT_PER_MIN` | 600 | 6000 | 60000 |
| `AXIAM__RATE_LIMIT__REVOKE_PER_MIN` | 60 | 600 | 6000 |
| `AXIAM__RATE_LIMIT__AUTHZ_CHECK_PER_MIN` | 1800 | 6000 | 60000 |
| `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC` | 100 | 1000 | 5000 |
| `AXIAM__GRPC__GRPC_IDENTITY_PER_SEC` | 500 | 5000 | 25000 |
| `AXIAM__GRPC__GRPC_ADMIN_PER_SEC` | 10 | 10 | 10 |
<!-- rate-limit-posture-table:end -->

Per-minute values are **per bucket**, and the bucket is whatever
`AXIAM__RATE_LIMIT__KEY` selects — per IP under `internet`, per OAuth2
`client_id` under both presets (on `/oauth2/token`, `/oauth2/revoke`,
`/oauth2/introspect` only; everything else is always per-IP).

The three `AXIAM__GRPC__*_PER_SEC` values are per **second** per IP, one
bucket per gRPC **method family** (see §3.1). Leave `GRPC_IDENTITY_PER_SEC`
unset and it is derived as 5x `GRPC_AUTHZ_PER_SEC`, which is why those two
rows move together with one variable.

`GRPC_ADMIN_PER_SEC` deliberately **does not move with the posture**: it is
a flat 10/s (600/min per IP) in every column. `UserService` holds
`ValidateCredentials`, an Argon2id password verification, so its ceiling is
a CPU guard on an online-guessing surface rather than a throughput number —
raising the authz ceiling for service-mesh capacity must not silently widen
password spraying (SEC-079). Set the env var explicitly if you need more;
explicit configuration still wins.

### 3.1 gRPC buckets are per method family

Until run 4 both gRPC rate-limit layers were **server-wide**: one bucket,
sized from `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC`, shared by every method on
every service. That made an authorization-sizing decision silently also a
userinfo-sizing decision — run 4 measured `GetUserInfo` (an identity read
that sustains ~12 700/s) collapsing to the authz ceiling under production
posture. The buckets are now split:

| Family | Services | Knob | Shipped |
|---|---|---|---|
| authz-check | `axiam.v1.AuthorizationService` | `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC` | 100/s |
| identity-read | `axiam.v1.UserInfoService`, `axiam.v1.TokenService` | `AXIAM__GRPC__GRPC_IDENTITY_PER_SEC` | 500/s (5x authz) |
| admin | `axiam.v1.UserService` | `AXIAM__GRPC__GRPC_ADMIN_PER_SEC` | 10/s (absolute — see below) |
| infrastructure | gRPC reflection (`grpc.reflection.*`), health (`grpc.health.*`) | *(none — fixed at 100/s)* | 100/s |

Notes:

- **Admin is an absolute CPU guard, not a multiple of anything (SEC-079).**
  `UserService/ValidateCredentials` performs an Argon2id verification
  (~19 MiB of memory arena each), so its ceiling bounds online password
  guessing and Argon2id CPU, not read throughput. It is therefore 10/s
  (600/min per IP) regardless of the posture: a `gateway`/`mesh` preset
  raising the authz ceiling for mesh capacity must not raise this one too.
  The family contains only `GetUser` and `ValidateCredentials` — the
  high-volume identity read is `GetUserInfo` on `UserInfoService`, which is
  in the identity-read family and unaffected. Pin
  `AXIAM__GRPC__GRPC_ADMIN_PER_SEC` if your provisioning loop needs more.
- **Reflection and health get a deliberately generous ceiling — but a
  finite one.** Their whole job is to answer during an incident, exactly
  when the other families are most likely to be saturated, and 100/s per IP
  is orders of magnitude above any real probe cadence, so this ceiling can
  never be what breaks a liveness check. It is not, however, a
  pass-through: the family is selected by prefix-matching the client-
  supplied gRPC `:path`, and an unmetered surface behind a client-chosen
  string is not something to leave open against a health service being
  registered later.
- **An unrecognized gRPC path is counted against the authz bucket**, not
  the infrastructure one. Adding a service without classifying it fails
  safe.
- Both layers (the in-memory governor and the cross-replica shared counter)
  use the same split and the same per-second numbers. The shared counter
  runs a 60-second window and converts internally — before run 4 it did
  not, which made the effective gRPC ceiling 1/60th of the configured one
  (fixed; `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC=100` now really means 100/s).

### 3.1a Sizing login also sizes refresh capacity

`login_per_min` is usually reasoned about as "how many password guesses will I
let one source make per minute". It is also, less obviously, a **ceiling on
session churn**: every session that expires costs one login to replace, so a
deployment with short sessions has its sustainable refresh rate bounded by its
login limit rather than by the refresh endpoint's capacity.

This matters in exactly one shape of deployment — short sessions behind a
shared egress IP (a NAT'd fleet, a mobile app behind a carrier gateway, a CI
farm). There, `login_per_min` is doing two jobs at once, and sizing it for the
brute-force job alone will silently cap the other.

If that is you: lengthen the session rather than raising the login limit. A
longer session reduces logins without widening the password-guessing surface,
whereas raising `login_per_min` widens both.

(Run 5's benchmark harness rediscovered this the hard way — its refresh cell
reported a 4.4 % error rate that was login throttling, not refresh failures.
See `benchmarks/docs/methodology.md`.)

### 3.2 The two layers, and which one decides

Every rate-limited surface runs **two** cooperating limiters. Knowing which
one decides is not trivia — run 5 found both a starvation bug and an
over-admission bug that were purely consequences of how the two compose.

| Layer | Scope | Algorithm | Job |
|---|---|---|---|
| in-memory `governor` | one replica | GCRA token bucket, per-second quota + burst | the admission decision |
| shared counter (`rate_limit_bucket`) | all replicas | write-behind sliding window, 60 s | stop `replicas × limit` |

**The governor decides; the shared counter stops multiplication.** On a
single replica the governor's quota is the binding constraint and the shared
counter never trips, so the effective ceiling equals the configured one. With
N replicas, each admits its own quota, their sum reaches the shared window
budget, and the shared counter cuts in — which is the whole reason it exists.

Two consequences worth internalising before you tune anything:

- **Order matters, and the two listeners achieve it differently.** On gRPC
  the governor is the outer layer, so the shared counter only ever sees
  admitted traffic. On REST the shared middleware *must* be outermost (it is
  also what parses `client_id` out of the form body for the
  `client_id`/`ip_client_id` key modes), so it charges first and **refunds**
  when the governor rejects. Same invariant, reached two ways: the
  cross-replica counter counts *served* traffic, never attempts.

  Before run 5 the gRPC order was inverted and nothing refunded, so a flood
  burned an entire 60-second window budget on requests the per-second
  governor never let through. Effective admission collapsed to roughly
  `burst + rate × t_exhaust` per window — measured at **181/min against a
  configured 6 000/min**, i.e. 1/33 of the ceiling. If you are reading an
  older results tree, that is what those gRPC rows mean.

- **The shared window slides; it does not reset.** A fixed window hands out
  its whole budget again the instant it rolls over, so any rolling
  measurement that straddles a boundary sees up to twice the configured rate.
  Run 5 measured exactly that on the REST machine endpoints (+48 % introspect,
  +50 % authz check, +12 % token, against a ±10 % bar). The counter now
  charges a decayed share of the previous window against the current
  decision, which bounds *every* rolling minute rather than only the aligned
  ones.

#### The burst allowance, stated exactly

A key the limiter has never seen before is given its **pro-rata share of the
window it arrives in, plus 10 % of the limit**. It is not given the whole
remaining window — arriving at second 59 and arriving at second 0 buy the
same amount of capacity, which is the property that makes the admitted rate
independent of when a flood starts.

So the shipped, measurable contract for a sustained single-source flood is:

- **first rolling minute:** at most `1.1 × configured` (the burst allowance),
- **every minute after:** converges to `1.0 × configured`.

`benchmarks/runner/rl_prod_check.py` asserts ±10 %, so the shipped burst and
the assertion agree by construction — the 10 % allowance *is* the assertion's
tolerance, chosen so that the posture and the check can never drift apart.

Rollback knob: `AXIAM__RATE_LIMIT__SHARED_WINDOW=fixed` restores the
pre-run-5 fixed-window behaviour. Only the exact string `fixed` does; a typo
leaves the stricter default in place, so a misspelled rollback cannot
silently loosen enforcement.

### Where the preset numbers come from

Anchored to the measured envelope above, deliberately as a **small
fraction of the whole-server ceiling** so that one bucket can never be the
whole machine:

| Preset value | Derivation |
|---|---|
| `gateway` token 600/min | 10/s per client ≈ 0.55% of the measured ~1 800/s server ceiling — ~180 clients running flat out to saturate, so one compromised credential is not a DoS engine. |
| `gateway` introspect 6 000/min | 10× the token limit; resource servers introspect once per protected request (the public §6 rule of thumb). |
| `gateway` revoke 600/min | Paired with issuance — revocation is per-token, so it tracks the token rate. |
| `gateway` authz 6 000/min | 100/s per client, the **low** end of the 6 000–60 000 band in public §6; the server measured ~740/s cache-off in total. |
| `mesh` token 6 000/min | 100/s per client ≈ 5.6% of the measured ceiling. |
| `mesh` authz 60 000/min | 1 000/s per client — **above** the measured 740/s cache-off whole-server ceiling. On this hardware it stops a runaway retry loop, not an attacker. Sized honestly, not aspirationally. |
| gRPC authz 1 000 / 5 000 per sec | The gRPC authz path measured ~603/s per 2 cores (run 3) / ~887/s (run 4). These are coarse ceilings; see the keying caveat in §5. |
| gRPC identity 5 000 / 25 000 per sec | Derived as 5x the authz ceiling. `GetUserInfo` measured 12 665/s — an identity read is ~14x an authz check, so it must not inherit the authz number (§3.1). |
| gRPC admin 1 000 / 5 000 per sec | Derived as 1x the authz ceiling. `ValidateCredentials` is Argon2id-bound, so this is a CPU guard rather than a read ceiling. |

### Turning it on

```bash
# docker-compose / k8s env
AXIAM__RATE_LIMIT__PROFILE=gateway
# …and if one client legitimately needs more than the preset:
AXIAM__RATE_LIMIT__TOKEN_PER_MIN=2000     # wins over the preset
```

Behind a NAT/ingress also set `AXIAM__RATE_LIMIT__TRUSTED_HOPS` to the
number of trusted proxy hops, otherwise every bucket keys on the proxy's
IP (see [Deployment Guide § Rate limiting](README.md#rate-limiting)).

### Measured: the `gateway` preset actually applied (H7, 2026-07-29)

The `internet` (shipped default) posture pass in §2 above was measured; the
preset itself wasn't, until now. One labeled laptop-class pass, single
`client_id` generator, `p0-plaintext`:

| scenario | shipped default (`ip`-keyed) | `gateway` (`client_id`-keyed) |
|---|---:|---:|
| `oauth2_client_credentials` | 8.5% admitted, 91.5% throttled | **96.6% admitted**, 3.4% throttled, 22.15 ops/s |
| `token_introspection` | 3.7% admitted, 96.3% throttled | **100% admitted**, 23.82 ops/s |
| `authz_check_rest` | 68.9% admitted, 31.1% throttled | **100% admitted**, 23.39 ops/s |

**Read this as confirmation of the mechanism, not a new throughput ceiling:**
switching key mode + raising the per-bucket limits is what stopped this
single-`client_id` generator from being throttled — that's the preset doing
exactly what §3 says. It did **not** raise the ~20–24 ops/s the server
actually admitted per second on these three endpoints at the time of this
measurement; that number was set by a synchronous per-request datastore
write on the critical path (`claude_dev/postseed-transient-investigation.md`),
which every posture paid identically. Full numbers, the harness workaround
needed to test a preset at all (the bench compose's `neutralized` defaults
otherwise always outrank the preset — see precedence above), and the
arithmetic behind the one non-zero throttled row:
`claude_dev/rate-limit-posture-decision.md` §7.2.

**Fixed since this measurement.** The synchronous per-request write named
above has been replaced by a write-behind design
(`axiam_db::rate_limit_counter::SharedRateLimitCounter`) — see
[Deployment Guide § Shared-store consistency model](README.md#shared-store-consistency-model-write-behind)
for the mechanism and the new cross-replica overshoot bound this trades in.
The H7 numbers directly above remain a faithful pre-fix measurement and are
left as-is; they describe a ceiling that no longer exists in the current
code. Post-fix throughput has not been re-measured yet — the numbers will
land in `claude_dev/rate-limit-fix-verification.md` (not yet present at the
time of writing — produced by a separate, concurrent verification task) when
that run completes.

---

## 4. Sizing by hand

If no preset fits, size from your own traffic rather than from ours:

1. **Measure your per-client peak** over a 1-minute window in production
   (or staging under load), per endpoint class.
2. **Multiply by 2** for burst headroom — the limiter is a fixed 60 s
   window, so a client that bunches its requests at a window boundary can
   legitimately look 2× peak.
3. **Sanity-check against the envelope**: the sum of your per-bucket
   limits × expected concurrent buckets should not exceed what your
   hardware measured (§2). A limit above the machine's capacity is not a
   limit, it is documentation.
4. **Introspection**: 10–20× your token limit if resource servers
   introspect per request. Consider caching introspection results at the
   resource server instead.
5. **Authz checks**: enable `AXIAM__AUTHZ__DECISION_CACHE_ENABLED=true`
   before raising the authz limit — the measured 3× on checks buys more
   headroom than a bigger number does, and it cuts DB load 40–75%.
6. **Never size the human endpoints from throughput.** 10 logins/min/IP is
   not a capacity number; it is the number of password guesses you are
   willing to let one source make per minute.

---

## 5. Security caveats — read before selecting a preset

**1. `client_id` keying is not an anti-abuse control.** The `client_id` is
read from the *unauthenticated* form body (`client_secret_post`,
RFC 6749 §2.3.1) **before** any credential is verified. An attacker can
rotate `client_id` values and mint a fresh bucket per value. Under
`client_id` / `ip_client_id`, the token/introspect/revoke limits are a
**fairness control between cooperating clients**, not a defence against a
determined attacker — that job moves to your edge (WAF, API gateway,
mTLS, or IP allow-listing). This is a property of the key modes
themselves, not of the presets; the presets simply make it the active
posture, which is why they are opt-in and logged.

Selecting `client_id` — directly or via a preset — makes the server emit a
startup **`WARN`** naming this caveat and pointing back here (see §6). The
shipped `ip` default emits nothing; `ip_client_id` emits a softer `INFO`
note, because the same single-source evasion works but the source-IP half
of the key still stops a third party from exhausting a *known* client's
bucket from somewhere else.

**2. A rotating `client_id` also grows the bucket keyspace.** Distinct
keys accumulate in the in-memory governor and in the shared
`rate_limit_bucket` table. Neither is unbounded in practice (windows
expire and the cleanup task sweeps), but a sustained rotation flood is a
resource-consumption vector, and each rejected request still costs one
client lookup. Front an internet-exposed `client_id`-mode deployment with
something that rate-limits by IP before AXIAM sees the request.

**3. The gRPC limiters are per-IP only.** There is no client identity at
the layer that keys them (the `tower` layer runs before tonic resolves
per-RPC claims), so `AXIAM__GRPC__KEY` is reserved and currently a no-op.
Behind a shared ingress IP, the three `AXIAM__GRPC__*_PER_SEC` values are
**fleet-wide** ceilings, not per-client ones. The per-method-family split
(§3.1) separates *workloads*, not *callers* — it does not make the gRPC
limiter client-aware.

**4. Requests with no parseable `client_id` fall back to the IP key.**
That fallback is fail-safe (it never disables limiting), but note the
consequence under a preset: an anonymous or malformed flood is then
metered against the *preset's* larger per-IP number, not the strict
default. Point 2's advice applies.

**5. Presets cannot detect values set in `config/default.toml`.**
"Explicitly set" means *an `AXIAM__…` environment variable is present*. A
value coming from the optional TOML file source looks unset to the preset
and will be overwritten. Pin it with an env var.

**6. Human endpoints are excluded by construction.** No profile can raise
`login`, `register`, `password_reset` or `mfa` — the preset struct has no
field for them. If users arrive through a shared NAT and 10/min/IP is too
tight, raise `AXIAM__RATE_LIMIT__LOGIN_PER_MIN` explicitly, knowing you
are widening a password-guessing budget (and remembering that logins cost
~1/69th of a 2-core server each).

---

## 6. Confirming what you shipped

At boot the server emits exactly one line describing the **active**
posture — key mode, every per-minute value, the gRPC per-second ceiling,
whether a preset was applied, and which env vars overrode it:

```json
{"level":"INFO","fields":{"message":"Rate-limit posture active",
 "profile":"gateway","preset_applied":true,"key_mode":"client_id",
 "login_per_min":10,"register_per_min":5,"password_reset_per_min":3,
 "mfa_per_min":5,"token_per_min":2000,"introspect_per_min":6000,
 "revoke_per_min":600,"authz_check_per_min":6000,
 "grpc_authz_per_sec":1000,
 "operator_overrides":"AXIAM__RATE_LIMIT__TOKEN_PER_MIN"}}
```

Grep for `Rate-limit posture active` in your startup logs. If
`operator_overrides` is `none` and `preset_applied` is `false`, you are
running the shipped internet-facing defaults.

Immediately after that line, a **key-mode advisory** is emitted when — and
only when — the active key mode is one an unauthenticated caller can
influence (§5 caveat 1):

```json
{"level":"WARN","fields":{"key_mode":"client_id",
 "message":"rate-limit key mode `client_id` ACTIVE — the whole bucket key is the
 client_id read from the unauthenticated OAuth2 form body BEFORE any credential
 check, ..."}}
```

`client_id` logs at `WARN`, `ip_client_id` at `INFO`, and the shipped `ip`
default logs nothing at all — so the absence of this line is itself the
confirmation that no part of your bucket key is attacker-chosen.

The gRPC listener logs its own resolved family ceilings when it binds:

```json
{"level":"INFO","fields":{"message":"Starting gRPC server",
 "bind":"127.0.0.1:50051","grpc_authz_per_sec":100,
 "grpc_identity_per_sec":500,"grpc_admin_per_sec":10}}
```

### Is the `internet` posture throttling your machine traffic?

When the shipped `internet` defaults are active, the server watches the
sustained `429` ratio on the four **machine** endpoints
(`/oauth2/token`, `/oauth2/introspect`, `/oauth2/revoke`, authz check) over
rolling 5-minute intervals. If more than half of that traffic is being
rejected for long enough that it cannot be a burst, it logs once per
interval:

```
WARN  your limits are throttling what looks like legitimate machine
      traffic; see rate-limit-sizing
      (machine_denied_ratio=0.83 window_secs=300 …)
```

That line is advice, not an error: it means your fleet's real per-bucket
peak is above the shipped `internet` numbers, and you should either pick a
posture from §1 or size by hand from §4. Human endpoints are excluded from
the ratio — a `429` storm on `/auth/login` is a credential-stuffing signal,
not a sizing signal, and must never be answered by raising a limit.

---

## 7. Related

- [Deployment Guide § Rate limiting](README.md#rate-limiting) — mechanism,
  layers, `AXIAM__RATE_LIMIT__KEY` and `TRUSTED_HOPS` semantics.
- [`benchmarks/PUBLIC_BENCH_ANALYSIS.md`](../../benchmarks/PUBLIC_BENCH_ANALYSIS.md)
  §6 — the recommended-settings table these numbers derive from, plus every
  other tuning knob.
- [`claude_dev/rate-limit-posture-decision.md`](../../claude_dev/rate-limit-posture-decision.md)
  — why the defaults were **not** moved, and the abuse-vector analysis
  behind the preset values.

# Phase 19: Python SDK - Pattern Map

**Mapped:** 2026-07-01
**Files analyzed:** 27 (package modules, examples, tests, packaging, CI)
**Analogs found:** 24 / 27 (3 net-new, flagged MEDIUM confidence)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `sdks/python/pyproject.toml` | config | batch | `sdks/python/pyproject.toml` (existing scaffold, broken) | exact (fix-in-place) |
| `sdks/python/src/axiam_sdk/__init__.py` | config | request-response | `sdks/typescript/src/index.ts` / `sdks/go` root package exports | role-match |
| `sdks/python/src/axiam_sdk/py.typed` | config | — | n/a (PEP 561 marker, empty file) | no analog needed |
| `sdks/python/src/axiam_sdk/_client.py` | controller/service | request-response | `sdks/go/client.go` | exact |
| `sdks/python/src/axiam_sdk/_session.py` | service | request-response | `sdks/go/client.go` (jar/CSRF/org fields) + `sdks/typescript/src/rest/session.ts` | exact |
| `sdks/python/src/axiam_sdk/_models.py` | model | transform | `sdks/typescript/src/rest/types.ts` + Go `login.go` structs | role-match |
| `sdks/python/src/axiam_sdk/_errors.py` | utility (error taxonomy) | transform | `sdks/go/errors.go` + `sdks/typescript/src/core/errorMapper.ts` | exact |
| `sdks/python/src/axiam_sdk/_jwks.py` | service | request-response | `sdks/go/internal/jwks/verifier.go` + `sdks/rust/src/token/jwks.rs` | exact |
| `sdks/python/src/axiam_sdk/token/refresh_guard.py` | service | event-driven (concurrency guard) | `sdks/go/internal/refreshguard/guard.go` + `sdks/rust/src/token/refresh_guard.rs` | exact |
| `sdks/python/src/axiam_sdk/grpc/gen/*` | model (generated) | request-response | `sdks/go/internal/gen/axiam/v1/*.pb.go` (committed-stub precedent) | exact (codegen, not hand-authored) |
| `sdks/python/src/axiam_sdk/grpc/_interceptor.py` | middleware | request-response | `sdks/go/grpc/interceptor.go` | exact |
| `sdks/python/src/axiam_sdk/grpc/client.py` (sync+async) | service | request-response | `sdks/go/grpc/client.go` | exact |
| `sdks/python/src/axiam_sdk/amqp/_hmac.py` | utility | transform (crypto) | `sdks/go/amqp/hmac.go` (+ canonical spec `crates/axiam-amqp/src/messages.rs`) | exact |
| `sdks/python/src/axiam_sdk/amqp/__init__.py` (consumer) | service | event-driven | `sdks/go/amqp/consumer.go` | exact |
| `sdks/python/src/axiam_sdk/fastapi/__init__.py` | middleware (DI) | request-response | none in-repo (net-new); pattern drawn from `sdks/go/middleware/nethttp.go` conceptually | **NO ANALOG — MEDIUM confidence, net-new** |
| `sdks/python/src/axiam_sdk/django/middleware.py` | middleware | request-response | `sdks/go/middleware/nethttp.go` (closest cross-language shape) | role-match (framework idiom net-new) |
| `sdks/python/examples/login_mfa.py` | script | request-response | `sdks/go/examples/login-mfa/main.go` | exact |
| `sdks/python/examples/rest_authz.py` | script | request-response | `sdks/go/examples/authz-check/main.go` | exact |
| `sdks/python/examples/grpc_checkaccess.py` | script | request-response | `sdks/go/examples/grpc-checkaccess/main.go` | exact |
| `sdks/python/examples/amqp_consumer.py` | script | event-driven | `sdks/go/examples/amqp-consumer/main.go` | exact |
| `sdks/python/examples/fastapi_dependency.py` | script | request-response | none in-repo (net-new) | **NO ANALOG — MEDIUM confidence** |
| `sdks/python/examples/django_middleware.py` | script | request-response | `sdks/go/examples/middleware-guard/main.go` (conceptual) | role-match (framework idiom net-new) |
| `sdks/python/tests/test_single_flight.py` | test | event-driven | `sdks/go/internal/refreshguard/guard_test.go` | exact |
| `sdks/python/tests/test_error_redaction.py` | test | transform | TS `test/core/errorRedaction.test.ts` (referenced in CONTEXT.md; not directly present in repo tree — treat TS `errorMapper.ts`'s CR-04 intent as the analog) | role-match |
| `sdks/python/tests/test_amqp_hmac.py` | test | transform | `sdks/go/amqp/hmac_test.go` | exact |
| `sdks/python/tests/test_jwks.py` | test | request-response | `sdks/go/internal/jwks/verifier_test.go` | exact |
| `.github/workflows/python-sdk.yml` (or `sdk-ci-python.yml` rewrite) | config (CI) | batch | `.github/workflows/sdk-ci-go.yml` | exact |

## Pattern Assignments

### `sdks/python/src/axiam_sdk/_client.py` + `_session.py` (controller/service, request-response)

**Analog:** `sdks/go/client.go` (full file read, lines 1-326)

**Construction/options pattern to port** (lines 39-162): functional-option-style config accumulation → in Python, use keyword-only constructor args instead of the option-func pattern (more idiomatic), but preserve every invariant:
- `tenant_slug` required, empty → raise `AuthError` at construction (not a silent default) — CF-04.
- `org_slug`/`org_id` mutually-exclusive optional params (Pitfall 3) with a `resolved_org_id()` fallback populated from the access token's `org_id` claim after first login/refresh (mirrors lines 271-295 `setResolvedOrgID`/`resolvedOrgID`).
- The SDK's own cookie jar/TLS config always wins over anything a caller might inject — Python analog: never accept a raw `httpx.Client` override that could carry `verify=False`; only accept `verify=<ca-path>` (CF-03).

**CSRF capture pattern to port verbatim** (lines 220-255):
```go
var stateChangingMethods = map[string]bool{ http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true }

func (c *Client) decorateRequest(req *http.Request) {
    req.Header.Set("X-Tenant-ID", c.tenantSlug)
    if stateChangingMethods[strings.ToUpper(req.Method)] {
        if token := c.getCSRFToken(); token != "" {
            req.Header.Set("X-CSRF-Token", token)
        }
    }
}
func (c *Client) captureCSRFFromResponse(resp *http.Response) {
    if token := resp.Header.Get("X-CSRF-Token"); token != "" { ... }
}
```
Python: single `_Session._prepare_request(request)` sets `X-Tenant-ID` always + echoes captured `X-CSRF-Token` on POST/PUT/PATCH/DELETE; `_Session._capture_csrf(response)` called after every `httpx` call (sync AND async — same choke-point pattern as Go's `doRequest`, lines 261-269). Use `threading.Lock` for the CSRF token field (mirrors `csrfMu`) since it's touched from both sync and async request-issuing code paths.

**Single choke-point request pattern** (lines 257-269, `doRequest`): every REST call routes through one method — Python needs two thin variants (`_send_sync`, `_send_async`) both delegating into shared `_prepare_request`/`_capture_csrf` helpers, mirroring the one-function shape.

**Shared session skeleton to port directly from RESEARCH.md Pattern 1** (already vetted against this codebase's conventions): lazy `httpx.Client`/`httpx.AsyncClient` construction, `verify=True` hardcoded unless `custom_ca` supplied.

---

### `sdks/python/src/axiam_sdk/token/refresh_guard.py` (service, event-driven concurrency guard)

**Analog:** `sdks/go/internal/refreshguard/guard.go` (full file, lines 1-130) — **the single most direct analog in the entire phase**; SC#2's asyncio.Lock test is the literal Python port of this file's `guard_test.go` concurrency assertion.

**Core double-check-after-lock pattern to port verbatim** (lines 63-88):
```go
func (g *Guard) RefreshIfNeeded(ctx context.Context, observedAccess string, doRefresh func(ctx context.Context) (RefreshedTokens, error)) (Sensitive, error) {
    g.mu.Lock()
    defer g.mu.Unlock()
    if g.hasAny && string(g.access) != observedAccess {
        return g.access, nil   // another caller already refreshed while we waited
    }
    tokens, err := doRefresh(ctx)  // §9.3: no retry loop — propagate as-is
    if err != nil { return "", err }
    g.access = tokens.Access
    ...
    return g.access, nil
}
```
Python needs **two independent guard classes/paths** (per RESEARCH.md Pattern 2, itself citing this Go file): `_sync_lock: threading.Lock` + `_async_lock: asyncio.Lock`, each with its own double-check-after-lock body, both delegating to the same `_cached_access` field. Do NOT unify into one lock (RESEARCH.md's explicit anti-pattern warning). Non-blocking cached-read accessors `CachedAccessToken`/`CachedRefreshToken`/`CachedExp` (lines 90-115) map directly to Python `cached_access_token()` etc. — these back the gRPC interceptor's non-blocking `TokenFunc` (see below). `Seed()` (lines 117-129) primes the guard right after login/verify_mfa — port directly.

**Companion Rust analog for timing constants:** `sdks/rust/src/token/refresh_guard.rs` and `sdks/rust/src/token/jwks.rs` — carry forward the "no retry loop on failure" invariant and the double-check pattern; Rust's proactive-refresh timing constants inform (but don't dictate, per Claude's Discretion) the Python numeric defaults.

---

### `sdks/python/src/axiam_sdk/_errors.py` (utility, error taxonomy)

**Analog:** `sdks/go/errors.go` (full file, lines 1-181) — primary; `sdks/typescript/src/core/errorMapper.ts` (full file, lines 1-129) — secondary (redaction-choke-point idiom).

**Exception taxonomy to port 1:1** (Go lines 11-83): three classes `AuthError`/`AuthzError`/`NetworkError`, `AuthzError` carries optional `action`/`resource_id`, `NetworkError` wraps a redacted `cause`.

**Redact-before-wrap single choke point — CRITICAL, this is CR-04's fix, do not deviate** (Go lines 85-127, TS lines 29-72 `sanitizeAxiosError`):
```python
# Go: sanitizeResponse() strips Set-Cookie/Authorization/Cookie BEFORE
# newNetworkError() ever touches the response. TS: sanitizeAxiosError()
# does the equivalent for axios error objects. Python's _sanitize_response()
# must be the ONLY path by which an httpx.Response's headers ever reach a
# NetworkError instance.
_SENSITIVE_RESPONSE_HEADERS = {"set-cookie", "authorization", "cookie"}

def _sanitize_response(response: httpx.Response) -> str:
    safe = {k: v for k, v in response.headers.items() if k.lower() not in _SENSITIVE_RESPONSE_HEADERS}
    return f"http status {response.status_code}, headers: {safe}"
```
The Go doc comment (lines 104-117) states the invariant precisely: *"any caller-supplied cause is IGNORED in favor of an error built from the sanitized response, so a caller cannot accidentally smuggle raw response data into cause by pre-building it from the unredacted resp before calling this constructor."* Port this exact discipline — a single `error_from_http_status(status, message, response=None)` function, never a bare `NetworkError(response.headers)` call site anywhere else in the codebase.

**Status-code table to port verbatim** (Go lines 129-174, matches TS lines 74-129): 401→AuthError, 403/409→AuthzError, else→NetworkError (HTTP); UNAUTHENTICATED→AuthError, PERMISSION_DENIED→AuthzError, else→NetworkError (gRPC).

**RESEARCH.md's ready-to-use Code Example** (already project-fitted, Research doc lines 1025-1084) may be copied nearly as-is — it was explicitly authored as "pattern mirrors errorMapper.ts + errors.go."

---

### `sdks/python/src/axiam_sdk/_jwks.py` (service, request-response)

**Analog:** `sdks/go/internal/jwks/verifier.go` (full file, lines 1-123); secondary `sdks/rust/src/token/jwks.rs` (timing constants).

**Path constant + cache-tier constants to port verbatim** (lines 16-29):
```go
const jwksPath = "/oauth2/jwks"           // org-wide, NOT tenant-scoped
const minRefetchInterval = 60 * time.Second   // forced-refetch cooldown floor
const maxCacheInterval  = 300 * time.Second   // normal TTL ceiling
```
Python: `JWKS_PATH = "/oauth2/jwks"`, `PyJWKClient(jwks_url, cache_jwk_set=True, lifespan=300)` — do NOT enable `cache_keys=True` (RESEARCH.md Pattern 5 Pitfall, no direct Go equivalent needed since jwx's cache differs, but the *TTL discipline* is the same).

**EdDSA-only allowlist checked BEFORE any keyset lookup — algorithm-confusion defense, port verbatim** (Go lines 81-100):
```go
sigs := msg.Signatures()
if len(sigs) == 0 { return Claims{}, fmt.Errorf("jwks: token has no signatures") }
for _, sig := range sigs {
    alg, ok := sig.ProtectedHeaders().Algorithm()
    if !ok || alg != jwa.EdDSA() {
        return Claims{}, fmt.Errorf("jwks: unexpected alg %q: only EdDSA is accepted", alg.String())
    }
}
```
Python: `header = jwt.get_unverified_header(token); if header.get("alg") != "EdDSA": raise ValueError(...)` — checked before calling `PyJWKClient.get_signing_key_from_jwt`, exactly mirroring the ordering constraint.

**Unknown-kid forced-refetch-once retry pattern to port** (Go lines 107-119): on verify failure, force exactly one refetch, retry exactly once, then fail. Python: catch `PyJWKClientError`, invalidate `jwk_set_cache`, retry once (RESEARCH.md Pattern 5's example already does this — verify the `jwk_set_cache = None` attribute name against installed PyJWT 2.13 source per Assumption A3 before trusting it).

**Verify does NOT check expiry — caller's job** (Go doc comment lines 76-80): if the FastAPI/Django integrations reuse this verifier, they must independently check `exp` (see middleware pattern below, Go lines 67-76 does this explicitly).

---

### `sdks/python/src/axiam_sdk/grpc/_interceptor.py` (middleware, request-response)

**Analog:** `sdks/go/grpc/interceptor.go` (full file, lines 1-38) — extremely small, direct 1:1 port.

**Non-blocking TokenFunc pattern — critical invariant, port verbatim comment + shape** (lines 10-26):
```go
// tokenFn is read synchronously on every call and MUST be non-blocking —
// this closure runs on the hot RPC path and must NEVER acquire the async
// single-flight refresh mutex directly.
type TokenFunc func() (token string, ok bool)

func authUnaryInterceptor(tokenFn TokenFunc, tenantID string) grpc.UnaryClientInterceptor {
    return func(ctx, method, req, reply, cc, invoker, opts...) error {
        if token, ok := tokenFn(); ok {
            ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token, "x-tenant-id", tenantID)
        }
        return invoker(ctx, method, req, reply, cc, opts...)
    }
}
```
Python needs TWO interceptor classes per RESEARCH.md Pattern 3 (already codebase-fitted): `SyncAuthInterceptor(grpc.UnaryUnaryClientInterceptor)` (sync `intercept_unary_unary`) and `AsyncAuthInterceptor(grpc.aio.UnaryUnaryClientInterceptor)` (`async def intercept_unary_unary`, must `await continuation(...)`) — both backed by the SAME `_AuthMetadataMixin._build_metadata()` reading `refresh_guard.cached_access_token()` (the non-blocking accessor from `token/refresh_guard.py` above), never the blocking refresh call.

---

### `sdks/python/src/axiam_sdk/grpc/client.py` (service, request-response)

**Analog:** `sdks/go/grpc/client.go` (full file, lines 1-161).

**UNAUTHENTICATED single-flight-retry-exactly-once pattern to port verbatim** (lines 82-98, `CheckAccess`):
```go
resp, err := c.inner.CheckAccess(ctx, wire)
if err != nil {
    if c.refresh != nil && status.Code(err) == codes.Unauthenticated {
        if refreshErr := c.refresh(ctx); refreshErr != nil { return false, "", refreshErr }
        resp, err = c.inner.CheckAccess(ctx, wire)   // retry EXACTLY once
    }
    if err != nil { return false, "", mapGRPCError(err) }
}
```
Same shape for `BatchCheck` (lines 103-128). Python needs this pattern duplicated for sync (`grpcio`) and async (`grpc.aio`) — `RefreshFunc` is a caller-supplied callable (sync `Callable[[], None]` / async `Callable[[], Awaitable[None]]`), decoupling this module from the REST session exactly as Go's `RefreshFunc` (lines 28-32) decouples grpc/ from the root package (avoid import cycle equivalent — in Python this maps to "don't import `_client.py` from `grpc/client.py`; accept a refresh closure instead").

**Status mapping — identical table, reuse `_errors.py`'s central mapper** (lines 136-160) rather than re-deriving it here (this is exactly what Go's `mapGRPCError` does by delegating to the same taxonomy as `errors.go`).

---

### `sdks/python/src/axiam_sdk/amqp/_hmac.py` (utility, crypto transform)

**Analog:** `sdks/go/amqp/hmac.go` (full file, lines 1-67) — primary; canonical spec `crates/axiam-amqp/src/messages.rs` (verified: `sign_payload`/`verify_payload` at lines 35/45, with typed `AuthzRequest`/`AuditEventMessage`/`NotificationEvent` structs at lines 58/88/109 — confirms RESEARCH.md's Pitfall 2 concern that these are **declared-order structs, not BTreeMaps**).

**Algorithm to port, WITH THE CORRECTION RESEARCH.md ALREADY FLAGGED** (Go lines 33-67 uses `json.Marshal` on a `map[string]json.RawMessage`, which in Go alphabetizes keys — this happens to work for Go only if the server's field order is coincidentally alphabetical, which RESEARCH.md's Pitfall 2 flags as UNVERIFIED even for the existing Go SDK). For Python:
```python
def verify_hmac(signing_key: bytes, body: bytes) -> bool:
    try:
        msg: dict = json.loads(body)  # dict preserves insertion/wire order (PEP 468, 3.7+)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False
    sig_hex = msg.pop("hmac_signature", None)
    if sig_hex is None:
        return False  # strict mode default — missing signature = reject
    canonical = json.dumps(msg, separators=(",", ":")).encode("utf-8")  # NO sort_keys=True — preserve wire order
    try:
        expected = bytes.fromhex(sig_hex)
    except ValueError:
        return False
    computed = hmac.new(signing_key, canonical, hashlib.sha256).digest()
    return hmac.compare_digest(computed, expected)  # constant-time, mirrors Go's hmac.Equal
```
**MANDATORY Wave-0 action carried from RESEARCH.md, do not skip:** build a fixture-based cross-language test comparing this against a real `crates/axiam-amqp/src/messages.rs::sign_payload` output before trusting either Go's alphabetical approach or Python's insertion-order approach — this is the single highest-risk item in the phase per both CONTEXT.md and RESEARCH.md.

**Test analog:** `sdks/go/amqp/hmac_test.go` — port its test-vector structure into `tests/test_amqp_hmac.py`.

---

### `sdks/python/src/axiam_sdk/amqp/__init__.py` (consumer, event-driven)

**Analog:** `sdks/go/amqp/consumer.go` (full file, lines 1-206) — closure-handler shape is the direct model for D-02.

**Ack/nack decision matrix to port verbatim** (lines 108-155, `verifyAndDispatch`):
```go
if !verifyHMAC(signingKey, body) {
    logger.SecurityWarn("axiam_sdk_security: AMQP HMAC verification failed; nacking without requeue")
    delivery.Nack(false)   // never requeue an unverified message
    return
}
event, err := parseEvent(body)
if err != nil { ... delivery.Nack(false); return }   // parse failure after verify = also nack-without-requeue
if err := handler(ctx, event); err != nil {
    if errors.Is(err, ErrDrop) { delivery.Nack(false); return }   // poison message
    delivery.Nack(true); return   // transient — requeue
}
delivery.Ack()
```
Python (`aio-pika`, async-only per D-02) — RESEARCH.md's Pattern 4 code example already ports this exactly using `message.process(ignore_processed=True)` + `message.ack()`/`message.nack(requeue=...)` and an `ErrDrop` exception class mirroring Go's exported `ErrDrop` sentinel (`sdks/go/amqp/errdrop.go` — read this small file too if implementing the exact sentinel-matching semantics). Default prefetch `WithPrefetch`/`defaultPrefetch = 10` (Go line 13) → Python `prefetch: int = 10` kwarg default, `channel.set_qos(prefetch_count=prefetch)`.

**Security-log-never-includes-signature-value invariant** (Go lines 96-106, 131-133): the Python `logger.warning(...)` call must never interpolate `sig_hex` or `computed`/`expected` bytes — only the fact of failure.

---

### `sdks/python/src/axiam_sdk/fastapi/__init__.py` (middleware/DI) — NO IN-REPO ANALOG, MEDIUM CONFIDENCE

No FastAPI code exists anywhere in this repo (first Python SDK phase). RESEARCH.md's Pattern 6 (lines 770-822) is the only available reference, itself sourced from FastAPI's own official docs, not a codebase file — flag this as **net-new, MEDIUM confidence**. The closest *conceptual* analog for the cross-tenant-replay-defense invariant is `sdks/go/middleware/nethttp.go` lines 78-95 (`claims.TenantID != configuredTenant` check) — this specific security check MUST be carried into the FastAPI dependency verbatim (see Shared Patterns below), even though the surrounding DI plumbing has no Python precedent in this repo.

---

### `sdks/python/src/axiam_sdk/django/middleware.py` (middleware) — PARTIAL ANALOG, MEDIUM CONFIDENCE

**Analog:** `sdks/go/middleware/nethttp.go` (full file, lines 1-161) — closest cross-language shape (extract → verify → tenant-check → inject → 401/403), but the Go file is net/http-specific; Django's `sync_capable`/`async_capable` dual-mode dispatch (RESEARCH.md Pattern 7, lines 824-882) has no Go/Rust/TS precedent since none of those SDKs target a framework with Django's dual-mode middleware contract. Flag as **role-match, framework idiom itself net-new**.

**Extraction pattern to port from Go verbatim** (lines 109-125, `extractToken`):
```go
func extractToken(r *http.Request) (string, error) {
    if header := r.Header.Get("Authorization"); header != "" {
        scheme, credentials, found := strings.Cut(strings.TrimSpace(header), " ")
        if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(credentials) == "" {
            return "", errMissingCredentials
        }
        return strings.TrimSpace(credentials), nil
    }
    if cookie, err := r.Cookie("axiam_access"); err == nil && cookie.Value != "" {
        return cookie.Value, nil
    }
    return "", errMissingCredentials
}
```
Port to Python 1:1 (Authorization Bearer header, fallback to `axiam_access` cookie) for BOTH the FastAPI dependency and the Django middleware — this exact extraction order is a Shared Pattern (see below).

**Standardized error body to port verbatim** (lines 22-27, 136-145): `{"error": "authentication_failed", "message": "..."}` at 401, no raw token value ever included — same JSON shape for both FastAPI's `HTTPException(status_code=401, detail=...)` and Django's `JsonResponse(..., status=401)`.

---

### `sdks/python/examples/*.py`

**Analogs (1:1 file-to-file mapping):**
| Python example | Go analog |
|---|---|
| `login_mfa.py` | `sdks/go/examples/login-mfa/main.go` |
| `rest_authz.py` | `sdks/go/examples/authz-check/main.go` |
| `grpc_checkaccess.py` | `sdks/go/examples/grpc-checkaccess/main.go` |
| `amqp_consumer.py` | `sdks/go/examples/amqp-consumer/main.go` |
| `django_middleware.py` | `sdks/go/examples/middleware-guard/main.go` (conceptual only — Django-specific settings wiring is net-new) |
| `fastapi_dependency.py` | none — net-new, MEDIUM confidence |

Read each Go example at implementation time for the exact call sequence/output-shape it demonstrates; port the narrative structure (construct client → call → print result → handle error) directly.

---

### `sdks/python/pyproject.toml`

**Analog:** `sdks/python/pyproject.toml` itself (existing scaffold, read in full above) — this is a **fix-in-place**, not a from-scratch write.

**Exact bugs to fix** (scaffold lines 1-26):
```toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.backends.legacy:build"   # BROKEN — invalid backend path (D-03)
...
requires-python = ">=3.9"   # EOL — raise to ">=3.10" (D-11)
```
Fix: `build-backend = "setuptools.build_meta"` (D-03); `requires-python = ">=3.10"`, drop the `"Programming Language :: Python :: 3.9"` classifier (D-11); restructure to src-layout so `[tool.setuptools.packages.find]` points at `src/` (D-14); add `[project.optional-dependencies]` for `fastapi`/`django`/`dev` groups (Assumption A4); add `[tool.setuptools.package-data]` for the committed gRPC stub `.pyi`/`.py` files (D-04); add `[tool.pytest.ini_options]` with `asyncio_mode = "auto"`; add `[tool.mypy]` strict config and `[tool.ruff]` (D-20). Keep the `LICENSE`/`Repository`/`Documentation` metadata as-is (Apache-2.0 confirmed correct).

---

### `.github/workflows/sdk-ci-python.yml` (rewrite from stub)

**Analog:** `.github/workflows/sdk-ci-go.yml` (full file, lines 1-151) — the freshest, most complete SDK CI workflow in the repo; current Python workflow (lines 1-23) is only a placeholder scaffold-check.

**Structure to port, job-by-job:**
- `scaffold-check` job (Go lines 19-26) → keep as-is, already Python-adapted (`test -f sdks/python/LICENSE`).
- `test` job (Go lines 28-56) → Python: matrix `python-version: ['3.10','3.11','3.12','3.13']` (D-18) on `ubuntu-latest`; steps: install deps, `pytest sdks/python/tests -v`, build examples (import-check equivalent since Python has no compile step), run `mypy --strict` + `ruff check`/`ruff format --check` (D-20).
- `tls-bypass-gate` job (Go lines 58-76, grep-based) → **port verbatim as the SC#3 gate**, substituting the grep pattern:
  ```bash
  grep -rn "verify=False" sdks/python/src sdks/python/examples sdks/python/tests
  ```
  (see RESEARCH.md's ready-made script, Code Examples section, lines 1156-1173 — already fitted to this repo's path convention.)
- `buf-drift-check` job (Go lines 77-98) → Python: per RESEARCH.md Pitfall 5's recommendation, standardize on `python -m grpc_tools.protoc` instead of the `buf` CLI (both locally and in CI, since `buf` is confirmed absent from the dev sandbox and Go already set this precedent) — regenerate + apply the import-fixup script + `git diff --exit-code sdks/python/src/axiam_sdk/grpc/gen` (D-04).
- `publish` job (Go lines 100-151, tag-triggered, `if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/sdks/go/v')`) → Python: trigger on `refs/tags/sdks/python/v*` (D-05); replace Go's module-proxy-verification step with `python -m build && twine check dist/*` (SC#5) then `pypa/gh-action-pypi-publish` with Trusted Publishing (`id-token: write` permission, no token secret) — this is the one job with NO direct Go equivalent (Go's module proxy needs no explicit publish step; Python's PyPI does) — flag this sub-step as the CI job with the least direct 1:1 code to copy, though the *tag-trigger condition* and *re-run-drift-check-before-publish* structure (Go lines 115-129) still ports directly.

---

## Shared Patterns

### Redact-before-wrap error construction (applies to `_errors.py`, `grpc/client.py`, `amqp/__init__.py` logging)
**Source:** `sdks/go/errors.go` lines 104-127 (`newNetworkError`) + `sdks/typescript/src/core/errorMapper.ts` lines 45-72 (`sanitizeAxiosError`).
Single chokepoint function; every call site constructing a `NetworkError` from an `httpx.Response` MUST route through it. Never construct `NetworkError(raw_response_dump)` inline elsewhere.

### Cross-tenant replay defense (applies to `_jwks.py` consumers: `fastapi/__init__.py`, `django/middleware.py`)
**Source:** `sdks/go/middleware/nethttp.go` lines 78-95.
```go
if claims.TenantID == "" || claims.TenantID != configuredTenant {
    writeError(w, cfg, http.StatusUnauthorized, "authentication_failed", "token tenant_id does not match the configured tenant")
    return
}
```
The JWKS is organization-wide, not tenant-scoped — signature validity alone is insufficient. Both `require_authenticated_user()` (FastAPI) and `AxiamAuthMiddleware` (Django) MUST perform this check before trusting any claim further. This is a MUST-carry-forward control per RESEARCH.md's Security Domain section, not optional.

### Token extraction order (Authorization Bearer → cookie fallback)
**Source:** `sdks/go/middleware/nethttp.go` lines 109-125 (`extractToken`).
Applies identically to FastAPI dependency and Django middleware — same two-step extraction, same `axiam_access` cookie name, same "missing credentials" 401 on neither present.

### Non-blocking cached-token read on the hot RPC/interceptor path
**Source:** `sdks/go/internal/refreshguard/guard.go` lines 90-115 (`CachedAccessToken`/`CachedRefreshToken`/`CachedExp`) + `sdks/go/grpc/interceptor.go` lines 10-26 (doc comment on `TokenFunc`).
Applies to: `grpc/_interceptor.py`'s metadata-building closure. Never call the blocking refresh path from inside an interceptor; only read the guard's cached value.

### Single-flight-retry-exactly-once on auth failure
**Source:** `sdks/go/grpc/client.go` lines 82-98 (§9.3 "no retry loop" — retry the failed call exactly once after a successful refresh, propagate any second failure as-is).
Applies to: `grpc/client.py` (both sync+async), and implicitly to `_session.py`'s REST 401 handling path.

### Standardized error taxonomy status-code table
**Source:** `sdks/go/errors.go` lines 129-174 + `sdks/typescript/src/core/errorMapper.ts` lines 74-129 — identical table in both languages, confirming this is the one true source (CONTRACT.md §2).
Applies to: `_errors.py`'s `error_from_http_status`/`error_from_grpc_status`, and any place gRPC/REST call sites need to classify a failure.

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `sdks/python/src/axiam_sdk/fastapi/__init__.py` | middleware (DI) | request-response | No FastAPI code exists anywhere in the repo (first Python SDK phase); RESEARCH.md Pattern 6 (official FastAPI docs pattern) is the only reference. The cross-tenant-check and token-extraction sub-patterns DO have Go analogs (see Shared Patterns) — only the `Depends(...)` factory plumbing itself is net-new. |
| `sdks/python/examples/fastapi_dependency.py` | script | request-response | Same reason — no FastAPI example exists in any sibling SDK. |
| `sdks/python/src/axiam_sdk/django/middleware.py` (the `sync_capable`/`async_capable` dual-dispatch mechanics specifically) | middleware | request-response | Django's dual-mode middleware contract (`markcoroutinefunction`, `iscoroutinefunction`) has no precedent in Go/Rust/TS SDKs, none of which target Django. The surrounding extract/verify/inject/error-response logic DOES have a strong Go analog (`nethttp.go`) — only the sync/async dispatch shim is net-new. |

## Metadata

**Analog search scope:** `sdks/go/` (full tree, primary reference — freshest non-browser SDK), `sdks/typescript/src/core/` (error mapper + sensitive wrapper), `sdks/rust/src/token/` (JWKS/refresh-guard timing precedent), `crates/axiam-amqp/src/messages.rs` (canonical HMAC spec), `sdks/python/` (existing scaffold), `.github/workflows/sdk-ci-go.yml` + `sdk-ci-python.yml` (CI precedent).
**Files scanned:** 27 Go/TS/Rust source files read in full or targeted excerpt; 1 canonical Rust crate file; 2 pyproject/CI config files; existing Python scaffold (2 files).
**Pattern extraction date:** 2026-07-01

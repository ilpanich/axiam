/*
 * AXIAM C SDK benchmark — wired to the sibling axiam-c-sdk checkout
 * (ilpanich/axiam-c-sdk, linked in via CMakeLists.txt add_subdirectory()).
 *
 * Times the SDK's canonical CONTRACT.md §1 operations — axiam_login,
 * axiam_refresh, axiam_check_access, axiam_batch_check — against a running,
 * seeded AXIAM target. oauth2_token/introspect/userinfo are protocol-level
 * ops with no SDK wrapper (see ../HARNESS-SPEC.md) and are not measured here.
 *
 * All four ops are timed with a plain serial loop (no threads): the C SDK
 * documents that its client is safe under concurrent calls (single-flight
 * refresh guard, §9), but HARNESS-SPEC.md explicitly allows a serial C
 * harness ("the others may be serial in C — a serial loop is acceptable and
 * simplest; note it in notes") — see the `notes` field emitted below, and
 * `concurrency: 1` reported in the JSON record accordingly. This mirrors
 * the *shape* (warm-up, percentile math, JSON contract) of the reference
 * harnesses (../python/bench.py, ../typescript/bench.mjs) without their
 * bounded-worker-pool concurrency for login/check_access/batch_check.
 *
 * Keep the stdout JSON contract (axiam.sdk-bench/v1) intact.
 *
 * Build: cmake -S . -B build && cmake --build build
 * Run:   ./build/axiam-bench   (or: just sdk=c sdk-bench)
 */
#include <axiam/axiam.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__clang__)
#define AXIAM_BENCH_COMPILER "clang " __clang_version__
#elif defined(__GNUC__)
#define AXIAM_BENCH_COMPILER "gcc " __VERSION__
#else
#define AXIAM_BENCH_COMPILER "unknown"
#endif

/* ------------------------------------------------------------------ */
/* Config / env                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    char base_url[256];
    char tenant_slug[128];
    char org_slug[128];
    char username[128];
    char password[128];
    char action[128];
    char resource_id[128];
    char target[64];
    char profile[64];
} cfg_t;

static const char *getenv_or(const char *key, const char *fallback) {
    const char *v = getenv(key);
    return (v && v[0]) ? v : fallback;
}

static long getenv_long(const char *key, long fallback) {
    const char *v = getenv(key);
    if (!v || !v[0]) return fallback;
    char *end = NULL;
    long parsed = strtol(v, &end, 10);
    if (end == v) return fallback;
    return parsed;
}

static void cfg_load(cfg_t *cfg) {
    const char *scheme = getenv_or("BENCH_SCHEME", "http");
    const char *host = getenv_or("BENCH_HOST", "localhost");
    const char *port = getenv_or("BENCH_PORT", "8090");
    snprintf(cfg->base_url, sizeof(cfg->base_url), "%s://%s:%s", scheme, host, port);
    snprintf(cfg->tenant_slug, sizeof(cfg->tenant_slug), "%s", getenv_or("BENCH_TENANT_SLUG", "default"));
    snprintf(cfg->org_slug, sizeof(cfg->org_slug), "%s", getenv_or("BENCH_ORG_SLUG", "bench-org"));
    snprintf(cfg->username, sizeof(cfg->username), "%s", getenv_or("BENCH_USERNAME", "benchuser"));
    snprintf(cfg->password, sizeof(cfg->password), "%s", getenv_or("BENCH_PASSWORD", "Bench@User123!"));
    snprintf(cfg->action, sizeof(cfg->action), "%s", getenv_or("BENCH_ACTION", "read"));
    snprintf(cfg->resource_id, sizeof(cfg->resource_id), "%s", getenv_or("BENCH_RESOURCE_ID", "bench-resource"));
    snprintf(cfg->target, sizeof(cfg->target), "%s", getenv_or("BENCH_TARGET", "axiam"));
    snprintf(cfg->profile, sizeof(cfg->profile), "%s", getenv_or("BENCH_PROFILE", "p0-plaintext"));
}

/* ------------------------------------------------------------------ */
/* Percentile math (mirrors python/bench.py::pct, typescript/bench.mjs) */
/* ------------------------------------------------------------------ */

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

static double pct(double *sorted, int n, double p) {
    if (n <= 0) return 0.0;
    double k = (double)(n - 1) * (p / 100.0);
    int lo = (int)k;
    int hi = lo + 1;
    if (hi > n - 1) hi = n - 1;
    double frac = k - (double)lo;
    return sorted[lo] + (sorted[hi] - sorted[lo]) * frac;
}

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* ------------------------------------------------------------------ */
/* Timing loop                                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    double p50_ms, p95_ms, p99_ms, throughput_rps;
    int errors;
} op_result_t;

typedef int (*bench_fn_t)(void *ctx);

static op_result_t zero_op_result(void) {
    op_result_t r = {0.0, 0.0, 0.0, 0.0, 0};
    return r;
}

static op_result_t time_op(bench_fn_t fn, void *ctx, int warmup, int iters) {
    int errors = 0;
    for (int i = 0; i < warmup; i++) {
        if (fn(ctx) != 0) errors++;
    }

    if (iters <= 0) {
        op_result_t r = zero_op_result();
        r.errors = errors;
        return r;
    }

    double *lat = (double *)malloc(sizeof(double) * (size_t)iters);
    int n = 0;
    double t0 = now_s();
    for (int i = 0; i < iters; i++) {
        double s = now_s();
        int rc = fn(ctx);
        double e = now_s();
        if (rc == 0) {
            lat[n++] = (e - s) * 1000.0;
        } else {
            errors++;
        }
    }
    double secs = now_s() - t0;

    qsort(lat, (size_t)n, sizeof(double), cmp_double);

    op_result_t r;
    r.p50_ms = pct(lat, n, 50.0);
    r.p95_ms = pct(lat, n, 95.0);
    r.p99_ms = pct(lat, n, 99.0);
    r.throughput_rps = secs > 0.0 ? (double)n / secs : 0.0;
    r.errors = errors;
    free(lat);
    return r;
}

/* ------------------------------------------------------------------ */
/* Bench ops (CONTRACT.md §1: login, refresh, check_access, batch_check) */
/* ------------------------------------------------------------------ */

/* login: build-and-discard a fresh, short-lived client per call — mirrors
 * python's do_login()/typescript's login closure: a fresh unauthenticated
 * session per iteration is what the op measures. */
static int op_login(void *ctxp) {
    cfg_t *cfg = (cfg_t *)ctxp;
    axiam_client_config_t *c = axiam_client_config_new();
    if (!c) return 1;
    axiam_client_config_set_base_url(c, cfg->base_url);
    axiam_client_config_set_tenant_slug(c, cfg->tenant_slug);
    axiam_client_config_set_org_slug(c, cfg->org_slug);

    axiam_error_t err;
    axiam_client_t *client = axiam_client_new(c, &err);
    axiam_client_config_free(c);
    if (!client) return 1;

    axiam_login_result_t login;
    memset(&login, 0, sizeof(login));
    axiam_error_kind_t rc = axiam_login(client, cfg->username, cfg->password, &login, &err);
    axiam_login_result_dispose(&login);
    axiam_client_free(client);
    return rc == AXIAM_OK ? 0 : 1;
}

/* refresh/check_access/batch_check share one already-logged-in client. */
typedef struct {
    axiam_client_t *client;
    cfg_t *cfg;
    axiam_check_input_t checks[3];
} shared_ctx_t;

static int op_refresh(void *ctxp) {
    shared_ctx_t *ctx = (shared_ctx_t *)ctxp;
    axiam_error_t err;
    return axiam_refresh(ctx->client, &err) == AXIAM_OK ? 0 : 1;
}

static int op_check_access(void *ctxp) {
    shared_ctx_t *ctx = (shared_ctx_t *)ctxp;
    axiam_check_result_t res;
    memset(&res, 0, sizeof(res));
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_check_access(
        ctx->client, ctx->cfg->action, ctx->cfg->resource_id, NULL, NULL, &res, &err);
    axiam_check_result_dispose(&res);
    return rc == AXIAM_OK ? 0 : 1;
}

static int op_batch_check(void *ctxp) {
    shared_ctx_t *ctx = (shared_ctx_t *)ctxp;
    axiam_check_result_t results[3];
    memset(results, 0, sizeof(results));
    size_t count = 0;
    axiam_error_t err;
    axiam_error_kind_t rc = axiam_batch_check(ctx->client, ctx->checks, 3, results, &count, &err);
    for (size_t i = 0; i < count; i++) axiam_check_result_dispose(&results[i]);
    return rc == AXIAM_OK ? 0 : 1;
}

/* ------------------------------------------------------------------ */
/* JSON emission — keep the axiam.sdk-bench/v1 contract fixed.         */
/* ------------------------------------------------------------------ */

/* Minimal JSON string escaper for the free-text `notes` field (SDK error
 * messages are redacted per CONTRACT §2/§7 but may still contain quotes). */
static void json_escape(const char *in, char *out, size_t out_sz) {
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p && o + 2 < out_sz; p++) {
        switch (*p) {
            case '"': case '\\':
                if (o + 2 >= out_sz) break;
                out[o++] = '\\';
                out[o++] = (char)*p;
                break;
            case '\n': if (o + 2 < out_sz) { out[o++] = '\\'; out[o++] = 'n'; } break;
            case '\r': if (o + 2 < out_sz) { out[o++] = '\\'; out[o++] = 'r'; } break;
            case '\t': if (o + 2 < out_sz) { out[o++] = '\\'; out[o++] = 't'; } break;
            default:
                if (*p < 0x20) break; /* drop other control chars */
                out[o++] = (char)*p;
        }
    }
    out[o] = '\0';
}

static void print_op(const char *key, op_result_t r, int is_last) {
    printf("    \"%s\": {\"p50_ms\": %.3f, \"p95_ms\": %.3f, \"p99_ms\": %.3f, "
           "\"throughput_rps\": %.3f, \"errors\": %d}%s\n",
           key, r.p50_ms, r.p95_ms, r.p99_ms, r.throughput_rps, r.errors, is_last ? "" : ",");
}

static void emit_record(const cfg_t *cfg, const char *status, int iterations, int concurrency,
                         op_result_t op_login_r, op_result_t op_refresh_r,
                         op_result_t op_check_access_r, op_result_t op_batch_check_r,
                         const char *notes) {
    char notes_esc[1024];
    json_escape(notes, notes_esc, sizeof(notes_esc));

    printf("{\n");
    printf("  \"schema\": \"axiam.sdk-bench/v1\",\n");
    printf("  \"sdk\": \"c\",\n");
    printf("  \"sdk_version\": \"%s\",\n", axiam_version());
    printf("  \"language_runtime\": \"c11 (%s)\",\n", AXIAM_BENCH_COMPILER);
    printf("  \"target\": \"%s\",\n", cfg->target);
    printf("  \"profile\": \"%s\",\n", cfg->profile);
    printf("  \"status\": \"%s\",\n", status);
    printf("  \"iterations\": %d,\n", iterations);
    printf("  \"concurrency\": %d,\n", concurrency);
    printf("  \"ops\": {\n");
    print_op("login", op_login_r, 0);
    print_op("refresh", op_refresh_r, 0);
    print_op("check_access", op_check_access_r, 0);
    print_op("batch_check", op_batch_check_r, 1);
    printf("  },\n");
    printf("  \"client_cpu_ms_total\": 0,\n");
    printf("  \"client_rss_mib_peak\": 0,\n");
    printf("  \"notes\": \"%s\"\n", notes_esc);
    printf("}\n");
}

static void emit_error(const cfg_t *cfg, const char *notes) {
    op_result_t z = zero_op_result();
    emit_record(cfg, "error", 0, 0, z, z, z, z, notes);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(void) {
    cfg_t cfg;
    cfg_load(&cfg);

    int iterations = (int)getenv_long("SDK_BENCH_ITERATIONS", 2000);
    int warmup = (int)getenv_long("SDK_BENCH_WARMUP", 200);
    /* SDK_BENCH_CONCURRENCY is read (for parity with the other benches'
     * env-input surface) but intentionally not applied: this harness runs a
     * plain serial loop for every op (see the file header comment and
     * HARNESS-SPEC.md's explicit allowance for a serial C bench), so the
     * emitted `concurrency` is always 1 regardless of this env var. */
    (void)getenv_long("SDK_BENCH_CONCURRENCY", 16);

    /* Build the one shared, logged-in client used by refresh/check_access/
     * batch_check (login times its own short-lived clients instead). */
    axiam_client_config_t *shared_cfg = axiam_client_config_new();
    if (!shared_cfg) {
        emit_error(&cfg, "out of memory allocating client config");
        return 0;
    }
    axiam_client_config_set_base_url(shared_cfg, cfg.base_url);
    axiam_client_config_set_tenant_slug(shared_cfg, cfg.tenant_slug);
    axiam_client_config_set_org_slug(shared_cfg, cfg.org_slug);

    axiam_error_t err;
    axiam_client_t *client = axiam_client_new(shared_cfg, &err);
    axiam_client_config_free(shared_cfg);
    if (!client) {
        char notes[512];
        snprintf(notes, sizeof(notes), "client config error: %s", err.message);
        emit_error(&cfg, notes);
        return 0;
    }

    axiam_login_result_t login;
    memset(&login, 0, sizeof(login));
    if (axiam_login(client, cfg.username, cfg.password, &login, &err) != AXIAM_OK) {
        char notes[768];
        snprintf(notes, sizeof(notes),
                 "server unreachable or login failed against %s: %s", cfg.base_url, err.message);
        axiam_login_result_dispose(&login);
        axiam_client_free(client);
        emit_error(&cfg, notes);
        return 0;
    }
    axiam_login_result_dispose(&login);

    /* Fail fast if the grant is missing — otherwise we'd silently benchmark
     * the deny fast-path instead of a real allow decision (mirrors the
     * python/typescript reference harnesses). */
    axiam_check_result_t warm;
    memset(&warm, 0, sizeof(warm));
    axiam_error_kind_t warm_rc =
        axiam_check_access(client, cfg.action, cfg.resource_id, NULL, NULL, &warm, &err);
    int warm_allowed = warm.allowed;
    axiam_check_result_dispose(&warm);
    if (warm_rc != AXIAM_OK || !warm_allowed) {
        char notes[512];
        snprintf(notes, sizeof(notes),
                 "warm-up check_access denied for action=%s resource_id=%s — seed the "
                 "resource/role/grant (see runner/seed.sh)", cfg.action, cfg.resource_id);
        axiam_client_free(client);
        emit_error(&cfg, notes);
        return 0;
    }

    shared_ctx_t shared;
    shared.client = client;
    shared.cfg = &cfg;
    for (int i = 0; i < 3; i++) {
        shared.checks[i].action = cfg.action;
        shared.checks[i].resource_id = cfg.resource_id;
        shared.checks[i].scope = NULL;
        shared.checks[i].subject_id = NULL;
    }

    op_result_t r_login = time_op(op_login, &cfg, warmup, iterations);
    op_result_t r_refresh = time_op(op_refresh, &shared, warmup, iterations);
    op_result_t r_check_access = time_op(op_check_access, &shared, warmup, iterations);
    op_result_t r_batch_check = time_op(op_batch_check, &shared, warmup, iterations);

    axiam_logout(client, &err);
    axiam_client_free(client);

    emit_record(&cfg, "ok", iterations, /* concurrency */ 1,
                r_login, r_refresh, r_check_access, r_batch_check,
                "serial loop (concurrency=1) for all four ops, not just refresh — "
                "see HARNESS-SPEC.md's allowance for a simple C harness; "
                "SDK_BENCH_CONCURRENCY was read but not applied");
    return 0;
}

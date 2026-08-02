// AXIAM Go SDK benchmark (wired to github.com/ilpanich/axiam-go-sdk).
//
// Times the SDK's canonical CONTRACT.md §1 operations — login, refresh,
// check_access, batch_check — against a running, seeded AXIAM target.
// oauth2_token/introspect/userinfo are protocol-level ops with no SDK
// wrapper (see ../HARNESS-SPEC.md) and are not measured here. Mirrors the
// reference harnesses in ../python/bench.py and ../typescript/bench.mjs
// (timing loop, percentile math, JSON contract). The stdout JSON contract
// (axiam.sdk-bench/v1) must stay intact.
//
// Run: go run .   (or: cd benchmarks && just sdk=go sdk-bench)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	axiam "github.com/ilpanich/axiam-go-sdk"
)

// opKeys is the fixed set of ops emitted, in HARNESS-SPEC.md order.
var opKeys = []string{"login", "refresh", "check_access", "batch_check"}

type config struct {
	baseURL    string
	tenantSlug string
	orgSlug    string
	username   string
	password   string
	action     string
	resourceID string
	// H8 fix: HARNESS-SPEC.md documents BENCH_CA_CERT (a PEM file path) as
	// an input every SDK bench should honor under the TLS profiles (p2),
	// but this bench never read it — every p2 run failed at the first
	// HTTPS call against the profile's throwaway CA. Empty under p0.
	caCertPath string
	// p3-mtls client identity (CONTRACT.md §6.1) — the same cert/key pair k6
	// hands to `tlsAuth` and seed.sh to `curl --cert`. Both empty on
	// p0/p1/p2, where no client option is added and the SDK's default
	// bearer-cookie behavior is untouched (§6.1 rule 5: mTLS is opt-in).
	clientCertPath string
	clientKeyPath  string
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func loadConfig() config {
	scheme := env("BENCH_SCHEME", "http")
	host := env("BENCH_HOST", "localhost")
	port := env("BENCH_PORT", "8090")
	return config{
		baseURL:    fmt.Sprintf("%s://%s:%s", scheme, host, port),
		tenantSlug: env("BENCH_TENANT_SLUG", "default"),
		// H8 fix: this was never read/wired, so every login went out with no
		// org context — CONTRACT.md §5.1 requires org_slug on login/refresh,
		// and every other language bench (python/typescript/rust/java/csharp/
		// php) already passes it. Discovered when the CSRF header-echo fix
		// (crates/axiam-api-rest) unblocked check_access enough to reach this
		// as the next failure.
		orgSlug:    env("BENCH_ORG_SLUG", "bench-org"),
		username:   env("BENCH_USERNAME", "benchuser"),
		password:   env("BENCH_PASSWORD", "Bench@User123!"),
		action:     env("BENCH_ACTION", "read"),
		resourceID: env("BENCH_RESOURCE_ID", "bench-resource"),
		caCertPath: env("BENCH_CA_CERT", ""),

		clientCertPath: env("BENCH_CLIENT_CERT", ""),
		clientKeyPath:  env("BENCH_CLIENT_KEY", ""),
	}
}

// opResult is one op's measured latency distribution — JSON keys must match
// the axiam.sdk-bench/v1 contract exactly.
type opResult struct {
	P50Ms         float64 `json:"p50_ms"`
	P95Ms         float64 `json:"p95_ms"`
	P99Ms         float64 `json:"p99_ms"`
	ThroughputRPS float64 `json:"throughput_rps"`
	Errors        int     `json:"errors"`
}

// output is the single JSON object emitted to stdout (the stable contract).
type output struct {
	Schema           string              `json:"schema"`
	SDK              string              `json:"sdk"`
	SDKVersion       string              `json:"sdk_version"`
	LanguageRuntime  string              `json:"language_runtime"`
	Target           string              `json:"target"`
	Profile          string              `json:"profile"`
	Status           string              `json:"status"`
	Iterations       int                 `json:"iterations"`
	Concurrency      int                 `json:"concurrency"`
	Ops              map[string]opResult `json:"ops"`
	ClientCPUMsTotal int                 `json:"client_cpu_ms_total"`
	ClientRSSMiBPeak int                 `json:"client_rss_mib_peak"`
	Notes            string              `json:"notes"`
}

// pct mirrors the reference percentile method (linear interpolation between
// the two nearest ranks) in python/bench.py and typescript/bench.mjs.
func pct(arr []float64, p float64) float64 {
	if len(arr) == 0 {
		return 0
	}
	s := make([]float64, len(arr))
	copy(s, arr)
	sort.Float64s(s)
	k := float64(len(s)-1) * (p / 100.0)
	lo := int(k)
	hi := lo + 1
	if hi > len(s)-1 {
		hi = len(s) - 1
	}
	return s[lo] + (s[hi]-s[lo])*(k-float64(lo))
}

func zeroOps() map[string]opResult {
	ops := make(map[string]opResult, len(opKeys))
	for _, k := range opKeys {
		ops[k] = opResult{}
	}
	return ops
}

func emit(status string, ops map[string]opResult, iterations, concurrency int, notes string) {
	out := output{
		Schema:           "axiam.sdk-bench/v1",
		SDK:              "go",
		SDKVersion:       "1.0.0-alpha2",
		LanguageRuntime:  runtime.Version(),
		Target:           env("BENCH_TARGET", "axiam"),
		Profile:          env("BENCH_PROFILE", "p0-plaintext"),
		Status:           status,
		Iterations:       iterations,
		Concurrency:      concurrency,
		Ops:              ops,
		ClientCPUMsTotal: 0,
		ClientRSSMiBPeak: 0,
		Notes:            notes,
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		// Should never happen for this fixed shape; fall back to a minimal
		// valid error record rather than crashing.
		fmt.Printf("{\"schema\":\"axiam.sdk-bench/v1\",\"sdk\":\"go\",\"status\":\"error\",\"notes\":%q}\n", err.Error())
		return
	}
	fmt.Println(string(b))
}

// opFn is a single zero-config invocation of an SDK operation. It returns an
// error on failure so timeOp can count it without recording a latency.
type opFn func(ctx context.Context) error

// buildOps constructs one logged-in Client shared by refresh/check_access/
// batch_check, and returns the per-op closures. login builds and discards its
// own short-lived client per call (a fresh, unauthenticated session per
// iteration mirrors what the op measures); the shared client's refresh is
// routed through the SDK's sync.Mutex single-flight guard, so concurrent
// callers are safe.
func buildOps(ctx context.Context, cfg config) (map[string]opFn, error) {
	opts := []axiam.Option{axiam.WithOrgSlug(cfg.orgSlug)}
	if cfg.caCertPath != "" {
		pem, err := os.ReadFile(cfg.caCertPath)
		if err != nil {
			return nil, fmt.Errorf("BENCH_CA_CERT=%q could not be read: %w", cfg.caCertPath, err)
		}
		opts = append(opts, axiam.WithCustomCA(pem))
	}
	// p3-mtls: present the client identity (CONTRACT.md §6.1). Appending to
	// the same `opts` slice both construction sites below already share means
	// the identity cannot drift between the shared client and the fresh one
	// `login` builds per iteration — a login client without it would fail the
	// handshake while the others succeeded.
	if (cfg.clientCertPath == "") != (cfg.clientKeyPath == "") {
		// The SDK validates this too (§6.1 rule 1), but failing here names the
		// env var the operator actually got wrong.
		return nil, fmt.Errorf(
			"BENCH_CLIENT_CERT=%q and BENCH_CLIENT_KEY=%q must be set together — mTLS needs both (CONTRACT.md §6.1 rule 1)",
			cfg.clientCertPath, cfg.clientKeyPath)
	}
	if cfg.clientCertPath != "" {
		certPEM, err := os.ReadFile(cfg.clientCertPath)
		if err != nil {
			return nil, fmt.Errorf("BENCH_CLIENT_CERT=%q could not be read: %w", cfg.clientCertPath, err)
		}
		keyPEM, err := os.ReadFile(cfg.clientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("BENCH_CLIENT_KEY=%q could not be read: %w", cfg.clientKeyPath, err)
		}
		opts = append(opts, axiam.WithClientCertificate(certPEM, keyPEM))
	}
	client, err := axiam.NewClient(cfg.baseURL, cfg.tenantSlug, opts...)
	if err != nil {
		return nil, err
	}
	if _, err := client.Login(ctx, cfg.username, cfg.password); err != nil {
		return nil, err
	}

	// Three checks, all against the SAME resource id (no -0/-1/-2 suffix).
	checks := make([]axiam.AccessCheck, 3)
	for i := range checks {
		checks[i] = axiam.AccessCheck{Action: cfg.action, ResourceID: cfg.resourceID}
	}

	// The `login` op builds and discards a client per iteration, and the SDK
	// exposes no Close(): buildHTTPClient CLONES whatever transport it is
	// given (so CloseIdleConnections on our copy would close an unused pool),
	// and each client therefore ends the iteration owning a live keep-alive
	// connection that nothing reaps until IdleConnTimeout (90s) expires.
	// Under p0 that merely wastes sockets, but under p2/p3 every one of them
	// is a held-open TLS session on a CPU-capped server: 2200 iterations at
	// concurrency 16 drove handshake latency past net/http's 10s
	// TLSHandshakeTimeout and produced a reproducible 224 `login` errors on
	// BOTH TLS profiles (0 at p0) — measured as failures of AXIAM rather than
	// of this harness.
	//
	// Login is a single request (login.go), so the connection can never be
	// reused anyway: disabling keep-alives makes it close with the response,
	// which is what "discard the client" is supposed to mean. This is the Go
	// equivalent of python's `fresh.close()` / the C bench's
	// axiam_client_free(). Transport.Clone preserves DisableKeepAlives, so it
	// survives the SDK's clone.
	loginTransport := http.DefaultTransport.(*http.Transport).Clone()
	loginTransport.DisableKeepAlives = true
	loginOpts := append(append([]axiam.Option{}, opts...),
		axiam.WithHTTPClient(&http.Client{Transport: loginTransport}))

	ops := map[string]opFn{
		"login": func(ctx context.Context) error {
			fresh, err := axiam.NewClient(cfg.baseURL, cfg.tenantSlug, loginOpts...)
			if err != nil {
				return err
			}
			_, err = fresh.Login(ctx, cfg.username, cfg.password)
			return err
		},
		"refresh": func(ctx context.Context) error {
			return client.Refresh(ctx)
		},
		"check_access": func(ctx context.Context) error {
			_, _, err := client.CheckAccess(ctx, cfg.action, cfg.resourceID)
			return err
		},
		"batch_check": func(ctx context.Context) error {
			_, err := client.BatchCheck(ctx, checks)
			return err
		},
	}
	return ops, nil
}

// timeOp runs warmup (uncounted) then iter measured invocations of fn across
// conc goroutines (worker pool), recording per-call latency in milliseconds.
func timeOp(ctx context.Context, fn opFn, iter, warmup, conc int) opResult {
	if conc < 1 {
		conc = 1
	}

	// Warm-up (serial, uncounted).
	var errs int64
	for i := 0; i < warmup; i++ {
		if err := fn(ctx); err != nil {
			if n := atomic.AddInt64(&errs, 1); n <= 3 {
				fmt.Fprintf(os.Stderr, "[go] op error #%d (warm-up): %v\n", n, err)
			}
		}
	}

	var (
		idx int64
		mu  sync.Mutex
		lat = make([]float64, 0, iter)
		wg  sync.WaitGroup
	)

	start := time.Now()
	worker := func() {
		defer wg.Done()
		for {
			i := atomic.AddInt64(&idx, 1)
			if i > int64(iter) {
				return
			}
			t0 := time.Now()
			if err := fn(ctx); err != nil {
				// Report the first few verbatim on stderr (run-all.sh files it
				// under results/sdk/<profile>/go.log). The JSON record only
				// carries a COUNT, and a bare "login: 224 errors" is not
				// actionable — the p2/p3 handshake-timeout regression this
				// guards against was invisible for exactly that reason.
				if n := atomic.AddInt64(&errs, 1); n <= 3 {
					fmt.Fprintf(os.Stderr, "[go] op error #%d: %v\n", n, err)
				}
				continue
			}
			ms := float64(time.Since(t0).Nanoseconds()) / 1e6
			mu.Lock()
			lat = append(lat, ms)
			mu.Unlock()
		}
	}
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go worker()
	}
	wg.Wait()
	secs := time.Since(start).Seconds()

	rps := 0.0
	if secs > 0 {
		rps = float64(len(lat)) / secs
	}
	return opResult{
		P50Ms:         pct(lat, 50),
		P95Ms:         pct(lat, 95),
		P99Ms:         pct(lat, 99),
		ThroughputRPS: rps,
		Errors:        int(errs),
	}
}

func main() {
	cfg := loadConfig()
	iter := envInt("SDK_BENCH_ITERATIONS", 2000)
	warmup := envInt("SDK_BENCH_WARMUP", 200)
	conc := envInt("SDK_BENCH_CONCURRENCY", 16)

	ctx := context.Background()

	ops, err := buildOps(ctx, cfg)
	if err != nil {
		// Server unreachable / seed missing / auth failed — nothing to time.
		emit("error", zeroOps(), 0, 0, fmt.Sprintf("server unreachable or setup failed: %v", err))
		os.Exit(0)
	}

	results := make(map[string]opResult, len(opKeys))
	for _, k := range opKeys {
		// refresh is single-flight-guarded by the SDK, so running it
		// concurrently would measure the guard, not the wire cost — run it
		// serially (concurrency 1). All other ops run at the configured
		// concurrency.
		opConc := conc
		if k == "refresh" {
			opConc = 1
		}
		results[k] = timeOp(ctx, ops[k], iter, warmup, opConc)
	}

	emit("ok", results, iter, conc, "")
}

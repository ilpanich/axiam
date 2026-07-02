package axiam

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/ilpanich/axiam/sdks/go/internal/refreshguard"
)

const (
	// defaultConnectRequestTimeout is applied to the built http.Client when
	// no WithTimeout option is supplied (CF-03; mirrors the Rust reference's
	// 30s default request timeout).
	defaultConnectRequestTimeout = 30 * time.Second
)

// orgIdentifier is the optional organization identifier a client may be
// constructed with (RESEARCH.md Pitfall 3 — the real login/refresh
// endpoints require an org_id/org_slug beyond CONTRACT.md §5's documented
// tenant-only minimum). Mutually exclusive slug/id form, last-call-wins.
type orgIdentifier struct {
	slug string
	id   *uuid.UUID
}

// clientConfig accumulates functional-option state before NewClient builds
// the final *Client (D-03).
type clientConfig struct {
	customCAPEM    []byte
	requestTimeout time.Duration
	baseHTTPClient *http.Client
	org            orgIdentifier
	logger         *slog.Logger
}

func defaultConfig() *clientConfig {
	return &clientConfig{
		requestTimeout: defaultConnectRequestTimeout,
	}
}

// Option configures a Client at construction time (D-03).
type Option func(*clientConfig)

// WithCustomCA adds a PEM-encoded CA certificate to the TLS verification
// chain (§6). This is the ONLY TLS-related escape hatch — there is no
// option anywhere in this SDK that disables or weakens certificate
// verification. Returns a construction-time error via NewClient if pem is
// not valid PEM.
func WithCustomCA(pem []byte) Option {
	return func(c *clientConfig) { c.customCAPEM = pem }
}

// WithTimeout overrides the default request timeout applied to the SDK's
// http.Client (CF-03; default 30s).
func WithTimeout(d time.Duration) Option {
	return func(c *clientConfig) { c.requestTimeout = d }
}

// WithHTTPClient supplies a base *http.Client whose Transport/Timeout the
// SDK adopts. D-09: the SDK ALWAYS re-applies its own cookiejar and TLS
// config over the supplied client afterward — an override can never
// silently drop the jar (breaking every post-login request) or bypass TLS
// verification.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *clientConfig) { c.baseHTTPClient = hc }
}

// WithOrgSlug sets the organization slug the real login/refresh endpoints
// require (RESEARCH.md Pitfall 3). Mutually exclusive with WithOrgID —
// last call wins.
func WithOrgSlug(slug string) Option {
	return func(c *clientConfig) { c.org = orgIdentifier{slug: slug} }
}

// WithOrgID sets the organization UUID the real login/refresh endpoints
// require (RESEARCH.md Pitfall 3). Mutually exclusive with WithOrgSlug —
// last call wins.
func WithOrgID(id uuid.UUID) Option {
	return func(c *clientConfig) { c.org = orgIdentifier{id: &id} }
}

// WithLogger supplies an injectable, redaction-aware logger (CF-02). OFF
// by default (nil logger — the SDK never logs unless a logger is
// supplied). The SDK never emits raw token values regardless of the
// logger's configured level (Sensitive redacts itself in any log call).
func WithLogger(logger *slog.Logger) Option {
	return func(c *clientConfig) { c.logger = logger }
}

// Client is the AXIAM SDK's REST entry point (CONTRACT.md §1-§10). See
// NewClient.
type Client struct {
	baseURL    *url.URL
	tenantSlug string
	org        orgIdentifier
	httpc      *http.Client
	logger     *slog.Logger
	// guard is swapped atomically: Logout() replaces it with a fresh Guard
	// while Login/VerifyMfa/Refresh Load() it concurrently. Using an
	// atomic.Pointer (rather than a plain field) prevents the data race
	// between Logout's reassignment and concurrent Refresh reads (CR-01).
	guard       atomic.Pointer[refreshguard.Guard]
	csrfMu      sync.Mutex
	csrfToken   string
	orgIDMu     sync.Mutex
	resolvedOrg *uuid.UUID
}

// NewClient constructs a Client. baseURL and tenantSlug are positional and
// required (D-03): an empty tenantSlug returns an *AuthError — AXIAM is
// multi-tenant and there is no default tenant, so this can never be a
// silent default (CONTRACT.md §5, SC#1).
//
// The returned Client always owns a per-instance cookiejar and a
// TLS-1.3-minimum transport; WithHTTPClient may override the
// Transport/timeout, but the SDK re-applies its own jar and TLS config
// over any supplied client afterward (D-09) so neither can be silently
// dropped or bypassed.
func NewClient(baseURL, tenantSlug string, opts ...Option) (*Client, error) {
	if tenantSlug == "" {
		return nil, &AuthError{Message: "tenantSlug is required — AXIAM is multi-tenant and there is no default tenant (CONTRACT.md §5)"}
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, &NetworkError{Message: fmt.Sprintf("invalid baseURL: %v", err)}
	}

	cfg := defaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	httpc, err := buildHTTPClient(cfg)
	if err != nil {
		return nil, err
	}

	c := &Client{
		baseURL:    parsed,
		tenantSlug: tenantSlug,
		org:        cfg.org,
		httpc:      httpc,
		logger:     cfg.logger,
	}
	c.guard.Store(&refreshguard.Guard{})
	return c, nil
}

// buildHTTPClient constructs the SDK's http.Client per D-09: if cfg
// supplies a base client, its Transport/Timeout are adopted, but the
// SDK's own cookiejar and TLS config are ALWAYS re-applied afterward so an
// override can never drop the jar or weaken TLS verification.
func buildHTTPClient(cfg *clientConfig) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13} // CLAUDE.md project-wide TLS 1.3 floor.

	if len(cfg.customCAPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.customCAPEM) {
			return nil, &NetworkError{Message: "invalid custom CA PEM"}
		}
		tlsConfig.RootCAs = pool
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, &NetworkError{Message: fmt.Sprintf("failed to construct cookie jar: %v", err)}
	}

	var httpc *http.Client
	if cfg.baseHTTPClient != nil {
		// Shallow-copy so we never mutate the caller's original client.
		clone := *cfg.baseHTTPClient
		httpc = &clone
	} else {
		httpc = &http.Client{}
	}

	// D-09: the SDK's own jar and TLS config ALWAYS win — re-applied here,
	// unconditionally, regardless of what the supplied client had set.
	httpc.Jar = jar

	transport, ok := httpc.Transport.(*http.Transport)
	if !ok || transport == nil {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	} else {
		transport = transport.Clone()
	}
	transport.TLSClientConfig = tlsConfig
	httpc.Transport = transport

	if cfg.requestTimeout > 0 {
		httpc.Timeout = cfg.requestTimeout
	}

	return httpc, nil
}

// httpClient returns the SDK's underlying *http.Client (package-internal —
// used by login.go/authz.go request builders and by tests asserting
// override safety).
func (c *Client) httpClient() *http.Client {
	return c.httpc
}

// stateChangingMethods lists the HTTP verbs that echo the captured
// X-CSRF-Token per §3 non-browser CSRF behavior.
var stateChangingMethods = map[string]bool{
	http.MethodPost:   true,
	http.MethodPut:    true,
	http.MethodPatch:  true,
	http.MethodDelete: true,
}

// decorateRequest sets X-Tenant-ID on every outgoing request (§5) and
// echoes the captured X-CSRF-Token on state-changing verbs (§3
// non-browser: capture-from-response-header, echo-on-request).
func (c *Client) decorateRequest(req *http.Request) {
	req.Header.Set("X-Tenant-ID", c.tenantSlug)
	if stateChangingMethods[strings.ToUpper(req.Method)] {
		if token := c.getCSRFToken(); token != "" {
			req.Header.Set("X-CSRF-Token", token)
		}
	}
}

// captureCSRFFromResponse stores a freshly observed X-CSRF-Token response
// header value (§3 non-browser CSRF capture).
func (c *Client) captureCSRFFromResponse(resp *http.Response) {
	if token := resp.Header.Get("X-CSRF-Token"); token != "" {
		c.csrfMu.Lock()
		c.csrfToken = token
		c.csrfMu.Unlock()
	}
}

func (c *Client) getCSRFToken() string {
	c.csrfMu.Lock()
	defer c.csrfMu.Unlock()
	return c.csrfToken
}

// doRequest decorates req with the tenant + CSRF headers, executes it
// against the SDK's http.Client (cookie jar + TLS 1.3 transport), and
// captures any X-CSRF-Token the response carries. This is the single
// choke point every REST call in login.go/authz.go routes through.
func (c *Client) doRequest(req *http.Request) (*http.Response, error) {
	c.decorateRequest(req)
	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, newNetworkError(fmt.Sprintf("request failed: %v", err), nil, err)
	}
	c.captureCSRFFromResponse(resp)
	return resp, nil
}

// setResolvedOrgID caches the organization UUID resolved from the access
// token's org_id claim after a successful login/refresh (RESEARCH.md
// Pitfall 3), so Refresh can supply it without requiring the caller to
// have configured WithOrgID/WithOrgSlug up front.
func (c *Client) setResolvedOrgID(id uuid.UUID) {
	c.orgIDMu.Lock()
	defer c.orgIDMu.Unlock()
	c.resolvedOrg = &id
}

// resolvedOrgID returns the organization UUID to use in a request body:
// the explicitly configured WithOrgID value if present, otherwise the
// value resolved from the access token's org_id claim after login, if
// any.
func (c *Client) resolvedOrgID() (uuid.UUID, bool) {
	if c.org.id != nil {
		return *c.org.id, true
	}
	c.orgIDMu.Lock()
	defer c.orgIDMu.Unlock()
	if c.resolvedOrg != nil {
		return *c.resolvedOrg, true
	}
	return uuid.UUID{}, false
}

// url joins path against the client's configured base URL.
func (c *Client) url(path string) string {
	u := *c.baseURL
	u.Path = strings.TrimRight(u.Path, "/") + "/" + strings.TrimLeft(path, "/")
	return u.String()
}

// newRequest builds an *http.Request against the client's base URL with a
// context, without decorating or sending it.
func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.url(path), body)
	if err != nil {
		return nil, &NetworkError{Message: fmt.Sprintf("failed to build request: %v", err)}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// logf writes a redaction-safe log line via the configured logger, if any
// (CF-02: OFF by default, never emits raw token values since any Sensitive
// argument redacts itself through fmt/slog's Stringer/LogValuer paths).
func (c *Client) logf(ctx context.Context, msg string, args ...any) {
	if c.logger == nil {
		return
	}
	c.logger.InfoContext(ctx, msg, args...)
}

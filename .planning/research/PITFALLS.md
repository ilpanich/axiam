# Pitfalls Research — IAM Hardening

> Generated: 2026-03-30

## 1. Cookie Auth Migration

### Pitfall: CSRF vulnerability after moving to cookies
**Risk:** HIGH
**Warning signs:** POST/PUT/DELETE endpoints work without CSRF token after migration
**Prevention:**
- Use `SameSite=Strict` on auth cookies — blocks cross-origin cookie sending entirely
- For federation callbacks (cross-origin by design): validate `state` parameter, use `SameSite=Lax` only on the specific federation cookie
- Implement double-submit cookie pattern as defense-in-depth
- Frontend must send CSRF token in `X-CSRF-Token` header for state-changing requests
**Phase:** Should be addressed in the cookie migration phase

### Pitfall: Refresh token race condition
**Risk:** MEDIUM
**Warning signs:** Multiple concurrent requests trigger multiple refresh attempts, causing token revocation cascades
**Prevention:**
- Frontend must queue requests during token refresh (single-flight pattern)
- Backend should accept the old access token for a short grace period (~5s) after refresh
- Use a refresh lock (mutex) in the frontend auth store
**Phase:** Cookie migration phase

### Pitfall: Cookie path scoping
**Risk:** MEDIUM
**Warning signs:** Auth cookies sent to unrelated paths, or not sent to API paths
**Prevention:**
- Set `Path=/` for access token cookie (needed by all API endpoints)
- Set `Path=/api/v1/auth/refresh` for refresh token cookie (only needed by refresh endpoint)
- Never include tokens in URL parameters
**Phase:** Cookie migration phase

### Pitfall: Logout incomplete with cookies
**Risk:** MEDIUM
**Warning signs:** User still authenticated after clicking logout
**Prevention:**
- Backend must clear cookies with `Set-Cookie: token=; Max-Age=0; Path=/`
- Backend must also invalidate the refresh token in the database
- Frontend must clear all local state AND call the logout endpoint
**Phase:** Cookie migration phase

## 2. RBAC Wiring

### Pitfall: Admin bootstrap chicken-and-egg
**Risk:** HIGH
**Warning signs:** System deployed but no way to create the first admin user
**Prevention:**
- Implement a bootstrap endpoint that works ONLY when zero admin users exist
- Or: first user created via migration/CLI gets admin role automatically
- Bootstrap endpoint must be disabled after first admin is created
- Add an environment variable `AXIAM_BOOTSTRAP_ADMIN_EMAIL` for initial setup
**Phase:** RBAC wiring phase

### Pitfall: Missing authorization on forgotten endpoints
**Risk:** CRITICAL
**Warning signs:** Some endpoints return data without authorization after wiring
**Prevention:**
- Default-deny middleware: ALL routes require authorization unless explicitly marked public
- Maintain an explicit allowlist of public endpoints (login, register, health, OIDC discovery, JWKS)
- Integration test that verifies every registered route has an authorization requirement
**Phase:** RBAC wiring phase

### Pitfall: Privilege escalation via self-service endpoints
**Risk:** HIGH
**Warning signs:** User can modify their own roles, or access other users' data via ID manipulation
**Prevention:**
- Self-service endpoints (profile, MFA) must check `caller_user_id == target_user_id`
- Role/permission assignment requires specific admin permissions
- Never trust user-supplied IDs for authorization decisions without verification
**Phase:** RBAC wiring phase

## 3. Federation Verification

### Pitfall: JWKS key confusion / algorithm confusion attack
**Risk:** CRITICAL
**Warning signs:** Federation accepts tokens signed with unexpected algorithm
**Prevention:**
- Always validate `alg` claim matches expected algorithm for the provider
- Never allow `none` algorithm
- Pin expected algorithms per federation config (e.g., RS256 for Google, EdDSA for custom)
- Use `jsonwebtoken`'s `Validation::set_required_spec_claims` to enforce required claims
**Phase:** Federation hardening phase

### Pitfall: JWKS caching without refresh
**Risk:** HIGH
**Warning signs:** Federation breaks when IdP rotates keys
**Prevention:**
- Cache JWKS with TTL (e.g., 1 hour)
- On verification failure with cached keys, refetch JWKS once and retry
- Don't refetch more than once per minute (prevents DoS via invalid tokens)
**Phase:** Federation hardening phase

### Pitfall: Clock skew in token validation
**Risk:** MEDIUM
**Warning signs:** Intermittent "token expired" errors from federation
**Prevention:**
- Allow 30-60 second clock skew in `exp`/`nbf`/`iat` validation
- `jsonwebtoken` supports `set_clock_skew_in_secs(60)` in validation
**Phase:** Federation hardening phase

### Pitfall: SAML replay attack
**Risk:** HIGH
**Warning signs:** SAML assertion accepted multiple times
**Prevention:**
- Track consumed SAML assertion IDs with TTL (assertion validity + skew)
- Reject duplicate assertion IDs
- Validate `NotOnOrAfter` and `NotBefore` conditions
**Phase:** Federation hardening phase

## 4. Email Delivery

### Pitfall: Email template injection
**Risk:** MEDIUM
**Warning signs:** User-controlled data (username, email) rendered unsanitized in HTML templates
**Prevention:**
- Handlebars auto-escapes HTML by default — verify this is not bypassed with triple-stash `{{{}}}`
- Never include user-controlled URLs in email without validation
- Password reset URLs must use server-generated tokens, not user-supplied values
**Phase:** Email wiring phase

### Pitfall: Token leakage in email URLs
**Risk:** HIGH
**Warning signs:** Reset tokens appear in email server logs, browser history, referrer headers
**Prevention:**
- Use short-lived, single-use tokens (already implemented)
- Reset page should immediately POST the token to consume it (don't keep in URL after load)
- Set `Referrer-Policy: no-referrer` on reset/verification pages
**Phase:** Email wiring phase

## 5. GDPR Compliance

### Pitfall: Audit log conflicts with right-to-erasure
**Risk:** HIGH
**Warning signs:** User deletion leaves PII in audit logs; or audit logs are deleted (breaking immutability)
**Prevention:**
- Pseudonymization: replace user PII in audit logs with `DELETED_USER_<hash>` on erasure
- Keep audit log entries (immutability preserved) but strip identifiable data
- Document this approach in privacy policy
**Phase:** GDPR phase

### Pitfall: Incomplete data export
**Risk:** MEDIUM
**Warning signs:** Data export misses some tables/entities where user data exists
**Prevention:**
- Enumerate ALL tables that contain user references: users, groups (membership), roles (assignments), audit_logs, certificates, federation_links, sessions, mfa_configs
- Integration test that creates a user with data in every table, exports, and verifies completeness
**Phase:** GDPR phase

## 6. CI Security Scanning

### Pitfall: cargo-audit false positives blocking CI
**Risk:** MEDIUM
**Warning signs:** CI breaks on advisory for a dependency with no fix available
**Prevention:**
- Use `cargo-deny` with an `advisories.ignore` list for known unfixable advisories
- Review and update the ignore list monthly
- Don't block CI on informational advisories — only on vulnerabilities with patches
**Phase:** CI hardening phase

## 7. K8s Security

### Pitfall: NetworkPolicy blocks legitimate traffic
**Risk:** MEDIUM
**Warning signs:** Services can't communicate after applying policies
**Prevention:**
- Start with monitoring mode (log but don't block)
- Apply policies incrementally: server→surrealdb, server→rabbitmq, ingress→frontend, ingress→server
- Test each policy in dev before production
**Phase:** Infrastructure hardening phase

### Pitfall: Secrets in environment variables visible in pod spec
**Risk:** HIGH
**Warning signs:** `kubectl get pod -o yaml` shows secrets in plaintext
**Prevention:**
- Use `secretKeyRef` in env vars (references K8s Secret, not inline value)
- Already partially done — verify ALL secrets use this pattern
- Consider sealed-secrets or external-secrets-operator for GitOps
**Phase:** Infrastructure hardening phase

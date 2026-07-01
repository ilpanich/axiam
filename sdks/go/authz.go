package axiam

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	checkPath      = "/api/v1/authz/check"
	batchCheckPath = "/api/v1/authz/check/batch"
)

// AccessCheck is a single access check request (CONTRACT.md §1). ResourceID
// is a string (server-side UUID) rather than a typed UUID so callers can
// pass either a UUID string or, in future, other resource-id encodings
// without a breaking type change; the server is the source of truth for
// validation.
type AccessCheck struct {
	Action     string `json:"action"`
	ResourceID string `json:"resource_id"`
	Scope      string `json:"scope,omitempty"`
}

// AccessResult is the outcome of a single access check (mirrors
// CheckAccessResponse).
type AccessResult struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

type batchCheckRequestBody struct {
	Checks []AccessCheck `json:"checks"`
}

type batchCheckResponseWire struct {
	Results []AccessResult `json:"results"`
}

// authzRetryMaxAttempts bounds CF-01's retry to read-only authz checks
// only (state-changing auth calls in login.go never retry).
const authzRetryMaxAttempts = 3

// CheckAccess performs POST /api/v1/authz/check (CONTRACT.md §1),
// evaluating a single authorization check for the given action/
// resourceID/scope. This is a read-only, idempotent operation eligible
// for CF-01's bounded retry on transient NetworkError.
func (c *Client) CheckAccess(ctx context.Context, action, resourceID string, scope ...string) (bool, string, error) {
	req := AccessCheck{Action: action, ResourceID: resourceID}
	if len(scope) > 0 {
		req.Scope = scope[0]
	}
	result, err := c.checkAccessWithRetry(ctx, req)
	if err != nil {
		return false, "", err
	}
	return result.Allowed, result.Reason, nil
}

// Can is an alias for CheckAccess targeting browser/UI scenarios
// (CONTRACT.md §1 note) — returns only the allowed boolean.
func (c *Client) Can(ctx context.Context, action, resourceID string, scope ...string) (bool, error) {
	allowed, _, err := c.CheckAccess(ctx, action, resourceID, scope...)
	return allowed, err
}

// BatchCheck performs POST /api/v1/authz/check/batch (CONTRACT.md §1),
// evaluating an ordered list of checks; results are returned in the same
// order as reqs. Eligible for CF-01's bounded retry (read-only).
func (c *Client) BatchCheck(ctx context.Context, reqs []AccessCheck) ([]AccessResult, error) {
	body := batchCheckRequestBody{Checks: reqs}

	var wire batchCheckResponseWire
	err := c.retryReadOnly(ctx, func(ctx context.Context) error {
		w, err := c.sendAuthzPost(ctx, batchCheckPath, body)
		if err != nil {
			return err
		}
		wire = w
		return nil
	})
	if err != nil {
		return nil, err
	}
	return wire.Results, nil
}

func (c *Client) checkAccessWithRetry(ctx context.Context, req AccessCheck) (AccessResult, error) {
	var result AccessResult
	err := c.retryReadOnly(ctx, func(ctx context.Context) error {
		resp, err := c.sendAuthzPostSingle(ctx, checkPath, req)
		if err != nil {
			return err
		}
		result = resp
		return nil
	})
	return result, err
}

// sendAuthzPostSingle POSTs body to path and decodes a single AccessResult.
func (c *Client) sendAuthzPostSingle(ctx context.Context, path string, body any) (AccessResult, error) {
	var result AccessResult
	if err := c.sendAuthzPostInto(ctx, path, body, &result); err != nil {
		return AccessResult{}, err
	}
	return result, nil
}

// sendAuthzPost POSTs body to path and decodes a batchCheckResponseWire.
func (c *Client) sendAuthzPost(ctx context.Context, path string, body any) (batchCheckResponseWire, error) {
	var wire batchCheckResponseWire
	if err := c.sendAuthzPostInto(ctx, path, body, &wire); err != nil {
		return batchCheckResponseWire{}, err
	}
	return wire, nil
}

// sendAuthzPostInto is the shared HTTP mechanics for the two authz POST
// endpoints: builds the request, decorates it (X-Tenant-ID + CSRF via
// doRequest), sends it, maps non-2xx per §2, and decodes the 2xx body into
// out.
func (c *Client) sendAuthzPostInto(ctx context.Context, path string, body any, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return &NetworkError{Message: fmt.Sprintf("failed to encode authz request: %v", err)}
	}

	req, err := c.newRequest(ctx, http.MethodPost, path, bytes.NewReader(payload))
	if err != nil {
		return err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return mapErrorResponse(resp)
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return deserErr(err)
	}
	return nil
}

// retryReadOnly runs op with CF-01's bounded exponential backoff, retrying
// ONLY on *NetworkError (transient/429/5xx) — AuthError/AuthzError are
// decisive, never retried. Read-only authz checks are the only operations
// in this SDK eligible for this treatment; Login/VerifyMfa/Refresh/Logout
// in login.go never retry.
func (c *Client) retryReadOnly(ctx context.Context, op func(ctx context.Context) error) error {
	var lastErr error
	backoff := 100 * time.Millisecond
	for attempt := 1; attempt <= authzRetryMaxAttempts; attempt++ {
		lastErr = op(ctx)
		if lastErr == nil {
			return nil
		}
		if _, retryable := lastErr.(*NetworkError); !retryable {
			return lastErr
		}
		if attempt == authzRetryMaxAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return lastErr
}

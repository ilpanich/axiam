"""Local JWKS fetch/cache/verification (D-16/CF-07).

Verifies AXIAM access tokens locally against the organization-wide EdDSA
JWKS, using PyJWT's :class:`~jwt.PyJWKClient`. Mirrors
``sdks/go/internal/jwks/verifier.go`` and ``sdks/rust/src/token/jwks.rs``.

Endpoint: ``GET {base_url}/oauth2/jwks`` — a single, organization-wide
endpoint serving exactly one Ed25519 key today. This is NOT a generic OIDC
discovery-style JWKS path, and it is NOT tenant-scoped.

Security-critical invariant (algorithm-confusion defense, D-16): the token's
``alg`` header is checked against an explicit EdDSA-only allowlist BEFORE any
keyset lookup — the token's own ``alg`` header never selects the
verification algorithm. ``jwt.decode`` is always called with an explicit single-element EdDSA
algorithm allowlist (never a wildcard/unset algorithms argument, and never an
alg inferred from the token itself).

``verify()`` does NOT check token expiry — it validates the signature (and
``sub`` presence) only. Callers (FastAPI dependency / Django middleware,
19-06) MUST independently compare the returned claims' ``exp`` against the
current time before trusting the result.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWTError

# The AXIAM JWKS endpoint path — organization-wide, not tenant-scoped
# (D-16). This is NOT a generic OIDC discovery-style `/.well-known/jwks.json`
# path; do not substitute one.
JWKS_PATH = "/oauth2/jwks"

# Normal (non-forced) cache TTL, matching the Rust/Go references'
# JWKS_CACHE_TTL / maxCacheInterval.
_DEFAULT_LIFESPAN_SECONDS = 300

# Minimum interval between forced refetches triggered by an unknown `kid`,
# to avoid a hostile/rotating-kid token stream hammering the JWKS endpoint
# (matches the Rust reference's FORCED_REFETCH_MIN_INTERVAL / Go's
# minRefetchInterval). PyJWKClient has no built-in rate limit for forced
# refetches, so it is implemented here at the wrapper level.
_FORCED_REFETCH_MIN_INTERVAL_SECONDS = 60


class JwksVerifier:
    """Fetches, caches, and locally verifies AXIAM access tokens against the
    organization-wide EdDSA JWKS."""

    def __init__(self, base_url: str, *, lifespan: int = _DEFAULT_LIFESPAN_SECONDS) -> None:
        jwks_url = base_url.rstrip("/") + JWKS_PATH
        # The per-key LRU cache (opt-in via a separate constructor flag,
        # intentionally left at its default/disabled state here) has no
        # TTL/expiration (Pattern 5 Pitfall); relying solely on the TTL'd
        # jwk_set_cache (cache_jwk_set=True) avoids serving a rotated/revoked
        # key indefinitely.
        self._client = PyJWKClient(jwks_url, cache_jwk_set=True, lifespan=lifespan)
        self._last_forced_refetch: float | None = None
        self._refetch_lock = threading.Lock()

    def verify(self, token: str) -> dict[str, Any]:
        """Verify ``token``'s EdDSA signature against the cached JWKS,
        returning the decoded claims dict. Does NOT check ``exp`` — that is
        the caller's responsibility.

        Rejects any token whose header ``alg`` is not ``EdDSA`` BEFORE any
        keyset lookup is attempted (algorithm-confusion defense).
        """
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "EdDSA":
            raise ValueError(f"unexpected alg {header.get('alg')!r}: only EdDSA is accepted")

        signing_key = self._get_signing_key(token)

        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["EdDSA"],
            options={"require": ["sub"]},
        )

    def _get_signing_key(self, token: str) -> Any:
        """Resolve the signing key for *token*, single-flighted through
        ``_refetch_lock`` so a burst of concurrent callers against a cold
        or stale cache — forced-refetch or not — collapses to exactly one
        network fetch (D-08/D-09, PERF-03).

        The lock spans the ENTIRE lookup-and-fetch sequence, not merely the
        "should-I-invalidate" decision (the pre-existing TOCTOU gap this
        closes): every waiter, once it acquires the lock, first retries
        against whatever a prior lock-holder may have already
        fetched/repaired before ever triggering another fetch itself.
        """
        with self._refetch_lock:
            try:
                return self._client.get_signing_key_from_jwt(token)
            except PyJWTError:
                # Unknown kid, a stale in-TTL cache after key rotation, or
                # an empty/malformed keyset response (e.g. a rotation
                # window where the new key has not yet propagated).
                # PyJWTError is the common base of both PyJWKClientError
                # (unknown kid) and PyJWKSetError (empty/invalid keyset) —
                # both failure modes warrant the same forced-refetch
                # response below.
                pass

            now = time.monotonic()
            if (
                self._last_forced_refetch is not None
                and now - self._last_forced_refetch < _FORCED_REFETCH_MIN_INTERVAL_SECONDS
            ):
                # Rate-limited: another caller already forced a refetch
                # recently (while we waited for the lock, or just before
                # us) — surface whatever the current cache yields rather
                # than hammering the endpoint again.
                return self._client.get_signing_key_from_jwt(token)

            # Force exactly one rate-limited refetch, then retry once. A
            # second failure propagates to the caller.
            self._client.jwk_set_cache = None
            self._last_forced_refetch = now
            return self._client.get_signing_key_from_jwt(token)

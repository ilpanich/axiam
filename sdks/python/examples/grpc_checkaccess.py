"""grpc_checkaccess.py demonstrates the gRPC authorization transport: both
the sync (AuthzGrpcClient, grpcio) and async (AsyncAuthzGrpcClient, grpc.aio)
clients performing check_access/batch_check over a strict-TLS channel
(CONTRACT.md §1, §6, §9, D-12).

A REST login first obtains the initial access token/tenant_id shared with
the gRPC transport below (§9 — the same single-flight refresh guard backs
both transports in a full integration; this example keeps the token cache
minimal and thread-safe on its own, matching the Go reference example).

This example is illustrative/compilable — it reads connection details from
environment variables and does not require a live AXIAM server to
byte-compile. Running it end-to-end requires a reachable AXIAM gRPC
endpoint.

Run: python examples/grpc_checkaccess.py
"""

from __future__ import annotations

import asyncio
import os
import threading

from axiam_sdk import AsyncAxiamClient, AuthError, AxiamClient
from axiam_sdk.grpc import AsyncAuthzGrpcClient, AuthzGrpcClient


def getenv(key: str, fallback: str) -> str:
    return os.environ.get(key, fallback)


class TokenCache:
    """Minimal thread-safe holder for the current access token, backing the
    gRPC interceptor's non-blocking token_fn (the interceptor MUST read this
    without blocking on the hot RPC path)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._token: str | None = None

    def set(self, token: str | None) -> None:
        with self._lock:
            self._token = token

    def get(self) -> str | None:
        with self._lock:
            return self._token


def sync_grpc_checkaccess() -> None:
    base_url = getenv("AXIAM_BASE_URL", "https://localhost:8443")
    grpc_target = getenv("AXIAM_GRPC_TARGET", "localhost:9443")
    tenant_slug = getenv("AXIAM_TENANT_SLUG", "acme")
    email = getenv("AXIAM_EMAIL", "user@example.com")
    password = getenv("AXIAM_PASSWORD", "changeme")
    resource_id = getenv("AXIAM_RESOURCE_ID", "00000000-0000-0000-0000-000000000000")
    subject_id = getenv("AXIAM_SUBJECT_ID", "00000000-0000-0000-0000-000000000000")
    tenant_id = getenv("AXIAM_TENANT_ID", "00000000-0000-0000-0000-000000000000")

    rest = AxiamClient(base_url=base_url, tenant_slug=tenant_slug)
    try:
        result = rest.login(email, password)
    except AuthError as exc:
        print(f"login failed: {exc}")
        return
    if result.mfa_required:
        print("MFA is required for this account — see examples/login_mfa.py first.")
        return

    cache = TokenCache()
    # The access token itself is Sensitive and never printed; a real
    # integration would seed the cache from the REST client's own session
    # (this example demonstrates wiring only).
    cache.set(os.environ.get("AXIAM_ACCESS_TOKEN"))

    def refresh_fn() -> None:
        rest.refresh()
        cache.set(os.environ.get("AXIAM_ACCESS_TOKEN"))

    # §6: strict TLS is always on (build_channel_credentials never builds an
    # insecure channel); no custom CA in this example (production callers
    # with a private CA would pass its PEM path here instead).
    authz = AuthzGrpcClient(
        grpc_target,
        token_fn=cache.get,
        tenant_id=tenant_id,
        refresh_fn=refresh_fn,
    )
    try:
        decision = authz.check_access(subject_id, "resource:read", resource_id)
        print(f"gRPC check_access -> allowed: {decision.allowed}, reason: {decision.reason!r}")

        # batch_check — results preserve input order (CONTRACT.md §1).
        batch = [
            (subject_id, "resource:read", resource_id, None),
            (subject_id, "resource:delete", resource_id, "admin"),
        ]
        results = authz.batch_check(batch)
        for i, r in enumerate(results):
            print(f"gRPC batch_check[{i}] -> allowed: {r.allowed}")
    finally:
        authz.close()
        rest.close()


async def async_grpc_checkaccess() -> None:
    base_url = getenv("AXIAM_BASE_URL", "https://localhost:8443")
    grpc_target = getenv("AXIAM_GRPC_TARGET", "localhost:9443")
    tenant_slug = getenv("AXIAM_TENANT_SLUG", "acme")
    email = getenv("AXIAM_EMAIL", "user@example.com")
    password = getenv("AXIAM_PASSWORD", "changeme")
    resource_id = getenv("AXIAM_RESOURCE_ID", "00000000-0000-0000-0000-000000000000")
    subject_id = getenv("AXIAM_SUBJECT_ID", "00000000-0000-0000-0000-000000000000")
    tenant_id = getenv("AXIAM_TENANT_ID", "00000000-0000-0000-0000-000000000000")

    # AsyncAxiamClient (SDK-Q08) is a dedicated async client — a separate
    # class from the sync AxiamClient above, not an `async_*`-prefixed twin.
    rest = AsyncAxiamClient(base_url=base_url, tenant_slug=tenant_slug)
    try:
        result = await rest.login(email, password)
    except AuthError as exc:
        print(f"async login failed: {exc}")
        return
    if result.mfa_required:
        print("MFA is required for this account — see examples/login_mfa.py first.")
        return

    cache = TokenCache()
    cache.set(os.environ.get("AXIAM_ACCESS_TOKEN"))

    async def async_refresh_fn() -> None:
        await rest.refresh()
        cache.set(os.environ.get("AXIAM_ACCESS_TOKEN"))

    # AsyncAuthzGrpcClient is a first-class async transport (D-12), not a
    # thread-pool bridge over the sync client.
    authz = AsyncAuthzGrpcClient(
        grpc_target,
        token_fn=cache.get,
        tenant_id=tenant_id,
        refresh_fn=async_refresh_fn,
    )
    try:
        decision = await authz.check_access(subject_id, "resource:read", resource_id)
        print(
            f"async gRPC check_access -> allowed: {decision.allowed}, reason: {decision.reason!r}"
        )

        batch = [
            (subject_id, "resource:read", resource_id, None),
            (subject_id, "resource:delete", resource_id, "admin"),
        ]
        results = await authz.batch_check(batch)
        for i, r in enumerate(results):
            print(f"async gRPC batch_check[{i}] -> allowed: {r.allowed}")
    finally:
        await authz.close()
        await rest.aclose()


if __name__ == "__main__":
    sync_grpc_checkaccess()
    asyncio.run(async_grpc_checkaccess())

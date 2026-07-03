"""gRPC transport package: sync (``grpcio``) + async (``grpc.aio``)
authorization clients for ``CheckAccess``/``BatchCheckAccess`` (D-12).
"""

from __future__ import annotations

from axiam_sdk.grpc.client import AsyncAuthzGrpcClient, AuthzGrpcClient

__all__ = ["AsyncAuthzGrpcClient", "AuthzGrpcClient"]

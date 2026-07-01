"""Strict-TLS gRPC channel credentials (CF-03/SC#3, T-19-12).

Mirrors ``sdks/go/grpc/tls.go``: builds channel credentials via
``grpc.ssl_channel_credentials`` — root certs from a caller-supplied custom
CA PEM when provided, else the system trust roots. This module never
constructs a plaintext/unencrypted channel anywhere in this package
(T-19-12; CI grep gate in 19-07). The only escape hatch is ``custom_ca`` (a
CA bundle PEM path), never a boolean bypass.
"""

from __future__ import annotations

import grpc
import grpc.aio


def build_channel_credentials(custom_ca: str | None = None) -> grpc.ChannelCredentials:
    """Build strict TLS channel credentials via ``grpc.ssl_channel_credentials``.

    When ``custom_ca`` is supplied, it is read as a PEM-encoded CA bundle
    file path and used as the root certificate for verification (mirrors
    the Go SDK's ``customCAPEM`` parameter). When omitted, ``grpc`` falls
    back to the system trust roots. Certificate verification is never
    disabled by this function — this is the ONLY TLS-related construction
    point the gRPC transport exposes (CONTRACT.md §6, SC#3 absolute
    prohibition).
    """
    root_certificates: bytes | None = None
    if custom_ca:
        with open(custom_ca, "rb") as f:
            root_certificates = f.read()

    return grpc.ssl_channel_credentials(root_certificates=root_certificates)

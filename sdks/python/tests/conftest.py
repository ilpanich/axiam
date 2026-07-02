"""Shared pytest fixtures for the axiam-sdk test suite.

These fixtures are consumed by this plan's ``test_amqp_hmac.py`` and by
later Phase 19 plans (REST/gRPC/JWKS/framework-integration tests).
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest


@pytest.fixture
def signing_key() -> bytes:
    """A fixed test AMQP HMAC signing key.

    Not the real signing key used to derive tests/fixtures/amqp_hmac_vectors.json
    (each fixture vector carries its own ``signing_key_hex``); this fixture is
    for tests that need an arbitrary, stable key (e.g. negative-path unit tests).
    """
    return b"axiam-sdk-test-signing-key"


@pytest.fixture
def respx_mock() -> Iterator[object]:
    """Placeholder respx mock-transport fixture.

    Populated with real route mocks by the REST-transport plan (19-02+) once
    ``AxiamClient`` exists. Kept here as a shared fixture location per
    19-RESEARCH.md's Recommended Project Structure so downstream plans do not
    need to re-create tests/conftest.py.
    """
    import respx

    with respx.mock(assert_all_called=False) as router:
        yield router


@pytest.fixture
def jwks_mock() -> None:
    """Placeholder JWKS-mock fixture.

    Populated with a real mocked ``/oauth2/jwks`` response by the JWKS/token
    plan (19-02+). Kept here as a shared fixture location per
    19-RESEARCH.md's Recommended Project Structure.
    """
    return None

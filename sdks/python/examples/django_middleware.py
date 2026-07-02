"""django_middleware.py demonstrates registering
axiam_sdk.django.middleware.AxiamAuthMiddleware in a Django settings/urls
snippet and reading request.axiam_user in a view (CONTRACT.md §10, D-10,
SC#4).

AxiamAuthMiddleware verifies the inbound session LOCALLY via a JWKS-backed
verifier (settings.AXIAM_JWKS_BASE_URL), enforces the configured-tenant
claim (settings.AXIAM_TENANT_SLUG), and attaches request.axiam_user on
success — or returns a standardized 401 JSON response before the view ever
runs. It declares sync_capable/async_capable so it works under WSGI
(primary target) or ASGI without Django forcing an unnecessary sync<->async
adaptation shim.

This example is illustrative/importable — it does not require a live AXIAM
server to byte-compile or import (SC#4). Serving real traffic requires the
configured AXIAM_JWKS_BASE_URL to be a reachable AXIAM server (for the
middleware's JWKS fetch).

This file is a runnable settings+urls+view snippet, not a full Django
project — wire it into a real project's settings.py/urls.py, or run it
standalone via `python examples/django_middleware.py` (uses
django.conf.settings.configure(...) so no manage.py/project scaffold is
required for illustration).
"""

from __future__ import annotations

import os

from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.urls import path


def getenv(key: str, fallback: str) -> str:
    return os.environ.get(key, fallback)


if not settings.configured:
    settings.configure(
        DEBUG=False,
        SECRET_KEY="example-only-not-for-production",  # noqa: S105
        ALLOWED_HOSTS=["*"],
        ROOT_URLCONF=__name__,
        MIDDLEWARE=[
            # Register AxiamAuthMiddleware to guard every request behind it
            # (D-10). It attaches request.axiam_user on success.
            "axiam_sdk.django.middleware.AxiamAuthMiddleware",
        ],
        # Settings AxiamAuthMiddleware reads at construction time (§10):
        AXIAM_JWKS_BASE_URL=getenv("AXIAM_BASE_URL", "https://localhost:8443"),
        AXIAM_TENANT_SLUG=getenv("AXIAM_TENANT_SLUG", "acme"),
    )


def protected_view(request: HttpRequest) -> JsonResponse:
    """A view guarded by AxiamAuthMiddleware — reaching this handler means
    the caller's token was verified locally and matched the configured
    tenant (T-19-19 cross-tenant replay defense)."""
    user = request.axiam_user  # type: ignore[attr-defined]
    return JsonResponse(
        {
            "message": f"Hello, user {user.user_id} (tenant {user.tenant_id})",
            "roles": user.roles,
        }
    )


urlpatterns = [
    path("protected", protected_view),
]


if __name__ == "__main__":
    import django
    from django.core.management import execute_from_command_line

    django.setup()
    execute_from_command_line(["manage.py", "runserver"])

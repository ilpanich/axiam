"""Shared REST session: one cookie jar, CSRF capture, tenant header
injection, lazily-built sync+async httpx clients (CF-01/CF-02/CF-03).

Mirrors ``sdks/go/client.go``'s ``decorateRequest``/``captureCSRFFromResponse``/
``doRequest`` choke-point pattern and
``sdks/typescript/src/rest/session.ts``'s shared-session shape, adapted to
Python's sync+async duality (D-01).

CRITICAL — cookie-jar sharing (Assumption A1, empirically verified against
the pinned httpx 0.27.2): passing the SAME httpx cookie-jar wrapper instance
to both ``httpx.Client(cookies=...)`` and ``httpx.AsyncClient(cookies=...)``
does NOT share the underlying jar — the wrapper class's constructor copies
an existing wrapper argument's entries into a brand-new
``http.cookiejar.CookieJar()`` (see httpx's ``_models.py``). The only way to
get genuine sharing is to construct a raw ``http.cookiejar.CookieJar()``
directly and pass THAT to both clients — the wrapper constructor takes a
raw ``CookieJar`` as-is (the ``else`` branch) instead of copying it. This
module therefore owns one ``http.cookiejar.CookieJar`` and passes it,
wrapped once in a single wrapper instance, to both clients' ``cookies=``
kwarg — see ``sync_client``/``async_client`` below.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any

import httpx

from axiam_sdk.token.refresh_guard import RefreshGuard

if TYPE_CHECKING:
    from http.cookiejar import CookieJar

# HTTP methods that echo the captured CSRF token per CONTRACT.md §3
# (non-browser: capture-from-response-header, echo-on-state-changing-request).
_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_DEFAULT_CONNECT_TIMEOUT = 10.0
_DEFAULT_READ_TIMEOUT = 30.0


class _Session:
    """Shared REST session state. Not part of the public API (PEP 8
    leading-underscore convention — see ``sdks/python/19-RESEARCH.md``
    Recommended Project Structure).

    Owns:
    - the single shared cookie jar (``http.cookiejar.CookieJar``), passed to
      BOTH the lazily-built sync ``httpx.Client`` and async
      ``httpx.AsyncClient`` (Assumption A1, see module docstring);
    - CSRF token capture/echo, guarded by a ``threading.Lock`` since it is
      touched from both the sync and async request-issuing code paths;
    - the ``RefreshGuard`` (from 19-02) — a single instance shared by both
      the sync and async call paths on this session;
    - TLS config: ``verify=True`` hardcoded unless ``custom_ca`` is
      supplied — NEVER ``False`` (CF-03/SC#3). There is no parameter on this
      class, or on ``AxiamClient``, that could carry a boolean TLS bypass.
    """

    def __init__(
        self,
        base_url: str,
        tenant_slug: str,
        *,
        custom_ca: str | None = None,
        timeout: httpx.Timeout | None = None,
        logger: Any = None,
    ) -> None:
        """Build the session state shared by the lazily-constructed sync and
        async httpx clients.

        Args:
            base_url: The AXIAM server's base URL; also used to derive
                ``_base_host`` for the same-origin header-injection guard in
                :meth:`_prepare_request`.
            tenant_slug: Injected as ``X-Tenant-ID`` on every same-origin
                request (CONTRACT.md §5).
            custom_ca: The sole TLS-bypass escape hatch (§6) — a PEM CA
                bundle path/string, or ``None`` for strict default
                verification. Never a boolean.
            timeout: Overrides the default httpx connect/read/write/pool
                timeouts when supplied.
            logger: An injectable logger (D-15); stored as-is, not wrapped.
        """
        self.base_url = base_url
        # Host of our own origin — used to gate tenant/CSRF header injection
        # so those secrets never travel to a different host (defense in depth
        # against a cross-origin request or a followed redirect).
        self._base_host = httpx.URL(base_url).host
        self.tenant_slug = tenant_slug
        self._timeout = timeout or httpx.Timeout(
            connect=_DEFAULT_CONNECT_TIMEOUT,
            read=_DEFAULT_READ_TIMEOUT,
            write=_DEFAULT_READ_TIMEOUT,
            pool=_DEFAULT_CONNECT_TIMEOUT,
        )
        # SC#3/CF-03: the ONLY TLS escape hatch is a custom-CA path/bundle —
        # never a boolean. `custom_ca` is either None (-> True, strict
        # verification) or a CA bundle path/SSLContext httpx accepts
        # directly. A boolean value is never assigned here.
        self._verify: bool | str = custom_ca if custom_ca else True

        # Assumption A1: share ONE raw http.cookiejar.CookieJar between both
        # clients by wrapping it in exactly one cookie-jar wrapper instance
        # and handing that same instance's `.jar` to both — see module
        # docstring for why constructing a fresh wrapper per client does
        # NOT share state.
        self._cookies = httpx.Cookies()

        self._csrf_token: str | None = None
        self._csrf_lock = threading.Lock()

        self._sync_client: httpx.Client | None = None
        self._async_client: httpx.AsyncClient | None = None

        # Shared single-flight refresh guard (19-02) — one instance for
        # both the sync and async REST call paths on this session.
        self.refresh_guard = RefreshGuard()

        self._logger = logger

    @property
    def sync_client(self) -> httpx.Client:
        """Lazily-built sync httpx client — constructed on first use, not
        in ``__init__`` (avoids opening a sync connection pool a purely
        async caller never needs)."""
        if self._sync_client is None:
            self._sync_client = httpx.Client(
                base_url=self.base_url,
                cookies=self._shared_jar(),
                timeout=self._timeout,
                verify=self._verify,
            )
        return self._sync_client

    @property
    def async_client(self) -> httpx.AsyncClient:
        """Lazily-built async httpx client — constructed on first use, not
        in ``__init__``."""
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(
                base_url=self.base_url,
                cookies=self._shared_jar(),
                timeout=self._timeout,
                verify=self._verify,
            )
        return self._async_client

    def _shared_jar(self) -> CookieJar:
        """Return the single raw ``http.cookiejar.CookieJar`` backing this
        session's cookie-jar wrapper (Assumption A1). Handing this raw jar
        to ``httpx.Client(cookies=...)``/``httpx.AsyncClient`` makes both
        clients wrap the SAME jar object (the wrapper constructor takes a
        raw ``CookieJar`` as-is instead of copying it), so a cookie set via
        one paradigm is visible via the other."""
        return self._cookies.jar

    def _prepare_request(self, request: httpx.Request) -> None:
        """Single choke-point request decorator (mirrors Go's
        ``decorateRequest``): sets ``X-Tenant-ID`` on every request and
        echoes the captured CSRF token on state-changing methods.

        Defense in depth: if the request targets a host other than this
        session's own origin (e.g. a request built against an absolute
        third-party URL, or a followed redirect), skip injection so the
        tenant identifier and CSRF token are never leaked cross-origin. A
        relative/host-less request (the normal case, merged against
        ``base_url``) is treated as same-origin and decorated as before."""
        req_host = request.url.host
        if req_host and req_host != self._base_host:
            return
        request.headers["X-Tenant-ID"] = self.tenant_slug
        if request.method.upper() in _STATE_CHANGING_METHODS:
            token = self._get_csrf_token()
            if token:
                request.headers["X-CSRF-Token"] = token

    def _capture_csrf(self, response: httpx.Response) -> None:
        """Capture a freshly observed ``X-CSRF-Token`` response header
        value (CONTRACT.md §3 non-browser CSRF capture), guarded by a lock
        since this is called from both sync and async request paths."""
        token = response.headers.get("X-CSRF-Token")
        if token:
            with self._csrf_lock:
                self._csrf_token = token

    def _get_csrf_token(self) -> str | None:
        """Read the most recently captured CSRF token, if any, guarded by
        the same lock as :meth:`_capture_csrf` (called from both sync and
        async request paths). Returns ``None`` before any response has set
        the ``X-CSRF-Token`` header."""
        with self._csrf_lock:
            return self._csrf_token

    def _send_sync(self, request: httpx.Request) -> httpx.Response:
        """Single choke point for every sync REST call (mirrors Go's
        ``doRequest``): decorate -> send -> capture CSRF."""
        self._prepare_request(request)
        response = self.sync_client.send(request)
        self._capture_csrf(response)
        return response

    async def _send_async(self, request: httpx.Request) -> httpx.Response:
        """Async twin of :meth:`_send_sync`."""
        self._prepare_request(request)
        response = await self.async_client.send(request)
        self._capture_csrf(response)
        return response

    def cookie_value(self, name: str) -> str | None:
        """Read a named cookie's current value out of the shared jar.

        The server sets ``axiam_refresh`` (and, on a refresh response, a
        fresh ``axiam_access``) Path-scoped to ``/api/v1/auth/refresh``
        (Pitfall 4) while the initial login sets ``axiam_access`` at
        ``Path=/`` — the jar can therefore legitimately hold two distinct
        cookie entries with the same name at different paths, which
        ``httpx.Cookies.get()`` rejects as ambiguous (``CookieConflict``).
        Disambiguate by preferring the entry with the MOST SPECIFIC
        (longest) path, since that is always the one the most recent
        request/response actually targeted.
        """
        matches = [cookie for cookie in self._cookies.jar if cookie.name == name]
        if not matches:
            return None
        best = max(matches, key=lambda cookie: len(cookie.path or ""))
        return best.value

    def close(self) -> None:
        """Close the sync httpx client, if constructed (D-19). Never
        constructs a client merely to close it."""
        if self._sync_client is not None:
            self._sync_client.close()

    async def aclose(self) -> None:
        """Close the async httpx client, if constructed (D-19). Never
        constructs a client merely to close it."""
        if self._async_client is not None:
            await self._async_client.aclose()

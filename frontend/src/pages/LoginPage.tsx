import { useEffect, useState, useRef } from "react";
import { useNavigate, Link, useSearchParams } from "react-router";
import { useAuthStore } from "@/stores/auth";
import {
  webauthnService,
  isWebauthnSupported,
  isConditionalMediationAvailable,
  classifyWebauthnError,
  type WebauthnFailure,
} from "@/services/webauthn";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PublicLayout } from "@/components/layout/PublicLayout";
import { cn } from "@/lib/utils";
import api from "@/lib/api";
import {
  fetchCurrentUser,
  withReachableTenantSelected,
} from "@/lib/fetchCurrentUser";
import { KeyRound, ChevronRight, Loader2, AlertCircle, Fingerprint } from "lucide-react";
import { getApiErrorCode, getApiErrorMessage, getApiErrorStatus } from "@/lib/apiError";
import { sanitizeReturnTo } from "@/lib/returnTo";
import {
  ACR_MULTI_FACTOR,
  clearReauthAttempts,
  recordReauthAttempt,
  sanitizeRequiredAcr,
} from "@/lib/reauth";
import {
  type MessageKey,
  format,
  layoutClassFor,
  resolveLocale,
  sanitizeDisplay,
  sanitizeLoginHint,
  useMessages,
} from "@/i18n";
import {
  OpaqueExchangeFailedError,
  OpaqueNotOfferedError,
  loginOpaque,
} from "@/services/opaque";
import {
  rememberPendingSso,
  ssoCallbackUrl,
  ssoLoginService,
  submitSamlAuthnRequest,
  type PublicFederationProvider,
} from "@/services/ssoLogin";
import { ProviderSignInButton } from "@/components/providers/ProviderSignInButton";

type LoginStep = "org-tenant" | "credentials" | "mfa";

/**
 * W5 — each WebAuthn failure kind's message key.
 *
 * `@/services/webauthn` keeps its own English-only `webauthnErrorMessage` for
 * the admin console, which `ui_locales` cannot reach and this wave does not
 * translate. The sign-in page maps the classified kind here instead, so the
 * five messages are translated without dragging the console's whole string
 * inventory into scope.
 *
 * `Record<WebauthnFailure, MessageKey>` is total by type: a sixth failure kind
 * added to the service does not compile until it has a message here, which is
 * the property that keeps this map from silently going stale.
 */
const WEBAUTHN_MESSAGE_KEY: Record<WebauthnFailure, MessageKey> = {
  cancelled: "webauthnCancelled",
  "already-registered": "webauthnAlreadyRegistered",
  timeout: "webauthnTimeout",
  unsupported: "webauthnUnsupported",
  unknown: "webauthnUnknown",
};

interface OrgTenantData {
  orgSlug: string;
  tenantSlug: string;
}

interface LoginResponse {
  user?: {
    id: string;
    username: string;
    email: string;
    tenant_id: string;
  };
  session_id?: string;
  expires_in?: number;
  mfa_required?: boolean;
  challenge_token?: string;
  available_methods?: string[];
  mfa_setup_required?: boolean;
  setup_token?: string;
}

export function LoginPage() {
  const navigate = useNavigate();
  const { setUser, setTenantContext } = useAuthStore();
  const [searchParams, setSearchParams] = useSearchParams();

  // W5 — the presentation `/oauth2/authorize` asked for
  // (claude_dev/basic-op-gap-plan.md §4.5/§4.6).
  //
  // All three are read once from the initial URL, like `return_to`, and all
  // three are deliberately **not** stripped by the effect below: a user who
  // reloads this page mid-typing must not have it switch back to English,
  // shed its layout, or lose the username that was filled in for them.
  //
  // Each is sanitised here even though the server already allow-listed it.
  // Nothing stops someone handing a victim a `/login?ui_locale=…` of their
  // own, so these checks are the ones that have to hold on their own — the
  // same argument `sanitizeReturnTo` and `sanitizeRequiredAcr` make.
  const [locale] = useState(() => resolveLocale(searchParams.get("ui_locale")));
  const [displayMode] = useState(() =>
    sanitizeDisplay(searchParams.get("display")),
  );
  // The one value with no closed set: it is whatever identifier the relying
  // party believes this person types. It reaches the DOM through React value
  // binding and nowhere else — never `dangerouslySetInnerHTML`, never an
  // attribute built by string concatenation — which is what makes T5.2 a
  // property of how the field is written rather than of an escape somebody
  // remembered.
  const [loginHint] = useState(() =>
    sanitizeLoginHint(searchParams.get("login_hint")),
  );
  const m = useMessages(locale);

  // Derive the notice once from the initial URL so it survives stripping the
  // query param below (lazy initializer — no setState in an effect).
  const [bootstrapNotice] = useState<boolean>(
    () => searchParams.get("bootstrapped") === "1"
  );

  // W3 — the OpenID Connect login hop (claude_dev/basic-op-gap-plan.md §4.0).
  //
  // `/oauth2/authorize` sends an anonymous browser here on behalf of a client
  // registered `browser_sso`, with `?return_to=<path>` naming the authorization
  // request to resume. Both values are read once, from the URL this page was
  // loaded with, because the effect below rewrites the query string.
  //
  // `sanitizeReturnTo` is the second of the two checks the plan requires: the
  // server validated the value when it built it, and this page validates it
  // again before it will navigate. Nothing stops someone handing a victim a
  // `/login?return_to=…` of their own, so this check is the one that has to
  // hold on its own — see `@/lib/returnTo` for the rules and why they are the
  // same four the server applies.
  const [returnTo] = useState<string | null>(() =>
    sanitizeReturnTo(searchParams.get("return_to"))
  );
  // `reauth=1` says this browser arrived believing it was signed in and was
  // not — it presented an `axiam_op_session` cookie that resolved to no live
  // session. Trusting whatever is left in the store would be how a hop becomes
  // a loop, so the leftovers are cleared and the user is told why they are
  // being asked again.
  const [reauthRequested] = useState<boolean>(
    () => searchParams.get("reauth") === "1"
  );
  const [reauthNotice, setReauthNotice] = useState<string | null>(null);
  // W4 — the one factor this sign-in has to demand, when the authorization
  // endpoint asked for a step-up (`?acr=…`). Allow-listed to the two values
  // AXIAM defines: this page never chooses an authentication context class and
  // never reports one — the server derives the class from what the session
  // actually proves — so anything else is dropped rather than displayed.
  const [requiredAcr] = useState(() =>
    sanitizeRequiredAcr(searchParams.get("acr"))
  );
  // W4 (T1.6) — the loop guard. `null` until the check below runs; a string is
  // the message shown *instead* of the form.
  const [loopBlocked, setLoopBlocked] = useState<string | null>(null);

  useEffect(() => {
    if (
      searchParams.get("bootstrapped") === "1" ||
      searchParams.get("org") ||
      searchParams.get("tenant") ||
      searchParams.get("reauth") ||
      searchParams.get("acr")
    ) {
      // Strip the query params so a refresh doesn't re-show the notice or
      // re-seed the workspace fields.
      //
      // `reauth` joins them: it has been acted on by the effect below, and a
      // refresh that re-ran it would sign the user out again mid-typing.
      // `return_to` deliberately does NOT — a user who reloads this page must
      // still land back on the authorization request they came from, and the
      // value is re-validated on every read anyway.
      const next = new URLSearchParams(searchParams);
      next.delete("bootstrapped");
      next.delete("org");
      next.delete("tenant");
      next.delete("reauth");
      next.delete("acr");
      setSearchParams(next, { replace: true });
    }
  }, [searchParams, setSearchParams]);

  // W3 — `reauth` mode. End whatever session this browser still holds before
  // showing the form, so that what follows is a real authentication event:
  // a new session row with a new `authenticated_at`, which is the field a
  // later wave's `max_age` and `prompt=login` are worth anything only if it
  // moves. Best-effort by design — the session may already be gone, which is
  // the very condition that produced `reauth=1` — and it clears the local
  // store either way.
  useEffect(() => {
    if (!reauthRequested) return;

    // W4 (T1.6) — the loop guard, before anything else this effect does. A
    // relying party that answers `login_required` by restarting the
    // authorization request produces a fresh, individually well-behaved chain
    // every time; from here that is an unbroken sequence of sign-in forms, and
    // after three in a minute the honest answer is to stop. See `@/lib/reauth`.
    if (returnTo && !recordReauthAttempt(returnTo)) {
      setLoopBlocked(m.loopBlocked);
      return;
    }

    setReauthNotice(
      requiredAcr === ACR_MULTI_FACTOR ? m.reauthNoticeMfa : m.reauthNotice
    );
    void (async () => {
      try {
        await api.post("/api/v1/auth/logout");
      } catch {
        // An already-dead session answers 401. Nothing to recover: the point
        // was to leave this browser signed out, and it is.
      }
      useAuthStore.getState().clearAuth();
    })();
    // Runs once: `reauthRequested` is captured from the initial URL and never
    // changes for the life of the page.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // After bootstrap, /login?bootstrapped=1&org=…&tenant=… pre-fills the
  // workspace and jumps straight to the credentials step. Lazy initializers
  // read the initial URL once (no setState in an effect).
  const [step, setStep] = useState<LoginStep>(() =>
    searchParams.get("org") || searchParams.get("tenant")
      ? "credentials"
      : "org-tenant"
  );
  const [orgTenantData, setOrgTenantData] = useState<OrgTenantData>(() => ({
    orgSlug: searchParams.get("org") ?? "",
    tenantSlug: searchParams.get("tenant") ?? "",
  }));
  // W5 (plan §4.5) — the relying party's `login_hint`, pre-filled. Seeded once
  // as the field's initial value rather than forced on every render, so the
  // first keystroke replaces it: a hint is a guess about who is at the
  // keyboard, and a field the user cannot correct would be a worse guess.
  const [username, setUsername] = useState(() => loginHint ?? "");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [mfaChallengeToken, setMfaChallengeToken] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // C2: passkey sign-in. `passkeySupported` gates the button entirely --
  // offering a control that can only fail is worse than not offering it.
  const [passkeySupported] = useState(() => isWebauthnSupported());
  const [passkeyBusy, setPasskeyBusy] = useState(false);
  // Whether the server's MFA challenge says this user actually has a WebAuthn
  // credential. Without it the second-factor step must not offer passkey.
  const [mfaMethods, setMfaMethods] = useState<string[]>([]);
  // Guards the conditional-mediation ceremony so it is started at most once
  // per mount; a second concurrent request aborts the first in every browser.
  const conditionalStarted = useRef(false);

  // ─── Federated sign-in ────────────────────────────────────────────────────
  //
  // The provider list cannot load on mount: which providers exist depends on
  // the organization, and the page does not know it until the user types it.
  // So it is fetched when the workspace step is submitted. `null` means "not
  // asked yet" and renders nothing at all — an empty "no providers" state
  // before we have asked would be a claim we cannot support.
  const [providers, setProviders] = useState<PublicFederationProvider[] | null>(
    null,
  );
  const [providersLoading, setProvidersLoading] = useState(false);
  const [ssoBusyId, setSsoBusyId] = useState<string | null>(null);

  /**
   * Shared tail of every successful sign-in, whatever proved the identity.
   *
   * Password, TOTP and passkey all converge here on purpose: the session
   * cookie and CSRF rotation are set by the server response, so the only
   * client-side work left is hydrating the store. Duplicating it per method is
   * how one of them ends up skipping `/auth/me` and running with an empty
   * permissions array.
   */
  const completeSignIn = async () => {
    const hydrated = await fetchCurrentUser();
    if (!hydrated) {
      setError(m.authenticationError);
      navigate("/login");
      return;
    }
    // A tenant-restricted organization principal holds nothing in the
    // organization's own scope, so it is placed in one of the tenants it does
    // reach before the store is populated. No-op for everyone else.
    setUser(await withReachableTenantSelected(hydrated));
    setTenantContext(orgTenantData.tenantSlug, orgTenantData.orgSlug);

    // W3 — resume the authorization request this sign-in was for, if there was
    // one. `location.assign` rather than `navigate`, because the destination is
    // a server endpoint and not a route in this application: the browser has to
    // make a real request to `/oauth2/authorize`, carrying the
    // `axiam_op_session` cookie the login response just set.
    //
    // Re-validated here rather than trusted from the state above. It is one
    // call and it means the value cannot have been anything else at any point
    // between the two.
    const resume = sanitizeReturnTo(returnTo);
    if (resume) {
      // W4 — this hop is over. Forgetting its attempts here is what keeps a
      // user who signs in slowly from looking like a loop; the counter exists
      // for a destination that keeps *coming back*, not for one that took a
      // while.
      clearReauthAttempts(resume);
      window.location.assign(resume);
      return;
    }
    navigate("/dashboard");
  };

  /**
   * Shared wrapper around a passkey ceremony.
   *
   * `conditional` selects passkey autofill (the browser surfaces saved
   * passkeys from the username field). In that mode the promise may never
   * settle -- the user simply may not pick one -- so failures are swallowed
   * rather than shown: an error banner for a prompt the user never engaged
   * with would be noise on a page they are still typing into.
   */
  const runPasskey = async (
    ceremony: () => Promise<unknown>,
    conditional = false,
  ) => {
    if (!conditional) {
      setPasskeyBusy(true);
      setError(null);
    }
    try {
      await ceremony();
      await completeSignIn();
    } catch (err) {
      if (!conditional) {
        setError(m[WEBAUTHN_MESSAGE_KEY[classifyWebauthnError(err)]]);
      }
    } finally {
      if (!conditional) setPasskeyBusy(false);
    }
  };

  /** Passkey as a *second factor*, against an MFA challenge token. */
  const runMfaPasskey = (challengeToken: string) =>
    runPasskey(() => webauthnService.authenticate(challengeToken));

  /**
   * Sign in with a passkey without typing a username first.
   *
   * The server issues a challenge with an empty `allowCredentials`, so the
   * authenticator offers whichever discoverable credential it holds for this
   * relying party and the assertion itself identifies the user.
   *
   * The workspace still has to be named, because a discoverable credential is
   * resolved within one tenant -- which is why this is reachable only from the
   * credentials step, after the org/tenant step has collected it.
   */
  const runDiscoverablePasskey = (conditional = false) =>
    runPasskey(
      () =>
        webauthnService.authenticateDiscoverable(
          orgTenantData.orgSlug,
          orgTenantData.tenantSlug,
          { conditional },
        ),
      conditional,
    );

  const handleDiscoverablePasskey = () => runDiscoverablePasskey();

  /**
   * C2: conditional mediation ("passkey autofill") -- the browser offers saved
   * passkeys inside the username field rather than behind a button.
   *
   * Started once per mount, on the credentials step only, and only where the
   * browser actually advertises support. Everything about it degrades quietly:
   * a browser without conditional mediation simply keeps the explicit button,
   * and a user who ignores the autofill entry never sees an error, because the
   * ceremony they never engaged with is not a failure worth reporting.
   */
  useEffect(() => {
    if (step !== "credentials" || !passkeySupported || conditionalStarted.current) {
      return;
    }
    let cancelled = false;
    void (async () => {
      if (!(await isConditionalMediationAvailable()) || cancelled) return;
      conditionalStarted.current = true;
      await runDiscoverablePasskey(true);
    })();
    return () => {
      cancelled = true;
    };
    // `runDiscoverablePasskey` closes over navigation state and the workspace
    // slugs, neither of which changes within a step, and re-running this effect
    // would start a second ceremony that aborts the first.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step, passkeySupported]);

  /**
   * Fetch the sign-in buttons for a workspace.
   *
   * Failures are swallowed on purpose. The providers endpoint answers 200 with
   * an empty list for an unknown organization, so the only way here is a
   * network or server fault — and an error banner about federation on a page
   * whose password form still works would send the user looking in the wrong
   * place. The buttons simply do not appear.
   */
  const loadProviders = async (orgSlug: string, tenantSlug: string) => {
    setProvidersLoading(true);
    try {
      setProviders(
        await ssoLoginService.listProviders(
          orgSlug.trim(),
          tenantSlug.trim() || undefined,
        ),
      );
    } catch {
      setProviders([]);
    } finally {
      setProvidersLoading(false);
    }
  };

  /**
   * Start a federated login.
   *
   * Three protocols, three shapes. OIDC and OAuth2 return a URL to navigate to;
   * SAML returns a POST-binding payload the browser has to submit as a form,
   * because that is what the binding is.
   *
   * Nothing is stored client-side beyond which completion endpoint to use when
   * the browser comes back: the `state` round-trips through the provider, and
   * the nonce and PKCE verifier never leave the server.
   */
  const handleSsoSelect = async (provider: PublicFederationProvider) => {
    setError(null);
    setSsoBusyId(provider.id);
    const body = {
      org_slug: orgTenantData.orgSlug.trim(),
      ...(orgTenantData.tenantSlug.trim()
        ? { tenant_slug: orgTenantData.tenantSlug.trim() }
        : {}),
      federation_config_id: provider.id,
      redirect_uri: ssoCallbackUrl(),
    };
    rememberPendingSso({
      protocol: provider.protocol,
      displayName: provider.display_name,
    });
    try {
      if (provider.protocol === "Saml") {
        submitSamlAuthnRequest(await ssoLoginService.startSaml(body));
        return;
      }
      const start =
        provider.protocol === "OAuth2"
          ? await ssoLoginService.startOauth2(body)
          : await ssoLoginService.startOidc(body);
      window.location.assign(start.authorize_url);
    } catch (err) {
      setSsoBusyId(null);
      setError(
        getApiErrorMessage(
          err,
          format(m.ssoStartFailed, { provider: provider.display_name }),
        ),
      );
    }
  };

  const handleOrgTenantSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    // The tenant is optional now: omitting it signs in at organization level,
    // which is where organization-level principals live. A tenant user who
    // omits it is simply not found there, and gets the same generic failure as
    // a wrong password — so the field can be blank without the form having to
    // know which kind of user is typing into it.
    if (!orgTenantData.orgSlug.trim()) {
      setError(m.orgSlugRequired);
      return;
    }
    // Fire-and-forget: the credentials step renders immediately and the
    // buttons appear when the answer arrives. Blocking the step transition on
    // a network call would make every password login wait for federation.
    void loadProviders(orgTenantData.orgSlug, orgTenantData.tenantSlug);
    setStep("credentials");
  };

  const handleCredentialsSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!username.trim() || !password.trim()) {
      setError(m.credentialsRequired);
      return;
    }

    setIsLoading(true);
    try {
      // Try OPAQUE first, fall back to password login when the tenant does not
      // offer it. This order is what makes OPAQUE actually get used: the
      // reverse — password first, OPAQUE only when refused — would mean a
      // tenant on `opaque_mode: optional` never sees a single OPAQUE login from
      // the browser, which is the mode operators run during a migration.
      //
      // The probe is not cached. One extra 404 per sign-in attempt is nothing
      // (people log in rarely), and caching it would add both a staleness bug
      // when an operator enables OPAQUE and a place for an attacker to force a
      // downgrade.
      //
      // Note what is absent compared to the SRP version this replaces: a
      // server-proof mismatch branch. SRP needed one because the client had to
      // check `M2` itself, and an endpoint that failed the check had to be
      // refused *without* retrying over the password path — otherwise the
      // fallback handed that same endpoint the plaintext. RFC 9807's AKE
      // authenticates the server during the handshake, so that failure mode
      // and the branch guarding it are both gone.
      let data: LoginResponse;
      try {
        const outcome = await loginOpaque({
          usernameOrEmail: username,
          password,
          orgSlug: orgTenantData.orgSlug,
          tenantSlug: orgTenantData.tenantSlug,
        });
        data = outcome.data as LoginResponse;
      } catch (opaqueErr) {
        // Three things fall through to the password endpoint, and nothing else:
        // a tenant that does not offer OPAQUE, a browser that cannot perform
        // it, and — under `optional` only — an exchange that did not complete.
        //
        // That third case is the whole of `optional` mode. Every account has no
        // registration record the moment an operator turns OPAQUE on, and they
        // acquire one only as they next set a password; until then the server
        // answers a decoy exchange, which is indistinguishable from a wrong
        // password by design so that this endpoint cannot enumerate who is
        // enrolled. Ending the attempt there locked out every existing user of
        // any tenant that enabled `optional`.
        //
        // Under `required` the exchange failure is never converted, so the
        // plaintext is never sent — and `/auth/login` refuses for the whole
        // tenant anyway, which is where the guarantee actually lives.
        const canRetryWithPassword =
          opaqueErr instanceof OpaqueNotOfferedError ||
          opaqueErr instanceof OpaqueExchangeFailedError;
        if (!canRetryWithPassword) throw opaqueErr;

        const response = await api.post<LoginResponse>("/api/v1/auth/login", {
          username,
          password,
          // Omitted entirely when blank, rather than sent as "". The server
          // reads "no tenant named" as "sign in at organization level"; an
          // empty string would be a slug lookup that cannot match.
          ...(orgTenantData.tenantSlug.trim()
            ? { tenant_slug: orgTenantData.tenantSlug.trim() }
            : {}),
          org_slug: orgTenantData.orgSlug,
        });
        data = response.data;
      }

      if (data.mfa_required) {
        setMfaChallengeToken(data.challenge_token ?? "");
        // C2: the server tells us which factors this user actually has. A
        // passkey button on an account with no registered credential would
        // start a ceremony that can only fail.
        setMfaMethods(data.available_methods ?? []);
        setStep("mfa");
        return;
      }

      // CQ-F31 / D-16: MFA setup required — navigate to the public
      // /auth/mfa-setup route with setup_token as a URL query param (NOT
      // router state, which is lost on /profile/mfa's auth-guard redirect
      // and on refresh/bookmark — the dead-end this route replaces). This
      // happens when the user's account requires MFA but they haven't
      // enrolled yet (mfa_setup_required returned from backend).
      if (data.mfa_setup_required) {
        navigate(`/auth/mfa-setup?setup_token=${encodeURIComponent(data.setup_token ?? "")}`);
        return;
      }

      if (data.user) {
        // CQ-F30: hydrate via the shared completeSignIn tail rather than
        // degrading to `permissions: []` when /auth/me comes back null —
        // that used to silently log the user in with no permissions.
        await completeSignIn();
      } else {
        setError(m.authenticationError);
        navigate("/login");
      }
    } catch (err) {
      if (getApiErrorStatus(err) === 403) {
        // `opaque_required` is not a credential failure — the password may be
        // perfectly good, the tenant just refuses this route. Saying "invalid
        // credentials" here would send a user off to reset a password that
        // works. It is reachable when OPAQUE is required but this browser could
        // not complete the exchange.
        if (getApiErrorCode(err) === "opaque_required") {
          setError(m.opaqueRequired);
          return;
        }
        setError(m.securityRejected);
        return;
      }
      setError(getApiErrorMessage(err, m.invalidCredentials));
    } finally {
      setIsLoading(false);
    }
  };

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (totpCode.length !== 6) {
      setError(m.totpLengthRequired);
      return;
    }

    setIsLoading(true);
    try {
      const response = await api.post<LoginResponse>("/api/v1/auth/mfa/verify", {
        challenge_token: mfaChallengeToken,
        totp_code: totpCode,
      });

      const data = response.data;
      if (data.user) {
        // CQ-F30: hydrate via the shared completeSignIn tail rather than
        // degrading to `permissions: []` when /auth/me comes back null.
        await completeSignIn();
      } else {
        setError(m.authenticationError);
        navigate("/login");
      }
    } catch (err) {
      if (getApiErrorStatus(err) === 403) {
        setError(m.securityRejected);
        return;
      }
      setError(getApiErrorMessage(err, m.invalidMfaCode));
    } finally {
      setIsLoading(false);
    }
  };

  const steps: LoginStep[] = ["org-tenant", "credentials", "mfa"];
  const currentIndex = steps.indexOf(step);

  const layoutClass = layoutClassFor(displayMode);

  const content = (
    <>
      {/* Step indicator */}
      <div className="flex items-center justify-center gap-2 mb-6">
        {steps.map((s, i) => (
          <div key={s} className="flex items-center gap-2">
            <div
              className={cn(
                "h-2 w-2 rounded-full transition-all duration-300",
                step === s
                  ? "bg-primary shadow-glow-cyan scale-125"
                  : currentIndex > i
                    ? "bg-primary/60"
                    : "bg-muted-foreground/30",
              )}
              aria-hidden="true"
            />
            {i < 2 && (
              <div
                className="h-px w-6 bg-muted-foreground/20"
                aria-hidden="true"
              />
            )}
          </div>
        ))}
      </div>

      <div>
        {/* Bootstrap success notice (?bootstrapped=1) */}
        {bootstrapNotice && (
          <div
            role="status"
            className="mb-4 flex items-start gap-2 rounded-md border border-primary/30 bg-primary/10 p-3 text-sm text-primary"
          >
            <span>{m.bootstrapNotice}</span>
          </div>
        )}

        {/* W4 (T1.6): the reauthentication loop guard. Rendered *instead* of
            the sign-in form — offering a fourth form for a destination that
            has already rejected three would be the loop, not a fix for it. */}
        {loopBlocked && (
          <div
            role="alert"
            className="mb-4 flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
          >
            <AlertCircle size={16} className="shrink-0 mt-0.5" />
            <span>{loopBlocked}</span>
          </div>
        )}

        {/* W3: reauthentication notice (?reauth=1) */}
        {!loopBlocked && reauthNotice && (
          <div
            role="status"
            className="mb-4 flex items-start gap-2 rounded-md border border-primary/30 bg-primary/10 p-3 text-sm text-primary"
          >
            <span>{reauthNotice}</span>
          </div>
        )}

        {/* Error banner */}
        {error && (
          <div
            role="alert"
            className="flex items-start gap-2 mb-4 p-3 rounded-md bg-destructive/10 border border-destructive/30 text-destructive text-sm"
          >
            <AlertCircle size={16} className="shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        {/* Step 1: Org + Tenant */}
        {!loopBlocked && step === "org-tenant" && (
          <form onSubmit={handleOrgTenantSubmit}>
            <fieldset>
              <legend className="text-lg font-semibold text-foreground mb-1">
                {m.workspaceLegend}
              </legend>
              <p className="text-sm text-muted-foreground mb-6">
                {m.workspaceHelp}
              </p>

              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="org-slug">{m.orgSlugLabel}</Label>
                  <Input
                    id="org-slug"
                    type="text"
                    placeholder={m.orgSlugPlaceholder}
                    value={orgTenantData.orgSlug}
                    onChange={(e) =>
                      setOrgTenantData((d) => ({
                        ...d,
                        orgSlug: e.target.value,
                      }))
                    }
                    autoComplete="organization"
                    autoFocus
                    required
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="tenant-slug">
                    {m.tenantSlugLabel}{" "}
                    <span className="text-muted-foreground font-normal">
                      {m.optionalSuffix}
                    </span>
                  </Label>
                  <Input
                    id="tenant-slug"
                    type="text"
                    placeholder={m.tenantSlugPlaceholder}
                    value={orgTenantData.tenantSlug}
                    onChange={(e) =>
                      setOrgTenantData((d) => ({
                        ...d,
                        tenantSlug: e.target.value,
                      }))
                    }
                    autoComplete="off"
                    aria-describedby="tenant-slug-help"
                  />
                  <p
                    id="tenant-slug-help"
                    className="text-xs text-muted-foreground"
                  >
                    {m.tenantSlugHelp}
                  </p>
                </div>
              </div>

              <Button id="login-workspace-submit" type="submit" className="w-full mt-6">
                {m.continueAction}
                <ChevronRight size={16} aria-hidden="true" />
              </Button>
            </fieldset>
          </form>
        )}

        {/* Step 2: Credentials */}
        {!loopBlocked && step === "credentials" && (
          <form onSubmit={handleCredentialsSubmit}>
            <div className="mb-6">
              <h2 className="text-lg font-semibold text-foreground mb-1">
                {m.signInHeading}
              </h2>
              <p className="text-sm text-muted-foreground">
                {m.workspaceSummaryLabel}{" "}
                <span className="text-primary font-mono text-xs">
                  {orgTenantData.tenantSlug.trim()
                    ? `${orgTenantData.orgSlug}/${orgTenantData.tenantSlug}`
                    : `${orgTenantData.orgSlug} ${m.organizationScopeSuffix}`}
                </span>
              </p>
            </div>

            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="username">{m.usernameLabel}</Label>
                <Input
                  id="username"
                  type="text"
                  placeholder={m.usernamePlaceholder}
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  // C2: the `webauthn` token is what makes conditional
                  // mediation surface saved passkeys in this field's autofill
                  // list. Harmless where unsupported -- browsers ignore
                  // autocomplete tokens they do not know.
                  autoComplete={passkeySupported ? "username webauthn" : "username"}
                  autoFocus
                  required
                />
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label htmlFor="password">{m.passwordLabel}</Label>
                  <Link
                    to={{
                      pathname: "/auth/forgot-password",
                      search: new URLSearchParams({
                        ...(orgTenantData.orgSlug.trim()
                          ? { org: orgTenantData.orgSlug.trim() }
                          : {}),
                        ...(orgTenantData.tenantSlug.trim()
                          ? { tenant: orgTenantData.tenantSlug.trim() }
                          : {}),
                      }).toString(),
                    }}
                    className="text-xs text-primary hover:underline"
                  >
                    {m.forgotPassword}
                  </Link>
                </div>
                <Input
                  id="password"
                  type="password"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                  required
                />
              </div>
            </div>

            <div className="flex gap-3 mt-6">
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setStep("org-tenant");
                  setError(null);
                }}
                className="flex-1"
              >
                {m.backAction}
              </Button>
              {/*
                RFC 6749 §4.1.2.1 / OIDC Core §3.1.2.6 — refusing is a protocol
                outcome and needs somewhere to be expressed.

                Rendered only when `returnTo` names a pending authorization
                request. On an ordinary sign-in there is nothing to decline and
                nobody to tell, so the button would be a second, quieter "Back".

                It navigates rather than calling an API: the destination is
                `/oauth2/authorize`, the server's route and not this
                application's, exactly as the success path at `resume` does. The
                marker is appended to the value `sanitizeReturnTo` returned, so
                what is navigated to is the validated string plus one parameter
                this page controls — never a URL assembled from the query.
              */}
              {returnTo && (
                <Button
                  id="login-decline"
                  type="button"
                  variant="outline"
                  className="flex-1"
                  disabled={isLoading}
                  onClick={() => {
                    const target = sanitizeReturnTo(returnTo);
                    if (!target) return;
                    clearReauthAttempts(target);
                    window.location.assign(
                      `${target}${target.includes("?") ? "&" : "?"}axiam_user_declined=1`,
                    );
                  }}
                >
                  {m.cancelAuthorizationAction}
                </Button>
              )}
              <Button id="login-credentials-submit" type="submit" className="flex-1" disabled={isLoading}>
                {isLoading ? (
                  <>
                    <Loader2
                      size={16}
                      className="animate-spin"
                      aria-hidden="true"
                    />
                    {m.signingIn}
                  </>
                ) : (
                  m.signInAction
                )}
              </Button>
            </div>
          
            {/* Federated sign-in. Rendered only once the providers endpoint has
                answered *and* returned something: a "no providers" empty state
                on a page whose password form works would be noise, and one
                shown before we have asked would be a claim we cannot support.
                The skeleton reserves the same height so the layout does not
                jump when the answer arrives. */}
            {providersLoading && (
              <div className="mt-6" aria-hidden="true">
                <div className="flex items-center gap-3 my-5">
                  <span className="h-px flex-1 bg-border" />
                  <span className="text-xs uppercase tracking-wide text-muted-foreground">
                    {m.orSeparator}
                  </span>
                  <span className="h-px flex-1 bg-border" />
                </div>
                <div className="h-10 w-full animate-pulse rounded-md bg-white/5" />
              </div>
            )}
            {!providersLoading && providers && providers.length > 0 && (
              <div className="mt-6">
                <div className="flex items-center gap-3 my-5" aria-hidden="true">
                  <span className="h-px flex-1 bg-border" />
                  <span className="text-xs uppercase tracking-wide text-muted-foreground">
                    {m.orSeparator}
                  </span>
                  <span className="h-px flex-1 bg-border" />
                </div>
                <ul className="space-y-2 list-none p-0 m-0">
                  {providers.map((p) => (
                    <li key={p.id}>
                      <ProviderSignInButton
                        provider={p}
                        onSelect={handleSsoSelect}
                        busy={ssoBusyId === p.id}
                        disabled={
                          isLoading || passkeyBusy || ssoBusyId !== null
                        }
                      />
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {passkeySupported && (
              <>
                <div className="flex items-center gap-3 my-5" aria-hidden="true">
                  <span className="h-px flex-1 bg-border" />
                  <span className="text-xs uppercase tracking-wide text-muted-foreground">
                    {m.orSeparator}
                  </span>
                  <span className="h-px flex-1 bg-border" />
                </div>
                {/* Fallback ordering (C2): passkey first where the browser can
                    do it, then password, then TOTP at the second-factor step.
                    `type="button"` matters -- inside the credentials <form>,
                    a default-type button would submit the password flow. */}
                <Button
                  type="button"
                  variant="outline"
                  className="w-full"
                  onClick={handleDiscoverablePasskey}
                  disabled={passkeyBusy || isLoading}
                >
                  {passkeyBusy ? (
                    <>
                      <Loader2 size={16} className="animate-spin" aria-hidden="true" />
                      {m.waitingForDevice}
                    </>
                  ) : (
                    <>
                      <Fingerprint size={16} aria-hidden="true" />
                      {m.passkeySignIn}
                    </>
                  )}
                </Button>
              </>
            )}
          </form>
        )}

        {/* Step 3: MFA */}
        {!loopBlocked && step === "mfa" && (
          <form onSubmit={handleMfaSubmit}>
            <div className="flex flex-col items-center mb-6">
              <div className="h-12 w-12 rounded-full bg-primary/10 border border-primary/30 flex items-center justify-center mb-3 shadow-glow-cyan">
                <KeyRound size={22} className="text-primary" />
              </div>
              <h2 className="text-lg font-semibold text-foreground">
                {m.mfaHeading}
              </h2>
              <p className="text-sm text-muted-foreground text-center mt-1">
                {m.mfaPrompt}
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="totp-code">{m.mfaCodeLabel}</Label>
              <Input
                id="totp-code"
                type="text"
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                placeholder="000000"
                value={totpCode}
                onChange={(e) =>
                  setTotpCode(e.target.value.replace(/\D/g, "").slice(0, 6))
                }
                autoFocus
                autoComplete="one-time-code"
                className="text-center text-2xl tracking-[0.5em] font-mono"
                required
              />
            </div>

            {/* C2: WebAuthn as a second factor. Shown only when the server's
                challenge says this account actually has a passkey or security
                key registered -- otherwise the button starts a ceremony that
                can only fail. TOTP stays the default (it is focused above), so
                this is an addition to the fallback chain, not a reordering of
                it: passkey -> TOTP -> recovery. */}
            {passkeySupported &&
              mfaMethods.some((m) => {
                const k = m.toLowerCase();
                return k.includes("passkey") || k.includes("security") || k.includes("webauthn");
              }) && (
                <div className="mt-5">
                  <Button
                    type="button"
                    variant="outline"
                    className="w-full"
                    onClick={() => runMfaPasskey(mfaChallengeToken)}
                    disabled={passkeyBusy || isLoading}
                  >
                    {passkeyBusy ? (
                      <>
                        <Loader2 size={16} className="animate-spin" aria-hidden="true" />
                        {m.waitingForDevice}
                      </>
                    ) : (
                      <>
                        <Fingerprint size={16} aria-hidden="true" />
                        {m.mfaPasskeyAction}
                      </>
                    )}
                  </Button>
                </div>
              )}

            <div className="flex gap-3 mt-6">
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setStep("credentials");
                  setError(null);
                  setTotpCode("");
                }}
                className="flex-1"
              >
                {m.backAction}
              </Button>
              <Button id="login-mfa-submit" type="submit" className="flex-1" disabled={isLoading}>
                {isLoading ? (
                  <>
                    <Loader2
                      size={16}
                      className="animate-spin"
                      aria-hidden="true"
                    />
                    {m.verifying}
                  </>
                ) : (
                  m.verifyAction
                )}
              </Button>
            </div>
          </form>
        )}
      </div>
    </>
  );

  // W5 (plan §4.6) — the layout the relying party asked for, as a class name
  // this file chose from a fixed list. `display` is never rendered as text and
  // never reaches `className` as its own value: `layoutClassFor` maps `popup`
  // to a compact card and everything else to `""`.
  //
  // The wrapper element exists **only** when a layout was asked for. A `<div
  // class="">` that was always there would be markup no client sees today, and
  // invariant 4 for this wave is that a client on the `ignore` lane — which is
  // forwarded no `display` at all — renders the page byte for byte as before.
  return (
    <PublicLayout>
      {layoutClass ? <div className={layoutClass}>{content}</div> : content}
    </PublicLayout>
  );
}

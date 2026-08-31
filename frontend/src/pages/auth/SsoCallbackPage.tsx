import { useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams, Link } from "react-router";
import { AlertCircle, Loader2 } from "lucide-react";

import { PublicLayout } from "@/components/layout/PublicLayout";
import { Button } from "@/components/ui/button";
import {
  fetchCurrentUser,
  withReachableTenantSelected,
} from "@/lib/fetchCurrentUser";
import { getApiErrorMessage, getApiErrorStatus } from "@/lib/apiError";
import {
  HANDOFF_QUERY_PARAM,
  ssoLoginService,
  takePendingSso,
} from "@/services/ssoLogin";
import { useAuthStore } from "@/stores/auth";

/**
 * Where the browser lands after an identity provider is done with it.
 *
 * One route, three arrivals, because the provider decides which one happens and
 * the SPA has to handle whichever it gets:
 *
 * 1. **`?code=…&state=…`** — an OIDC or OAuth2 redirect. The SPA posts them to
 *    the matching completion endpoint **same-origin**, which is what lets that
 *    response set `SameSite=Strict` session cookies.
 * 2. **`?axiam_handoff=…`** — a SAML assertion or Apple's `form_post` came back
 *    cross-site to an AXIAM server endpoint, which could not set those cookies,
 *    so it minted a 60-second single-use code and redirected here with it. The
 *    SPA exchanges it same-origin. See
 *    `claude_dev/federation-sso-login-design.md` §5.2.
 * 3. **`?error=…`** — the user cancelled, or the provider refused.
 *
 * Every failure gets a sentence of its own. "Sign-in failed" on a blank page is
 * the outcome this route exists to avoid: a person who cancelled at Google, one
 * whose ten-minute state row expired, and one whose GitHub email is unverified
 * need three different next actions.
 */
export function SsoCallbackPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { setUser } = useAuthStore();
  const [error, setError] = useState<string | null>(null);
  // React 18 StrictMode mounts effects twice in development, and every
  // credential this route consumes is single-use — a second attempt would
  // always fail and would report *that* failure to the user.
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;

    const pending = takePendingSso();
    const providerName = pending?.displayName ?? "your identity provider";

    const finish = async () => {
      // Strip the credential from the address bar before anything else. It is
      // spent either way, but a code sitting in browser history and in the
      // `Referer` of every subsequent request is worth one line to avoid.
      const clean = () =>
        window.history.replaceState(null, "", window.location.pathname);

      const idpError = searchParams.get("error");
      if (idpError) {
        clean();
        setError(errorMessageFor(idpError, providerName));
        return;
      }

      const handoff = searchParams.get(HANDOFF_QUERY_PARAM);
      const code = searchParams.get("code");
      const state = searchParams.get("state");

      try {
        if (handoff) {
          clean();
          await ssoLoginService.completeHandoff(handoff);
        } else if (code && state) {
          clean();
          // Which endpoint verifies this depends on how AXIAM authenticated
          // the provider, which the redirect itself does not say. The pending
          // record is how the SPA knows; OIDC is the fallback because it is
          // both the common case and the one that existed first.
          await (pending?.protocol === "OAuth2"
            ? ssoLoginService.completeOauth2(state, code)
            : ssoLoginService.completeOidc(state, code));
        } else {
          setError(
            "This sign-in link is incomplete. Start again from the sign-in page.",
          );
          return;
        }
      } catch (err) {
        setError(completionMessage(err, providerName));
        return;
      }

      // The session cookies are set; hydrate the store the same way every
      // other sign-in path does.
      const hydrated = await fetchCurrentUser();
      if (!hydrated) {
        setError("Signed in, but your account could not be loaded.");
        return;
      }
      setUser(await withReachableTenantSelected(hydrated));
      navigate("/dashboard", { replace: true });
    };

    void finish();
    // Deliberately once per mount: every value read here is single-use.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (!error) {
    return (
      <PublicLayout>
        <div
          className="flex flex-col items-center gap-3 py-8"
          role="status"
          aria-live="polite"
        >
          <Loader2 size={28} className="animate-spin text-primary" aria-hidden="true" />
          <p className="text-sm text-muted-foreground">
            Completing sign-in&hellip;
          </p>
        </div>
      </PublicLayout>
    );
  }

  return (
    <PublicLayout>
      <div
        role="alert"
        className="mb-4 flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
      >
        <AlertCircle size={16} className="mt-0.5 shrink-0" aria-hidden="true" />
        <span>{error}</span>
      </div>
      <Button asChild className="w-full">
        <Link to="/login">Back to sign in</Link>
      </Button>
    </PublicLayout>
  );
}

/**
 * Turn a provider's OAuth error code into something a person can act on.
 *
 * The codes are RFC 6749 §4.1.2.1 plus each provider's own additions. Only the
 * ones with a distinct user action are named; the rest fall through to a
 * message that at least says which provider refused.
 */
function errorMessageFor(code: string, providerName: string): string {
  switch (code) {
    case "access_denied":
    case "user_cancelled_authorize":
      return `Sign-in with ${providerName} was cancelled. You can try again, or sign in with your password.`;
    case "consent_required":
    case "interaction_required":
    case "login_required":
      return `${providerName} needs you to sign in there first, then try again.`;
    case "temporarily_unavailable":
    case "server_error":
      return `${providerName} could not complete the sign-in. Try again shortly.`;
    case "invalid_scope":
    case "unauthorized_client":
    case "invalid_client":
      return `This ${providerName} sign-in is not configured correctly. Ask an administrator to check the federation settings.`;
    default:
      return `${providerName} refused the sign-in (${code}).`;
  }
}

/** The message for a failure on AXIAM's own completion call. */
function completionMessage(err: unknown, providerName: string): string {
  if (getApiErrorStatus(err) === 401) {
    // The single-use state or handoff row was missing or expired — which is
    // one message, because the server deliberately does not distinguish them,
    // and because the user's action is the same either way.
    //
    // The server's own reason is preferred when it has one: an unverified
    // GitHub email also arrives as a 401, and "verify your email at GitHub" is
    // a very different next step from "start again".
    return getApiErrorMessage(
      err,
      `This sign-in has expired or was already used. Start again from the sign-in page.`,
    );
  }
  return getApiErrorMessage(
    err,
    `Could not complete sign-in with ${providerName}. Please try again.`,
  );
}

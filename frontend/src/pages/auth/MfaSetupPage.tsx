import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { Loader2, ShieldAlert, KeyRound, Fingerprint, Usb } from "lucide-react";
import { authService } from "@/services/auth";
import {
  webauthnService,
  isWebauthnSupported,
  classifyWebauthnError,
  webauthnErrorMessage,
  type AuthenticatorKind,
} from "@/services/webauthn";
import { fetchCurrentUser } from "@/lib/fetchCurrentUser";
import { useAuthStore } from "@/stores/auth";
import { PublicLayout } from "@/components/layout/PublicLayout";
import { Button } from "@/components/ui/button";
import { TotpSetupPanel, type TotpSetupPanelData } from "@/components/auth/TotpSetupPanel";
import { getApiErrorMessage, getApiErrorStatus } from "@/lib/apiError";
import { resumeLoginHop } from "@/lib/returnTo";

// ---------------------------------------------------------------------------
// API error response type
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// MfaSetupPage states
// ---------------------------------------------------------------------------

type PageState = "no-token" | "loading" | "enroll-error" | "ready";

// ---------------------------------------------------------------------------
// MfaSetupPage — public route (CORR-05b / D-16)
// ---------------------------------------------------------------------------
//
// An MFA-mandated login (mfa_required + setup_token) previously navigated to
// /profile/mfa with router state, which is nested under AppLayout's auth
// guard and dead-ends an unauthenticated setup-token carrier back at /login
// on refresh/bookmark (D-16). This route is a top-level sibling of
// /auth/reset-password, OUTSIDE the auth guard, and carries setup_token as a
// URL query param — bookmark/refresh-safe, mirroring ResetPasswordPage.

export function MfaSetupPage() {
  const navigate = useNavigate();
  const { setUser, setTenantContext } = useAuthStore();
  const [searchParams] = useSearchParams();
  const setupToken = searchParams.get("setup_token");
  // M-4 (R-D): the OAuth2 login-hop `return_to` LoginPage's mfa_setup_required
  // branch carried through here. Read once, alongside `setupToken`, from the
  // URL this page was loaded with — `resumeLoginHop` (below) re-validates it
  // with `sanitizeReturnTo` before it is ever navigated to, because this page
  // is a third side of that check and gets no exemption (see `@/lib/returnTo`'s
  // header comment for why both of the other two check independently).
  const returnTo = searchParams.get("return_to");

  const [state, setState] = useState<PageState>(setupToken ? "loading" : "no-token");
  const [setupData, setSetupData] = useState<TotpSetupPanelData | null>(null);
  const [code, setCode] = useState("");
  const [confirmError, setConfirmError] = useState<string | null>(null);
  const [isConfirming, setIsConfirming] = useState(false);

  // M-3 — a passkey or security key as the FIRST factor, offered alongside
  // the authenticator app the effect below already started enrolling.
  // `isWebauthnSupported()` gates the two device-based options exactly as
  // MfaManagementPage.tsx gates its own "Add a passkey" / "Add a security
  // key" buttons — a browser with no WebAuthn cannot be talked into having
  // it, so hiding the option beats offering a click that can only fail.
  const webauthnSupported = isWebauthnSupported();
  const [webauthnKind, setWebauthnKind] = useState<AuthenticatorKind | null>(null);
  const [isWebauthnPending, setIsWebauthnPending] = useState(false);
  const [webauthnError, setWebauthnError] = useState<string | null>(null);

  // useRef once-guard: prevents a second enroll HTTP request under React 18
  // StrictMode, which mounts effects twice in dev. Mirrors VerifyEmailPage's
  // verifiedRef idiom exactly (T-26-08-03).
  //
  // The reason is not that the token is single-use — it is not, and saying so
  // here was wrong. The setup token carries no `jti` and nothing server-side
  // records that it was spent (T-32's residual R-E), so a second `enroll` under
  // the same token would succeed and **replace** the pending secret: the user
  // would be looking at a QR code for a secret the server has already
  // discarded, and their first code would be rejected. The guard exists to stop
  // this component doing that to itself.
  const enrolledRef = useRef(false);

  useEffect(() => {
    if (!setupToken) return;
    if (enrolledRef.current) return;
    enrolledRef.current = true;

    async function doEnroll() {
      setState("loading");
      try {
        const data = await authService.setupEnrollMfa(setupToken!);
        setSetupData(data);
        setState("ready");
      } catch {
        // Expired/invalid/already-used setup_token — indistinguishable from
        // a missing token to the user (UI-SPEC: enroll-error mirrors
        // no-token exactly).
        setState("enroll-error");
      }
    }

    doEnroll();
  }, [setupToken]);

  /**
   * The tail shared by every way this page can finish: a TOTP code
   * confirmed, or a passkey/security key ceremony completed. Both events are
   * the same thing from the account's point of view — a first MFA factor
   * was enrolled and the sign-in that demanded one now completes — so both
   * branches run this instead of keeping their own copy (M-3 factors it out
   * of what used to be `handleConfirm`'s inline tail; M-4's comments below
   * are unchanged by the move).
   */
  const completeSetup = async () => {
    // Strips setup_token *and* return_to together — both live in the query
    // string this component read, and `pathname` alone drops it entirely.
    window.history.replaceState({}, document.title, window.location.pathname);
    // Hydrate tenant context via fetchCurrentUser() (relying on the
    // 26-05 /auth/me tenant_slug/org_slug), not ambient login-form
    // slugs — this route has no login-form context (RESEARCH Pattern 5).
    const hydrated = await fetchCurrentUser();
    if (hydrated) {
      setUser(hydrated);
      if (hydrated.tenantSlug && hydrated.orgSlug) {
        setTenantContext(hydrated.tenantSlug, hydrated.orgSlug);
      }
    }
    // M-4 (R-D): resume the login hop this forced setup interrupted, the
    // same tail LoginPage's completeSignIn runs on an ordinary sign-in.
    resumeLoginHop(returnTo, navigate);
  };

  const handleConfirm = async (totpCode: string) => {
    if (!setupToken) return;
    setConfirmError(null);
    setIsConfirming(true);
    try {
      await authService.setupConfirmMfa(setupToken, totpCode);
      await completeSetup();
    } catch (err) {
      const status = getApiErrorStatus(err);
      if (status === 401 || status === 410) {
        // Token-level failure (expired/invalid/used) — bounce to the
        // invalid-link state, not a wrong-code inline error.
        window.history.replaceState({}, document.title, window.location.pathname);
        setState("enroll-error");
        return;
      }
      const msg = getApiErrorMessage(err, "Invalid or expired code. Please try again.");
      setConfirmError(msg);
    } finally {
      setIsConfirming(false);
    }
  };

  /**
   * The WebAuthn branch (M-3): a passkey or security key enrolled directly
   * as the first factor, in place of the authenticator app above. Unlike
   * `doEnroll`, there is no once-guard here — `enrolledRef` exists to stop a
   * single automatic effect call from firing twice under StrictMode, and
   * this branch is started only by a click, so a second attempt is an
   * ordinary retry, not a double-submit. `isWebauthnPending` disables both
   * buttons while one ceremony is in flight instead.
   */
  const startWebauthnEnrollment = async (kind: AuthenticatorKind) => {
    if (!setupToken) return;
    setWebauthnError(null);
    setWebauthnKind(kind);
    setIsWebauthnPending(true);
    try {
      await webauthnService.registerWithSetupToken(
        setupToken,
        kind === "platform" ? "Passkey" : "Security key",
        kind,
      );
      await completeSetup();
    } catch (err) {
      const status = getApiErrorStatus(err);
      if (status === 401) {
        // The setup token itself is invalid, expired, or already used — the
        // same dead end the TOTP branch bounces to above, and for the same
        // reason: contract §25.2 makes it the only credential this endpoint
        // accepts, so a rejected token has no page left to show but this one.
        window.history.replaceState({}, document.title, window.location.pathname);
        setState("enroll-error");
        return;
      }
      if (status === 403) {
        // Denied by the tenant's attestation policy: the token is fine, this
        // device or credential type just isn't one the tenant accepts. An
        // inline message, not "invalid link" — the authenticator-app panel
        // below is untouched and still finishes the same sign-in.
        setWebauthnError(
          getApiErrorMessage(
            err,
            "This device isn't allowed by your organization's security policy. Try a different device, or use the authenticator app instead."
          )
        );
        return;
      }
      // Anything else is either a ceremony failure the browser reports as a
      // DOMException (cancelled, timed out, unsupported, or an authenticator
      // that already holds a credential for this account — the same
      // classification MfaManagementPage.tsx uses for its own passkey/security
      // key buttons) or an unexpected server error, which has a status but no
      // ceremony to classify.
      setWebauthnError(
        status === undefined
          ? webauthnErrorMessage(classifyWebauthnError(err))
          : getApiErrorMessage(err, "Something went wrong setting up this device. Please try again.")
      );
    } finally {
      setIsWebauthnPending(false);
    }
  };

  if (state === "no-token" || state === "enroll-error") {
    return (
      <PublicLayout>
        <div className="text-center space-y-4">
          <div className="flex justify-center">
            <div className="h-14 w-14 rounded-full bg-destructive/10 border border-destructive/30 flex items-center justify-center">
              <ShieldAlert size={28} className="text-destructive" />
            </div>
          </div>
          <div>
            <h2 className="text-lg font-semibold text-foreground">Invalid setup link</h2>
            <p className="text-sm text-muted-foreground mt-2">
              This MFA setup link is invalid, expired, or already used. Please log in again to
              continue.
            </p>
          </div>
          <Button variant="outline" asChild className="w-full">
            <Link to="/login">Back to Login</Link>
          </Button>
        </div>
      </PublicLayout>
    );
  }

  if (state === "loading") {
    return (
      <PublicLayout>
        <div className="text-center space-y-4 py-4">
          <div className="flex justify-center">
            <div className="h-14 w-14 rounded-full bg-primary/10 border border-primary/30 flex items-center justify-center animate-pulse">
              <Loader2 size={28} className="text-primary animate-spin" />
            </div>
          </div>
          <p className="text-sm text-muted-foreground">Preparing your authenticator setup…</p>
        </div>
      </PublicLayout>
    );
  }

  // Ready state — QR + secret + code input
  return (
    <PublicLayout maxWidth="max-w-lg">
      <div className="mb-6">
        <h2 className="text-lg font-semibold text-foreground text-center">
          Set up your authenticator
        </h2>
        <p className="text-sm text-muted-foreground text-center mt-1">
          Scan the QR code with your authenticator app, then enter the 6-digit code to continue.
        </p>
      </div>

      {setupData && (
        <div className="space-y-5">
          {/* M-3 — method chooser. The authenticator app below has already
              started enrolling (the effect above runs unconditionally on
              mount), so it is shown as the active method rather than a
              button; a passkey or security key is an alternative to it, not
              a second step after it. */}
          <div role="group" aria-label="Choose how to secure your account">
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-2">
              Method
            </p>
            <div className="flex flex-wrap gap-2">
              <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium border bg-primary/10 border-primary/30 text-primary">
                <KeyRound size={14} aria-hidden="true" />
                Authenticator app
              </span>
              {webauthnSupported && (
                <>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => startWebauthnEnrollment("platform")}
                    disabled={isWebauthnPending}
                  >
                    {isWebauthnPending && webauthnKind === "platform" ? (
                      <>
                        <Loader2 size={14} className="animate-spin" aria-hidden="true" />
                        Waiting for your device…
                      </>
                    ) : (
                      <>
                        <Fingerprint size={14} aria-hidden="true" />
                        Passkey on this device
                      </>
                    )}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => startWebauthnEnrollment("cross-platform")}
                    disabled={isWebauthnPending}
                  >
                    {isWebauthnPending && webauthnKind === "cross-platform" ? (
                      <>
                        <Loader2 size={14} className="animate-spin" aria-hidden="true" />
                        Waiting for your key…
                      </>
                    ) : (
                      <>
                        <Usb size={14} aria-hidden="true" />
                        Security key
                      </>
                    )}
                  </Button>
                </>
              )}
            </div>
            {webauthnError && (
              <div
                role="alert"
                className="flex items-start gap-2 mt-3 p-3 rounded-md bg-destructive/10 border border-destructive/30 text-destructive text-sm"
              >
                <ShieldAlert size={14} className="shrink-0 mt-0.5" aria-hidden="true" />
                <span>{webauthnError}</span>
              </div>
            )}
          </div>

          <TotpSetupPanel
            setupData={setupData}
            code={code}
            onCodeChange={setCode}
            onConfirm={handleConfirm}
            error={confirmError}
            isPending={isConfirming}
            confirmLabel="Confirm & Continue"
            confirmPendingLabel="Confirming…"
          />
        </div>
      )}

      <p className="text-center mt-4">
        <Link to="/login" className="text-sm text-primary hover:underline">
          Back to login
        </Link>
      </p>
    </PublicLayout>
  );
}

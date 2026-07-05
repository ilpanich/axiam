import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Loader2, ShieldAlert } from "lucide-react";
import { authService } from "@/services/auth";
import { fetchCurrentUser } from "@/lib/fetchCurrentUser";
import { useAuthStore } from "@/stores/auth";
import { PublicLayout } from "@/components/layout/PublicLayout";
import { Button } from "@/components/ui/button";
import { TotpSetupPanel, type TotpSetupPanelData } from "@/components/auth/TotpSetupPanel";
import type { AxiosError } from "axios";

// ---------------------------------------------------------------------------
// API error response type
// ---------------------------------------------------------------------------

interface ErrorResponse {
  message?: string;
  error?: string;
}

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

  const [state, setState] = useState<PageState>(setupToken ? "loading" : "no-token");
  const [setupData, setSetupData] = useState<TotpSetupPanelData | null>(null);
  const [code, setCode] = useState("");
  const [confirmError, setConfirmError] = useState<string | null>(null);
  const [isConfirming, setIsConfirming] = useState(false);

  // useRef once-guard: prevents a second enroll HTTP request under React 18
  // StrictMode (which mounts effects twice in dev) so a single-use
  // setup_token is never consumed twice (T-26-08-03), mirroring
  // VerifyEmailPage's verifiedRef idiom exactly.
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

  const handleConfirm = async (totpCode: string) => {
    if (!setupToken) return;
    setConfirmError(null);
    setIsConfirming(true);
    try {
      await authService.setupConfirmMfa(setupToken, totpCode);
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
      navigate("/dashboard");
    } catch (err) {
      const axiosErr = err as AxiosError<ErrorResponse>;
      if (axiosErr.response?.status === 401 || axiosErr.response?.status === 410) {
        // Token-level failure (expired/invalid/used) — bounce to the
        // invalid-link state, not a wrong-code inline error.
        window.history.replaceState({}, document.title, window.location.pathname);
        setState("enroll-error");
        return;
      }
      const msg =
        axiosErr.response?.data?.message ??
        axiosErr.response?.data?.error ??
        "Invalid or expired code. Please try again.";
      setConfirmError(msg);
    } finally {
      setIsConfirming(false);
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
      )}

      <p className="text-center mt-4">
        <Link to="/login" className="text-sm text-primary hover:underline">
          Back to login
        </Link>
      </p>
    </PublicLayout>
  );
}

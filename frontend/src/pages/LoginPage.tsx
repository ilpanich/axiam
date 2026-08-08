import { useEffect, useState, useRef } from "react";
import { useNavigate, Link, useSearchParams } from "react-router";
import { useAuthStore } from "@/stores/auth";
import {
  webauthnService,
  isWebauthnSupported,
  isConditionalMediationAvailable,
  classifyWebauthnError,
  webauthnErrorMessage,
} from "@/services/webauthn";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PublicLayout } from "@/components/layout/PublicLayout";
import { cn } from "@/lib/utils";
import api from "@/lib/api";
import { fetchCurrentUser } from "@/lib/fetchCurrentUser";
import { KeyRound, ChevronRight, Loader2, AlertCircle, Fingerprint } from "lucide-react";
import type { AxiosError } from "axios";

type LoginStep = "org-tenant" | "credentials" | "mfa";

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

interface ErrorResponse {
  message?: string;
  error?: string;
}

export function LoginPage() {
  const navigate = useNavigate();
  const { setUser, setTenantContext } = useAuthStore();
  const [searchParams, setSearchParams] = useSearchParams();
  // Derive the notice once from the initial URL so it survives stripping the
  // query param below (lazy initializer — no setState in an effect).
  const [bootstrapNotice] = useState<string | null>(() =>
    searchParams.get("bootstrapped") === "1"
      ? "Admin account created. Sign in to continue."
      : null
  );

  useEffect(() => {
    if (
      searchParams.get("bootstrapped") === "1" ||
      searchParams.get("org") ||
      searchParams.get("tenant")
    ) {
      // Strip the query params so a refresh doesn't re-show the notice or
      // re-seed the workspace fields.
      const next = new URLSearchParams(searchParams);
      next.delete("bootstrapped");
      next.delete("org");
      next.delete("tenant");
      setSearchParams(next, { replace: true });
    }
  }, [searchParams, setSearchParams]);

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
  const [username, setUsername] = useState("");
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
      setError("Authentication error. Please sign in again.");
      navigate("/login");
      return;
    }
    setUser(hydrated);
    setTenantContext(orgTenantData.tenantSlug, orgTenantData.orgSlug);
    navigate("/dashboard");
  };

  /**
   * Run a WebAuthn assertion against an MFA challenge token.
   *
   * `conditional` selects passkey autofill (the browser surfaces saved
   * passkeys from the username field). In that mode the promise may never
   * settle -- the user simply may not pick one -- so failures are swallowed
   * rather than shown: an error banner for a prompt the user never engaged
   * with would be noise on a page they are still typing into.
   */
  const runPasskey = async (challengeToken: string, conditional = false) => {
    if (!conditional) {
      setPasskeyBusy(true);
      setError(null);
    }
    try {
      await webauthnService.authenticate(challengeToken, { conditional });
      await completeSignIn();
    } catch (err) {
      if (!conditional) {
        setError(webauthnErrorMessage(classifyWebauthnError(err)));
      }
    } finally {
      if (!conditional) setPasskeyBusy(false);
    }
  };

  /**
   * Sign in with a passkey without typing a username first.
   *
   * The server issues a challenge with an empty `allowCredentials`, so the
   * authenticator offers whichever discoverable credential it holds for this
   * relying party and the assertion itself identifies the user. An empty
   * challenge token is what asks for that shape.
   */
  const handleDiscoverablePasskey = () => runPasskey("");

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
      await runPasskey("", true);
    })();
    return () => {
      cancelled = true;
    };
    // `runPasskey` closes over navigation state that does not change within a
    // step, and re-running this effect would start a second ceremony that
    // aborts the first.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step, passkeySupported]);

  const handleOrgTenantSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!orgTenantData.orgSlug.trim() || !orgTenantData.tenantSlug.trim()) {
      setError("Please enter both organization and tenant slug.");
      return;
    }
    setStep("credentials");
  };

  const handleCredentialsSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!username.trim() || !password.trim()) {
      setError("Please enter your username and password.");
      return;
    }

    setIsLoading(true);
    try {
      const response = await api.post<LoginResponse>("/api/v1/auth/login", {
        username,
        password,
        tenant_slug: orgTenantData.tenantSlug,
        org_slug: orgTenantData.orgSlug,
      });

      const data = response.data;

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
        // Re-fetch via /auth/me so the store is populated with the
        // permissions array — the login response does not include it.
        const hydrated = await fetchCurrentUser();
        setUser(hydrated ?? { ...data.user, permissions: [] });
        setTenantContext(orgTenantData.tenantSlug, orgTenantData.orgSlug);
        navigate("/dashboard");
      } else {
        setError("Authentication error. Please sign in again.");
        navigate("/login");
      }
    } catch (err) {
      const axiosErr = err as AxiosError<ErrorResponse>;
      if (axiosErr.response?.status === 403) {
        setError(
          "Request rejected for security reasons. Please refresh the page and try again."
        );
        return;
      }
      const msg =
        axiosErr.response?.data?.message ??
        axiosErr.response?.data?.error ??
        "Invalid credentials. Please try again.";
      setError(msg);
    } finally {
      setIsLoading(false);
    }
  };

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (totpCode.length !== 6) {
      setError("Please enter the 6-digit code from your authenticator app.");
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
        // Re-fetch via /auth/me so the store is populated with the
        // permissions array — the login response does not include it.
        const hydrated = await fetchCurrentUser();
        setUser(hydrated ?? { ...data.user, permissions: [] });
        setTenantContext(orgTenantData.tenantSlug, orgTenantData.orgSlug);
        navigate("/dashboard");
      } else {
        setError("Authentication error. Please sign in again.");
        navigate("/login");
      }
    } catch (err) {
      const axiosErr = err as AxiosError<ErrorResponse>;
      if (axiosErr.response?.status === 403) {
        setError(
          "Request rejected for security reasons. Please refresh the page and try again."
        );
        return;
      }
      const msg =
        axiosErr.response?.data?.message ??
        axiosErr.response?.data?.error ??
        "Invalid or expired MFA code.";
      setError(msg);
    } finally {
      setIsLoading(false);
    }
  };

  const steps: LoginStep[] = ["org-tenant", "credentials", "mfa"];
  const currentIndex = steps.indexOf(step);

  return (
    <PublicLayout>
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
            <span>{bootstrapNotice}</span>
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
        {step === "org-tenant" && (
          <form onSubmit={handleOrgTenantSubmit} noValidate>
            <fieldset>
              <legend className="text-lg font-semibold text-foreground mb-1">
                Select your workspace
              </legend>
              <p className="text-sm text-muted-foreground mb-6">
                Enter your organization and tenant to continue.
              </p>

              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="org-slug">Organization slug</Label>
                  <Input
                    id="org-slug"
                    type="text"
                    placeholder="my-organization"
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
                  <Label htmlFor="tenant-slug">Tenant slug</Label>
                  <Input
                    id="tenant-slug"
                    type="text"
                    placeholder="default"
                    value={orgTenantData.tenantSlug}
                    onChange={(e) =>
                      setOrgTenantData((d) => ({
                        ...d,
                        tenantSlug: e.target.value,
                      }))
                    }
                    autoComplete="off"
                    required
                  />
                </div>
              </div>

              <Button type="submit" className="w-full mt-6">
                Continue
                <ChevronRight size={16} aria-hidden="true" />
              </Button>
            </fieldset>
          </form>
        )}

        {/* Step 2: Credentials */}
        {step === "credentials" && (
          <form onSubmit={handleCredentialsSubmit} noValidate>
            <div className="mb-6">
              <h2 className="text-lg font-semibold text-foreground mb-1">
                Sign in
              </h2>
              <p className="text-sm text-muted-foreground">
                Workspace:{" "}
                <span className="text-primary font-mono text-xs">
                  {orgTenantData.orgSlug}/{orgTenantData.tenantSlug}
                </span>
              </p>
            </div>

            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="username">Username or email</Label>
                <Input
                  id="username"
                  type="text"
                  placeholder="username or email"
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
                  <Label htmlFor="password">Password</Label>
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
                    Forgot password?
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
                Back
              </Button>
              <Button type="submit" className="flex-1" disabled={isLoading}>
                {isLoading ? (
                  <>
                    <Loader2
                      size={16}
                      className="animate-spin"
                      aria-hidden="true"
                    />
                    Signing in...
                  </>
                ) : (
                  "Sign in"
                )}
              </Button>
            </div>
          
            {passkeySupported && (
              <>
                <div className="flex items-center gap-3 my-5" aria-hidden="true">
                  <span className="h-px flex-1 bg-border" />
                  <span className="text-xs uppercase tracking-wide text-muted-foreground">
                    or
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
                      Waiting for your device…
                    </>
                  ) : (
                    <>
                      <Fingerprint size={16} aria-hidden="true" />
                      Sign in with a passkey
                    </>
                  )}
                </Button>
              </>
            )}
          </form>
        )}

        {/* Step 3: MFA */}
        {step === "mfa" && (
          <form onSubmit={handleMfaSubmit} noValidate>
            <div className="flex flex-col items-center mb-6">
              <div className="h-12 w-12 rounded-full bg-primary/10 border border-primary/30 flex items-center justify-center mb-3 shadow-glow-cyan">
                <KeyRound size={22} className="text-primary" />
              </div>
              <h2 className="text-lg font-semibold text-foreground">
                Two-factor authentication
              </h2>
              <p className="text-sm text-muted-foreground text-center mt-1">
                Enter the 6-digit code from your authenticator app.
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="totp-code">Authentication code</Label>
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
                    onClick={() => runPasskey(mfaChallengeToken)}
                    disabled={passkeyBusy || isLoading}
                  >
                    {passkeyBusy ? (
                      <>
                        <Loader2 size={16} className="animate-spin" aria-hidden="true" />
                        Waiting for your device…
                      </>
                    ) : (
                      <>
                        <Fingerprint size={16} aria-hidden="true" />
                        Use a passkey or security key instead
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
                Back
              </Button>
              <Button type="submit" className="flex-1" disabled={isLoading}>
                {isLoading ? (
                  <>
                    <Loader2
                      size={16}
                      className="animate-spin"
                      aria-hidden="true"
                    />
                    Verifying...
                  </>
                ) : (
                  "Verify"
                )}
              </Button>
            </div>
          </form>
        )}
      </div>
    </PublicLayout>
  );
}

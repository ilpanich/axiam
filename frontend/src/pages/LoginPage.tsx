import { useEffect, useState } from "react";
import { useNavigate, Link, useSearchParams } from "react-router-dom";
import { useAuthStore } from "@/stores/auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PublicLayout } from "@/components/layout/PublicLayout";
import { cn } from "@/lib/utils";
import api from "@/lib/api";
import { fetchCurrentUser } from "@/lib/fetchCurrentUser";
import { KeyRound, ChevronRight, Loader2, AlertCircle } from "lucide-react";
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
  const [bootstrapNotice, setBootstrapNotice] = useState<string | null>(null);

  useEffect(() => {
    if (searchParams.get("bootstrapped") === "1") {
      setBootstrapNotice("Admin account created. Sign in to continue.");
      // Strip the query param so a refresh doesn't re-show the notice.
      const next = new URLSearchParams(searchParams);
      next.delete("bootstrapped");
      setSearchParams(next, { replace: true });
    }
  }, [searchParams, setSearchParams]);

  const [step, setStep] = useState<LoginStep>("org-tenant");
  const [orgTenantData, setOrgTenantData] = useState<OrgTenantData>({
    orgSlug: "",
    tenantSlug: "",
  });
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [mfaChallengeToken, setMfaChallengeToken] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
        setStep("mfa");
        return;
      }

      // CQ-F31: MFA setup required — navigate to setup flow with setup_token.
      // This happens when the user's account requires MFA but they haven't
      // enrolled yet (mfa_setup_required returned from backend).
      if (data.mfa_setup_required) {
        navigate("/profile/mfa", {
          state: { setup_token: data.setup_token },
        });
        return;
      }

      if (data.user) {
        // Re-fetch via /auth/me so the store is populated with the
        // permissions array — login response does not include it.
        // Fallback to login payload with empty permissions if /me
        // fails (e.g., cookies still propagating).
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
        // permissions array — login response does not include it.
        // Fallback to login payload with empty permissions if /me
        // fails (e.g., cookies still propagating).
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
                  autoComplete="username"
                  autoFocus
                  required
                />
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label htmlFor="password">Password</Label>
                  <Link
                    to="/auth/forgot-password"
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

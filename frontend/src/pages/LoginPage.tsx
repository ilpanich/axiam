import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuthStore } from "@/stores/auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";
import api from "@/lib/api";
import { KeyRound, ChevronRight, Loader2, AlertCircle } from "lucide-react";
import type { AxiosError } from "axios";

type LoginStep = "org-tenant" | "credentials" | "mfa";

interface OrgTenantData {
  orgSlug: string;
  tenantSlug: string;
}

interface LoginResponse {
  access_token?: string;
  mfa_required?: boolean;
  mfa_session_token?: string;
  user?: {
    id: string;
    username: string;
    email: string;
  };
}

interface ErrorResponse {
  message?: string;
  error?: string;
}

export function LoginPage() {
  const navigate = useNavigate();
  const { setTokens, setTenantContext } = useAuthStore();

  const [step, setStep] = useState<LoginStep>("org-tenant");
  const [orgTenantData, setOrgTenantData] = useState<OrgTenantData>({
    orgSlug: "",
    tenantSlug: "",
  });
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [mfaSessionToken, setMfaSessionToken] = useState("");
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
      const response = await api.post<LoginResponse>("/auth/login", {
        username,
        password,
        tenant_id: orgTenantData.tenantSlug,
        org_id: orgTenantData.orgSlug,
      });

      const data = response.data;

      if (data.mfa_required) {
        setMfaSessionToken(data.mfa_session_token ?? "");
        setStep("mfa");
        return;
      }

      if (data.access_token && data.user) {
        setTokens(data.access_token, data.user);
        setTenantContext(orgTenantData.tenantSlug, orgTenantData.orgSlug);
        navigate("/dashboard");
      }
    } catch (err) {
      const axiosErr = err as AxiosError<ErrorResponse>;
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
      const response = await api.post<LoginResponse>("/auth/mfa/verify", {
        code: totpCode,
        session_token: mfaSessionToken,
      });

      const data = response.data;
      if (data.access_token && data.user) {
        setTokens(data.access_token, data.user);
        setTenantContext(orgTenantData.tenantSlug, orgTenantData.orgSlug);
        navigate("/dashboard");
      }
    } catch (err) {
      const axiosErr = err as AxiosError<ErrorResponse>;
      const msg =
        axiosErr.response?.data?.message ??
        axiosErr.response?.data?.error ??
        "Invalid or expired MFA code.";
      setError(msg);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-axiam-gradient px-4">
      {/* Background ambient glow */}
      <div
        className="fixed inset-0 overflow-hidden pointer-events-none"
        aria-hidden="true"
      >
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[600px] rounded-full bg-primary/5 blur-[120px]" />
        <div className="absolute bottom-1/4 left-1/3 w-[400px] h-[400px] rounded-full bg-accent/5 blur-[100px]" />
      </div>

      <div className="relative w-full max-w-md">
        {/* Logo area with neon ring effect */}
        <div className="flex flex-col items-center mb-8">
          <div className="relative mb-4">
            {/* Animated neon rings */}
            <div
              className="absolute inset-0 rounded-full border-2 border-primary/30 animate-ring-spin"
              style={{ margin: "-16px" }}
              aria-hidden="true"
            />
            <div
              className="absolute inset-0 rounded-full border border-accent/20 animate-ring-spin-reverse"
              style={{ margin: "-24px" }}
              aria-hidden="true"
            />
            <div className="relative h-16 w-16 rounded-full bg-primary/10 border border-primary/30 flex items-center justify-center shadow-glow-cyan">
              <img
                src="/axiam_logo.png"
                alt="AXIAM"
                className="h-10 w-10 object-contain"
              />
            </div>
          </div>
          <h1 className="text-3xl font-bold text-foreground tracking-tight">
            AXIAM
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Identity & Access Management
          </p>
        </div>

        {/* Step indicator */}
        <div className="flex items-center justify-center gap-2 mb-6">
          {(["org-tenant", "credentials", "mfa"] as LoginStep[]).map(
            (s, i) => (
              <div key={s} className="flex items-center gap-2">
                <div
                  className={cn(
                    "h-2 w-2 rounded-full transition-all duration-300",
                    step === s
                      ? "bg-primary shadow-glow-cyan scale-125"
                      : ["org-tenant", "credentials", "mfa"].indexOf(step) > i
                        ? "bg-primary/60"
                        : "bg-muted-foreground/30"
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
            )
          )}
        </div>

        {/* Glass card */}
        <div className="glass-card p-8">
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
                    <a
                      href="/auth/reset-password"
                      className="text-xs text-primary hover:underline"
                    >
                      Forgot password?
                    </a>
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
                      <Loader2 size={16} className="animate-spin" aria-hidden="true" />
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
                      <Loader2 size={16} className="animate-spin" aria-hidden="true" />
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

        <p className="text-center text-xs text-muted-foreground/50 mt-6">
          Secured by AXIAM IAM · GDPR & ISO27001 compliant
        </p>
      </div>
    </div>
  );
}

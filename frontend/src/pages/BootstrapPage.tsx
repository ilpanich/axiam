import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { AlertCircle, Loader2, ShieldCheck } from "lucide-react";
import type { AxiosError } from "axios";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PasswordPolicyChecker, checkPasswordPolicy } from "@/components/PasswordPolicyChecker";
import { PublicLayout } from "@/components/layout/PublicLayout";
import { slugify } from "@/lib/utils";
import api from "@/lib/api";

/**
 * BootstrapPage — first-run provisioning.
 *
 * On a brand-new deployment nothing exists yet, so this page collects the
 * organization, the default tenant and the admin credentials and posts them to
 * `POST /api/v1/admin/bootstrap`, which creates all three in one call. When the
 * `AXIAM_BOOTSTRAP_ADMIN_EMAIL` env gate is not set, the server mints a one-time
 * setup token at first boot (logged once) — paste it into the Setup token field.
 * On success it redirects to `/login` with the org/tenant slugs pre-filled.
 */
interface BootstrapErrorResponse {
  message?: string;
  error?: string;
}

export function BootstrapPage() {
  const navigate = useNavigate();

  const [orgName, setOrgName] = useState("");
  const [orgSlug, setOrgSlug] = useState("");
  const [tenantName, setTenantName] = useState("Default");
  const [tenantSlug, setTenantSlug] = useState("default");
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [setupToken, setSetupToken] = useState("");

  const [orgSlugTouched, setOrgSlugTouched] = useState(false);
  const [tenantSlugTouched, setTenantSlugTouched] = useState(false);

  const [isLoading, setIsLoading] = useState(false);
  const [emailError, setEmailError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [alreadyInitialized, setAlreadyInitialized] = useState(false);

  useEffect(() => {
    const prev = document.title;
    document.title = "Initialize AXIAM — AXIAM";
    return () => {
      document.title = prev;
    };
  }, []);

  const handleOrgNameChange = (v: string) => {
    setOrgName(v);
    if (!orgSlugTouched) setOrgSlug(slugify(v));
  };

  const handleTenantNameChange = (v: string) => {
    setTenantName(v);
    if (!tenantSlugTouched) setTenantSlug(slugify(v));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setEmailError(null);
    setFormError(null);

    const effectiveOrgSlug = orgSlug.trim() || slugify(orgName);
    const effectiveTenantSlug = tenantSlug.trim() || slugify(tenantName) || "default";

    if (
      !orgName.trim() ||
      !effectiveOrgSlug ||
      !email.trim() ||
      !username.trim() ||
      !password.trim()
    ) {
      setFormError("Organization, email, username and password are required.");
      return;
    }

    if (!checkPasswordPolicy(password)) {
      setFormError("Password does not meet the requirements.");
      return;
    }

    setIsLoading(true);
    try {
      await api.post("/api/v1/admin/bootstrap", {
        organization_name: orgName.trim(),
        organization_slug: effectiveOrgSlug,
        tenant_name: tenantName.trim() || "Default",
        tenant_slug: effectiveTenantSlug,
        email: email.trim(),
        username: username.trim(),
        password,
        ...(setupToken.trim() ? { setup_token: setupToken.trim() } : {}),
      });
      const params = new URLSearchParams({
        bootstrapped: "1",
        org: effectiveOrgSlug,
        tenant: effectiveTenantSlug,
      });
      navigate(`/login?${params.toString()}`);
    } catch (err) {
      const axiosErr = err as AxiosError<BootstrapErrorResponse>;
      const status = axiosErr.response?.status;
      if (status === 403) {
        setEmailError(
          "Bootstrap is not authorized. Check the email gate or paste a valid setup token.",
        );
      } else if (status === 409) {
        setAlreadyInitialized(true);
      } else {
        const msg =
          axiosErr.response?.data?.message ??
          axiosErr.response?.data?.error ??
          "Could not initialize AXIAM. Verify the server is running and check the server logs.";
        setFormError(msg);
      }
    } finally {
      setIsLoading(false);
    }
  };

  if (alreadyInitialized) {
    return (
      <PublicLayout>
        <div className="mb-6 flex flex-col items-center text-center">
          <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-full border border-primary/30 bg-primary/10">
            <ShieldCheck size={22} className="text-primary" aria-hidden="true" />
          </div>
          <h1 className="text-2xl font-semibold text-foreground">
            Already Initialized
          </h1>
          <p className="mt-2 text-sm text-muted-foreground">
            This instance has already been initialized. Sign in to continue.
          </p>
        </div>
        <Link to="/login" className="block">
          <Button className="w-full">Go to sign in</Button>
        </Link>
      </PublicLayout>
    );
  }

  return (
    <PublicLayout>
      <div className="mb-6">
        <h1 className="text-2xl font-semibold text-foreground">
          Initialize AXIAM
        </h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Create your organization, its default tenant and the first
          administrator to get started.
        </p>
      </div>

      {formError && (
        <div
          role="alert"
          className="mb-4 flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
        >
          <AlertCircle size={16} className="mt-0.5 shrink-0" aria-hidden="true" />
          <span>{formError}</span>
        </div>
      )}

      <form onSubmit={handleSubmit} noValidate>
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="bootstrap-org-name">Organization name</Label>
            <Input
              id="bootstrap-org-name"
              type="text"
              placeholder="Acme Corporation"
              value={orgName}
              onChange={(e) => handleOrgNameChange(e.target.value)}
              autoComplete="organization"
              autoFocus
              required
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="bootstrap-org-slug">Organization slug</Label>
            <Input
              id="bootstrap-org-slug"
              type="text"
              placeholder="acme"
              value={orgSlug}
              onChange={(e) => {
                setOrgSlugTouched(true);
                setOrgSlug(slugify(e.target.value));
              }}
              autoComplete="off"
              required
            />
            <p className="text-xs text-muted-foreground">
              Used to sign in. Lowercase letters, numbers and dashes.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-2">
              <Label htmlFor="bootstrap-tenant-name">Tenant name</Label>
              <Input
                id="bootstrap-tenant-name"
                type="text"
                placeholder="Default"
                value={tenantName}
                onChange={(e) => handleTenantNameChange(e.target.value)}
                autoComplete="off"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="bootstrap-tenant-slug">Tenant slug</Label>
              <Input
                id="bootstrap-tenant-slug"
                type="text"
                placeholder="default"
                value={tenantSlug}
                onChange={(e) => {
                  setTenantSlugTouched(true);
                  setTenantSlug(slugify(e.target.value));
                }}
                autoComplete="off"
                required
              />
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="bootstrap-email">Email address</Label>
            <Input
              id="bootstrap-email"
              type="email"
              placeholder="admin@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
              aria-invalid={emailError ? "true" : undefined}
              aria-describedby={emailError ? "bootstrap-email-error" : undefined}
              required
            />
            {emailError && (
              <p
                id="bootstrap-email-error"
                role="alert"
                className="text-sm text-destructive"
              >
                {emailError}
              </p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="bootstrap-username">Username</Label>
            <Input
              id="bootstrap-username"
              type="text"
              placeholder="admin"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="bootstrap-password">Password</Label>
            <Input
              id="bootstrap-password"
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="new-password"
              required
            />
            {password.length > 0 && (
              <div className="mt-2">
                <PasswordPolicyChecker password={password} />
              </div>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="bootstrap-setup-token">
              Setup token{" "}
              <span className="text-muted-foreground">(if required)</span>
            </Label>
            <Input
              id="bootstrap-setup-token"
              type="text"
              placeholder="From the server's first-boot logs"
              value={setupToken}
              onChange={(e) => setSetupToken(e.target.value)}
              autoComplete="off"
            />
            <p className="text-xs text-muted-foreground">
              Required unless the server sets AXIAM_BOOTSTRAP_ADMIN_EMAIL.
            </p>
          </div>
        </div>

        <Button
          type="submit"
          className="mt-6 w-full"
          disabled={isLoading}
          aria-busy={isLoading ? "true" : "false"}
        >
          {isLoading ? (
            <Loader2 size={14} className="animate-spin" aria-hidden="true" />
          ) : (
            "Create Organization & Admin"
          )}
        </Button>
      </form>

      <p className="mt-4 text-center text-xs text-muted-foreground">
        Already initialized?{" "}
        <Link to="/login" className="text-primary hover:underline">
          Sign in
        </Link>
      </p>
    </PublicLayout>
  );
}

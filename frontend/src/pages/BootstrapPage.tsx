import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { AlertCircle, Loader2, ShieldCheck } from "lucide-react";
import type { AxiosError } from "axios";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PublicLayout } from "@/components/layout/PublicLayout";
import api from "@/lib/api";

/**
 * BootstrapPage — first-run admin setup.
 *
 * Calls `POST /api/v1/admin/bootstrap` with the organization/tenant IDs
 * and the admin credentials. Renders inline error states for the three
 * documented failure modes (403 wrong email, 404 already initialized,
 * generic 4xx/5xx) and redirects to `/login?bootstrapped=1` on success.
 */
interface BootstrapErrorResponse {
  message?: string;
  error?: string;
}

export function BootstrapPage() {
  const navigate = useNavigate();

  const [orgId, setOrgId] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

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

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setEmailError(null);
    setFormError(null);

    if (
      !orgId.trim() ||
      !tenantId.trim() ||
      !email.trim() ||
      !username.trim() ||
      !password.trim()
    ) {
      setFormError("All fields are required.");
      return;
    }

    setIsLoading(true);
    try {
      await api.post("/api/v1/admin/bootstrap", {
        org_id: orgId.trim(),
        tenant_id: tenantId.trim(),
        email: email.trim(),
        username: username.trim(),
        password,
      });
      navigate("/login?bootstrapped=1");
    } catch (err) {
      const axiosErr = err as AxiosError<BootstrapErrorResponse>;
      const status = axiosErr.response?.status;
      if (status === 403) {
        setEmailError(
          "This email address is not authorized for bootstrap.",
        );
      } else if (status === 404) {
        setAlreadyInitialized(true);
      } else {
        const msg =
          axiosErr.response?.data?.message ??
          axiosErr.response?.data?.error ??
          "Could not create admin account. Verify the server is running and check the server logs.";
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
          No admin users exist. Create the first administrator to get started.
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
            <Label htmlFor="bootstrap-org-id">Organization ID</Label>
            <Input
              id="bootstrap-org-id"
              type="text"
              placeholder="00000000-0000-0000-0000-000000000000"
              value={orgId}
              onChange={(e) => setOrgId(e.target.value)}
              autoComplete="off"
              required
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="bootstrap-tenant-id">Tenant ID</Label>
            <Input
              id="bootstrap-tenant-id"
              type="text"
              placeholder="00000000-0000-0000-0000-000000000000"
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
              autoComplete="off"
              required
            />
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
            "Create Admin Account"
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

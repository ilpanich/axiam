import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router";
import { AlertCircle, Loader2, ShieldCheck } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PasswordPolicyChecker, checkPasswordPolicy } from "@/components/PasswordPolicyChecker";
import { OpaquePolicyFields } from "@/components/OpaquePolicyFields";
import { PublicLayout } from "@/components/layout/PublicLayout";
import { DEFAULT_OPAQUE_POLICY, type OpaquePolicy } from "@/services/opaquePolicy";
import { slugify } from "@/lib/utils";
import api from "@/lib/api";
import { getApiErrorMessage, getApiErrorStatus } from "@/lib/apiError";

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
export function BootstrapPage() {
  const navigate = useNavigate();

  const [orgName, setOrgName] = useState("");
  const [orgSlug, setOrgSlug] = useState("");
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [setupToken, setSetupToken] = useState("");
  // `POST /api/v1/admin/bootstrap` has accepted these three since OPAQUE
  // shipped, and enrols the administrator itself — it is the one enrolment path
  // where the server holds the plaintext and can build the record without a
  // client. Not offering them here meant the only way to start a deployment
  // with OPAQUE on was to bootstrap over the API by hand, and every
  // browser-bootstrapped deployment began with it off.
  const [opaquePolicy, setOpaquePolicy] = useState<OpaquePolicy>(
    DEFAULT_OPAQUE_POLICY,
  );

  const [orgSlugTouched, setOrgSlugTouched] = useState(false);

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

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setEmailError(null);
    setFormError(null);

    const effectiveOrgSlug = orgSlug.trim() || slugify(orgName);

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
        // No tenant. Bootstrap provisions the organization's own scope and the
        // administrator inside it, so that administrator can reach every tenant
        // created afterwards. Choosing a tenant here is what used to leave
        // every *later* tenant unreachable by everybody.
        email: email.trim(),
        username: username.trim(),
        password,
        ...(setupToken.trim() ? { setup_token: setupToken.trim() } : {}),
        ...opaquePolicy,
      });
      // No `tenant` param: the administrator just created is
      // organization-level, and the login page reads a blank tenant as
      // "sign in at organization level".
      const params = new URLSearchParams({
        bootstrapped: "1",
        org: effectiveOrgSlug,
      });
      navigate(`/login?${params.toString()}`);
    } catch (err) {
      const status = getApiErrorStatus(err);
      if (status === 403) {
        setEmailError(
          "Bootstrap is not authorized. Check the email gate or paste a valid setup token.",
        );
      } else if (status === 409) {
        setAlreadyInitialized(true);
      } else {
        setFormError(
          getApiErrorMessage(
            err,
            "Could not initialize AXIAM. Verify the server is running and check the server logs.",
          ),
        );
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
          Create your organization and the first
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

          {/* No tenant fields.

              The administrator created here is organization-level: its grants
              live in the organization's own scope and apply to every tenant the
              organization ever has. Creating a tenant at this step is what
              produced the opposite — the administrator's roles were rows in one
              tenant, and every tenant created later was reachable by nobody,
              not even them.

              Tenants are created after signing in, from Organization →
              Tenants. */}
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

          <details className="rounded-md border border-primary/15 bg-white/2 p-3">
            <summary className="cursor-pointer text-sm text-foreground/80">
              OPAQUE sign-in{" "}
              <span className="text-muted-foreground">
                (optional — off by default)
              </span>
            </summary>
            <div className="mt-4">
              <p className="mb-4 text-xs text-muted-foreground">
                RFC 9807 augmented PAKE: the password never reaches the server,
                on any request. Bootstrap enrols this administrator directly, so
                turning it on here is the one moment a deployment can start with
                OPAQUE already working. The server must be started with
                AXIAM__AUTH__OPAQUE_SESSION_KEY and
                AXIAM__AUTH__OPAQUE_SETUP_KEY, or bootstrap refuses anything but
                Disabled.
              </p>
              <OpaquePolicyFields
                idPrefix="bootstrap"
                value={opaquePolicy}
                onChange={setOpaquePolicy}
              />
            </div>
          </details>

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

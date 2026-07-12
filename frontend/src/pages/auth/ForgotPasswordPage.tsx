import { useActionState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ArrowLeft, Loader2, Mail, CheckCircle2 } from "lucide-react";
import { authService } from "@/services/auth";
import { PublicLayout } from "@/components/layout/PublicLayout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

// ---------------------------------------------------------------------------
// Action state type
// ---------------------------------------------------------------------------

interface ForgotPasswordState {
  /** Whether the form has been submitted (always show success message after submit) */
  submitted: boolean;
  /** Internal error (network failure etc.) — still show success to prevent enumeration */
  internalError: boolean;
}

// ---------------------------------------------------------------------------
// ForgotPasswordPage
// ---------------------------------------------------------------------------

export function ForgotPasswordPage() {
  // D-04 / Open Question 1: the public forgot-password page has no prior
  // tenant context, so it carries the org/tenant slug in its OWN URL
  // (e.g. from the "Forgot password?" link on LoginPage). No user-typed
  // tenant field, no email-domain inference.
  const [searchParams] = useSearchParams();
  const orgSlug = searchParams.get("org") ?? undefined;
  const tenantSlug = searchParams.get("tenant") ?? undefined;

  const [state, formAction, isPending] = useActionState<ForgotPasswordState, FormData>(
    async (_prev, formData) => {
      const email = (formData.get("email") as string).trim();
      let internalError = false;
      try {
        await authService.requestPasswordReset(email, orgSlug, tenantSlug);
      } catch {
        // Intentionally swallow errors to prevent user enumeration.
        // We always show the same success message regardless of outcome.
        console.warn("[ForgotPassword] reset request failed (details redacted for privacy)");
        internalError = true;
      }
      return { submitted: true, internalError };
    },
    { submitted: false, internalError: false }
  );

  return (
    <PublicLayout>
      {state.submitted ? (
        /* ---- Post-submit success state (always shown, even on error) ---- */
        <div className="text-center space-y-4">
          <div className="flex justify-center">
            <div className="h-14 w-14 rounded-full bg-primary/10 border border-primary/30 flex items-center justify-center shadow-glow-cyan">
              <CheckCircle2 size={28} className="text-primary" />
            </div>
          </div>
          <div>
            <h2 className="text-lg font-semibold text-foreground">Check your email</h2>
            <p className="text-sm text-muted-foreground mt-2 leading-relaxed">
              If an account with that email exists, you&apos;ll receive a reset link shortly.
            </p>
          </div>
          <Link
            to="/login"
            className="inline-flex items-center gap-1.5 text-sm text-primary hover:underline"
          >
            <ArrowLeft size={14} aria-hidden="true" />
            Back to login
          </Link>
        </div>
      ) : (
        /* ---- Form ---- */
        <form action={formAction} noValidate>
          <div className="mb-6">
            <div className="flex justify-center mb-4">
              <div className="h-12 w-12 rounded-full bg-primary/10 border border-primary/30 flex items-center justify-center shadow-glow-cyan">
                <Mail size={22} className="text-primary" />
              </div>
            </div>
            <h2 className="text-lg font-semibold text-foreground text-center">
              Reset your password
            </h2>
            <p className="text-sm text-muted-foreground text-center mt-1">
              Enter your email and we&apos;ll send you a reset link.
            </p>
          </div>

          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email address</Label>
              <Input
                id="email"
                name="email"
                type="email"
                placeholder="you@example.com"
                autoComplete="email"
                autoFocus
                required
              />
            </div>
          </div>

          <Button type="submit" className="w-full mt-5" disabled={isPending}>
            {isPending ? (
              <>
                <Loader2 size={16} className="animate-spin" aria-hidden="true" />
                Sending…
              </>
            ) : (
              "Send Reset Link"
            )}
          </Button>

          <p className="text-center mt-4">
            <Link to="/login" className="text-sm text-primary hover:underline inline-flex items-center gap-1">
              <ArrowLeft size={13} aria-hidden="true" />
              Back to login
            </Link>
          </p>
        </form>
      )}
    </PublicLayout>
  );
}

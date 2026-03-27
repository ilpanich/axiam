import { useState, useActionState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ArrowLeft, Loader2, CheckCircle2, AlertCircle } from "lucide-react";
import api from "@/lib/api";
import { PublicLayout } from "@/components/layout/PublicLayout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PasswordPolicyChecker, checkPasswordPolicy } from "@/components/PasswordPolicyChecker";
import type { AxiosError } from "axios";

// ---------------------------------------------------------------------------
// API helper
// ---------------------------------------------------------------------------

interface ErrorResponse {
  message?: string;
  error?: string;
}

async function resetPassword(token: string, newPassword: string): Promise<void> {
  await api.post("/auth/reset-password", { token, new_password: newPassword });
}

// ---------------------------------------------------------------------------
// Action state type
// ---------------------------------------------------------------------------

interface ResetPasswordState {
  error: string | null;
  success: boolean;
}

// ---------------------------------------------------------------------------
// ResetPasswordPage
// ---------------------------------------------------------------------------

export function ResetPasswordPage() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token");

  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [confirmTouched, setConfirmTouched] = useState(false);

  const policyMet = checkPasswordPolicy(newPassword);
  const passwordsMatch = newPassword === confirmPassword;
  const confirmError = confirmTouched && confirmPassword.length > 0 && !passwordsMatch;
  const canSubmit = policyMet && passwordsMatch && confirmPassword.length > 0 && Boolean(token);

  const [state, formAction, isPending] = useActionState<ResetPasswordState, FormData>(
    async (_prev, formData) => {
      const newPw = formData.get("new_password") as string;
      const confirmPw = formData.get("confirm_password") as string;

      if (!token) {
        return { error: "Invalid or missing reset token.", success: false };
      }
      if (!checkPasswordPolicy(newPw)) {
        return { error: "Password does not meet the requirements.", success: false };
      }
      if (newPw !== confirmPw) {
        return { error: "Passwords do not match.", success: false };
      }

      try {
        await resetPassword(token, newPw);
        return { error: null, success: true };
      } catch (err) {
        const axiosErr = err as AxiosError<ErrorResponse>;
        const msg =
          axiosErr.response?.data?.message ??
          axiosErr.response?.data?.error ??
          "This reset link is invalid or has expired. Please request a new one.";
        return { error: msg, success: false };
      }
    },
    { error: null, success: false }
  );

  // Success state
  if (state.success) {
    return (
      <PublicLayout>
        <div className="text-center space-y-4">
          <div className="flex justify-center">
            <div className="h-14 w-14 rounded-full bg-emerald-400/10 border border-emerald-400/30 flex items-center justify-center">
              <CheckCircle2 size={28} className="text-emerald-400" />
            </div>
          </div>
          <div>
            <h2 className="text-lg font-semibold text-foreground">Password reset successfully</h2>
            <p className="text-sm text-muted-foreground mt-2">
              You can now log in with your new password.
            </p>
          </div>
          <Button asChild className="w-full">
            <Link to="/login">Go to Login</Link>
          </Button>
        </div>
      </PublicLayout>
    );
  }

  // No token in URL
  if (!token) {
    return (
      <PublicLayout>
        <div className="text-center space-y-4">
          <div className="flex justify-center">
            <div className="h-14 w-14 rounded-full bg-destructive/10 border border-destructive/30 flex items-center justify-center">
              <AlertCircle size={28} className="text-destructive" />
            </div>
          </div>
          <div>
            <h2 className="text-lg font-semibold text-foreground">Invalid reset link</h2>
            <p className="text-sm text-muted-foreground mt-2">
              This password reset link is invalid or missing.
            </p>
          </div>
          <Button variant="outline" asChild className="w-full">
            <Link to="/auth/forgot-password">Request new reset link</Link>
          </Button>
          <p className="text-center">
            <Link to="/login" className="text-sm text-primary hover:underline inline-flex items-center gap-1">
              <ArrowLeft size={13} aria-hidden="true" />
              Back to login
            </Link>
          </p>
        </div>
      </PublicLayout>
    );
  }

  // Password reset form
  return (
    <PublicLayout maxWidth="max-w-lg">
      <form action={formAction} noValidate>
        <div className="mb-6">
          <h2 className="text-lg font-semibold text-foreground text-center">
            Set your new password
          </h2>
          <p className="text-sm text-muted-foreground text-center mt-1">
            Choose a strong password for your account.
          </p>
        </div>

        {state.error && (
          <div
            role="alert"
            className="flex items-start gap-2 mb-5 p-3 rounded-md bg-destructive/10 border border-destructive/30 text-destructive text-sm"
          >
            <AlertCircle size={16} className="shrink-0 mt-0.5" />
            <span>{state.error}</span>
          </div>
        )}

        <div className="space-y-4">
          {/* New password */}
          <div className="space-y-1.5">
            <Label htmlFor="new_password">New Password</Label>
            <Input
              id="new_password"
              name="new_password"
              type="password"
              placeholder="New secure password"
              autoComplete="new-password"
              autoFocus
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
            />
            {newPassword.length > 0 && (
              <div className="mt-2">
                <PasswordPolicyChecker password={newPassword} />
              </div>
            )}
          </div>

          {/* Confirm password */}
          <div className="space-y-1.5">
            <Label htmlFor="confirm_password">Confirm Password</Label>
            <Input
              id="confirm_password"
              name="confirm_password"
              type="password"
              placeholder="Repeat new password"
              autoComplete="new-password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              onBlur={() => setConfirmTouched(true)}
              aria-describedby={confirmError ? "confirm-error" : undefined}
              required
            />
            {confirmError && (
              <p id="confirm-error" className="text-xs text-destructive mt-1">
                Passwords do not match.
              </p>
            )}
          </div>
        </div>

        <Button type="submit" className="w-full mt-5" disabled={isPending || !canSubmit}>
          {isPending ? (
            <>
              <Loader2 size={16} className="animate-spin" aria-hidden="true" />
              Resetting…
            </>
          ) : (
            "Reset Password"
          )}
        </Button>

        <p className="text-center mt-4">
          <Link to="/login" className="text-sm text-primary hover:underline inline-flex items-center gap-1">
            <ArrowLeft size={13} aria-hidden="true" />
            Back to login
          </Link>
        </p>
      </form>
    </PublicLayout>
  );
}

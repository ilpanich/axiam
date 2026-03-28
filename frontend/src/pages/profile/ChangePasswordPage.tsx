import { useState, useActionState } from "react";
import { Link } from "react-router-dom";
import { ArrowLeft, Loader2, AlertCircle, CheckCircle2 } from "lucide-react";
import api from "@/lib/api";
import { PageHeader } from "@/components/PageHeader";
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

async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  await api.post("/auth/change-password", {
    current_password: currentPassword,
    new_password: newPassword,
  });
}

// ---------------------------------------------------------------------------
// Action state type
// ---------------------------------------------------------------------------

interface ChangePasswordState {
  error: string | null;
  success: boolean;
}

// ---------------------------------------------------------------------------
// ChangePasswordPage
// ---------------------------------------------------------------------------

export function ChangePasswordPage() {
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [confirmTouched, setConfirmTouched] = useState(false);

  const policyMet = checkPasswordPolicy(newPassword);
  const passwordsMatch = newPassword === confirmPassword;
  const confirmError = confirmTouched && confirmPassword.length > 0 && !passwordsMatch;
  const canSubmit = policyMet && passwordsMatch && confirmPassword.length > 0;

  const [state, formAction, isPending] = useActionState<ChangePasswordState, FormData>(
    async (_prev, formData) => {
      const currentPassword = formData.get("current_password") as string;
      const newPw = formData.get("new_password") as string;
      const confirmPw = formData.get("confirm_password") as string;

      if (!checkPasswordPolicy(newPw)) {
        return { error: "New password does not meet the requirements.", success: false };
      }
      if (newPw !== confirmPw) {
        return { error: "Passwords do not match.", success: false };
      }

      try {
        await changePassword(currentPassword, newPw);
        return { error: null, success: true };
      } catch (err) {
        const axiosErr = err as AxiosError<ErrorResponse>;
        const msg =
          axiosErr.response?.data?.message ??
          axiosErr.response?.data?.error ??
          "Failed to change password. Please try again.";
        return { error: msg, success: false };
      }
    },
    { error: null, success: false }
  );

  if (state.success) {
    return (
      <div className="max-w-lg space-y-6">
        <PageHeader title="Change Password" />
        <div className="glass-card p-8 text-center space-y-4">
          <div className="flex justify-center">
            <div className="h-14 w-14 rounded-full bg-emerald-400/10 border border-emerald-400/30 flex items-center justify-center">
              <CheckCircle2 size={28} className="text-emerald-400" />
            </div>
          </div>
          <div>
            <p className="text-base font-semibold text-foreground">Password changed successfully</p>
            <p className="text-sm text-muted-foreground mt-1">
              Your password has been updated. Use it next time you log in.
            </p>
          </div>
          <Button variant="outline" asChild>
            <Link to="/profile">
              <ArrowLeft size={14} aria-hidden="true" />
              Back to Profile
            </Link>
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-lg space-y-6">
      <PageHeader
        title="Change Password"
        description="Update your account password. Choose a strong, unique password."
      />

      <div className="glass-card p-6">
        <form action={formAction} noValidate>
          {state.error && (
            <div
              role="alert"
              className="flex items-start gap-2 mb-5 p-3 rounded-md bg-destructive/10 border border-destructive/30 text-destructive text-sm"
            >
              <AlertCircle size={16} className="shrink-0 mt-0.5" />
              <span>{state.error}</span>
            </div>
          )}

          <div className="space-y-5">
            {/* Current password */}
            <div className="space-y-2">
              <Label htmlFor="current_password">Current Password</Label>
              <Input
                id="current_password"
                name="current_password"
                type="password"
                placeholder="Your current password"
                autoComplete="current-password"
                required
              />
            </div>

            {/* New password */}
            <div className="space-y-2">
              <Label htmlFor="new_password">New Password</Label>
              <Input
                id="new_password"
                name="new_password"
                type="password"
                placeholder="New secure password"
                autoComplete="new-password"
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

            {/* Confirm new password */}
            <div className="space-y-2">
              <Label htmlFor="confirm_password">Confirm New Password</Label>
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

          <div className="flex gap-3 mt-6">
            <Button type="submit" disabled={isPending || !canSubmit}>
              {isPending ? (
                <>
                  <Loader2 size={14} className="animate-spin" aria-hidden="true" />
                  Updating…
                </>
              ) : (
                "Update Password"
              )}
            </Button>
            <Button type="button" variant="outline" asChild>
              <Link to="/profile">Cancel</Link>
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}

import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { CheckCircle2, AlertCircle, Loader2, MailOpen } from "lucide-react";
import api from "@/lib/api";
import { PublicLayout } from "@/components/layout/PublicLayout";
import { Button } from "@/components/ui/button";
import { useAuthStore } from "@/stores/auth";
import type { AxiosError } from "axios";

// ---------------------------------------------------------------------------
// API helper
// ---------------------------------------------------------------------------

interface ErrorResponse {
  message?: string;
  error?: string;
}

async function verifyEmail(token: string): Promise<void> {
  await api.get(`/auth/verify-email?token=${encodeURIComponent(token)}`);
}

// ---------------------------------------------------------------------------
// Verification states
// ---------------------------------------------------------------------------

type VerifyState = "idle" | "loading" | "success" | "error" | "no-token";

// ---------------------------------------------------------------------------
// VerifyEmailPage
// ---------------------------------------------------------------------------

export function VerifyEmailPage() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token");
  const { isAuthenticated } = useAuthStore();

  const [verifyState, setVerifyState] = useState<VerifyState>(token ? "loading" : "no-token");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!token) return;

    let cancelled = false;

    async function doVerify() {
      setVerifyState("loading");
      try {
        await verifyEmail(token!);
        if (!cancelled) setVerifyState("success");
      } catch (err) {
        if (cancelled) return;
        const axiosErr = err as AxiosError<ErrorResponse>;
        const msg =
          axiosErr.response?.data?.message ??
          axiosErr.response?.data?.error ??
          "Verification failed. The link may be expired or already used.";
        setErrorMessage(msg);
        setVerifyState("error");
      }
    }

    doVerify();
    return () => {
      cancelled = true;
    };
  }, [token]);

  return (
    <PublicLayout>
      {verifyState === "loading" && (
        <div className="text-center space-y-4 py-4">
          <div className="flex justify-center">
            <div className="h-14 w-14 rounded-full bg-primary/10 border border-primary/30 flex items-center justify-center animate-pulse">
              <Loader2 size={28} className="text-primary animate-spin" />
            </div>
          </div>
          <p className="text-sm text-muted-foreground">Verifying your email address…</p>
        </div>
      )}

      {verifyState === "success" && (
        <div className="text-center space-y-4">
          <div className="flex justify-center">
            {/* CSS-only checkmark animation */}
            <div
              className="h-14 w-14 rounded-full bg-emerald-400/10 border border-emerald-400/30 flex items-center justify-center"
              style={{ animation: "fadeInScale 0.4s ease-out" }}
            >
              <CheckCircle2 size={28} className="text-emerald-400" />
            </div>
          </div>
          <div>
            <h2 className="text-lg font-semibold text-foreground">Email verified!</h2>
            <p className="text-sm text-muted-foreground mt-2">
              Your email address has been successfully verified.
            </p>
          </div>
          <Button asChild className="w-full">
            <Link to="/dashboard">Go to Dashboard</Link>
          </Button>
        </div>
      )}

      {verifyState === "error" && (
        <div className="text-center space-y-4">
          <div className="flex justify-center">
            <div className="h-14 w-14 rounded-full bg-destructive/10 border border-destructive/30 flex items-center justify-center">
              <AlertCircle size={28} className="text-destructive" />
            </div>
          </div>
          <div>
            <h2 className="text-lg font-semibold text-foreground">Verification failed</h2>
            <p className="text-sm text-muted-foreground mt-2">
              {errorMessage ?? "The verification link may be expired or already used."}
            </p>
          </div>

          {isAuthenticated ? (
            <div className="space-y-3">
              <p className="text-xs text-muted-foreground">
                You can request a new verification email from your profile settings.
              </p>
              <Button asChild variant="outline" className="w-full">
                <Link to="/profile">Go to Profile</Link>
              </Button>
            </div>
          ) : (
            <div className="space-y-3">
              <p className="text-xs text-muted-foreground">
                To resend the verification email, please log in to your account first.
              </p>
              <Button asChild variant="outline" className="w-full">
                <Link to="/login">Log in to resend</Link>
              </Button>
            </div>
          )}
        </div>
      )}

      {verifyState === "no-token" && (
        <div className="text-center space-y-4">
          <div className="flex justify-center">
            <div className="h-14 w-14 rounded-full bg-muted/20 border border-muted/30 flex items-center justify-center">
              <MailOpen size={28} className="text-muted-foreground" />
            </div>
          </div>
          <div>
            <h2 className="text-lg font-semibold text-foreground">Invalid verification link</h2>
            <p className="text-sm text-muted-foreground mt-2">
              This link is invalid or incomplete. Please use the link from your verification email.
            </p>
          </div>
          <Button asChild variant="outline" className="w-full">
            <Link to="/login">Back to Login</Link>
          </Button>
        </div>
      )}
    </PublicLayout>
  );
}

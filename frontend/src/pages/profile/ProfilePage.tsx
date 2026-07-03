import { useState, useActionState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { User, Lock, Shield, CheckCircle2, AlertCircle, Pencil, X, Loader2 } from "lucide-react";
import api from "@/lib/api";
import { authService } from "@/services/auth";
import { useAuthStore } from "@/stores/auth";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { AxiosError } from "axios";

// ---------------------------------------------------------------------------
// API helpers (inline, per spec)
// ---------------------------------------------------------------------------

// Backend UserResponse: there is NO `display_name` column — it lives inside
// the free-form `metadata` object (key `display_name`, shared with the users
// admin UI). `email_verified` is serialized directly on UserResponse.
// Source: crates/axiam-api-rest/src/handlers/users.rs (UserResponse,
// UpdateUserRequest).
interface UserMetadata {
  display_name?: string;
  [key: string]: unknown;
}

interface UserResponse {
  id: string;
  username: string;
  email: string;
  email_verified: boolean;
  metadata: UserMetadata;
}

/** View-model with `display_name` projected out of `metadata` for the UI. */
interface UserProfile {
  id: string;
  username: string;
  email: string;
  email_verified: boolean;
  display_name: string | null;
  /** Raw metadata, preserved so updates don't clobber other keys. */
  metadata: UserMetadata;
}

// CQ-F17: use canonical MfaMethod type from services/users.ts
import type { MfaMethod } from "@/services/users";

interface UpdateProfilePayload {
  email?: string;
  metadata?: UserMetadata;
}

interface ErrorResponse {
  message?: string;
  error?: string;
}

// The backend addresses users by their real id — there is no `/users/me`
// alias — so the authenticated user's id is threaded in from the auth store.
async function getCurrentUser(userId: string): Promise<UserProfile> {
  const res = await api.get<UserResponse>(`/api/v1/users/${userId}`);
  const u = res.data;
  const metadata = u.metadata ?? {};
  return {
    id: u.id,
    username: u.username,
    email: u.email,
    email_verified: u.email_verified,
    display_name:
      typeof metadata.display_name === "string" ? metadata.display_name : null,
    metadata,
  };
}

async function updateProfile(
  userId: string,
  data: UpdateProfilePayload,
): Promise<UserResponse> {
  const res = await api.put<UserResponse>(`/api/v1/users/${userId}`, data);
  return res.data;
}

async function getMfaMethods(userId: string): Promise<MfaMethod[]> {
  const res = await api.get<MfaMethod[] | { items: MfaMethod[] }>(
    `/api/v1/users/${userId}/mfa-methods`,
  );
  return Array.isArray(res.data) ? res.data : res.data.items;
}

// ---------------------------------------------------------------------------
// Avatar helper
// ---------------------------------------------------------------------------

function UserAvatar({ username }: { username: string }) {
  const letter = username.charAt(0).toUpperCase();
  return (
    <div
      className="h-16 w-16 rounded-full flex items-center justify-center text-2xl font-bold text-background shrink-0"
      style={{
        background: "linear-gradient(135deg, #00d4ff 0%, #a855f7 100%)",
        boxShadow: "0 0 20px rgba(0,212,255,0.3)",
      }}
      aria-hidden="true"
    >
      {letter}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Edit Profile action state
// ---------------------------------------------------------------------------

interface EditFormState {
  error: string | null;
  success: boolean;
}

// ---------------------------------------------------------------------------
// ProfilePage
// ---------------------------------------------------------------------------

export function ProfilePage() {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [verificationMessage, setVerificationMessage] = useState<string | null>(null);

  const userId = useAuthStore((s) => s.user?.id);
  const currentUser = useAuthStore((s) => s.user);

  const { data: profile, isLoading, error: loadError } = useQuery({
    queryKey: ["currentUser", userId],
    queryFn: () => getCurrentUser(userId!),
    enabled: !!userId,
  });

  const { data: mfaMethods } = useQuery({
    queryKey: ["mfaMethods", userId],
    queryFn: () => getMfaMethods(userId!),
    enabled: !!userId,
  });

  // 23-RESEARCH Pitfall 4: `resendVerification` is a PUBLIC/unauthenticated
  // backend route that requires BOTH `tenant_id` AND `email` in the body —
  // both are already available from the authenticated auth store.
  const resendMutation = useMutation({
    mutationFn: () => {
      if (!currentUser?.tenant_id || !currentUser?.email) {
        return Promise.reject(new Error("missing tenant context or email"));
      }
      return authService.resendVerification(currentUser.tenant_id, currentUser.email);
    },
    onSuccess: () => {
      setVerificationMessage("Verification email sent. Please check your inbox.");
    },
    onError: () => {
      setVerificationMessage("Failed to resend verification email. Try again later.");
    },
  });

  // useActionState for profile edit form submission
  const [editState, editAction, editPending] = useActionState<EditFormState, FormData>(
    async (_prev, formData) => {
      const display_name = (formData.get("display_name") as string).trim();
      const email = (formData.get("email") as string).trim();
      try {
        // display_name has no backend column — persist it inside `metadata`,
        // merging with existing keys so we don't drop other metadata.
        const metadata: UserMetadata = { ...(profile?.metadata ?? {}) };
        if (display_name) {
          metadata.display_name = display_name;
        } else {
          delete metadata.display_name;
        }
        await updateProfile(userId!, {
          email: email || undefined,
          metadata,
        });
        await queryClient.invalidateQueries({ queryKey: ["currentUser"] });
        setEditing(false);
        return { error: null, success: true };
      } catch (err) {
        const axiosErr = err as AxiosError<ErrorResponse>;
        const msg =
          axiosErr.response?.data?.message ??
          axiosErr.response?.data?.error ??
          "Failed to update profile.";
        return { error: msg, success: false };
      }
    },
    { error: null, success: false }
  );

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <Loader2 className="animate-spin text-primary" size={32} />
      </div>
    );
  }

  if (loadError || !profile) {
    return (
      <div
        role="alert"
        className="flex items-center gap-2 p-4 rounded-md bg-destructive/10 border border-destructive/30 text-destructive text-sm"
      >
        <AlertCircle size={16} />
        <span>Failed to load profile. Please refresh the page.</span>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-2xl">
      <PageHeader title="My Profile" description="Manage your account information and security settings." />

      {/* ------------------------------------------------------------------ */}
      {/* Section 1 — Profile card                                           */}
      {/* ------------------------------------------------------------------ */}
      <section className="glass-card p-6" aria-label="Profile information">
        <div className="flex items-center gap-3 mb-5">
          <User size={18} className="text-primary" aria-hidden="true" />
          <h2 className="text-base font-semibold text-foreground">Account Details</h2>
        </div>

        {!editing ? (
          /* ---- View mode ---- */
          <div className="space-y-4">
            <div className="flex items-center gap-4">
              <UserAvatar username={profile.username} />
              <div className="min-w-0">
                <p className="text-lg font-semibold text-foreground truncate">
                  {profile.display_name ?? profile.username}
                </p>
                <p className="text-sm text-muted-foreground font-mono">@{profile.username}</p>
              </div>
            </div>

            <div className="grid gap-3 pt-2">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wide mb-0.5">Email</p>
                  <p className="text-sm text-foreground">{profile.email}</p>
                </div>
                {profile.email_verified ? (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-400/10 text-emerald-400 border border-emerald-400/20 shrink-0">
                    <CheckCircle2 size={11} aria-hidden="true" />
                    Verified
                  </span>
                ) : (
                  <div className="flex flex-col items-end gap-2 shrink-0">
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-amber-400/10 text-amber-400 border border-amber-400/20">
                      <AlertCircle size={11} aria-hidden="true" />
                      Unverified
                    </span>
                    <button
                      onClick={() => {
                        setVerificationMessage(null);
                        resendMutation.mutate();
                      }}
                      disabled={resendMutation.isPending}
                      className="text-xs text-primary hover:underline disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {resendMutation.isPending ? "Sending..." : "Resend verification email"}
                    </button>
                  </div>
                )}
              </div>

              {profile.display_name && (
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wide mb-0.5">Display Name</p>
                  <p className="text-sm text-foreground">{profile.display_name}</p>
                </div>
              )}
            </div>

            {verificationMessage && (
              <p className="text-xs text-muted-foreground bg-white/5 rounded px-3 py-2 border border-white/10">
                {verificationMessage}
              </p>
            )}

            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setEditing(true);
                setVerificationMessage(null);
              }}
              className="mt-1"
            >
              <Pencil size={14} aria-hidden="true" />
              Edit Profile
            </Button>
          </div>
        ) : (
          /* ---- Edit mode ---- */
          <form action={editAction} noValidate>
            <div className="flex items-center gap-4 mb-5">
              <UserAvatar username={profile.username} />
              <div>
                <p className="text-sm font-semibold text-foreground font-mono">@{profile.username}</p>
                <p className="text-xs text-muted-foreground">Username cannot be changed</p>
              </div>
            </div>

            {editState.error && (
              <div
                role="alert"
                className="flex items-start gap-2 mb-4 p-3 rounded-md bg-destructive/10 border border-destructive/30 text-destructive text-sm"
              >
                <AlertCircle size={16} className="shrink-0 mt-0.5" />
                <span>{editState.error}</span>
              </div>
            )}

            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="display_name">Display Name</Label>
                <Input
                  id="display_name"
                  name="display_name"
                  type="text"
                  defaultValue={profile.display_name ?? ""}
                  placeholder="Your display name"
                  autoFocus
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  name="email"
                  type="email"
                  defaultValue={profile.email}
                  placeholder="you@example.com"
                  required
                />
              </div>
            </div>

            <div className="flex gap-3 mt-5">
              <Button type="submit" disabled={editPending} size="sm">
                {editPending ? (
                  <>
                    <Loader2 size={14} className="animate-spin" aria-hidden="true" />
                    Saving…
                  </>
                ) : (
                  "Save Changes"
                )}
              </Button>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setEditing(false)}
                disabled={editPending}
              >
                <X size={14} aria-hidden="true" />
                Cancel
              </Button>
            </div>
          </form>
        )}
      </section>

      {/* ------------------------------------------------------------------ */}
      {/* Section 2 — Account Security card                                  */}
      {/* ------------------------------------------------------------------ */}
      <section className="glass-card p-6" aria-label="Account security">
        <div className="flex items-center gap-3 mb-5">
          <Lock size={18} className="text-primary" aria-hidden="true" />
          <h2 className="text-base font-semibold text-foreground">Account Security</h2>
        </div>

        <div className="space-y-4">
          {/* Change Password */}
          <div className="flex items-center justify-between gap-4 py-3 border-b border-white/5">
            <div>
              <p className="text-sm font-medium text-foreground">Password</p>
              <p className="text-xs text-muted-foreground mt-0.5">Update your account password</p>
            </div>
            <Button variant="outline" size="sm" asChild>
              <Link to="/profile/change-password">Change Password</Link>
            </Button>
          </div>

          {/* MFA Status */}
          <div className="flex items-center justify-between gap-4 py-3">
            <div>
              <div className="flex items-center gap-2">
                <Shield size={14} className="text-primary" aria-hidden="true" />
                <p className="text-sm font-medium text-foreground">Multi-Factor Authentication</p>
              </div>
              {mfaMethods && mfaMethods.length > 0 ? (
                <p className="text-xs text-emerald-400 mt-0.5">
                  Enabled · {mfaMethods.length} method{mfaMethods.length !== 1 ? "s" : ""}
                </p>
              ) : (
                <p className="text-xs text-amber-400 mt-0.5">Disabled — recommended for security</p>
              )}
            </div>
            <Button variant="outline" size="sm" asChild>
              <Link to="/profile/mfa">Manage MFA</Link>
            </Button>
          </div>
        </div>
      </section>
    </div>
  );
}

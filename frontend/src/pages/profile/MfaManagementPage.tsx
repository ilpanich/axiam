import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Shield,
  Trash2,
  Loader2,
  AlertCircle,
  KeyRound,
  Fingerprint,
  Usb,
} from "lucide-react";
import {
  webauthnService,
  isWebauthnSupported,
  classifyWebauthnError,
  webauthnErrorMessage,
  type AuthenticatorKind,
} from "@/services/webauthn";
import { authService } from "@/services/auth";
import { useAuthStore } from "@/stores/auth";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { DataTable } from "@/components/DataTable";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { TotpSetupPanel } from "@/components/auth/TotpSetupPanel";
import type { Column } from "@/components/DataTable";
import type { AxiosError } from "axios";

// ---------------------------------------------------------------------------
// Types & API helpers
// ---------------------------------------------------------------------------

// CQ-F17/QUAL-06: use canonical MfaMethod type + userService methods from
// services/users.ts instead of inline api.get/api.delete (D-16).
import { userService, type MfaMethod } from "@/services/users";
export type { MfaMethod };

interface TotpSetupResponse {
  secret_base32: string;
  totp_uri: string;
}

interface ErrorResponse {
  message?: string;
  error?: string;
}

// ---------------------------------------------------------------------------
// Method type badge
// ---------------------------------------------------------------------------

/**
 * C1: the server's unified `MfaMethod` view already distinguishes
 * `Totp | Passkey | SecurityKey`, so the badge does too. A user with a phone
 * passkey and a YubiKey needs to tell which row is which before deciding what
 * to remove — "WEBAUTHN" on both rows would make that guesswork.
 */
const METHOD_LABELS: Record<string, { label: string; icon: typeof KeyRound; tone: string }> = {
  totp: {
    label: "TOTP",
    icon: KeyRound,
    tone: "bg-primary/10 text-primary border-primary/20",
  },
  passkey: {
    label: "Passkey",
    icon: Fingerprint,
    tone: "bg-accent/10 text-accent border-accent/20",
  },
  securitykey: {
    label: "Security key",
    icon: Usb,
    tone: "bg-accent/10 text-accent border-accent/20",
  },
};

function MethodTypeBadge({ type }: { type: string }) {
  const key = type.toLowerCase().replace(/[^a-z]/g, "");
  const meta = METHOD_LABELS[key] ?? {
    label: type,
    icon: Fingerprint,
    tone: "bg-muted text-muted-foreground border-border",
  };
  const Icon = meta.icon;
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border ${meta.tone}`}
    >
      <Icon size={10} aria-hidden="true" />
      {meta.label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// TOTP Setup Dialog
// ---------------------------------------------------------------------------

interface TotpSetupDialogProps {
  open: boolean;
  onClose: () => void;
  setupData: TotpSetupResponse | null;
  onConfirm: (code: string) => Promise<void>;
  isConfirming: boolean;
  confirmError: string | null;
}

function TotpSetupDialog({
  open,
  onClose,
  setupData,
  onConfirm,
  isConfirming,
  confirmError,
}: TotpSetupDialogProps) {
  const [code, setCode] = useState("");

  useEffect(() => {
    if (open) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setCode("");
    }
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [open, onClose]);

  if (!open || !setupData) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      aria-modal="true"
      role="dialog"
      aria-labelledby="totp-setup-title"
    >
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-xs"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Panel */}
      <div className="relative z-10 glass-card w-full max-w-sm space-y-5">
        <div>
          <h2 id="totp-setup-title" className="text-lg font-semibold text-foreground">
            Set up TOTP Authenticator
          </h2>
          <p className="text-sm text-muted-foreground mt-1">
            Scan the QR code with your authenticator app, then enter the 6-digit code to confirm.
          </p>
        </div>

        <TotpSetupPanel
          setupData={setupData}
          code={code}
          onCodeChange={setCode}
          onConfirm={onConfirm}
          error={confirmError}
          isPending={isConfirming}
          onCancel={onClose}
        />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// MfaManagementPage
// ---------------------------------------------------------------------------

export function MfaManagementPage() {
  const queryClient = useQueryClient();
  const userId = useAuthStore((s) => s.user?.id);
  const [deleteTarget, setDeleteTarget] = useState<MfaMethod | null>(null);
  const [totpDialogOpen, setTotpDialogOpen] = useState(false);
  const [totpSetupData, setTotpSetupData] = useState<TotpSetupResponse | null>(null);
  const [totpConfirmError, setTotpConfirmError] = useState<string | null>(null);
  // C1: WebAuthn enrolment state. `pendingKind` exists only so the two buttons
  // can show their own spinner — one shared `isPending` would spin both.
  const [webauthnError, setWebauthnError] = useState<string | null>(null);
  const [pendingKind, setPendingKind] = useState<AuthenticatorKind | null>(null);
  const webauthnSupported = isWebauthnSupported();

  const { data: methods = [], isLoading } = useQuery({
    queryKey: ["mfaMethods", userId],
    queryFn: () => userService.listMfaMethods(userId!),
    enabled: !!userId,
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => userService.deleteMfaMethod(userId!, id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["mfaMethods"] });
      setDeleteTarget(null);
    },
  });

  const setupMutation = useMutation({
    mutationFn: authService.enrollMfa,
    onSuccess: (data) => {
      setTotpSetupData(data);
      setTotpConfirmError(null);
      setTotpDialogOpen(true);
    },
  });

  const confirmMutation = useMutation({
    mutationFn: authService.confirmMfa,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["mfaMethods"] });
      setTotpDialogOpen(false);
      setTotpSetupData(null);
    },
    onError: (err) => {
      const axiosErr = err as AxiosError<ErrorResponse>;
      const msg =
        axiosErr.response?.data?.message ??
        axiosErr.response?.data?.error ??
        "Invalid or expired code. Please try again.";
      setTotpConfirmError(msg);
    },
  });

  const enrolMutation = useMutation({
    mutationFn: ({ name, kind }: { name: string; kind: AuthenticatorKind }) =>
      webauthnService.register(name, kind),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["mfaMethods"] });
      setWebauthnError(null);
      setPendingKind(null);
    },
    onError: (err) => {
      // Every ceremony failure arrives as a DOMException whose `name` is the
      // only machine-readable part; the service classifies it so this page
      // does not have to know that "NotAllowedError" means "cancelled or
      // timed out, and the spec will not tell you which".
      setWebauthnError(webauthnErrorMessage(classifyWebauthnError(err)));
      setPendingKind(null);
    },
  });

  const startEnrolment = (kind: AuthenticatorKind) => {
    setWebauthnError(null);
    setPendingKind(kind);
    // A default name the user can recognise later. Both kinds land in the same
    // credential list, so the name is what tells "my laptop" from "my YubiKey".
    const existing = methods.filter(
      (m) => m.method_type.toLowerCase() !== "totp",
    ).length;
    const label = kind === "platform" ? "Passkey" : "Security key";
    enrolMutation.mutate({
      name: existing > 0 ? `${label} ${existing + 1}` : label,
      kind,
    });
  };

  const handleConfirmTotp = async (code: string) => {
    setTotpConfirmError(null);
    confirmMutation.mutate(code);
  };

  const columns: Column<MfaMethod>[] = [
    {
      key: "method_type",
      header: "Type",
      render: (row) => <MethodTypeBadge type={row.method_type} />,
      width: "w-28",
    },
    {
      key: "name",
      header: "Name",
    },
    {
      key: "created_at",
      header: "Added",
      render: (row) => (
        <span className="text-muted-foreground text-xs">
          {new Date(row.created_at).toLocaleDateString()}
        </span>
      ),
      width: "w-32",
    },
    {
      key: "actions",
      header: "",
      render: (row) => (
        <button
          onClick={() => setDeleteTarget(row)}
          className="inline-flex items-center gap-1 px-2 py-1 text-xs rounded text-destructive/80 hover:text-destructive hover:bg-destructive/10 transition-colors"
          aria-label={`Remove ${row.name}`}
        >
          <Trash2 size={12} aria-hidden="true" />
          Remove
        </button>
      ),
      width: "w-20",
    },
  ];

  return (
    <div className="space-y-6 max-w-2xl">
      <PageHeader
        title="MFA Methods"
        description="Manage your multi-factor authentication methods."
      />

      {/* ------------------------------------------------------------------ */}
      {/* Registered methods                                                  */}
      {/* ------------------------------------------------------------------ */}
      <section aria-label="Registered MFA methods">
        <div className="flex items-center gap-3 mb-4">
          <Shield size={16} className="text-primary" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-foreground uppercase tracking-wide">
            Registered Methods
          </h2>
        </div>
        <DataTable
          columns={columns}
          data={methods}
          isLoading={isLoading}
          emptyMessage="No MFA methods registered. Add one below for better security."
        />
      </section>

      {/* ------------------------------------------------------------------ */}
      {/* Add TOTP                                                            */}
      {/* ------------------------------------------------------------------ */}
      <section className="glass-card p-5" aria-label="Add TOTP authenticator">
        <div className="flex items-center gap-3 mb-3">
          <KeyRound size={16} className="text-primary" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-foreground">Authenticator App (TOTP)</h2>
        </div>
        <p className="text-sm text-muted-foreground mb-4">
          Use an authenticator app (Google Authenticator, Authy, 1Password, etc.) to generate
          time-based one-time passwords.
        </p>
        {setupMutation.isError && (
          <div
            role="alert"
            className="flex items-start gap-2 mb-3 p-3 rounded-md bg-destructive/10 border border-destructive/30 text-destructive text-sm"
          >
            <AlertCircle size={14} className="shrink-0 mt-0.5" />
            <span>Failed to start TOTP setup. Please try again.</span>
          </div>
        )}
        <Button
          onClick={() => setupMutation.mutate()}
          disabled={setupMutation.isPending}
          size="sm"
        >
          {setupMutation.isPending ? (
            <>
              <Loader2 size={14} className="animate-spin" aria-hidden="true" />
              Setting up…
            </>
          ) : (
            "Set up TOTP Authenticator"
          )}
        </Button>
      </section>

      {/* ------------------------------------------------------------------ */}
      {/* Passkeys & security keys (C1)                                       */}
      {/* ------------------------------------------------------------------ */}
      <section className="glass-card p-5" aria-label="Passkeys and security keys">
        <div className="flex items-center gap-3 mb-3">
          <Fingerprint size={16} className="text-accent" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-foreground">Passkeys &amp; security keys</h2>
        </div>
        <p className="text-sm text-muted-foreground mb-4">
          Sign in with Touch&nbsp;ID, Face&nbsp;ID, Windows&nbsp;Hello, or a hardware
          security key instead of typing a code. Both are phishing-resistant: they
          only work on this site, so a lookalike page cannot use them.
        </p>

        {!webauthnSupported ? (
          // Feature detection rather than letting a click fail: a browser
          // without WebAuthn cannot be talked into having it, so offering the
          // button would only produce an error the user cannot act on.
          <p
            role="note"
            className="flex items-start gap-2 p-3 rounded-md bg-muted/40 border border-border text-sm text-muted-foreground"
          >
            <AlertCircle size={14} className="shrink-0 mt-0.5" aria-hidden="true" />
            <span>
              This browser does not support passkeys. Try a recent version of Chrome,
              Safari, Edge or Firefox — your other sign-in methods still work here.
            </span>
          </p>
        ) : (
          <>
            {webauthnError && (
              <div
                role="alert"
                className="flex items-start gap-2 mb-3 p-3 rounded-md bg-destructive/10 border border-destructive/30 text-destructive text-sm"
              >
                <AlertCircle size={14} className="shrink-0 mt-0.5" aria-hidden="true" />
                <span>{webauthnError}</span>
              </div>
            )}
            <div className="flex flex-wrap gap-2">
              <Button
                onClick={() => startEnrolment("platform")}
                disabled={enrolMutation.isPending}
                size="sm"
              >
                {enrolMutation.isPending && pendingKind === "platform" ? (
                  <>
                    <Loader2 size={14} className="animate-spin" aria-hidden="true" />
                    Waiting for your device…
                  </>
                ) : (
                  <>
                    <Fingerprint size={14} aria-hidden="true" />
                    Add a passkey
                  </>
                )}
              </Button>
              <Button
                onClick={() => startEnrolment("cross-platform")}
                disabled={enrolMutation.isPending}
                size="sm"
                variant="outline"
              >
                {enrolMutation.isPending && pendingKind === "cross-platform" ? (
                  <>
                    <Loader2 size={14} className="animate-spin" aria-hidden="true" />
                    Waiting for your key…
                  </>
                ) : (
                  <>
                    <Usb size={14} aria-hidden="true" />
                    Add a security key
                  </>
                )}
              </Button>
            </div>
          </>
        )}
      </section>

      {/* Confirm delete dialog */}
      <ConfirmDialog
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => {
          if (deleteTarget) deleteMutation.mutate(deleteTarget.id);
        }}
        title="Remove MFA Method"
        description={`Remove "${deleteTarget?.name ?? "this method"}"? You can re-add it later.`}
        isLoading={deleteMutation.isPending}
        confirmLabel="Remove"
      />

      {/* TOTP Setup Dialog */}
      <TotpSetupDialog
        open={totpDialogOpen}
        onClose={() => {
          setTotpDialogOpen(false);
          setTotpSetupData(null);
          setTotpConfirmError(null);
        }}
        setupData={totpSetupData}
        onConfirm={handleConfirmTotp}
        isConfirming={confirmMutation.isPending}
        confirmError={totpConfirmError}
      />
    </div>
  );
}

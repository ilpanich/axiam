import { useState, useRef, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Shield, Trash2, Loader2, AlertCircle, Copy, Check, KeyRound, Fingerprint } from "lucide-react";
import api from "@/lib/api";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { DataTable } from "@/components/DataTable";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import type { Column } from "@/components/DataTable";
import type { AxiosError } from "axios";

// ---------------------------------------------------------------------------
// Types & API helpers
// ---------------------------------------------------------------------------

export interface MfaMethod {
  id: string;
  method_type: string;
  name: string;
  created_at: string;
}

interface TotpSetupResponse {
  secret: string;
  qr_code_uri: string;
}

interface ErrorResponse {
  message?: string;
  error?: string;
}

async function getMfaMethods(): Promise<MfaMethod[]> {
  const res = await api.get<MfaMethod[]>("/api/v1/users/me/mfa-methods");
  return res.data;
}

async function deleteMfaMethod(id: string): Promise<void> {
  await api.delete(`/api/v1/users/me/mfa-methods/${id}`);
}

async function setupTotp(): Promise<TotpSetupResponse> {
  const res = await api.post<TotpSetupResponse>("/auth/mfa/setup");
  return res.data;
}

async function confirmTotp(code: string): Promise<void> {
  await api.post("/auth/mfa/confirm", { code });
}

// ---------------------------------------------------------------------------
// Method type badge
// ---------------------------------------------------------------------------

function MethodTypeBadge({ type }: { type: string }) {
  const isTotp = type.toLowerCase() === "totp";
  return (
    <span
      className={
        isTotp
          ? "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-primary/10 text-primary border border-primary/20"
          : "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-accent/10 text-accent border border-accent/20"
      }
    >
      {isTotp ? <KeyRound size={10} aria-hidden="true" /> : <Fingerprint size={10} aria-hidden="true" />}
      {type.toUpperCase()}
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
  const [copied, setCopied] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setCode("");
      setCopied(false);
      setTimeout(() => inputRef.current?.focus(), 100);
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

  const isDataUrl = setupData.qr_code_uri.startsWith("data:");

  const handleCopy = async () => {
    await navigator.clipboard.writeText(setupData.secret);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (code.length === 6) {
      await onConfirm(code);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      aria-modal="true"
      role="dialog"
      aria-labelledby="totp-setup-title"
    >
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
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

        {/* QR code area */}
        <div className="flex flex-col items-center gap-3">
          {isDataUrl ? (
            <img
              src={setupData.qr_code_uri}
              alt="TOTP QR code — scan with your authenticator app"
              className="h-40 w-40 rounded-lg border border-white/10 bg-white p-1"
            />
          ) : (
            <div className="text-xs text-muted-foreground text-center p-4 bg-white/5 rounded-lg border border-white/10">
              <p className="font-mono break-all">{setupData.qr_code_uri}</p>
              <p className="mt-2">Scan this URI with your authenticator app.</p>
            </div>
          )}
        </div>

        {/* Manual entry */}
        <div className="space-y-1.5">
          <p className="text-xs text-muted-foreground">Or enter this key manually:</p>
          <div className="flex items-center gap-2">
            <code className="flex-1 text-xs font-mono bg-white/5 border border-white/10 rounded px-3 py-2 text-primary break-all">
              {setupData.secret}
            </code>
            <button
              type="button"
              onClick={handleCopy}
              className="p-2 rounded hover:bg-white/10 transition-colors text-muted-foreground hover:text-foreground shrink-0"
              aria-label="Copy secret key"
            >
              {copied ? (
                <Check size={14} className="text-emerald-400" />
              ) : (
                <Copy size={14} />
              )}
            </button>
          </div>
        </div>

        {/* Verification input */}
        <form onSubmit={handleSubmit} noValidate>
          {confirmError && (
            <div
              role="alert"
              className="flex items-start gap-2 mb-3 p-3 rounded-md bg-destructive/10 border border-destructive/30 text-destructive text-sm"
            >
              <AlertCircle size={14} className="shrink-0 mt-0.5" />
              <span>{confirmError}</span>
            </div>
          )}

          <div className="space-y-1.5">
            <Label htmlFor="totp-verify-code">Verification Code</Label>
            <input
              ref={inputRef}
              id="totp-verify-code"
              type="text"
              inputMode="numeric"
              pattern="[0-9]{6}"
              maxLength={6}
              placeholder="000000"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              autoComplete="one-time-code"
              className="flex h-10 w-full rounded-md px-3 py-2 text-sm bg-white/5 border border-primary/20 text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/40 focus:border-primary disabled:cursor-not-allowed disabled:opacity-50 transition-colors duration-200 text-center text-xl tracking-[0.4em] font-mono"
              required
            />
          </div>

          <div className="flex justify-end gap-3 mt-4">
            <Button type="button" variant="outline" size="sm" onClick={onClose} disabled={isConfirming}>
              Cancel
            </Button>
            <Button type="submit" size="sm" disabled={isConfirming || code.length !== 6}>
              {isConfirming ? (
                <>
                  <Loader2 size={14} className="animate-spin" aria-hidden="true" />
                  Confirming…
                </>
              ) : (
                "Confirm"
              )}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// MfaManagementPage
// ---------------------------------------------------------------------------

export function MfaManagementPage() {
  const queryClient = useQueryClient();
  const [deleteTarget, setDeleteTarget] = useState<MfaMethod | null>(null);
  const [totpDialogOpen, setTotpDialogOpen] = useState(false);
  const [totpSetupData, setTotpSetupData] = useState<TotpSetupResponse | null>(null);
  const [totpConfirmError, setTotpConfirmError] = useState<string | null>(null);

  const { data: methods = [], isLoading } = useQuery({
    queryKey: ["mfaMethods"],
    queryFn: getMfaMethods,
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteMfaMethod(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["mfaMethods"] });
      setDeleteTarget(null);
    },
  });

  const setupMutation = useMutation({
    mutationFn: setupTotp,
    onSuccess: (data) => {
      setTotpSetupData(data);
      setTotpConfirmError(null);
      setTotpDialogOpen(true);
    },
  });

  const confirmMutation = useMutation({
    mutationFn: confirmTotp,
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
      {/* Passkeys — Coming soon                                              */}
      {/* ------------------------------------------------------------------ */}
      <section className="glass-card p-5 opacity-70" aria-label="Passkeys coming soon">
        <div className="flex items-center gap-3 mb-3">
          <Fingerprint size={16} className="text-accent" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-foreground">WebAuthn / Passkeys</h2>
          <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-accent/10 text-accent border border-accent/20">
            Coming soon
          </span>
        </div>
        <p className="text-sm text-muted-foreground mb-4">
          Use a hardware security key, Touch ID, Face ID, or Windows Hello as a second factor.
          WebAuthn/Passkey support is planned for a future release.
        </p>
        <Button size="sm" disabled>
          <Fingerprint size={14} aria-hidden="true" />
          Add Passkey
        </Button>
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

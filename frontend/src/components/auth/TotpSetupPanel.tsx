import { useEffect, useRef, useState } from "react";
import { AlertCircle, Copy, Check, Loader2 } from "lucide-react";
import { QRCodeSVG } from "qrcode.react";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";

// ---------------------------------------------------------------------------
// TotpSetupPanel — shared presentational TOTP QR/secret/code-input UI
// ---------------------------------------------------------------------------
//
// Extracted from `MfaManagementPage`'s private `TotpSetupDialog` (26-08 /
// CORR-05b, RESEARCH Pattern 5 / Assumption A3) so the same QR+secret+code
// markup can be reused both inside MfaManagementPage's existing dialog
// chrome (self-service enroll/confirm) and inlined as a page body on the new
// public `/auth/mfa-setup` route (`MfaSetupPage`, no authenticated shell to
// host a modal over).
//
// Purely props-driven — no internal data fetching, no endpoint knowledge.

export interface TotpSetupPanelData {
  secret_base32: string;
  totp_uri: string;
}

export interface TotpSetupPanelProps {
  setupData: TotpSetupPanelData;
  code: string;
  onCodeChange: (code: string) => void;
  onConfirm: (code: string) => void | Promise<void>;
  error: string | null;
  isPending: boolean;
  /** Copy for the primary submit button when idle (default: "Confirm"). */
  confirmLabel?: string;
  /** Copy for the primary submit button while pending (default: "Confirming…"). */
  confirmPendingLabel?: string;
  /**
   * Optional Cancel action, rendered alongside the submit button (preserves
   * MfaManagementPage's existing dialog chrome — Cancel + Confirm in one
   * row). Omitted on the public MfaSetupPage, which has no cancel action.
   */
  onCancel?: () => void;
  cancelLabel?: string;
}

export function TotpSetupPanel({
  setupData,
  code,
  onCodeChange,
  onConfirm,
  error,
  isPending,
  confirmLabel = "Confirm",
  confirmPendingLabel = "Confirming…",
  onCancel,
  cancelLabel = "Cancel",
}: TotpSetupPanelProps) {
  const [copied, setCopied] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Autofocus the code input when the panel mounts (setup data resolved),
  // mirroring TotpSetupDialog's original focus-on-open behavior.
  useEffect(() => {
    const t = setTimeout(() => inputRef.current?.focus(), 100);
    return () => clearTimeout(t);
  }, []);

  const isDataUrl = setupData.totp_uri.startsWith("data:");

  const handleCopy = async () => {
    await navigator.clipboard.writeText(setupData.secret_base32);
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
    <div className="space-y-5">
      {/* QR code area — backend returns an otpauth:// URI; render it as a
          scannable QR client-side (it is not a data: image). */}
      <div className="flex flex-col items-center gap-3">
        {isDataUrl ? (
          <img
            src={setupData.totp_uri}
            alt="TOTP QR code — scan with your authenticator app"
            className="h-40 w-40 rounded-lg border border-white/10 bg-white p-1"
          />
        ) : (
          <QRCodeSVG
            value={setupData.totp_uri}
            size={160}
            level="M"
            marginSize={2}
            bgColor="#ffffff"
            fgColor="#0a0a0a"
            title="TOTP QR code — scan with your authenticator app"
            className="h-44 w-44 rounded-lg border border-white/10 bg-white p-2"
          />
        )}
      </div>

      {/* Manual entry */}
      <div className="space-y-2">
        <p className="text-xs text-muted-foreground">Or enter this key manually:</p>
        <div className="flex items-center gap-2">
          <code className="flex-1 text-xs font-mono bg-white/5 border border-white/10 rounded px-3 py-2 text-primary break-all">
            {setupData.secret_base32}
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
        {error && (
          <div
            role="alert"
            className="flex items-start gap-2 mb-3 p-3 rounded-md bg-destructive/10 border border-destructive/30 text-destructive text-sm"
          >
            <AlertCircle size={14} className="shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <div className="space-y-2">
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
            onChange={(e) => onCodeChange(e.target.value.replace(/\D/g, "").slice(0, 6))}
            autoComplete="one-time-code"
            className="flex h-10 w-full rounded-md px-3 py-2 text-sm bg-white/5 border border-primary/20 text-foreground placeholder:text-muted-foreground focus:outline-hidden focus:ring-2 focus:ring-primary/40 focus:border-primary disabled:cursor-not-allowed disabled:opacity-50 transition-colors duration-200 text-center text-xl tracking-[0.4em] font-mono"
            required
          />
        </div>

        <div className="flex justify-end gap-3 mt-4">
          {onCancel && (
            <Button type="button" variant="outline" size="sm" onClick={onCancel} disabled={isPending}>
              {cancelLabel}
            </Button>
          )}
          <Button type="submit" size="sm" disabled={isPending || code.length !== 6}>
            {isPending ? (
              <>
                <Loader2 size={14} className="animate-spin" aria-hidden="true" />
                {confirmPendingLabel}
              </>
            ) : (
              confirmLabel
            )}
          </Button>
        </div>
      </form>
    </div>
  );
}

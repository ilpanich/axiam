import { useCallback, useEffect, useRef, useState } from "react";
import { Check, Copy, Download, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useModalA11y } from "@/hooks/useModalA11y";
import { certificateFilename, downloadTextFile } from "@/lib/download";

/**
 * One labelled field in the summary grid.
 */
export interface CertificateDetail {
  label: string;
  /** Rendered as-is; pass a `<code>`/`<StatusBadge>` for anything non-textual. */
  value: React.ReactNode;
}

export interface CertificateViewDialogProps {
  open: boolean;
  onClose: () => void;
  /** Names the dialog and seeds the download filename. */
  subject: string;
  /** Heading — "Certificate" or "CA Certificate". */
  title?: string;
  /** PEM-encoded public certificate. */
  publicCertPem: string;
  /**
   * The issuers above it, concatenated PEM, nearest first.
   *
   * When present, a third download offers certificate-plus-chain as one file,
   * which is what a server or an mTLS client normally wants: most TLS stacks
   * take a single file containing the leaf followed by its issuers, and
   * assembling that by hand is where operators lose a newline.
   */
  chainPem?: string;
  /** Summary rows — subject, fingerprint, validity, status, and so on. */
  details: CertificateDetail[];
}

// ─── Copy-to-clipboard, with the same two-second acknowledgement the secret
//     reveal modal uses so the two dialogs do not behave differently ──────────

function CopyPemButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(
    () => () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    },
    []
  );

  async function handleCopy() {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
      } else {
        // Non-secure contexts and older browsers have no Clipboard API.
        const el = document.createElement("textarea");
        el.value = value;
        el.style.position = "fixed";
        el.style.top = "-9999px";
        document.body.appendChild(el);
        el.select();
        document.execCommand("copy");
        document.body.removeChild(el);
      }
      setCopied(true);
      if (timerRef.current) clearTimeout(timerRef.current);
      timerRef.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard access is refused outright in some contexts; the download
      // button next to this one still works, so there is nothing to report.
    }
  }

  return (
    <button
      type="button"
      onClick={() => void handleCopy()}
      aria-label={copied ? `${label} copied` : `Copy ${label}`}
      className="focus-ring shrink-0 inline-flex items-center gap-1.5 rounded border border-white/10 px-2.5 py-1 text-xs font-medium text-muted-foreground transition-colors hover:text-foreground"
    >
      {copied ? <Check size={12} /> : <Copy size={12} />}
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

/**
 * Read the public half of a certificate, and take a copy of it.
 *
 * The private key is shown once, on generation, and never again — that is
 * deliberate and unchanged. The *public* certificate is not a secret and is
 * exactly what has to be distributed: to a device being provisioned, to a
 * relying party pinning an issuer, to whoever is debugging why a chain will not
 * validate. It was previously reachable only through the API, which left the
 * admin UI able to create certificates and unable to hand one over.
 */
export function CertificateViewDialog({
  open,
  onClose,
  subject,
  title = "Certificate",
  publicCertPem,
  chainPem,
  details,
}: CertificateViewDialogProps) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);

  useModalA11y(open);

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
        return;
      }
      if (e.key !== "Tab" || !dialogRef.current) return;
      const focusable = dialogRef.current.querySelectorAll<HTMLElement>(
        'button:not([disabled]), [href], [tabindex]:not([tabindex="-1"])'
      );
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    },
    [onClose]
  );

  useEffect(() => {
    if (!open) return;
    closeRef.current?.focus();
  }, [open]);

  useEffect(() => {
    if (!open) return;
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [open, handleKeyDown]);

  if (!open) return null;

  // `.crt` for the certificate alone and `.pem` for a bundle, which is the
  // convention every tool that reads them already assumes.
  const fullChain = chainPem
    ? `${publicCertPem.trimEnd()}\n${chainPem.trimEnd()}\n`
    : null;

  return (
    <div
      ref={dialogRef}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      aria-modal="true"
      role="dialog"
      aria-labelledby="certificate-view-title"
    >
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-xs"
        onClick={onClose}
        aria-hidden="true"
      />

      <div className="relative z-10 glass-card flex max-h-[90dvh] w-full max-w-2xl flex-col p-6">
        <div className="flex items-start justify-between gap-4 border-b border-primary/10 pb-4">
          <div className="min-w-0">
            <h2
              id="certificate-view-title"
              className="text-lg font-semibold text-foreground"
            >
              {title}
            </h2>
            <p className="mt-0.5 truncate text-sm text-muted-foreground">
              {subject}
            </p>
          </div>
          <button
            ref={closeRef}
            onClick={onClose}
            className="focus-ring rounded p-1 text-muted-foreground transition-colors hover:text-foreground"
            aria-label="Close dialog"
          >
            <X size={18} />
          </button>
        </div>

        <div className="min-h-0 flex-1 space-y-5 overflow-y-auto py-4">
          <dl className="grid gap-x-4 gap-y-3 sm:grid-cols-2">
            {details.map((detail) => (
              <div key={detail.label} className="min-w-0">
                <dt className="text-xs font-semibold uppercase tracking-wider text-primary/70">
                  {detail.label}
                </dt>
                <dd className="mt-1 break-all text-sm text-foreground/90">
                  {detail.value}
                </dd>
              </div>
            ))}
          </dl>

          <div className="space-y-1.5">
            <div className="flex items-center justify-between gap-3">
              <span className="text-xs font-semibold uppercase tracking-wider text-primary/70">
                Certificate (PEM)
              </span>
              <CopyPemButton value={publicCertPem} label="certificate PEM" />
            </div>
            <div className="overflow-x-auto rounded-md border border-white/10 bg-white/[0.04] p-3">
              <pre className="whitespace-pre-wrap break-all font-mono text-xs leading-relaxed text-foreground/80">
                {publicCertPem}
              </pre>
            </div>
          </div>

          {chainPem && (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between gap-3">
                <span className="text-xs font-semibold uppercase tracking-wider text-primary/70">
                  Issuing chain (PEM)
                </span>
                <CopyPemButton value={chainPem} label="chain PEM" />
              </div>
              <div className="overflow-x-auto rounded-md border border-white/10 bg-white/[0.04] p-3">
                <pre className="whitespace-pre-wrap break-all font-mono text-xs leading-relaxed text-foreground/80">
                  {chainPem}
                </pre>
              </div>
              <p className="text-xs text-muted-foreground">
                Everything above this certificate, nearest issuer first. A
                relying party needs it to validate a chain — and when the CA
                lives in Vault&rsquo;s PKI engine, this is the only copy of the
                root outside Vault.
              </p>
            </div>
          )}
        </div>

        <div className="flex shrink-0 flex-wrap justify-end gap-3 border-t border-primary/10 pt-4">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() =>
              downloadTextFile(
                certificateFilename(subject, "crt"),
                publicCertPem.endsWith("\n") ? publicCertPem : `${publicCertPem}\n`
              )
            }
          >
            <Download size={14} />
            Certificate (.crt)
          </Button>
          {fullChain && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() =>
                downloadTextFile(
                  certificateFilename(`${subject}-fullchain`, "pem"),
                  fullChain
                )
              }
            >
              <Download size={14} />
              Full chain (.pem)
            </Button>
          )}
          <Button type="button" size="sm" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </div>
  );
}

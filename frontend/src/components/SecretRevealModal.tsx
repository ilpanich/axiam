import { useEffect, useRef, useState } from "react";
import { AlertTriangle, Check, Copy } from "lucide-react";
import { buttonVariants } from "@/components/ui/button";

export interface SecretEntry {
  label: string;
  value: string;
  mono?: boolean;
}

export interface SecretRevealModalProps {
  open: boolean;
  onClose: () => void;
  title: string;
  description: string;
  secrets: SecretEntry[];
}

// ─── Copy button with 2-second "Copied!" feedback ─────────────────────────────

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
      } else {
        // Graceful fallback for environments without Clipboard API
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
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Silently fail — clipboard access denied in some contexts
    }
  }

  return (
    <button
      type="button"
      onClick={() => void handleCopy()}
      aria-label={copied ? "Copied!" : "Copy to clipboard"}
      className="shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium border transition-all duration-150 focus:outline-none focus:ring-2 focus:ring-primary/40"
      style={
        copied
          ? {
              borderColor: "rgba(0,212,255,0.4)",
              color: "rgb(0,212,255)",
              background: "rgba(0,212,255,0.08)",
            }
          : {
              borderColor: "rgba(255,255,255,0.12)",
              color: "rgba(255,255,255,0.55)",
              background: "transparent",
            }
      }
    >
      {copied ? (
        <>
          <Check size={12} />
          Copied!
        </>
      ) : (
        <>
          <Copy size={12} />
          Copy
        </>
      )}
    </button>
  );
}

// ─── Main modal ───────────────────────────────────────────────────────────────

export function SecretRevealModal({
  open,
  onClose,
  title,
  description,
  secrets,
}: SecretRevealModalProps) {
  const ackRef = useRef<HTMLButtonElement>(null);

  // Focus the acknowledge button when opened; no Escape to close (force acknowledgment)
  useEffect(() => {
    if (!open) return;
    // Small delay to allow render
    const id = setTimeout(() => ackRef.current?.focus(), 50);
    return () => clearTimeout(id);
  }, [open]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center p-4"
      aria-modal="true"
      role="alertdialog"
      aria-labelledby="secret-modal-title"
      aria-describedby="secret-modal-desc"
    >
      {/* Backdrop — intentionally non-interactive (no onClick) to force acknowledgment */}
      <div
        className="absolute inset-0 bg-black/70 backdrop-blur-sm"
        aria-hidden="true"
      />

      {/* Panel */}
      <div className="relative z-10 w-full max-w-lg flex flex-col max-h-[90vh] rounded-xl border border-white/10 bg-[#0d0d2b]/95 shadow-2xl shadow-black/60 backdrop-blur-xl">
        {/* Warning banner */}
        <div className="flex items-start gap-3 px-5 py-4 rounded-t-xl bg-amber-500/10 border-b border-amber-500/25">
          <AlertTriangle
            size={18}
            className="shrink-0 mt-0.5 text-amber-400"
            aria-hidden="true"
          />
          <p className="text-sm font-medium text-amber-300 leading-snug">
            Save this information now — it will never be shown again
          </p>
        </div>

        {/* Header */}
        <div className="px-5 pt-5 pb-3">
          <h2
            id="secret-modal-title"
            className="text-lg font-semibold text-foreground"
          >
            {title}
          </h2>
          {description && (
            <p
              id="secret-modal-desc"
              className="mt-1 text-sm text-muted-foreground"
            >
              {description}
            </p>
          )}
        </div>

        {/* Secrets list */}
        <div className="overflow-y-auto px-5 py-2 space-y-4 flex-1">
          {secrets.map((secret, idx) => (
            <div key={idx} className="space-y-1.5">
              <div className="flex items-center justify-between gap-3">
                <span className="text-xs font-semibold uppercase tracking-wider text-primary/70">
                  {secret.label}
                </span>
                <CopyButton value={secret.value} />
              </div>
              <div
                className="relative rounded-md border border-white/10 bg-white/[0.04] p-3 overflow-x-auto"
                role="region"
                aria-label={secret.label}
              >
                <pre
                  className={
                    secret.mono !== false
                      ? "text-xs text-foreground/80 whitespace-pre-wrap break-all font-mono leading-relaxed"
                      : "text-sm text-foreground/80 whitespace-pre-wrap break-all leading-relaxed"
                  }
                >
                  {secret.value}
                </pre>
              </div>
            </div>
          ))}
        </div>

        {/* Footer — only "I've saved" button, no X/Cancel */}
        <div className="px-5 py-4 border-t border-white/10 flex justify-end">
          <button
            ref={ackRef}
            type="button"
            onClick={onClose}
            className={buttonVariants({ className: "min-w-[220px]" })}
          >
            I've saved this information
          </button>
        </div>
      </div>
    </div>
  );
}

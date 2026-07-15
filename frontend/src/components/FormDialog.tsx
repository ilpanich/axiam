import { type ReactNode, useEffect, useRef, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Loader2, X } from "lucide-react";
import { useModalA11y } from "@/hooks/useModalA11y";

interface FormDialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  onSubmit: (e: React.FormEvent<HTMLFormElement>) => void;
  isLoading?: boolean;
  submitLabel?: string;
}

export function FormDialog({
  open,
  onClose,
  title,
  children,
  onSubmit,
  isLoading = false,
  submitLabel = "Save",
}: FormDialogProps) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);

  // Restore focus to the trigger and lock background scroll while open.
  useModalA11y(open);

  // Keep Tab cycling within the dialog and close on Escape
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        if (!isLoading) onClose();
        return;
      }
      if (e.key === "Tab" && dialogRef.current) {
        const focusable = dialogRef.current.querySelectorAll<HTMLElement>(
          'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
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
      }
    },
    [onClose, isLoading],
  );

  // Move focus into the dialog WHEN IT OPENS — prefer the first form field, fall
  // back to the close button. This must depend on `open` ALONE. Previously the
  // focus call shared an effect with the keydown listener (dep: handleKeyDown),
  // and since callers pass an inline `onClose`, handleKeyDown changed identity on
  // every render — so every keystroke re-ran the effect and stole focus back to
  // the close button.
  useEffect(() => {
    if (!open) return;
    const firstField = dialogRef.current?.querySelector<HTMLElement>(
      'input:not([disabled]), select:not([disabled]), textarea:not([disabled])',
    );
    (firstField ?? closeRef.current)?.focus();
  }, [open]);

  // Escape/Tab handling. Re-attaches when the handler identity changes but has no
  // focus side-effect, so re-renders never disturb the caret.
  useEffect(() => {
    if (!open) return;
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [open, handleKeyDown]);

  if (!open) return null;

  return (
    <div
      ref={dialogRef}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      aria-modal="true"
      role="dialog"
      aria-labelledby="form-dialog-title"
    >
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-xs"
        onClick={isLoading ? undefined : onClose}
        aria-hidden="true"
      />

      {/* Panel */}
      <div className="relative z-10 glass-card w-full max-w-md flex flex-col max-h-[90dvh] p-6">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-primary/10">
          <h2
            id="form-dialog-title"
            className="text-lg font-semibold text-foreground"
          >
            {title}
          </h2>
          <button
            ref={closeRef}
            onClick={isLoading ? undefined : onClose}
            className="focus-ring text-muted-foreground hover:text-foreground transition-colors rounded p-1"
            aria-label="Close dialog"
            disabled={isLoading}
          >
            <X size={18} />
          </button>
        </div>

        {/* Body + Footer */}
        <form onSubmit={onSubmit}>
          <div className="overflow-y-auto py-4 space-y-4 -mx-6 px-6">
            {children}
          </div>
          <div className="flex justify-end gap-3 pt-4 border-t border-primary/10">
            <Button
              type="button"
              variant="ghost"
              onClick={onClose}
              disabled={isLoading}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={isLoading} className="min-w-[80px]">
              {isLoading ? (
                <Loader2 size={14} className="animate-spin" />
              ) : (
                submitLabel
              )}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}

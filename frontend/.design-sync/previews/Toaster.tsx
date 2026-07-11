import { useEffect, type ReactNode } from "react";
// Both come from the bundle: the bundled `Toaster` registers its dispatch in the
// BUNDLE's useToast module, so the hook that fires toasts must be the bundle's one
// too. A source-imported `useToast` is a different module instance whose dispatch
// singleton stays null — the card then renders empty, with no error.
import { Toaster, useToast } from "frontend";
import type { ToastOptions } from "@/hooks/useToast";

/**
 * Toast.Viewport is `position: fixed`. The `transform` here makes this wrapper
 * the containing block for fixed descendants (CSS Transforms spec), so toasts
 * dock to the bottom-right of the CELL instead of escaping to the whole sheet.
 */
function Stage({ children }: { children: ReactNode }) {
  return (
    <div
      style={{
        position: "relative",
        transform: "translateZ(0)",
        height: 240,
        width: "100%",
        overflow: "hidden",
        borderRadius: 12,
        border: "1px solid rgba(255,255,255,0.08)",
        background: "linear-gradient(135deg, #0d0d2b 0%, #1a0a3d 100%)",
      }}
    >
      {children}
    </div>
  );
}

function Seed({ toasts }: { toasts: ToastOptions[] }) {
  const { toast } = useToast();
  useEffect(() => {
    // Long duration: the default 5s auto-dismiss would empty the card if the
    // screenshot lands late.
    toasts.forEach((t) => toast({ duration: 600_000, ...t }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return null;
}

function ToastHost({ toasts }: { toasts: ToastOptions[] }) {
  return (
    <Stage>
      <Toaster />
      <Seed toasts={toasts} />
    </Stage>
  );
}

export function DefaultToast() {
  return (
    <ToastHost
      toasts={[{ description: "Role tenant-admin updated — 4 permissions added." }]}
    />
  );
}

export function DestructiveToast() {
  return (
    <ToastHost
      toasts={[
        {
          description:
            "Failed to revoke certificate 3f:a9:1c — the organization CA is offline.",
          variant: "destructive",
        },
      ]}
    />
  );
}

export function StackedToasts() {
  return (
    <ToastHost
      toasts={[
        { description: "Webhook cert-events re-delivered to 2 endpoints." },
        { description: "MFA enforcement is now required for tenant acme-prod." },
        {
          description: "Service account ci-deploy-bot could not be deleted.",
          variant: "destructive",
        },
      ]}
    />
  );
}

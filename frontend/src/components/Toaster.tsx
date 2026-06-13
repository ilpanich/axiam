import { useState, useCallback } from "react";
import * as Toast from "@radix-ui/react-toast";
import { X } from "lucide-react";
import { cn } from "@/lib/utils";
import { type ToastOptions, setToastDispatch } from "@/hooks/useToast";

export type { ToastOptions };

interface ToastEntry extends ToastOptions {
  id: number;
}

let _idCounter = 0;

/**
 * Toaster — mount once in App.tsx.
 * Registers the global dispatch function so useToast() works anywhere
 * in the component tree without a React context.
 */
export function Toaster() {
  const [toasts, setToasts] = useState<ToastEntry[]>([]);

  const dispatch = useCallback((opts: ToastOptions) => {
    const id = ++_idCounter;
    setToasts((prev) => [...prev, { ...opts, id }]);
  }, []);

  setToastDispatch(dispatch);

  function dismiss(id: number) {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }

  return (
    <Toast.Provider swipeDirection="right">
      {toasts.map((t) => (
        <Toast.Root
          key={t.id}
          duration={t.duration ?? 5000}
          onOpenChange={(open) => {
            if (!open) dismiss(t.id);
          }}
          className={cn(
            "flex items-start justify-between gap-3 rounded-md border px-4 py-3 shadow-lg",
            "data-[state=open]:animate-in data-[state=closed]:animate-out",
            "data-[swipe=end]:animate-out data-[state=closed]:fade-out-80",
            "data-[state=open]:slide-in-from-top-full",
            t.variant === "destructive"
              ? "border-destructive/40 bg-destructive/10 text-destructive"
              : "border-primary/20 bg-background/90 text-foreground",
          )}
        >
          <Toast.Description className="text-sm leading-snug">
            {t.description}
          </Toast.Description>
          <Toast.Close
            className="shrink-0 rounded p-0.5 opacity-60 hover:opacity-100 transition-opacity"
            aria-label="Dismiss"
          >
            <X size={14} />
          </Toast.Close>
        </Toast.Root>
      ))}
      <Toast.Viewport className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2 w-[360px] max-w-[90vw]" />
    </Toast.Provider>
  );
}

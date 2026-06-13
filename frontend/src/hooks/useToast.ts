import { useCallback } from "react";

export interface ToastOptions {
  description: string;
  variant?: "default" | "destructive";
  duration?: number;
}

// Module-level dispatcher — set by Toaster on mount, null before mount.
// Using a simple singleton avoids prop-drilling and context overhead for
// a single global toast provider.
export let _toastDispatch: ((opts: ToastOptions) => void) | null = null;

export function setToastDispatch(fn: ((opts: ToastOptions) => void) | null) {
  _toastDispatch = fn;
}

export function useToast() {
  const toast = useCallback((opts: ToastOptions) => {
    if (_toastDispatch) {
      _toastDispatch(opts);
    }
  }, []);
  return { toast };
}

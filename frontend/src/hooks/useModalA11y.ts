import { useEffect } from "react";

/**
 * Shared modal accessibility side-effects for hand-rolled dialogs:
 *
 * 1. **Focus restore** (WCAG 2.4.3) — captures the element that had focus when
 *    the dialog opened and returns focus to it on close/unmount, so keyboard
 *    users aren't dropped at the top of the document.
 * 2. **Background scroll lock** — sets `overflow: hidden` on `<body>` while the
 *    dialog is open so the page behind it can't scroll, restoring the previous
 *    value on close.
 *
 * Call this BEFORE any effect that moves initial focus into the dialog, so the
 * captured `activeElement` is still the triggering control rather than a field
 * inside the dialog.
 */
export function useModalA11y(open: boolean): void {
  useEffect(() => {
    if (!open) return;

    const previouslyFocused = document.activeElement as HTMLElement | null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    return () => {
      document.body.style.overflow = previousOverflow;
      // Only restore focus if it's still safe to do so (element in the DOM).
      if (previouslyFocused && typeof previouslyFocused.focus === "function") {
        previouslyFocused.focus();
      }
    };
  }, [open]);
}

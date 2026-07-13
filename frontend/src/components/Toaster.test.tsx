import { describe, it, expect, afterEach } from "vitest";
import { render, screen, act, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Toaster } from "@/components/Toaster";
import { _toastDispatch, setToastDispatch, type ToastOptions } from "@/hooks/useToast";

// Toaster registers the module-level dispatcher on mount; we push through it
// directly (the live `_toastDispatch` binding) rather than calling the useToast
// hook outside a component.
function push(opts: ToastOptions) {
  act(() => _toastDispatch?.(opts));
}

afterEach(() => setToastDispatch(null));

describe("Toaster", () => {
  it("registers a dispatcher and renders toasts pushed through it", async () => {
    render(<Toaster />);
    expect(_toastDispatch).toBeTypeOf("function");
    push({ description: "Saved!" });
    expect(await screen.findByText("Saved!")).toBeInTheDocument();
  });

  it("renders a destructive toast and dismisses it via the close button", async () => {
    render(<Toaster />);
    push({ description: "Failed!", variant: "destructive" });
    expect(await screen.findByText("Failed!")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Dismiss" }));
    await waitFor(() => expect(screen.queryByText("Failed!")).not.toBeInTheDocument());
  });
});

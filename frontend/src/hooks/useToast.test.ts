import { describe, it, expect, beforeEach, vi } from "vitest";
import { renderHook } from "@testing-library/react";
import { useToast, setToastDispatch, _toastDispatch } from "./useToast";

beforeEach(() => setToastDispatch(null));

describe("useToast", () => {
  it("no-ops safely when no dispatcher is registered", () => {
    const { result } = renderHook(() => useToast());
    expect(() => result.current.toast({ description: "hi" })).not.toThrow();
  });

  it("forwards options to the registered dispatcher", () => {
    const spy = vi.fn();
    setToastDispatch(spy);
    const { result } = renderHook(() => useToast());
    result.current.toast({ description: "saved", variant: "destructive" });
    expect(spy).toHaveBeenCalledWith({ description: "saved", variant: "destructive" });
  });

  it("setToastDispatch installs and clears the module singleton", () => {
    const fn = vi.fn();
    setToastDispatch(fn);
    expect(_toastDispatch).toBe(fn);
    setToastDispatch(null);
    expect(_toastDispatch).toBeNull();
  });

  it("returns a stable toast callback across renders", () => {
    const { result, rerender } = renderHook(() => useToast());
    const first = result.current.toast;
    rerender();
    expect(result.current.toast).toBe(first);
  });
});

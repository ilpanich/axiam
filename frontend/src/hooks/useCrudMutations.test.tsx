import { describe, it, expect, beforeEach, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { useCrudMutations } from "./useCrudMutations";
import { setToastDispatch } from "@/hooks/useToast";

function wrapper(client: QueryClient) {
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
}

let toastSpy: ReturnType<typeof vi.fn>;

beforeEach(() => {
  toastSpy = vi.fn();
  setToastDispatch(toastSpy as unknown as Parameters<typeof setToastDispatch>[0]);
});

describe("useCrudMutations", () => {
  it("create success invalidates queries and fires onCreateSuccess", async () => {
    const client = new QueryClient();
    const invalidate = vi.spyOn(client, "invalidateQueries");
    const onCreateSuccess = vi.fn();
    const createFn = vi.fn().mockResolvedValue({ id: "1" });
    const { result } = renderHook(
      () => useCrudMutations({ queryKey: ["things"], createFn, onCreateSuccess }),
      { wrapper: wrapper(client) }
    );
    result.current.createMutation.mutate({ name: "x" });
    await waitFor(() => expect(onCreateSuccess).toHaveBeenCalled());
    expect(createFn).toHaveBeenCalledWith({ name: "x" });
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ["things"] });
  });

  it("create error routes message to onCreateError and toasts destructive", async () => {
    const client = new QueryClient();
    const onCreateError = vi.fn();
    const createFn = vi.fn().mockRejectedValue({
      isAxiosError: true,
      response: { data: { error: "Name taken" } },
    });
    const { result } = renderHook(
      () => useCrudMutations({ queryKey: ["t"], createFn, onCreateError }),
      { wrapper: wrapper(client) }
    );
    result.current.createMutation.mutate({});
    await waitFor(() => expect(onCreateError).toHaveBeenCalledWith("Name taken"));
    expect(toastSpy).toHaveBeenCalledWith({ description: "Name taken", variant: "destructive" });
  });

  it("update success invalidates and fires onUpdateSuccess", async () => {
    const client = new QueryClient();
    const invalidate = vi.spyOn(client, "invalidateQueries");
    const onUpdateSuccess = vi.fn();
    const updateFn = vi.fn().mockResolvedValue({});
    const { result } = renderHook(
      () => useCrudMutations({ queryKey: ["t"], updateFn, onUpdateSuccess }),
      { wrapper: wrapper(client) }
    );
    result.current.updateMutation.mutate({ id: "1", payload: { name: "y" } });
    await waitFor(() => expect(onUpdateSuccess).toHaveBeenCalled());
    expect(updateFn).toHaveBeenCalledWith("1", { name: "y" });
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ["t"] });
  });

  it("update error routes to onUpdateError", async () => {
    const client = new QueryClient();
    const onUpdateError = vi.fn();
    const updateFn = vi.fn().mockRejectedValue(new Error("nope"));
    const { result } = renderHook(
      () => useCrudMutations({ queryKey: ["t"], updateFn, onUpdateError }),
      { wrapper: wrapper(client) }
    );
    result.current.updateMutation.mutate({ id: "1", payload: {} });
    await waitFor(() => expect(onUpdateError).toHaveBeenCalledWith("nope"));
  });

  it("delete success invalidates and fires onDeleteSuccess", async () => {
    const client = new QueryClient();
    const onDeleteSuccess = vi.fn();
    const deleteFn = vi.fn().mockResolvedValue(undefined);
    const { result } = renderHook(
      () => useCrudMutations({ queryKey: ["t"], deleteFn, onDeleteSuccess }),
      { wrapper: wrapper(client) }
    );
    result.current.deleteMutation.mutate("1");
    await waitFor(() => expect(onDeleteSuccess).toHaveBeenCalled());
    expect(deleteFn).toHaveBeenCalledWith("1");
  });

  it("delete error toasts destructive", async () => {
    const client = new QueryClient();
    const deleteFn = vi.fn().mockRejectedValue({
      isAxiosError: true,
      response: { data: { message: "cannot delete" } },
    });
    const { result } = renderHook(
      () => useCrudMutations({ queryKey: ["t"], deleteFn }),
      { wrapper: wrapper(client) }
    );
    result.current.deleteMutation.mutate("1");
    await waitFor(() =>
      expect(toastSpy).toHaveBeenCalledWith({ description: "cannot delete", variant: "destructive" })
    );
  });

  it("throws when a mutation is invoked without its service fn", async () => {
    const client = new QueryClient();
    const { result } = renderHook(() => useCrudMutations({ queryKey: ["t"] }), {
      wrapper: wrapper(client),
    });
    result.current.createMutation.mutate({});
    await waitFor(() => expect(result.current.createMutation.isError).toBe(true));
    expect(result.current.createMutation.error).toEqual(new Error("createFn not provided"));
  });
});

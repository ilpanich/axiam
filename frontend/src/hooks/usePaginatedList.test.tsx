import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { usePaginatedList } from "@/hooks/usePaginatedList";

interface Row {
  id: string;
}

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

/** The params of the most recent GET. */
function lastParams(): Record<string, unknown> {
  const calls = apiMock.get.mock.calls;
  const last = calls.at(-1);
  if (!last) throw new Error("no GET was issued");
  return (last[1] as { params: Record<string, unknown> }).params;
}

function page(items: Row[], total = items.length, limit = 20) {
  return res({ items, total, offset: 0, limit });
}

describe("usePaginatedList", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiMock.get.mockResolvedValue(page([{ id: "a" }]));
  });

  it("asks the server for the first page", async () => {
    const { result } = renderHook(
      () => usePaginatedList<Row>(["roles"], "/api/v1/roles"),
      { wrapper },
    );
    await waitFor(() => expect(result.current.items).toHaveLength(1));
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/roles", expect.anything());
    expect(lastParams()).toMatchObject({ offset: 0, limit: 20 });
  });

  it("omits `search` entirely when the box is empty", async () => {
    // Sent as `""` this would be a substring match against every row for the
    // same intent — a different query plan for "no filter".
    const { result } = renderHook(
      () => usePaginatedList<Row>(["roles"], "/api/v1/roles"),
      { wrapper },
    );
    await waitFor(() => expect(result.current.items).toHaveLength(1));
    expect(lastParams()).not.toHaveProperty("search");
    expect(result.current.isFiltered).toBe(false);
  });

  it("sends a trimmed term once the debounce elapses", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const { result } = renderHook(
        () => usePaginatedList<Row>(["roles"], "/api/v1/roles"),
        { wrapper },
      );
      await waitFor(() => expect(result.current.items).toHaveLength(1));

      act(() => result.current.setSearch("  admin  "));
      // Not yet: every keystroke would otherwise be a request, and the
      // responses can arrive out of order.
      expect(lastParams()).not.toHaveProperty("search");

      await act(async () => {
        vi.advanceTimersByTime(300);
      });
      await waitFor(() => expect(lastParams()).toMatchObject({ search: "admin" }));
      expect(result.current.isFiltered).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("derives the page count from the server's total", async () => {
    apiMock.get.mockResolvedValue(page([{ id: "a" }], 97, 20));
    const { result } = renderHook(
      () => usePaginatedList<Row>(["roles"], "/api/v1/roles"),
      { wrapper },
    );
    await waitFor(() => expect(result.current.total).toBe(97));
    expect(result.current.totalPages).toBe(5);
  });

  it("never reports fewer than one page, even for an empty list", async () => {
    // `Math.ceil(0 / 20)` is 0, and "Page 1 of 0" is not a thing.
    apiMock.get.mockResolvedValue(page([], 0, 20));
    const { result } = renderHook(
      () => usePaginatedList<Row>(["roles"], "/api/v1/roles"),
      { wrapper },
    );
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.totalPages).toBe(1);
  });

  it("turns the page", async () => {
    apiMock.get.mockResolvedValue(page([{ id: "a" }], 97, 20));
    const { result } = renderHook(
      () => usePaginatedList<Row>(["roles"], "/api/v1/roles"),
      { wrapper },
    );
    await waitFor(() => expect(result.current.total).toBe(97));

    act(() => result.current.setPage((p) => p + 1));
    await waitFor(() => expect(result.current.page).toBe(2));
    await waitFor(() => expect(lastParams()).toMatchObject({ offset: 20 }));
  });

  /**
   * The property the term-keyed page state exists for.
   *
   * A filtered result set is shorter, so page 4 of the unfiltered list is very
   * often past the end of the filtered one — the user would see an empty table
   * for a term that matches plenty. Resetting via an effect would render once
   * with the stale page first, asking the server for a page that may not exist.
   */
  it("returns to page 1 when the term changes, with no intermediate request", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      apiMock.get.mockResolvedValue(page([{ id: "a" }], 97, 20));
      const { result } = renderHook(
        () => usePaginatedList<Row>(["roles"], "/api/v1/roles"),
        { wrapper },
      );
      await waitFor(() => expect(result.current.total).toBe(97));

      act(() => result.current.setPage(() => 4));
      await waitFor(() => expect(result.current.page).toBe(4));

      act(() => result.current.setSearch("admin"));
      await act(async () => {
        vi.advanceTimersByTime(300);
      });

      await waitFor(() => expect(result.current.page).toBe(1));
      await waitFor(() =>
        expect(lastParams()).toMatchObject({ search: "admin", offset: 0 }),
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it("treats a bare array as one unpaginated page", async () => {
    // Some endpoints answer with a plain JSON array and are not paginated at
    // all; the hook must not report `total: undefined` and zero pages for them.
    apiMock.get.mockResolvedValue(res([{ id: "a" }, { id: "b" }]));
    const { result } = renderHook(
      () => usePaginatedList<Row>(["groups"], "/api/v1/groups"),
      { wrapper },
    );
    await waitFor(() => expect(result.current.items).toHaveLength(2));
    expect(result.current.total).toBe(2);
    expect(result.current.totalPages).toBe(1);
  });

  it("honours a caller's page size and extra params", async () => {
    apiMock.get.mockResolvedValue(page([{ id: "a" }], 5, 5));
    const { result } = renderHook(
      () =>
        usePaginatedList<Row>(["scopes"], "/api/v1/scopes", {
          perPage: 5,
          params: { resource_id: "r1" },
        }),
      { wrapper },
    );
    await waitFor(() => expect(result.current.items).toHaveLength(1));
    expect(lastParams()).toMatchObject({ limit: 5, resource_id: "r1" });
  });

  it("fetches nothing while disabled", async () => {
    renderHook(
      () =>
        usePaginatedList<Row>(["roles"], "/api/v1/roles", { enabled: false }),
      { wrapper },
    );
    await new Promise((r) => setTimeout(r, 20));
    expect(apiMock.get).not.toHaveBeenCalled();
  });
});

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useState } from "react";

import api from "@/lib/api";
import type { PaginatedResult } from "@/services/_pagination";

/** How long to wait after the last keystroke before asking the server. */
const SEARCH_DEBOUNCE_MS = 250;

/**
 * Debounce a value.
 *
 * Search runs on the server now, so every keystroke would otherwise be a
 * request — and the responses can arrive out of order, which makes the list
 * flicker between results for prefixes of what was typed.
 */
export function useDebounced<T>(value: T, delayMs = SEARCH_DEBOUNCE_MS): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(t);
  }, [value, delayMs]);
  return debounced;
}

export interface PaginatedListOptions {
  /** Rows per page. The server clamps this to 200. */
  perPage?: number;
  /** Extra query parameters sent with every page. */
  params?: Record<string, string | number | boolean | undefined>;
  /** Skip fetching until true. */
  enabled?: boolean;
}

export interface PaginatedList<T> {
  items: T[];
  total: number;
  page: number;
  perPage: number;
  totalPages: number;
  isLoading: boolean;
  /** The live value of the search box. */
  search: string;
  setSearch: (v: string) => void;
  setPage: (updater: (p: number) => number) => void;
  /** True while a search term is in effect, for empty-state wording. */
  isFiltered: boolean;
}

/**
 * A server-paginated, server-searched list.
 *
 * # Why the search is not client-side
 *
 * It used to be, on the one page that had a search box: the page fetched 20
 * rows and filtered *those*. Typing a username that existed on page 3 found
 * nothing, and the box gave no hint that it had only looked at what was
 * already on screen. `Pagination.search` moves the filter into the query, so
 * the term applies to the whole collection and `total` counts matches.
 *
 * # Why the page resets on a new term
 *
 * A filtered result set is shorter, so page 4 of the unfiltered list is very
 * often past the end of the filtered one — and the user would see an empty
 * table for a term that matches plenty.
 */
export function usePaginatedList<T>(
  queryKey: readonly unknown[],
  url: string,
  { perPage = 20, params, enabled = true }: PaginatedListOptions = {},
): PaginatedList<T> {
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebounced(search);

  // Page is stored per search term rather than reset by an effect.
  //
  // The obvious version — `useEffect(() => setPage(1), [debouncedSearch])` —
  // renders once with the stale page before the effect corrects it, which is a
  // request for a page the filtered set may not have. Keeping the term the page
  // belongs to alongside it makes "page 1 for a new term" true during the render
  // that introduces the term, with no second render and no intermediate fetch.
  //
  // A page reset is needed at all because a filtered result set is shorter: page
  // 4 of the unfiltered list is very often past the end of the filtered one, and
  // the user would see an empty table for a term that matches plenty.
  const [pageState, setPageState] = useState({ term: "", page: 1 });
  const page = pageState.term === debouncedSearch ? pageState.page : 1;

  const setPage = useCallback(
    (updater: (p: number) => number) => {
      setPageState((prev) => {
        const current = prev.term === debouncedSearch ? prev.page : 1;
        return { term: debouncedSearch, page: updater(current) };
      });
    },
    [debouncedSearch],
  );

  const { data, isLoading } = useQuery({
    queryKey: [...queryKey, page, perPage, debouncedSearch, params],
    enabled,
    // Keeps the previous page on screen while the next one loads, so paging
    // does not blank the table on every click.
    placeholderData: keepPreviousData,
    queryFn: async () => {
      const res = await api.get<PaginatedResult<T> | T[]>(url, {
        params: {
          ...params,
          offset: (page - 1) * perPage,
          limit: perPage,
          // Omitted entirely when blank: the server reads a missing `search` as
          // "no filter", and an empty string would be a substring match against
          // every row for the same intent.
          ...(debouncedSearch.trim() ? { search: debouncedSearch.trim() } : {}),
        },
      });
      // Some endpoints answer with a bare array and are not paginated at all.
      if (Array.isArray(res.data)) {
        return {
          items: res.data,
          total: res.data.length,
          offset: 0,
          limit: res.data.length,
        } satisfies PaginatedResult<T>;
      }
      return res.data;
    },
  });

  const total = data?.total ?? 0;
  const effectivePerPage = data?.limit || perPage;
  const totalPages = useMemo(
    () => Math.max(1, Math.ceil(total / effectivePerPage)),
    [total, effectivePerPage],
  );

  return {
    items: data?.items ?? [],
    total,
    page,
    perPage: effectivePerPage,
    totalPages,
    isLoading,
    search,
    setSearch,
    setPage,
    isFiltered: debouncedSearch.trim().length > 0,
  };
}

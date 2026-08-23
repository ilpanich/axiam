import api from "@/lib/api";

/** Unwrap a list response that may be a bare array or a PaginatedResult ({ items }). */
export function unwrapList<T>(data: T[] | { items?: T[] } | null | undefined): T[] {
  if (Array.isArray(data)) return data;
  return data?.items ?? [];
}

/**
 * The largest page the server will serve.
 *
 * `clamp_pagination_limit` in `crates/axiam-core/src/repository.rs` clamps
 * `limit` to `[1, 200]` at deserialization time, so asking for more is not an
 * error — it is silently reduced to 200, which would make a loop that trusted
 * its own page size skip records. Keep this in step with that clamp.
 */
export const MAX_PAGE_SIZE = 200;

/**
 * A hard ceiling on how many pages a single `fetchAllPages` call will walk.
 *
 * Only reachable if the server reports a `total` it never delivers — a bug or
 * a table growing faster than the loop drains it. Without it that shape is an
 * infinite request loop against the API, which is a worse failure than a
 * short list.
 */
const MAX_PAGES = 100;

/** The paginated envelope every `PaginatedResult<T>` endpoint returns. */
interface PaginatedEnvelope<T> {
  items: T[];
  total?: number;
  offset?: number;
  limit?: number;
}

type ListResponse<T> = T[] | PaginatedEnvelope<T> | null | undefined;

function isPaginated<T>(data: ListResponse<T>): data is PaginatedEnvelope<T> {
  return (
    !!data &&
    !Array.isArray(data) &&
    Array.isArray((data as PaginatedEnvelope<T>).items)
  );
}

/**
 * Fetch every record from a list endpoint, following pagination to the end.
 *
 * The backend's `Pagination` extractor defaults to `limit = 50` when a request
 * carries no pagination parameters, so a plain `GET /api/v1/permissions` on a
 * tenant seeded with the ~110-entry permission registry returns the first 50
 * rows and nothing tells the caller the rest exist. That is what made
 * operator-created permissions invisible in both the Permissions page and the
 * role grant picker: they were in the database and in the response's `total`,
 * just past the end of the only page anybody asked for.
 *
 * Endpoints that answer with a bare JSON array are not paginated at all; those
 * come back in one request and the loop stops immediately.
 *
 * Extra query parameters (filters, a parent id) go in `params` and are sent on
 * every page.
 */
export async function fetchAllPages<T>(
  url: string,
  params?: Record<string, string | number | boolean | undefined>
): Promise<T[]> {
  const collected: T[] = [];
  let offset = 0;

  for (let page = 0; page < MAX_PAGES; page++) {
    const res = await api.get<ListResponse<T>>(url, {
      params: { ...params, offset, limit: MAX_PAGE_SIZE },
    });

    // Not a paginated endpoint — the whole collection arrived in one array.
    if (!isPaginated(res.data)) return unwrapList(res.data);

    const { items, total } = res.data;
    collected.push(...items);

    // A short page is the end of the collection, whatever `total` claims.
    // Checking it before `total` means a server that omits `total` (or reports
    // it wrongly) still terminates on the page that actually ran out.
    if (items.length < MAX_PAGE_SIZE) return collected;
    if (typeof total === "number" && collected.length >= total) return collected;

    offset += items.length;
  }

  return collected;
}

/** Unwrap a list response that may be a bare array or a PaginatedResult ({ items }). */
export function unwrapList<T>(data: T[] | { items?: T[] } | null | undefined): T[] {
  if (Array.isArray(data)) return data;
  return data?.items ?? [];
}

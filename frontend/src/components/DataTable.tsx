import type { ReactNode } from "react";
import { ArrowDown, ArrowUp, ArrowUpDown, RotateCw } from "lucide-react";
import { cn } from "@/lib/utils";

export type SortDirection = "asc" | "desc";

export interface Column<T> {
  key: string;
  header: string;
  render?: (row: T) => ReactNode;
  width?: string;
  /** Enable click-to-sort on this column's header. */
  sortable?: boolean;
}

export interface SortState {
  key: string;
  direction: SortDirection;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  isLoading?: boolean;
  emptyMessage?: string;
  getRowKey?: (row: T, index: number) => string | number;
  /**
   * Error state for failed async loads. When set (and not loading), an error
   * row with an optional retry affordance is shown instead of the data/empty
   * state.
   */
  error?: string | null;
  /** Retry handler; renders a "Try again" button in the error state. */
  onRetry?: () => void;
  /** Current sort state (for `sortable` columns). */
  sort?: SortState | null;
  /** Called with the next sort state when a sortable header is activated. */
  onSortChange?: (next: SortState) => void;
}

function SkeletonRow({ colCount }: { colCount: number }) {
  return (
    <tr>
      {Array.from({ length: colCount }).map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-4 bg-white/10 rounded animate-pulse" />
        </td>
      ))}
    </tr>
  );
}

function SortIcon({ direction }: { direction: SortDirection | null }) {
  if (direction === "asc") return <ArrowUp size={12} aria-hidden="true" />;
  if (direction === "desc") return <ArrowDown size={12} aria-hidden="true" />;
  return <ArrowUpDown size={12} aria-hidden="true" className="opacity-40" />;
}

export function DataTable<T extends object>({
  columns,
  data,
  isLoading = false,
  emptyMessage = "No data found.",
  getRowKey,
  error = null,
  onRetry,
  sort = null,
  onSortChange,
}: DataTableProps<T>) {
  function handleSort(key: string) {
    const nextDirection: SortDirection =
      sort?.key === key && sort.direction === "asc" ? "desc" : "asc";
    onSortChange?.({ key, direction: nextDirection });
  }

  return (
    <div className="glass-card overflow-hidden p-0">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-primary/25">
              {columns.map((col) => {
                const isSorted = sort?.key === col.key;
                const ariaSort: React.AriaAttributes["aria-sort"] =
                  col.sortable
                    ? isSorted
                      ? sort?.direction === "asc"
                        ? "ascending"
                        : "descending"
                      : "none"
                    : undefined;
                return (
                  <th
                    key={col.key}
                    scope="col"
                    aria-sort={ariaSort}
                    className={cn(
                      "px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-primary/80",
                      col.width
                    )}
                  >
                    {col.sortable && onSortChange ? (
                      <button
                        type="button"
                        onClick={() => handleSort(col.key)}
                        className="focus-ring inline-flex items-center gap-1.5 uppercase tracking-wider hover:text-primary transition-colors"
                      >
                        {col.header}
                        <SortIcon
                          direction={isSorted ? sort!.direction : null}
                        />
                      </button>
                    ) : (
                      col.header
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody className="divide-y divide-white/10">
            {isLoading ? (
              <>
                <SkeletonRow colCount={columns.length} />
                <SkeletonRow colCount={columns.length} />
                <SkeletonRow colCount={columns.length} />
              </>
            ) : error ? (
              <tr>
                <td
                  colSpan={columns.length}
                  className="px-4 py-12 text-center text-muted-foreground"
                >
                  <div className="flex flex-col items-center gap-3" role="alert">
                    <span className="text-sm text-destructive">{error}</span>
                    {onRetry && (
                      <button
                        type="button"
                        onClick={onRetry}
                        className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-primary/30 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/10 transition-colors"
                      >
                        <RotateCw size={12} aria-hidden="true" />
                        Try again
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ) : data.length === 0 ? (
              <tr>
                <td
                  colSpan={columns.length}
                  className="px-4 py-12 text-center text-muted-foreground"
                >
                  <div className="flex flex-col items-center gap-2">
                    <span className="text-4xl opacity-30" aria-hidden="true">
                      &#9632;
                    </span>
                    <span>{emptyMessage}</span>
                  </div>
                </td>
              </tr>
            ) : (
              data.map((row, rowIdx) => (
                <tr
                  key={getRowKey ? getRowKey(row, rowIdx) : String((row as Record<string, unknown>).id ?? rowIdx)}
                  className="hover:bg-white/[0.06] active:bg-white/[0.06] transition-colors duration-150"
                >
                  {columns.map((col) => (
                    <td
                      key={col.key}
                      className="px-4 py-3 text-foreground/90 align-middle"
                    >
                      {col.render
                        ? col.render(row)
                        : String(
                            (row as Record<string, unknown>)[col.key] ?? ""
                          )}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

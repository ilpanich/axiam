import { Search, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

interface SearchBoxProps {
  value: string;
  onChange: (v: string) => void;
  /** What is being searched, for the placeholder: "users", "roles", … */
  noun: string;
  className?: string;
}

/**
 * The search box every list page carries.
 *
 * One component rather than a copy per page so the placeholder, the clear
 * affordance and the accessible name stay identical — and so the promise the
 * placeholder makes ("name or ID") stays true to what the server actually
 * matches, which is each repository's identifying columns plus `meta::id(id)`.
 */
export function SearchBox({ value, onChange, noun, className }: SearchBoxProps) {
  return (
    <div className={cn("relative", className)}>
      <Search
        size={14}
        aria-hidden="true"
        className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none"
      />
      <Input
        type="search"
        role="searchbox"
        aria-label={`Search ${noun}`}
        placeholder={`Search ${noun} by name or ID…`}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="pl-9 pr-9"
      />
      {value && (
        <button
          type="button"
          aria-label="Clear search"
          onClick={() => onChange("")}
          className="absolute right-2 top-1/2 -translate-y-1/2 p-1 rounded text-muted-foreground hover:text-foreground"
        >
          <X size={14} aria-hidden="true" />
        </button>
      )}
    </div>
  );
}

interface PaginationControlsProps {
  page: number;
  totalPages: number;
  total: number;
  onPageChange: (updater: (p: number) => number) => void;
  /** Hidden entirely when there is only one page and nothing is filtered. */
  alwaysShow?: boolean;
}

/**
 * Previous/next paging with a count.
 *
 * The count is shown alongside the page numbers because it is the thing an
 * operator is usually actually after — "how many are there" — and because a
 * page count on its own gives no sense of scale.
 */
export function PaginationControls({
  page,
  totalPages,
  total,
  onPageChange,
  alwaysShow = false,
}: PaginationControlsProps) {
  if (!alwaysShow && totalPages <= 1) {
    // Nothing to page through. Rendering disabled buttons under every short
    // list is noise that makes the page look more complicated than it is.
    return total > 0 ? (
      <p className="mt-4 text-sm text-muted-foreground">
        {total} {total === 1 ? "result" : "results"}
      </p>
    ) : null;
  }

  return (
    <div className="flex items-center justify-between mt-4 text-sm text-muted-foreground">
      <span>
        Page {page} of {totalPages}
        <span className="ml-2 opacity-70">
          ({total} {total === 1 ? "result" : "results"})
        </span>
      </span>
      <div className="flex gap-2">
        <Button
          variant="ghost"
          size="sm"
          disabled={page <= 1}
          onClick={() => onPageChange((p) => Math.max(1, p - 1))}
        >
          Previous
        </Button>
        <Button
          variant="ghost"
          size="sm"
          disabled={page >= totalPages}
          onClick={() => onPageChange((p) => Math.min(totalPages, p + 1))}
        >
          Next
        </Button>
      </div>
    </div>
  );
}

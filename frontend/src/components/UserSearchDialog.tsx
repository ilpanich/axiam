import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { userService, type User } from "@/services/users";
import { Button } from "@/components/ui/button";
import { Loader2, Plus, Search } from "lucide-react";
import { cn } from "@/lib/utils";

export interface UserSearchDialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  actionLabel: string;
  /** Called when the user clicks the action button for a result item */
  onAction: (user: User) => Promise<void>;
  /** Optional set of user IDs to mark as already added/assigned */
  existingIds?: Set<string>;
  /** Label shown for users that are already in existingIds */
  existingLabel?: string;
  tenantId?: string;
}

export function UserSearchDialog({
  open,
  onClose,
  title,
  actionLabel,
  onAction,
  existingIds,
  existingLabel = "Added",
}: UserSearchDialogProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [actingId, setActingId] = useState<string | null>(null);

  const { data, isFetching } = useQuery({
    queryKey: ["user-search", searchTerm],
    queryFn: () => userService.list(1, 20, searchTerm),
    enabled: searchTerm.length >= 2,
    staleTime: 10_000,
  });

  const results = data?.items ?? [];

  async function handleAction(user: User) {
    setActingId(user.id);
    try {
      await onAction(user);
    } catch {
      // silently ignore; caller handles invalidation
    } finally {
      setActingId(null);
    }
  }

  function handleClose() {
    setSearchTerm("");
    onClose();
  }

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      aria-modal="true"
      role="dialog"
      aria-labelledby="user-search-dialog-title"
    >
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-xs"
        onClick={handleClose}
        aria-hidden="true"
      />
      <div className="relative z-10 glass-card w-full max-w-md flex flex-col max-h-[80vh]">
        <div className="flex items-center justify-between pb-4 border-b border-primary/10">
          <h2
            id="user-search-dialog-title"
            className="text-lg font-semibold text-foreground"
          >
            {title}
          </h2>
          <button
            onClick={handleClose}
            className="text-muted-foreground hover:text-foreground transition-colors rounded p-1 focus:outline-hidden focus:ring-2 focus:ring-primary/40"
            aria-label="Close dialog"
          >
            ✕
          </button>
        </div>

        <div className="py-4 flex flex-col gap-3 overflow-hidden">
          <div className="relative">
            <Search
              size={15}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none"
              aria-hidden="true"
            />
            <input
              type="search"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search users…"
              aria-label="Search users"
              className={cn(
                "h-9 w-full rounded-md pl-9 pr-3 text-sm",
                "bg-white/5 border border-primary/20 text-foreground",
                "placeholder:text-muted-foreground",
                "focus:outline-hidden focus:ring-2 focus:ring-primary/40 focus:border-primary",
                "transition-colors duration-200",
              )}
            />
          </div>

          <div className="overflow-y-auto flex-1 min-h-[120px] max-h-60 rounded-md border border-white/5">
            {isFetching ? (
              <div className="flex items-center justify-center py-6">
                <Loader2 size={20} className="animate-spin text-primary/60" />
              </div>
            ) : searchTerm.length < 2 ? (
              <p className="text-sm text-muted-foreground text-center py-6">
                Type at least 2 characters to search.
              </p>
            ) : results.length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-6">
                No users found.
              </p>
            ) : (
              <ul>
                {results.map((user) => {
                  const alreadyExists = existingIds?.has(user.id) ?? false;
                  return (
                    <li
                      key={user.id}
                      className="flex items-center justify-between px-3 py-2.5 hover:bg-white/5 border-b border-white/5 last:border-0"
                    >
                      <div>
                        <p className="text-sm font-medium text-foreground/90">
                          {user.display_name ?? user.username}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {user.email}
                        </p>
                      </div>
                      {alreadyExists ? (
                        <span className="text-xs text-muted-foreground">
                          {existingLabel}
                        </span>
                      ) : (
                        <button
                          onClick={() => void handleAction(user)}
                          disabled={actingId === user.id}
                          className="flex items-center gap-1 text-xs px-2.5 py-1 rounded bg-primary/20 text-primary hover:bg-primary/30 transition-colors disabled:opacity-50"
                        >
                          {actingId === user.id ? (
                            <Loader2 size={12} className="animate-spin" />
                          ) : (
                            <Plus size={12} />
                          )}
                          {actionLabel}
                        </button>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </div>

        <div className="flex justify-end pt-4 border-t border-primary/10">
          <Button variant="ghost" onClick={handleClose}>
            Done
          </Button>
        </div>
      </div>
    </div>
  );
}

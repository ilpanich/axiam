import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight, ChevronDown, ChevronUp, X } from "lucide-react";
import { auditService, type AuditLog, type AuditFilters } from "@/services/audit";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { cn, formatDateTime } from "@/lib/utils";

// ─── Outcome badge ────────────────────────────────────────────────────────────

function OutcomeBadge({ outcome }: { outcome: AuditLog["outcome"] }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium border",
        outcome === "success"
          ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
          : "bg-red-500/15 text-red-400 border-red-500/30"
      )}
    >
      <span
        className={cn(
          "w-1.5 h-1.5 rounded-full",
          outcome === "success" ? "bg-emerald-400" : "bg-red-400"
        )}
        aria-hidden="true"
      />
      {outcome === "success" ? "Success" : "Failure"}
    </span>
  );
}

// ─── Details expander ─────────────────────────────────────────────────────────

function DetailsExpander({
  details,
}: {
  details: Record<string, unknown> | undefined;
}) {
  const [open, setOpen] = useState(false);

  if (!details || Object.keys(details).length === 0) {
    return <span className="text-muted-foreground text-xs">—</span>;
  }

  return (
    <div>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="inline-flex items-center gap-1 text-xs text-primary hover:text-primary/80 transition-colors focus:outline-none focus:ring-1 focus:ring-primary/40 rounded"
        aria-expanded={open}
      >
        {open ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        {open ? "Hide" : "Show"}
      </button>
      {open && (
        <pre className="mt-2 text-xs text-foreground/70 bg-white/[0.04] border border-white/10 rounded p-2 overflow-x-auto max-w-xs whitespace-pre-wrap break-all">
          {JSON.stringify(details, null, 2)}
        </pre>
      )}
    </div>
  );
}

// ─── Filter bar ───────────────────────────────────────────────────────────────

interface FilterBarProps {
  actor: string;
  action: string;
  outcome: "" | "success" | "failure";
  from: string;
  to: string;
  onActorChange: (v: string) => void;
  onActionChange: (v: string) => void;
  onOutcomeChange: (v: "" | "success" | "failure") => void;
  onFromChange: (v: string) => void;
  onToChange: (v: string) => void;
  onClear: () => void;
  hasFilters: boolean;
}

function FilterBar({
  actor,
  action,
  outcome,
  from,
  to,
  onActorChange,
  onActionChange,
  onOutcomeChange,
  onFromChange,
  onToChange,
  onClear,
  hasFilters,
}: FilterBarProps) {
  return (
    <div className="flex flex-wrap items-end gap-3 mb-4 p-4 rounded-xl border border-white/8 bg-white/[0.02]">
      <div className="flex-1 min-w-36 space-y-1">
        <label htmlFor="filter-actor" className="text-xs font-medium text-muted-foreground">
          Actor
        </label>
        <Input
          id="filter-actor"
          value={actor}
          onChange={(e) => onActorChange(e.target.value)}
          placeholder="Username or ID"
          className="h-8 text-sm"
        />
      </div>

      <div className="flex-1 min-w-36 space-y-1">
        <label htmlFor="filter-action" className="text-xs font-medium text-muted-foreground">
          Action
        </label>
        <Input
          id="filter-action"
          value={action}
          onChange={(e) => onActionChange(e.target.value)}
          placeholder="e.g. user.created"
          className="h-8 text-sm"
        />
      </div>

      <div className="flex-1 min-w-32 space-y-1">
        <label htmlFor="filter-outcome" className="text-xs font-medium text-muted-foreground">
          Outcome
        </label>
        <select
          id="filter-outcome"
          value={outcome}
          onChange={(e) =>
            onOutcomeChange(e.target.value as "" | "success" | "failure")
          }
          className="h-8 w-full text-sm rounded-md border border-input bg-background/50 px-2 text-foreground focus:outline-none focus:ring-2 focus:ring-primary/40"
        >
          <option value="">All</option>
          <option value="success">Success</option>
          <option value="failure">Failure</option>
        </select>
      </div>

      <div className="flex-1 min-w-32 space-y-1">
        <label htmlFor="filter-from" className="text-xs font-medium text-muted-foreground">
          From
        </label>
        <Input
          id="filter-from"
          type="date"
          value={from}
          onChange={(e) => onFromChange(e.target.value)}
          className="h-8 text-sm"
        />
      </div>

      <div className="flex-1 min-w-32 space-y-1">
        <label htmlFor="filter-to" className="text-xs font-medium text-muted-foreground">
          To
        </label>
        <Input
          id="filter-to"
          type="date"
          value={to}
          onChange={(e) => onToChange(e.target.value)}
          className="h-8 text-sm"
        />
      </div>

      {hasFilters && (
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={onClear}
          className="h-8 gap-1.5 text-muted-foreground hover:text-foreground"
        >
          <X size={14} />
          Clear
        </Button>
      )}
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

const PER_PAGE = 20;

export function AuditLogsPage() {
  // Raw filter inputs (undbounced for actors/actions)
  const [actorInput, setActorInput] = useState("");
  const [actionInput, setActionInput] = useState("");
  const [outcome, setOutcome] = useState<"" | "success" | "failure">("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [page, setPage] = useState(1);

  // Simple debounce for text inputs to avoid hammering the API
  const [actorDebounced, setActorDebounced] = useState("");
  const [actionDebounced, setActionDebounced] = useState("");
  const [actorTimer, setActorTimer] = useState<ReturnType<typeof setTimeout> | null>(null);
  const [actionTimer, setActionTimer] = useState<ReturnType<typeof setTimeout> | null>(null);

  function handleActorChange(v: string) {
    setActorInput(v);
    if (actorTimer) clearTimeout(actorTimer);
    const t = setTimeout(() => {
      setActorDebounced(v);
      setPage(1);
    }, 400);
    setActorTimer(t);
  }

  function handleActionChange(v: string) {
    setActionInput(v);
    if (actionTimer) clearTimeout(actionTimer);
    const t = setTimeout(() => {
      setActionDebounced(v);
      setPage(1);
    }, 400);
    setActionTimer(t);
  }

  function handleOutcomeChange(v: "" | "success" | "failure") {
    setOutcome(v);
    setPage(1);
  }

  function handleFromChange(v: string) {
    setFrom(v);
    setPage(1);
  }

  function handleToChange(v: string) {
    setTo(v);
    setPage(1);
  }

  function clearFilters() {
    setActorInput("");
    setActorDebounced("");
    setActionInput("");
    setActionDebounced("");
    setOutcome("");
    setFrom("");
    setTo("");
    setPage(1);
  }

  const hasFilters =
    actorInput !== "" ||
    actionInput !== "" ||
    outcome !== "" ||
    from !== "" ||
    to !== "";

  const filters: AuditFilters = {
    page,
    per_page: PER_PAGE,
    actor_id: actorDebounced || undefined,
    action: actionDebounced || undefined,
    outcome: outcome || undefined,
    from: from || undefined,
    to: to || undefined,
  };

  const { data, isLoading } = useQuery({
    queryKey: ["audit-logs", filters],
    queryFn: () => auditService.list(filters),
    placeholderData: (prev) => prev,
  });

  const logs = data?.data ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE));

  // ─── Table columns ─────────────────────────────────────────────────────────

  const columns: Column<AuditLog>[] = [
    {
      key: "created_at",
      header: "Timestamp",
      render: (row) => (
        <span className="text-sm text-foreground/80 whitespace-nowrap">
          {formatDateTime(row.created_at)}
        </span>
      ),
    },
    {
      key: "actor",
      header: "Actor",
      render: (row) => (
        <span className="text-sm font-medium truncate block max-w-[140px]" title={row.actor_id}>
          {row.actor_username ?? row.actor_id}
        </span>
      ),
    },
    {
      key: "action",
      header: "Action",
      render: (row) => (
        <span
          className={cn(
            "text-sm font-mono",
            row.outcome === "success" ? "text-blue-400" : "text-red-400"
          )}
        >
          {row.action}
        </span>
      ),
    },
    {
      key: "resource",
      header: "Resource",
      render: (row) => (
        <div className="text-sm">
          <span className="text-foreground/80">{row.resource_type}</span>
          {row.resource_id && (
            <span
              className="block text-xs text-muted-foreground font-mono truncate max-w-[120px]"
              title={row.resource_id}
            >
              {row.resource_id}
            </span>
          )}
        </div>
      ),
    },
    {
      key: "outcome",
      header: "Outcome",
      render: (row) => <OutcomeBadge outcome={row.outcome} />,
    },
    {
      key: "ip_address",
      header: "IP Address",
      render: (row) => (
        <span className="text-sm text-muted-foreground font-mono">
          {row.ip_address ?? "—"}
        </span>
      ),
    },
    {
      key: "details",
      header: "Details",
      render: (row) => <DetailsExpander details={row.details} />,
    },
  ];

  return (
    <div>
      <PageHeader
        title="Audit Logs"
        description="Append-only record of all actions performed in this tenant."
      />

      <FilterBar
        actor={actorInput}
        action={actionInput}
        outcome={outcome}
        from={from}
        to={to}
        onActorChange={handleActorChange}
        onActionChange={handleActionChange}
        onOutcomeChange={handleOutcomeChange}
        onFromChange={handleFromChange}
        onToChange={handleToChange}
        onClear={clearFilters}
        hasFilters={hasFilters}
      />

      <DataTable
        columns={columns}
        data={logs}
        isLoading={isLoading}
        emptyMessage="No audit log entries found."
      />

      {/* Pagination */}
      <div className="mt-4 flex items-center justify-between gap-4">
        <p className="text-sm text-muted-foreground">
          {total > 0
            ? `Page ${page} of ${totalPages} (${total} total records)`
            : "No records"}
        </p>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1 || isLoading}
            aria-label="Previous page"
          >
            <ChevronLeft size={14} />
            Prev
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page === totalPages || isLoading}
            aria-label="Next page"
          >
            Next
            <ChevronRight size={14} />
          </Button>
        </div>
      </div>
    </div>
  );
}

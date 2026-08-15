import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  reactorService,
  strictestDefaultPolicy,
  notInterceptable,
  MAX_TIMEOUT_MS,
  DEFAULT_TIMEOUT_MS,
  type Reactor,
  type ReactorEventDescriptor,
  type ReactorMode,
  type FailurePolicy,
  type CreateReactorPayload,
  type UpdateReactorPayload,
} from "@/services/reactors";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { StatusBadge } from "@/components/StatusBadge";
import { SectionCard, ToggleField } from "@/components/shared";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { AlertTriangle, Pencil, Plus, Trash2 } from "lucide-react";

import { formatRelativeTime } from "@/lib/utils";

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Render a `mutable_fields` entry. An entry ending in `.` is a namespace
 * prefix server-side, so `ext.` is shown as `ext.*` — otherwise it reads as a
 * claim literally named `ext.`, which is the one thing the server refuses.
 */
function formatMutableField(field: string): string {
  return field.endsWith(".") ? `${field}*` : field;
}

/** One-line summary of what a reply to this event may change. */
function mutationSummary(spec: ReactorEventDescriptor): string {
  if (!spec.mutable) return "Veto only — no patch";
  if (spec.mutable_fields.length === 0) return "Veto only — no patch";
  return `May set ${spec.mutable_fields.map(formatMutableField).join(", ")}`;
}

const POLICY_LABEL: Record<FailurePolicy, string> = {
  fail_closed: "Fail closed",
  fail_open: "Fail open",
};

const MODE_LABEL: Record<ReactorMode, string> = {
  intercept: "Intercept",
  listen: "Listen",
};

// ─── Liveness ─────────────────────────────────────────────────────────────────

/**
 * `last_seen_at === null` is a registration no process has ever attached to,
 * which is a different operational state from one that connected and went
 * quiet — the server models it as `Option` for exactly that reason, so the
 * console must not collapse the two into one "unknown".
 */
function LivenessCell({ reactor }: { reactor: Reactor }) {
  if (reactor.last_seen_at !== null) {
    return (
      <span className="text-muted-foreground text-sm">
        {formatRelativeTime(reactor.last_seen_at)}
      </span>
    );
  }

  // An enabled interceptor that has never connected is not merely un-observed:
  // every dispatch to it will hit the failure path. Which path is knowable from
  // the registration itself, so state the consequence rather than a vague
  // warning.
  const consequence =
    reactor.enabled && reactor.mode === "intercept"
      ? reactor.failure_policy === "fail_closed"
        ? "Enabled interceptor has never connected — its events are being denied (fail closed)."
        : "Enabled interceptor has never connected — its events proceed unmodified (fail open)."
      : null;

  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-amber-500/15 text-amber-400 border border-amber-500/30">
        Never connected
      </span>
      {consequence && (
        <AlertTriangle
          size={13}
          className="text-amber-400 shrink-0"
          aria-label={consequence}
        />
      )}
    </span>
  );
}

// ─── Event selector ───────────────────────────────────────────────────────────

interface EventSelectorProps {
  registry: ReactorEventDescriptor[];
  selected: string[];
  mode: ReactorMode;
  onChange: (events: string[]) => void;
}

function EventSelector({
  registry,
  selected,
  mode,
  onChange,
}: EventSelectorProps) {
  function toggle(event: string) {
    onChange(
      selected.includes(event)
        ? selected.filter((e) => e !== event)
        : [...selected, event]
    );
  }

  if (registry.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        No hookable events are available.
      </p>
    );
  }

  return (
    <div className="space-y-2.5 max-h-56 overflow-y-auto pr-1">
      {registry.map((spec) => {
        const isSelected = selected.includes(spec.name);
        // Blocked only for events not already chosen: an event that became
        // illegal when the mode changed must stay clickable so it can be
        // cleared, otherwise the form is stuck in a state it cannot leave.
        const blocked = mode === "intercept" && !spec.interceptable;
        const disabled = blocked && !isSelected;

        return (
          <div key={spec.name}>
            <label
              className={
                disabled
                  ? "flex items-start gap-2.5 cursor-not-allowed opacity-50"
                  : "flex items-start gap-2.5 cursor-pointer hover:text-foreground transition-colors"
              }
            >
              <input
                type="checkbox"
                checked={isSelected}
                disabled={disabled}
                onChange={() => toggle(spec.name)}
                className="w-3.5 h-3.5 mt-0.5 accent-cyan-400 cursor-pointer disabled:cursor-not-allowed"
                aria-label={spec.name}
              />
              <span className="min-w-0">
                <span className="flex flex-wrap items-center gap-1.5">
                  <span className="text-sm text-foreground/80 font-mono">
                    {spec.name}
                  </span>
                  {!spec.interceptable && (
                    <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-muted/40 text-muted-foreground border border-border">
                      listen-only
                    </span>
                  )}
                  <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-purple-500/15 text-purple-400 border border-purple-500/30">
                    {mutationSummary(spec)}
                  </span>
                </span>
                <span className="block text-xs text-muted-foreground mt-0.5">
                  {spec.description}
                </span>
                {blocked && isSelected && (
                  <span className="block text-xs text-destructive mt-0.5">
                    Listen-only — cannot be intercepted. Clear it or switch the
                    mode to Listen.
                  </span>
                )}
              </span>
            </label>
          </div>
        );
      })}
    </div>
  );
}

// ─── Shared form fields ───────────────────────────────────────────────────────

interface ReactorFieldsProps {
  idPrefix: string;
  registry: ReactorEventDescriptor[];
  name: string;
  description: string;
  events: string[];
  mode: ReactorMode;
  priority: string;
  timeoutMs: string;
  /** Empty string means "take the registry default". */
  failurePolicy: FailurePolicy | "";
  enabled: boolean;
  onNameChange: (v: string) => void;
  onDescriptionChange: (v: string) => void;
  onEventsChange: (v: string[]) => void;
  onModeChange: (v: ReactorMode) => void;
  onPriorityChange: (v: string) => void;
  onTimeoutMsChange: (v: string) => void;
  onFailurePolicyChange: (v: FailurePolicy | "") => void;
  onEnabledChange: (v: boolean) => void;
}

function ReactorFields({
  idPrefix,
  registry,
  name,
  description,
  events,
  mode,
  priority,
  timeoutMs,
  failurePolicy,
  enabled,
  onNameChange,
  onDescriptionChange,
  onEventsChange,
  onModeChange,
  onPriorityChange,
  onTimeoutMsChange,
  onFailurePolicyChange,
  onEnabledChange,
}: ReactorFieldsProps) {
  const inheritedPolicy = strictestDefaultPolicy(events, registry);

  return (
    <>
      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-name`}>Name *</Label>
        <Input
          id={`${idPrefix}-name`}
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          placeholder="fraud-check"
          required
          autoComplete="off"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-description`}>Description</Label>
        <Input
          id={`${idPrefix}-description`}
          value={description}
          onChange={(e) => onDescriptionChange(e.target.value)}
          placeholder="Scores logins against the fraud service"
          autoComplete="off"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-mode`}>Mode *</Label>
        <select
          id={`${idPrefix}-mode`}
          value={mode}
          onChange={(e) => onModeChange(e.target.value as ReactorMode)}
          className="flex h-9 w-full rounded-md border border-input bg-background/50 px-3 py-1 text-sm"
        >
          <option value="intercept">
            Intercept — server waits; reply may veto or patch
          </option>
          <option value="listen">
            Listen — fire-and-forget; cannot affect the outcome
          </option>
        </select>
      </div>

      <div className="space-y-2">
        <Label>Events *</Label>
        <div className="rounded-md border border-input bg-background/50 p-3">
          <EventSelector
            registry={registry}
            selected={events}
            mode={mode}
            onChange={onEventsChange}
          />
        </div>
        {events.length === 0 && (
          <p className="text-xs text-muted-foreground">
            Subscribe to at least one event.
          </p>
        )}
      </div>

      {mode === "intercept" && (
        <>
          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-priority`}>Priority</Label>
            <Input
              id={`${idPrefix}-priority`}
              type="number"
              value={priority}
              onChange={(e) => onPriorityChange(e.target.value)}
              placeholder="0"
              autoComplete="off"
            />
            <p className="text-xs text-muted-foreground">
              Ascending: lower runs first. Ties break by id, so the order is
              stable across restarts.
            </p>
          </div>

          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-timeout`}>Timeout (ms)</Label>
            <Input
              id={`${idPrefix}-timeout`}
              type="number"
              value={timeoutMs}
              onChange={(e) => onTimeoutMsChange(e.target.value)}
              placeholder={String(DEFAULT_TIMEOUT_MS)}
              autoComplete="off"
            />
            <p className="text-xs text-muted-foreground">
              Blank takes the {DEFAULT_TIMEOUT_MS} ms default. Maximum{" "}
              {MAX_TIMEOUT_MS} ms.
            </p>
          </div>

          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-policy`}>Failure policy</Label>
            <select
              id={`${idPrefix}-policy`}
              value={failurePolicy}
              onChange={(e) =>
                onFailurePolicyChange(e.target.value as FailurePolicy | "")
              }
              className="flex h-9 w-full rounded-md border border-input bg-background/50 px-3 py-1 text-sm"
            >
              <option value="">
                Registry default
                {events.length > 0
                  ? ` — ${POLICY_LABEL[inheritedPolicy]}`
                  : ""}
              </option>
              <option value="fail_closed">
                Fail closed — deny the operation
              </option>
              <option value="fail_open">
                Fail open — proceed as if allowed
              </option>
            </select>
            <p className="text-xs text-muted-foreground">
              Applies when the reactor does not answer: timeout, crash, bad
              signature, or a rejected patch.
            </p>
          </div>
        </>
      )}

      <ToggleField
        id={`${idPrefix}-enabled`}
        label="Enabled"
        checked={enabled}
        onChange={onEnabledChange}
      />
    </>
  );
}

// ─── Registry reference ───────────────────────────────────────────────────────

function EventRegistryCard({
  registry,
  isLoading,
}: {
  registry: ReactorEventDescriptor[];
  isLoading: boolean;
}) {
  return (
    <SectionCard title="Hookable events">
      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading the registry…</p>
      ) : registry.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No hookable events are available.
        </p>
      ) : (
        <div className="space-y-3">
          {registry.map((spec) => (
            <div
              key={spec.name}
              className="flex flex-wrap items-baseline gap-x-2 gap-y-1"
            >
              <span className="text-sm font-mono text-foreground/90">
                {spec.name}
              </span>
              <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-muted/40 text-muted-foreground border border-border">
                {spec.interceptable ? "interceptable" : "listen-only"}
              </span>
              <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-purple-500/15 text-purple-400 border border-purple-500/30">
                {mutationSummary(spec)}
              </span>
              <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-muted/40 text-muted-foreground border border-border">
                default {POLICY_LABEL[spec.default_failure_policy]}
              </span>
              <span className="block w-full text-xs text-muted-foreground">
                {spec.description}
              </span>
            </div>
          ))}
        </div>
      )}
    </SectionCard>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function ReactorsPage() {
  const queryClient = useQueryClient();

  const {
    data: reactors = [],
    isLoading,
    error: listError,
    refetch,
  } = useQuery({
    queryKey: ["reactors"],
    queryFn: () => reactorService.list(),
  });

  const { data: registry = [], isLoading: registryLoading } = useQuery({
    queryKey: ["reactor-events"],
    queryFn: () => reactorService.listEvents(),
  });

  // ─── Create state ──────────────────────────────────────────────────────────
  const [createOpen, setCreateOpen] = useState(false);
  const [createName, setCreateName] = useState("");
  const [createDescription, setCreateDescription] = useState("");
  const [createEvents, setCreateEvents] = useState<string[]>([]);
  const [createMode, setCreateMode] = useState<ReactorMode>("intercept");
  const [createPriority, setCreatePriority] = useState("");
  const [createTimeout, setCreateTimeout] = useState("");
  const [createPolicy, setCreatePolicy] = useState<FailurePolicy | "">("");
  const [createEnabled, setCreateEnabled] = useState(true);
  const [createError, setCreateError] = useState("");

  const createMutation = useMutation({
    mutationFn: (payload: CreateReactorPayload) =>
      reactorService.create(payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["reactors"] });
      setCreateOpen(false);
      resetCreateForm();
    },
    onError: (err: unknown) => {
      setCreateError(
        err instanceof Error ? err.message : "Failed to create reactor."
      );
    },
  });

  function resetCreateForm() {
    setCreateName("");
    setCreateDescription("");
    setCreateEvents([]);
    setCreateMode("intercept");
    setCreatePriority("");
    setCreateTimeout("");
    setCreatePolicy("");
    setCreateEnabled(true);
    setCreateError("");
  }

  /**
   * Shared pre-flight for both dialogs. Every rule here has a counterpart in
   * `validate_registration` server-side; this exists to name the problem at
   * the field rather than as a 400 after submit, not to be the authority.
   */
  function validate(
    name: string,
    events: string[],
    mode: ReactorMode,
    timeoutRaw: string,
    priorityRaw: string
  ): string | null {
    if (!name.trim()) return "Name is required.";
    if (events.length === 0) return "Select at least one event.";

    const illegal = notInterceptable(events, registry);
    if (mode === "intercept" && illegal.length > 0) {
      return `${illegal.join(", ")} cannot be intercepted. Clear ${
        illegal.length === 1 ? "it" : "them"
      } or switch the mode to Listen.`;
    }

    if (timeoutRaw.trim()) {
      const timeout = Number(timeoutRaw);
      if (!Number.isInteger(timeout) || timeout < 1 || timeout > MAX_TIMEOUT_MS) {
        return `Timeout must be a whole number between 1 and ${MAX_TIMEOUT_MS} ms.`;
      }
    }
    if (priorityRaw.trim() && !Number.isInteger(Number(priorityRaw))) {
      return "Priority must be a whole number.";
    }
    return null;
  }

  function handleCreateSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setCreateError("");
    const problem = validate(
      createName,
      createEvents,
      createMode,
      createTimeout,
      createPriority
    );
    if (problem) {
      setCreateError(problem);
      return;
    }

    const payload: CreateReactorPayload = {
      name: createName.trim(),
      description: createDescription.trim(),
      events: createEvents,
      mode: createMode,
      enabled: createEnabled,
    };
    // Omit rather than send a guessed value: the server fills priority,
    // timeout and policy from the registry, and a blank field means "whatever
    // the registry says", not zero.
    if (createMode === "intercept") {
      if (createPriority.trim()) payload.priority = Number(createPriority);
      if (createTimeout.trim()) payload.timeout_ms = Number(createTimeout);
      if (createPolicy) payload.failure_policy = createPolicy;
    }
    createMutation.mutate(payload);
  }

  // ─── Edit state ────────────────────────────────────────────────────────────
  const [editReactor, setEditReactor] = useState<Reactor | null>(null);
  const [editName, setEditName] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editEvents, setEditEvents] = useState<string[]>([]);
  const [editMode, setEditMode] = useState<ReactorMode>("intercept");
  const [editPriority, setEditPriority] = useState("");
  const [editTimeout, setEditTimeout] = useState("");
  const [editPolicy, setEditPolicy] = useState<FailurePolicy | "">("");
  const [editEnabled, setEditEnabled] = useState(true);
  const [editError, setEditError] = useState("");

  const editMutation = useMutation({
    mutationFn: ({
      id,
      payload,
    }: {
      id: string;
      payload: UpdateReactorPayload;
    }) => reactorService.update(id, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["reactors"] });
      setEditReactor(null);
    },
    onError: (err: unknown) => {
      setEditError(
        err instanceof Error ? err.message : "Failed to update reactor."
      );
    },
  });

  function openEdit(reactor: Reactor) {
    setEditReactor(reactor);
    setEditName(reactor.name);
    setEditDescription(reactor.description);
    setEditEvents(reactor.events);
    setEditMode(reactor.mode);
    setEditPriority(String(reactor.priority));
    setEditTimeout(String(reactor.timeout_ms));
    // The stored policy is always concrete — the server resolved the default
    // at write time — so edit shows it explicitly rather than re-offering
    // "registry default", which would silently re-resolve against a changed
    // event set.
    setEditPolicy(reactor.failure_policy);
    setEditEnabled(reactor.enabled);
    setEditError("");
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setEditError("");
    if (!editReactor) return;

    const problem = validate(
      editName,
      editEvents,
      editMode,
      editTimeout,
      editPriority
    );
    if (problem) {
      setEditError(problem);
      return;
    }

    const payload: UpdateReactorPayload = {
      name: editName.trim(),
      description: editDescription.trim(),
      events: editEvents,
      mode: editMode,
      enabled: editEnabled,
    };
    if (editMode === "intercept") {
      if (editPriority.trim()) payload.priority = Number(editPriority);
      if (editTimeout.trim()) payload.timeout_ms = Number(editTimeout);
      if (editPolicy) payload.failure_policy = editPolicy;
    }
    editMutation.mutate({ id: editReactor.id, payload });
  }

  // ─── Delete state ──────────────────────────────────────────────────────────
  const [deleteReactor, setDeleteReactor] = useState<Reactor | null>(null);

  const deleteMutation = useMutation({
    mutationFn: (id: string) => reactorService.remove(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["reactors"] });
      setDeleteReactor(null);
    },
  });

  // ─── Table columns ─────────────────────────────────────────────────────────
  const columns: Column<Reactor>[] = [
    {
      key: "name",
      header: "Name",
      sortable: true,
      render: (row) => (
        <div className="min-w-0">
          <span className="font-medium text-foreground/90 text-sm block truncate">
            {row.name}
          </span>
          {row.description && (
            <span
              className="text-xs text-muted-foreground block truncate max-w-[240px]"
              title={row.description}
            >
              {row.description}
            </span>
          )}
        </div>
      ),
    },
    {
      key: "mode",
      header: "Mode",
      render: (row) => (
        <span
          className={
            row.mode === "intercept"
              ? "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-cyan-500/15 text-cyan-400 border border-cyan-500/30"
              : "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-muted/40 text-muted-foreground border border-border"
          }
        >
          {MODE_LABEL[row.mode]}
        </span>
      ),
    },
    {
      key: "events",
      header: "Events",
      render: (row) => (
        <span
          className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-purple-500/15 text-purple-400 border border-purple-500/30"
          title={row.events.join(", ")}
        >
          {row.events.length} {row.events.length === 1 ? "event" : "events"}
        </span>
      ),
    },
    {
      key: "failure_policy",
      header: "On failure",
      render: (row) =>
        // Only an interceptor has a failure path — the server never reads a
        // listener's reply, so showing a policy there would imply a control
        // that does not exist.
        row.mode === "intercept" ? (
          <span
            className={
              row.failure_policy === "fail_closed"
                ? "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-amber-500/15 text-amber-400 border border-amber-500/30"
                : "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-muted/40 text-muted-foreground border border-border"
            }
          >
            {POLICY_LABEL[row.failure_policy]}
          </span>
        ) : (
          <span className="text-muted-foreground text-sm">—</span>
        ),
    },
    {
      key: "timeout_ms",
      header: "Timeout",
      render: (row) =>
        row.mode === "intercept" ? (
          <span className="text-muted-foreground text-sm">
            {row.timeout_ms} ms
          </span>
        ) : (
          <span className="text-muted-foreground text-sm">—</span>
        ),
    },
    {
      key: "last_seen_at",
      header: "Last seen",
      render: (row) => <LivenessCell reactor={row} />,
    },
    {
      key: "enabled",
      header: "Status",
      render: (row) => (
        <StatusBadge status={row.enabled ? "active" : "inactive"} />
      ),
    },
    {
      key: "actions",
      header: "Actions",
      width: "w-24",
      render: (row) => (
        <div className="flex items-center gap-1">
          <button
            aria-label={`Edit reactor ${row.name}`}
            onClick={() => openEdit(row)}
            className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
          >
            <Pencil size={14} />
          </button>
          <button
            aria-label={`Delete reactor ${row.name}`}
            onClick={() => setDeleteReactor(row)}
            className="p-1.5 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-colors"
          >
            <Trash2 size={14} />
          </button>
        </div>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="Reactors"
        description="External processes that observe, veto or enrich operations over AMQP."
        action={
          <Button
            onClick={() => {
              resetCreateForm();
              setCreateOpen(true);
            }}
          >
            <Plus size={16} />
            New Reactor
          </Button>
        }
      />

      <DataTable
        columns={columns}
        data={reactors}
        isLoading={isLoading}
        emptyMessage="No reactors registered."
        error={listError ? "Failed to load reactors." : null}
        onRetry={() => void refetch()}
      />

      <div className="mt-6">
        <EventRegistryCard registry={registry} isLoading={registryLoading} />
      </div>

      {/* Create dialog */}
      <FormDialog
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          resetCreateForm();
        }}
        title="New Reactor"
        onSubmit={handleCreateSubmit}
        isLoading={createMutation.isPending}
        submitLabel="Create"
        error={createError}
        errorId="reactor-create-error"
      >
        <ReactorFields
          idPrefix="rc-create"
          registry={registry}
          name={createName}
          description={createDescription}
          events={createEvents}
          mode={createMode}
          priority={createPriority}
          timeoutMs={createTimeout}
          failurePolicy={createPolicy}
          enabled={createEnabled}
          onNameChange={setCreateName}
          onDescriptionChange={setCreateDescription}
          onEventsChange={setCreateEvents}
          onModeChange={setCreateMode}
          onPriorityChange={setCreatePriority}
          onTimeoutMsChange={setCreateTimeout}
          onFailurePolicyChange={setCreatePolicy}
          onEnabledChange={setCreateEnabled}
        />
      </FormDialog>

      {/* Edit dialog */}
      <FormDialog
        open={editReactor !== null}
        onClose={() => setEditReactor(null)}
        title="Edit Reactor"
        onSubmit={handleEditSubmit}
        isLoading={editMutation.isPending}
        submitLabel="Save Changes"
        error={editError}
        errorId="reactor-edit-error"
      >
        <ReactorFields
          idPrefix="rc-edit"
          registry={registry}
          name={editName}
          description={editDescription}
          events={editEvents}
          mode={editMode}
          priority={editPriority}
          timeoutMs={editTimeout}
          failurePolicy={editPolicy}
          enabled={editEnabled}
          onNameChange={setEditName}
          onDescriptionChange={setEditDescription}
          onEventsChange={setEditEvents}
          onModeChange={setEditMode}
          onPriorityChange={setEditPriority}
          onTimeoutMsChange={setEditTimeout}
          onFailurePolicyChange={setEditPolicy}
          onEnabledChange={setEditEnabled}
        />
      </FormDialog>

      {/* Delete confirm */}
      <ConfirmDialog
        open={deleteReactor !== null}
        onClose={() => setDeleteReactor(null)}
        onConfirm={() =>
          deleteReactor && deleteMutation.mutate(deleteReactor.id)
        }
        title="Delete Reactor"
        description={`Are you sure you want to delete the reactor "${deleteReactor?.name}"? Its queue stops being fed and any operation it was vetoing will proceed. This action cannot be undone.`}
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}

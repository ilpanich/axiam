import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  webhookService,
  WEBHOOK_EVENT_GROUPS,
  DEFAULT_RETRY_POLICY,
  RETRY_POLICY_BOUNDS,
  validateRetryPolicy,
  type Webhook,
  type CreateWebhookPayload,
  type UpdateWebhookPayload,
  type RetryPolicy,
} from "@/services/webhooks";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { PaginationControls, SearchBox } from "@/components/ListToolbar";
import { usePaginatedList } from "@/hooks/usePaginatedList";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Pencil, Plus, Trash2 } from "lucide-react";

import { formatDate } from "@/lib/utils";
import { getApiErrorMessage } from "@/lib/apiError";
import { ToggleField } from "@/components/shared";

// ─── Helpers ──────────────────────────────────────────────────────────────────

// ─── Event type multi-select ──────────────────────────────────────────────────

interface EventTypeSelectorProps {
  selected: string[];
  onChange: (events: string[]) => void;
}

function EventTypeSelector({ selected, onChange }: EventTypeSelectorProps) {
  function toggle(event: string) {
    if (selected.includes(event)) {
      onChange(selected.filter((e) => e !== event));
    } else {
      onChange([...selected, event]);
    }
  }

  return (
    <div className="space-y-3 max-h-48 overflow-y-auto pr-1">
      {WEBHOOK_EVENT_GROUPS.map((group) => (
        <div key={group.label}>
          <p className="text-xs font-semibold uppercase tracking-wider text-primary/60 mb-1.5">
            {group.label}
          </p>
          <div className="space-y-1">
            {group.events.map((event) => (
              <label
                key={event}
                className="flex items-center gap-2.5 cursor-pointer hover:text-foreground transition-colors"
              >
                <input
                  type="checkbox"
                  checked={selected.includes(event)}
                  onChange={() => toggle(event)}
                  className="w-3.5 h-3.5 accent-cyan-400 cursor-pointer"
                  aria-label={event}
                />
                <span className="text-sm text-foreground/80 font-mono">
                  {event}
                </span>
              </label>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Retry policy fields ──────────────────────────────────────────────────────
//
// Delivery is retried with exponential backoff; the three numbers are the whole
// of that policy. Bounds come from `validate_retry_policy` in the webhooks
// handler, repeated here so an out-of-range value is caught before the round
// trip rather than as a 400.

interface RetryPolicyFieldsProps {
  idPrefix: string;
  value: RetryPolicy;
  onChange: (next: RetryPolicy) => void;
}

function RetryPolicyFields({ idPrefix, value, onChange }: RetryPolicyFieldsProps) {
  const previewDelays = [0, 1, 2]
    .map((n) =>
      Math.round(value.initial_delay_secs * value.backoff_multiplier ** n)
    )
    .join("s, ");

  return (
    <div className="space-y-3">
      <Label>Retry Policy</Label>
      <div className="grid gap-3 sm:grid-cols-3">
        <div className="space-y-1">
          <Label htmlFor={`${idPrefix}-retry-max`} className="text-xs">
            Max retries
          </Label>
          <Input
            id={`${idPrefix}-retry-max`}
            type="number"
            min={RETRY_POLICY_BOUNDS.max_retries.min}
            max={RETRY_POLICY_BOUNDS.max_retries.max}
            value={value.max_retries}
            onChange={(e) =>
              onChange({ ...value, max_retries: Number(e.target.value) })
            }
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor={`${idPrefix}-retry-delay`} className="text-xs">
            Initial delay (s)
          </Label>
          <Input
            id={`${idPrefix}-retry-delay`}
            type="number"
            min={RETRY_POLICY_BOUNDS.initial_delay_secs.min}
            max={RETRY_POLICY_BOUNDS.initial_delay_secs.max}
            value={value.initial_delay_secs}
            onChange={(e) =>
              onChange({ ...value, initial_delay_secs: Number(e.target.value) })
            }
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor={`${idPrefix}-retry-backoff`} className="text-xs">
            Backoff multiplier
          </Label>
          <Input
            id={`${idPrefix}-retry-backoff`}
            type="number"
            step={0.1}
            min={RETRY_POLICY_BOUNDS.backoff_multiplier.min}
            max={RETRY_POLICY_BOUNDS.backoff_multiplier.max}
            value={value.backoff_multiplier}
            onChange={(e) =>
              onChange({ ...value, backoff_multiplier: Number(e.target.value) })
            }
          />
        </div>
      </div>
      <p className="text-xs text-muted-foreground">
        {value.max_retries === 0
          ? "No retries: a failed delivery is dropped after the first attempt."
          : `First three retries after roughly ${previewDelays}s.`}
      </p>
    </div>
  );
}

// ─── Create form fields ───────────────────────────────────────────────────────

interface CreateWebhookFieldsProps {
  url: string;
  eventTypes: string[];
  secret: string;
  retryPolicy: RetryPolicy;
  onUrlChange: (v: string) => void;
  onEventTypesChange: (v: string[]) => void;
  onSecretChange: (v: string) => void;
  onRetryPolicyChange: (v: RetryPolicy) => void;
}

function CreateWebhookFields({
  url,
  eventTypes,
  secret,
  retryPolicy,
  onUrlChange,
  onEventTypesChange,
  onSecretChange,
  onRetryPolicyChange,
}: CreateWebhookFieldsProps) {
  return (
    <>
      <div className="space-y-2">
        <Label htmlFor="wh-url">URL *</Label>
        <Input
          id="wh-url"
          type="url"
          value={url}
          onChange={(e) => onUrlChange(e.target.value)}
          placeholder="https://hooks.example.com/axiam"
          required
          autoComplete="off"
        />
      </div>

      <div className="space-y-2">
        <Label>Event Types *</Label>
        <div className="rounded-md border border-input bg-background/50 p-3">
          <EventTypeSelector
            selected={eventTypes}
            onChange={onEventTypesChange}
          />
        </div>
        {eventTypes.length === 0 && (
          <p className="text-xs text-muted-foreground">
            Select at least one event type.
          </p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="wh-secret">Secret *</Label>
        <Input
          id="wh-secret"
          value={secret}
          onChange={(e) => onSecretChange(e.target.value)}
          placeholder="Shared secret"
          required
          autoComplete="off"
        />
        <p className="text-xs text-muted-foreground">
          Used for HMAC-SHA256 signature verification.
        </p>
      </div>

      <RetryPolicyFields
        idPrefix="wh"
        value={retryPolicy}
        onChange={onRetryPolicyChange}
      />
    </>
  );
}

// ─── Edit form fields ─────────────────────────────────────────────────────────

interface EditWebhookFieldsProps {
  url: string;
  enabled: boolean;
  eventTypes: string[];
  retryPolicy: RetryPolicy;
  secret: string;
  onUrlChange: (v: string) => void;
  onEnabledChange: (v: boolean) => void;
  onEventTypesChange: (v: string[]) => void;
  onRetryPolicyChange: (v: RetryPolicy) => void;
  onSecretChange: (v: string) => void;
}

function EditWebhookFields({
  url,
  enabled,
  eventTypes,
  retryPolicy,
  secret,
  onUrlChange,
  onEnabledChange,
  onEventTypesChange,
  onRetryPolicyChange,
  onSecretChange,
}: EditWebhookFieldsProps) {
  return (
    <>
      <div className="space-y-2">
        <Label htmlFor="edit-wh-url">URL *</Label>
        <Input
          id="edit-wh-url"
          type="url"
          value={url}
          onChange={(e) => onUrlChange(e.target.value)}
          placeholder="https://hooks.example.com/axiam"
          required
        />
      </div>

      <ToggleField
        id="edit-wh-enabled"
        label="Enabled"
        checked={enabled}
        onChange={onEnabledChange}
      />

      <div className="space-y-2">
        <Label>Event Types *</Label>
        <div className="rounded-md border border-input bg-background/50 p-3">
          <EventTypeSelector
            selected={eventTypes}
            onChange={onEventTypesChange}
          />
        </div>
      </div>

      <RetryPolicyFields
        idPrefix="edit-wh"
        value={retryPolicy}
        onChange={onRetryPolicyChange}
      />

      {/* D-02 secret rotation. Left blank the field is omitted from the
          payload, which is what leaves the stored secret in place — an empty
          string would be rejected rather than meaning "no change". */}
      <div className="space-y-2">
        <Label htmlFor="edit-wh-secret">Rotate secret</Label>
        <Input
          id="edit-wh-secret"
          value={secret}
          onChange={(e) => onSecretChange(e.target.value)}
          placeholder="Leave blank to keep the current secret"
          autoComplete="off"
        />
        <p className="text-xs text-muted-foreground">
          Deliveries are signed with the new secret as soon as this is saved.
          Update the receiver first, or it will reject every event.
        </p>
      </div>
    </>
  );
}

// ─── Main page ─────────────────────────────────────────────────────────────────

export function WebhooksPage() {
  const queryClient = useQueryClient();

  // Server-paged and server-searched. This page used to fetch the tenant's
  // entire collection in one request and render all of it, which is fine at ten
  // rows and unusable at two hundred with no way to find one by name.
  const {
    items: webhooks,
    isLoading,
    search,
    setSearch,
    page,
    totalPages,
    total,
    setPage,
    isFiltered,
  } = usePaginatedList<Webhook>(["webhooks"], "/api/v1/webhooks");

  // ─── Create state ──────────────────────────────────────────────────────────
  const [createOpen, setCreateOpen] = useState(false);
  const [createUrl, setCreateUrl] = useState("");
  const [createEventTypes, setCreateEventTypes] = useState<string[]>([]);
  const [createSecret, setCreateSecret] = useState("");
  const [createRetryPolicy, setCreateRetryPolicy] =
    useState<RetryPolicy>(DEFAULT_RETRY_POLICY);
  const [createError, setCreateError] = useState("");

  const createMutation = useMutation({
    mutationFn: (payload: CreateWebhookPayload) =>
      webhookService.create(payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["webhooks"] });
      setCreateOpen(false);
      resetCreateForm();
    },
    onError: (err: unknown) => {
      setCreateError(
        getApiErrorMessage(
          err,
          err instanceof Error ? err.message : "Failed to create webhook."
        )
      );
    },
  });

  function resetCreateForm() {
    setCreateUrl("");
    setCreateEventTypes([]);
    setCreateSecret("");
    setCreateRetryPolicy(DEFAULT_RETRY_POLICY);
    setCreateError("");
  }

  function handleCreateSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setCreateError("");
    if (!createUrl.trim()) {
      setCreateError("URL is required.");
      return;
    }
    if (createEventTypes.length === 0) {
      setCreateError("Select at least one event type.");
      return;
    }
    if (!createSecret.trim()) {
      setCreateError("Secret is required.");
      return;
    }
    const retryError = validateRetryPolicy(createRetryPolicy);
    if (retryError) {
      setCreateError(retryError);
      return;
    }
    const payload: CreateWebhookPayload = {
      url: createUrl.trim(),
      events: createEventTypes,
      secret: createSecret.trim(),
      retry_policy: createRetryPolicy,
    };
    createMutation.mutate(payload);
  }

  // ─── Edit state ────────────────────────────────────────────────────────────
  const [editWebhook, setEditWebhook] = useState<Webhook | null>(null);
  const [editUrl, setEditUrl] = useState("");
  const [editEnabled, setEditEnabled] = useState(true);
  const [editEventTypes, setEditEventTypes] = useState<string[]>([]);
  const [editRetryPolicy, setEditRetryPolicy] =
    useState<RetryPolicy>(DEFAULT_RETRY_POLICY);
  const [editSecret, setEditSecret] = useState("");
  const [editError, setEditError] = useState("");

  const editMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: UpdateWebhookPayload }) =>
      webhookService.update(id, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["webhooks"] });
      setEditWebhook(null);
    },
    onError: (err: unknown) => {
      setEditError(
        getApiErrorMessage(
          err,
          err instanceof Error ? err.message : "Failed to update webhook."
        )
      );
    },
  });

  function openEdit(hook: Webhook) {
    setEditWebhook(hook);
    setEditUrl(hook.url);
    setEditEnabled(hook.enabled);
    setEditEventTypes(hook.events);
    // A row from a server that predates the field would carry none.
    setEditRetryPolicy(hook.retry_policy ?? DEFAULT_RETRY_POLICY);
    setEditSecret("");
    setEditError("");
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setEditError("");
    if (!editWebhook || !editUrl.trim()) {
      setEditError("URL is required.");
      return;
    }
    const retryError = validateRetryPolicy(editRetryPolicy);
    if (retryError) {
      setEditError(retryError);
      return;
    }
    editMutation.mutate({
      id: editWebhook.id,
      payload: {
        url: editUrl.trim(),
        events: editEventTypes,
        enabled: editEnabled,
        retry_policy: editRetryPolicy,
        // Only when the admin typed one: an omitted `secret` keeps the stored
        // one, an empty string is a validation error.
        ...(editSecret.trim() ? { secret: editSecret.trim() } : {}),
      },
    });
  }

  // ─── Delete state ──────────────────────────────────────────────────────────
  const [deleteWebhook, setDeleteWebhook] = useState<Webhook | null>(null);

  const deleteMutation = useMutation({
    mutationFn: (id: string) => webhookService.remove(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["webhooks"] });
      setDeleteWebhook(null);
    },
  });

  // ─── Table columns ─────────────────────────────────────────────────────────
  const columns: Column<Webhook>[] = [
    {
      key: "url",
      header: "URL",
      render: (row) => (
        <span
          className="font-medium text-foreground/90 text-sm max-w-[260px] truncate block"
          title={row.url}
        >
          {row.url}
        </span>
      ),
    },
    {
      key: "events",
      header: "Events",
      render: (row) => (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-purple-500/15 text-purple-400 border border-purple-500/30">
          {row.events.length}{" "}
          {row.events.length === 1 ? "event" : "events"}
        </span>
      ),
    },
    {
      key: "enabled",
      header: "Status",
      render: (row) => (
        <StatusBadge status={row.enabled ? "active" : "inactive"} />
      ),
    },
    {
      key: "created_at",
      header: "Created",
      render: (row) => (
        <span className="text-muted-foreground text-sm">
          {formatDate(row.created_at)}
        </span>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      width: "w-24",
      render: (row) => (
        <div className="flex items-center gap-1">
          <button
            aria-label={`Edit webhook ${row.url}`}
            onClick={() => openEdit(row)}
            className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
          >
            <Pencil size={14} />
          </button>
          <button
            aria-label={`Delete webhook ${row.url}`}
            onClick={() => setDeleteWebhook(row)}
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
        title="Webhooks"
        description="Deliver real-time event notifications to external systems."
        action={
          <Button
            onClick={() => {
              resetCreateForm();
              setCreateOpen(true);
            }}
          >
            <Plus size={16} />
            New Webhook
          </Button>
        }
      />

      <SearchBox
        value={search}
        onChange={setSearch}
        noun="webhooks"
        className="mb-4 max-w-sm"
        />

      <DataTable
        columns={columns}
        data={webhooks}
        isLoading={isLoading}
        emptyMessage={
          isFiltered ? "No webhooks match your search." : "No webhooks configured."
        }
        />

      <PaginationControls
        page={page}
        totalPages={totalPages}
        total={total}
        onPageChange={setPage}
        />

      {/* Create dialog */}
      <FormDialog
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          resetCreateForm();
        }}
        title="New Webhook"
        onSubmit={handleCreateSubmit}
        isLoading={createMutation.isPending}
        submitLabel="Create"
        error={createError}
        errorId="webhook-create-error"
      >
        <CreateWebhookFields
          url={createUrl}
          eventTypes={createEventTypes}
          secret={createSecret}
          onUrlChange={setCreateUrl}
          onEventTypesChange={setCreateEventTypes}
          onSecretChange={setCreateSecret}
          retryPolicy={createRetryPolicy}
          onRetryPolicyChange={setCreateRetryPolicy}
        />
      </FormDialog>

      {/* Edit dialog */}
      <FormDialog
        open={editWebhook !== null}
        onClose={() => setEditWebhook(null)}
        title="Edit Webhook"
        onSubmit={handleEditSubmit}
        isLoading={editMutation.isPending}
        submitLabel="Save Changes"
        error={editError}
        errorId="webhook-edit-error"
      >
        <EditWebhookFields
          url={editUrl}
          enabled={editEnabled}
          eventTypes={editEventTypes}
          onUrlChange={setEditUrl}
          onEnabledChange={setEditEnabled}
          onEventTypesChange={setEditEventTypes}
          retryPolicy={editRetryPolicy}
          onRetryPolicyChange={setEditRetryPolicy}
          secret={editSecret}
          onSecretChange={setEditSecret}
        />
      </FormDialog>

      {/* Delete confirm */}
      <ConfirmDialog
        open={deleteWebhook !== null}
        onClose={() => setDeleteWebhook(null)}
        onConfirm={() =>
          deleteWebhook && deleteMutation.mutate(deleteWebhook.id)
        }
        title="Delete Webhook"
        description={`Are you sure you want to delete the webhook for "${deleteWebhook?.url}"? This action cannot be undone.`}
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  webhookService,
  WEBHOOK_EVENT_GROUPS,
  type Webhook,
  type CreateWebhookPayload,
  type UpdateWebhookPayload,
} from "@/services/webhooks";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { StatusBadge } from "@/components/StatusBadge";
import { SecretRevealModal } from "@/components/SecretRevealModal";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Pencil, Plus, Trash2 } from "lucide-react";

// ─── Helpers ──────────────────────────────────────────────────────────────────

const formatDate = (iso: string) =>
  new Intl.DateTimeFormat("en-US", { dateStyle: "medium" }).format(
    new Date(iso)
  );

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

// ─── Toggle field ─────────────────────────────────────────────────────────────

interface ToggleFieldProps {
  id: string;
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}

function ToggleField({ id, label, checked, onChange }: ToggleFieldProps) {
  return (
    <div className="flex items-center gap-3">
      <input
        type="checkbox"
        id={id}
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="w-4 h-4 accent-cyan-400 cursor-pointer"
      />
      <Label htmlFor={id} className="cursor-pointer">
        {label}
      </Label>
    </div>
  );
}

// ─── Create form fields ───────────────────────────────────────────────────────

interface CreateWebhookFieldsProps {
  url: string;
  description: string;
  isActive: boolean;
  eventTypes: string[];
  secret: string;
  onUrlChange: (v: string) => void;
  onDescriptionChange: (v: string) => void;
  onIsActiveChange: (v: boolean) => void;
  onEventTypesChange: (v: string[]) => void;
  onSecretChange: (v: string) => void;
  error?: string;
}

function CreateWebhookFields({
  url,
  description,
  isActive,
  eventTypes,
  secret,
  onUrlChange,
  onDescriptionChange,
  onIsActiveChange,
  onEventTypesChange,
  onSecretChange,
  error,
}: CreateWebhookFieldsProps) {
  return (
    <>
      <div className="space-y-1.5">
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

      <div className="space-y-1.5">
        <Label htmlFor="wh-description">Description</Label>
        <Input
          id="wh-description"
          value={description}
          onChange={(e) => onDescriptionChange(e.target.value)}
          placeholder="Optional description"
          autoComplete="off"
        />
      </div>

      <ToggleField
        id="wh-is-active"
        label="Active"
        checked={isActive}
        onChange={onIsActiveChange}
      />

      <div className="space-y-1.5">
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

      <div className="space-y-1.5">
        <Label htmlFor="wh-secret">Secret</Label>
        <Input
          id="wh-secret"
          value={secret}
          onChange={(e) => onSecretChange(e.target.value)}
          placeholder="Leave empty to auto-generate"
          autoComplete="off"
        />
        <p className="text-xs text-muted-foreground">
          Used for HMAC-SHA256 signature verification. Leave blank to
          auto-generate.
        </p>
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}
    </>
  );
}

// ─── Edit form fields ─────────────────────────────────────────────────────────

interface EditWebhookFieldsProps {
  url: string;
  description: string;
  isActive: boolean;
  eventTypes: string[];
  onUrlChange: (v: string) => void;
  onDescriptionChange: (v: string) => void;
  onIsActiveChange: (v: boolean) => void;
  onEventTypesChange: (v: string[]) => void;
  error?: string;
}

function EditWebhookFields({
  url,
  description,
  isActive,
  eventTypes,
  onUrlChange,
  onDescriptionChange,
  onIsActiveChange,
  onEventTypesChange,
  error,
}: EditWebhookFieldsProps) {
  return (
    <>
      <div className="space-y-1.5">
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

      <div className="space-y-1.5">
        <Label htmlFor="edit-wh-description">Description</Label>
        <Input
          id="edit-wh-description"
          value={description}
          onChange={(e) => onDescriptionChange(e.target.value)}
          placeholder="Optional description"
        />
      </div>

      <ToggleField
        id="edit-wh-is-active"
        label="Active"
        checked={isActive}
        onChange={onIsActiveChange}
      />

      <div className="space-y-1.5">
        <Label>Event Types *</Label>
        <div className="rounded-md border border-input bg-background/50 p-3">
          <EventTypeSelector
            selected={eventTypes}
            onChange={onEventTypesChange}
          />
        </div>
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}
    </>
  );
}

// ─── Main page ─────────────────────────────────────────────────────────────────

export function WebhooksPage() {
  const queryClient = useQueryClient();

  const { data: webhooks = [], isLoading } = useQuery({
    queryKey: ["webhooks"],
    queryFn: () => webhookService.list(),
  });

  // ─── Create state ──────────────────────────────────────────────────────────
  const [createOpen, setCreateOpen] = useState(false);
  const [createUrl, setCreateUrl] = useState("");
  const [createDescription, setCreateDescription] = useState("");
  const [createIsActive, setCreateIsActive] = useState(true);
  const [createEventTypes, setCreateEventTypes] = useState<string[]>([]);
  const [createSecret, setCreateSecret] = useState("");
  const [createError, setCreateError] = useState("");

  // ─── Secret reveal state ───────────────────────────────────────────────────
  const [secretOpen, setSecretOpen] = useState(false);
  const [revealedSecret, setRevealedSecret] = useState("");

  const createMutation = useMutation({
    mutationFn: (payload: CreateWebhookPayload) =>
      webhookService.create(payload),
    onSuccess: (resp) => {
      void queryClient.invalidateQueries({ queryKey: ["webhooks"] });
      setCreateOpen(false);
      resetCreateForm();
      if (resp.secret) {
        setRevealedSecret(resp.secret);
        setSecretOpen(true);
      }
    },
    onError: (err: unknown) => {
      setCreateError(
        err instanceof Error ? err.message : "Failed to create webhook."
      );
    },
  });

  function resetCreateForm() {
    setCreateUrl("");
    setCreateDescription("");
    setCreateIsActive(true);
    setCreateEventTypes([]);
    setCreateSecret("");
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
    const payload: CreateWebhookPayload = {
      url: createUrl.trim(),
      event_types: createEventTypes,
      is_active: createIsActive,
      description: createDescription.trim() || undefined,
      secret: createSecret.trim() || undefined,
    };
    createMutation.mutate(payload);
  }

  // ─── Edit state ────────────────────────────────────────────────────────────
  const [editWebhook, setEditWebhook] = useState<Webhook | null>(null);
  const [editUrl, setEditUrl] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editIsActive, setEditIsActive] = useState(true);
  const [editEventTypes, setEditEventTypes] = useState<string[]>([]);
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
        err instanceof Error ? err.message : "Failed to update webhook."
      );
    },
  });

  function openEdit(hook: Webhook) {
    setEditWebhook(hook);
    setEditUrl(hook.url);
    setEditDescription(hook.description ?? "");
    setEditIsActive(hook.is_active);
    setEditEventTypes(hook.event_types);
    setEditError("");
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setEditError("");
    if (!editWebhook || !editUrl.trim()) {
      setEditError("URL is required.");
      return;
    }
    editMutation.mutate({
      id: editWebhook.id,
      payload: {
        url: editUrl.trim(),
        event_types: editEventTypes,
        is_active: editIsActive,
        description: editDescription.trim() || undefined,
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
      key: "event_types",
      header: "Events",
      render: (row) => (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-purple-500/15 text-purple-400 border border-purple-500/30">
          {row.event_types.length}{" "}
          {row.event_types.length === 1 ? "event" : "events"}
        </span>
      ),
    },
    {
      key: "is_active",
      header: "Status",
      render: (row) => (
        <StatusBadge status={row.is_active ? "active" : "inactive"} />
      ),
    },
    {
      key: "description",
      header: "Description",
      render: (row) => (
        <span className="text-muted-foreground text-sm">
          {row.description ?? "—"}
        </span>
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

      <DataTable
        columns={columns}
        data={webhooks}
        isLoading={isLoading}
        emptyMessage="No webhooks configured."
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
      >
        <CreateWebhookFields
          url={createUrl}
          description={createDescription}
          isActive={createIsActive}
          eventTypes={createEventTypes}
          secret={createSecret}
          onUrlChange={setCreateUrl}
          onDescriptionChange={setCreateDescription}
          onIsActiveChange={setCreateIsActive}
          onEventTypesChange={setCreateEventTypes}
          onSecretChange={setCreateSecret}
          error={createError}
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
      >
        <EditWebhookFields
          url={editUrl}
          description={editDescription}
          isActive={editIsActive}
          eventTypes={editEventTypes}
          onUrlChange={setEditUrl}
          onDescriptionChange={setEditDescription}
          onIsActiveChange={setEditIsActive}
          onEventTypesChange={setEditEventTypes}
          error={editError}
        />
      </FormDialog>

      {/* Auto-generated secret reveal */}
      <SecretRevealModal
        open={secretOpen}
        onClose={() => setSecretOpen(false)}
        title="Webhook Created"
        description="Your webhook has been created. Save the secret now — it will not be shown again."
        secrets={[
          {
            label: "Webhook Secret (HMAC-SHA256)",
            value: revealedSecret,
          },
        ]}
      />

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

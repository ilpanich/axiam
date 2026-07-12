import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Pencil, Trash2 } from "lucide-react";
import {
  notificationRuleService,
  notificationEventLabel,
  NOTIFICATION_EVENTS,
  type NotificationRule,
  type CreateNotificationRulePayload,
  type UpdateNotificationRulePayload,
} from "@/services/notificationRules";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { formatDate } from "@/lib/utils";
import { Textarea } from "@/components/ui/textarea";
import { ToggleField } from "@/components/shared";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function parseEmails(raw: string): string[] {
  return raw
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function validateEmails(raw: string): string | null {
  const emails = parseEmails(raw);
  if (emails.length === 0) return "At least one recipient email is required.";
  const invalid = emails.filter((e) => !isValidEmail(e));
  if (invalid.length > 0) {
    return `Invalid email${invalid.length > 1 ? "s" : ""}: ${invalid.slice(0, 3).join(", ")}`;
  }
  return null;
}

// ─── Rule form fields ─────────────────────────────────────────────────────────

interface RuleFormFieldsProps {
  name: string;
  events: string[];
  recipientEmails: string;
  enabled: boolean;
  description: string;
  onNameChange: (v: string) => void;
  onEventsChange: (v: string[]) => void;
  onRecipientEmailsChange: (v: string) => void;
  onEnabledChange: (v: boolean) => void;
  onDescriptionChange: (v: string) => void;
  error?: string;
  idPrefix: string;
}

function RuleFormFields({
  name,
  events,
  recipientEmails,
  enabled,
  description,
  onNameChange,
  onEventsChange,
  onRecipientEmailsChange,
  onEnabledChange,
  onDescriptionChange,
  error,
  idPrefix,
}: RuleFormFieldsProps) {
  function toggleEvent(value: string, checked: boolean) {
    if (checked) {
      onEventsChange(events.includes(value) ? events : [...events, value]);
    } else {
      onEventsChange(events.filter((e) => e !== value));
    }
  }

  return (
    <>
      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-name`}>Name *</Label>
        <Input
          id={`${idPrefix}-name`}
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          placeholder="e.g. Security alerts"
          autoComplete="off"
        />
      </div>

      <div className="space-y-2">
        <span className="text-sm font-medium leading-none">Events *</span>
        <div
          role="group"
          aria-label="Events"
          className="max-h-48 overflow-y-auto rounded-md border border-input bg-background/50 p-3 grid grid-cols-1 sm:grid-cols-2 gap-2"
        >
          {NOTIFICATION_EVENTS.map((evt) => {
            const checkboxId = `${idPrefix}-evt-${evt.value}`;
            return (
              <div key={evt.value} className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id={checkboxId}
                  checked={events.includes(evt.value)}
                  onChange={(e) => toggleEvent(evt.value, e.target.checked)}
                  className="w-4 h-4 accent-cyan-400 cursor-pointer"
                />
                <Label htmlFor={checkboxId} className="cursor-pointer text-sm font-normal">
                  {evt.label}
                </Label>
              </div>
            );
          })}
        </div>
        <p className="text-xs text-muted-foreground">Select one or more events.</p>
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-emails`}>Recipient Emails *</Label>
        <Textarea
          id={`${idPrefix}-emails`}
          value={recipientEmails}
          onChange={(e) => onRecipientEmailsChange(e.target.value)}
          placeholder={"admin@example.com\nops@example.com"}
          rows={3}
          aria-label="Recipient Emails (one per line)"
        />
        <p className="text-xs text-muted-foreground">One email address per line.</p>
      </div>

      <ToggleField
        id={`${idPrefix}-enabled`}
        label="Enabled"
        checked={enabled}
        onChange={onEnabledChange}
      />

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-description`}>Description</Label>
        <Input
          id={`${idPrefix}-description`}
          value={description}
          onChange={(e) => onDescriptionChange(e.target.value)}
          placeholder="Optional description"
          autoComplete="off"
        />
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}
    </>
  );
}

// ─── Form state hook ──────────────────────────────────────────────────────────

function useRuleFormState() {
  const [name, setName] = useState("");
  const [events, setEvents] = useState<string[]>([]);
  const [recipientEmails, setRecipientEmails] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [description, setDescription] = useState("");
  const [error, setError] = useState("");

  function reset() {
    setName("");
    setEvents([]);
    setRecipientEmails("");
    setEnabled(true);
    setDescription("");
    setError("");
  }

  function load(rule: NotificationRule) {
    setName(rule.name);
    setEvents(rule.events);
    setRecipientEmails(rule.recipient_emails.join("\n"));
    setEnabled(rule.enabled);
    setDescription(rule.description ?? "");
    setError("");
  }

  return {
    name,
    setName,
    events,
    setEvents,
    recipientEmails,
    setRecipientEmails,
    enabled,
    setEnabled,
    description,
    setDescription,
    error,
    setError,
    reset,
    load,
  };
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function NotificationRulesPage() {
  const queryClient = useQueryClient();

  const { data: rules = [], isLoading } = useQuery({
    queryKey: ["notification-rules"],
    queryFn: () => notificationRuleService.list(),
  });

  // ─── Create state ──────────────────────────────────────────────────────────
  const [createOpen, setCreateOpen] = useState(false);
  const createForm = useRuleFormState();

  const createMutation = useMutation({
    mutationFn: (payload: CreateNotificationRulePayload) =>
      notificationRuleService.create(payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["notification-rules"] });
      setCreateOpen(false);
      createForm.reset();
    },
    onError: (err: unknown) => {
      createForm.setError(
        err instanceof Error ? err.message : "Failed to create notification rule."
      );
    },
  });

  function handleCreateSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    createForm.setError("");
    if (!createForm.name.trim()) {
      createForm.setError("Name is required.");
      return;
    }
    if (createForm.events.length === 0) {
      createForm.setError("At least one event is required.");
      return;
    }
    const emailError = validateEmails(createForm.recipientEmails);
    if (emailError) {
      createForm.setError(emailError);
      return;
    }
    const payload: CreateNotificationRulePayload = {
      name: createForm.name.trim(),
      description: createForm.description.trim(),
      events: createForm.events,
      recipient_emails: parseEmails(createForm.recipientEmails),
    };
    createMutation.mutate(payload);
  }

  // ─── Edit state ────────────────────────────────────────────────────────────
  const [editRule, setEditRule] = useState<NotificationRule | null>(null);
  const editForm = useRuleFormState();

  const editMutation = useMutation({
    mutationFn: ({
      id,
      payload,
    }: {
      id: string;
      payload: UpdateNotificationRulePayload;
    }) => notificationRuleService.update(id, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["notification-rules"] });
      setEditRule(null);
    },
    onError: (err: unknown) => {
      editForm.setError(
        err instanceof Error ? err.message : "Failed to update notification rule."
      );
    },
  });

  function openEdit(rule: NotificationRule) {
    setEditRule(rule);
    editForm.load(rule);
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    editForm.setError("");
    if (!editRule) return;
    if (!editForm.name.trim()) {
      editForm.setError("Name is required.");
      return;
    }
    if (editForm.events.length === 0) {
      editForm.setError("At least one event is required.");
      return;
    }
    const emailError = validateEmails(editForm.recipientEmails);
    if (emailError) {
      editForm.setError(emailError);
      return;
    }
    editMutation.mutate({
      id: editRule.id,
      payload: {
        name: editForm.name.trim(),
        description: editForm.description.trim(),
        events: editForm.events,
        recipient_emails: parseEmails(editForm.recipientEmails),
        enabled: editForm.enabled,
      },
    });
  }

  // ─── Delete state ──────────────────────────────────────────────────────────
  const [deleteRule, setDeleteRule] = useState<NotificationRule | null>(null);

  const deleteMutation = useMutation({
    mutationFn: (id: string) => notificationRuleService.remove(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["notification-rules"] });
      setDeleteRule(null);
    },
  });

  // ─── Table columns ─────────────────────────────────────────────────────────

  const columns: Column<NotificationRule>[] = [
    {
      key: "name",
      header: "Name",
      render: (row) => (
        <span className="text-sm font-medium text-foreground">{row.name}</span>
      ),
    },
    {
      key: "events",
      header: "Events",
      render: (row) => (
        <div className="flex flex-wrap gap-1 max-w-xs">
          {row.events.length === 0 ? (
            <span className="text-sm text-muted-foreground">—</span>
          ) : (
            row.events.map((evt) => (
              <span
                key={evt}
                className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-purple-500/15 text-purple-400 border border-purple-500/30"
              >
                {notificationEventLabel(evt)}
              </span>
            ))
          )}
        </div>
      ),
    },
    {
      key: "recipient_emails",
      header: "Recipients",
      render: (row) => (
        <div>
          <span className="text-sm text-foreground/80">
            {row.recipient_emails[0] ?? "—"}
          </span>
          {row.recipient_emails.length > 1 && (
            <span className="ml-1.5 text-xs text-muted-foreground">
              +{row.recipient_emails.length - 1} more
            </span>
          )}
        </div>
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
      key: "description",
      header: "Description",
      render: (row) => (
        <span className="text-sm text-muted-foreground">
          {row.description || "—"}
        </span>
      ),
    },
    {
      key: "created_at",
      header: "Created",
      render: (row) => (
        <span className="text-sm text-muted-foreground">
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
            aria-label={`Edit rule ${row.name}`}
            onClick={() => openEdit(row)}
            className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
          >
            <Pencil size={14} />
          </button>
          <button
            aria-label={`Delete rule ${row.name}`}
            onClick={() => setDeleteRule(row)}
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
        title="Notification Rules"
        description="Configure email notifications triggered by IAM events."
        action={
          <Button
            onClick={() => {
              createForm.reset();
              setCreateOpen(true);
            }}
          >
            <Plus size={16} />
            New Rule
          </Button>
        }
      />

      <DataTable
        columns={columns}
        data={rules}
        isLoading={isLoading}
        emptyMessage="No notification rules configured."
      />

      {/* Create dialog */}
      <FormDialog
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          createForm.reset();
        }}
        title="New Notification Rule"
        onSubmit={handleCreateSubmit}
        isLoading={createMutation.isPending}
        submitLabel="Create"
      >
        <RuleFormFields
          name={createForm.name}
          events={createForm.events}
          recipientEmails={createForm.recipientEmails}
          enabled={createForm.enabled}
          description={createForm.description}
          onNameChange={createForm.setName}
          onEventsChange={createForm.setEvents}
          onRecipientEmailsChange={createForm.setRecipientEmails}
          onEnabledChange={createForm.setEnabled}
          onDescriptionChange={createForm.setDescription}
          error={createForm.error}
          idPrefix="create"
        />
      </FormDialog>

      {/* Edit dialog */}
      <FormDialog
        open={editRule !== null}
        onClose={() => setEditRule(null)}
        title="Edit Notification Rule"
        onSubmit={handleEditSubmit}
        isLoading={editMutation.isPending}
        submitLabel="Save Changes"
      >
        <RuleFormFields
          name={editForm.name}
          events={editForm.events}
          recipientEmails={editForm.recipientEmails}
          enabled={editForm.enabled}
          description={editForm.description}
          onNameChange={editForm.setName}
          onEventsChange={editForm.setEvents}
          onRecipientEmailsChange={editForm.setRecipientEmails}
          onEnabledChange={editForm.setEnabled}
          onDescriptionChange={editForm.setDescription}
          error={editForm.error}
          idPrefix="edit"
        />
      </FormDialog>

      {/* Delete confirm */}
      <ConfirmDialog
        open={deleteRule !== null}
        onClose={() => setDeleteRule(null)}
        onConfirm={() =>
          deleteRule && deleteMutation.mutate(deleteRule.id)
        }
        title="Delete Notification Rule"
        description={`Are you sure you want to delete the notification rule "${deleteRule?.name}"? This action cannot be undone.`}
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}

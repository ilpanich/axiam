import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Pencil, Trash2 } from "lucide-react";
import {
  notificationRuleService,
  type NotificationRule,
  type CreateNotificationRulePayload,
  type UpdateNotificationRulePayload,
} from "@/services/notificationRules";
import { WEBHOOK_EVENTS } from "@/services/webhooks";
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

// ─── Rule form fields ─────────────────────────────────────────────────────────

interface RuleFormFieldsProps {
  eventType: string;
  recipientEmails: string;
  isActive: boolean;
  description: string;
  onEventTypeChange: (v: string) => void;
  onRecipientEmailsChange: (v: string) => void;
  onIsActiveChange: (v: boolean) => void;
  onDescriptionChange: (v: string) => void;
  error?: string;
  idPrefix: string;
}

function RuleFormFields({
  eventType,
  recipientEmails,
  isActive,
  description,
  onEventTypeChange,
  onRecipientEmailsChange,
  onIsActiveChange,
  onDescriptionChange,
  error,
  idPrefix,
}: RuleFormFieldsProps) {
  return (
    <>
      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-event-type`}>Event Type *</Label>
        <select
          id={`${idPrefix}-event-type`}
          value={eventType}
          onChange={(e) => onEventTypeChange(e.target.value)}
          className="w-full rounded-md border border-input bg-background/50 px-3 py-2 text-sm text-foreground font-mono focus:outline-none focus:ring-2 focus:ring-primary/40"
          aria-label="Event Type"
        >
          <option value="">Select an event type...</option>
          {WEBHOOK_EVENTS.map((evt) => (
            <option key={evt} value={evt}>
              {evt}
            </option>
          ))}
        </select>
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
        id={`${idPrefix}-active`}
        label="Active"
        checked={isActive}
        onChange={onIsActiveChange}
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
  const [eventType, setEventType] = useState("");
  const [recipientEmails, setRecipientEmails] = useState("");
  const [isActive, setIsActive] = useState(true);
  const [description, setDescription] = useState("");
  const [error, setError] = useState("");

  function reset() {
    setEventType("");
    setRecipientEmails("");
    setIsActive(true);
    setDescription("");
    setError("");
  }

  function load(rule: NotificationRule) {
    setEventType(rule.event_type);
    setRecipientEmails(rule.recipient_emails.join("\n"));
    setIsActive(rule.is_active);
    setDescription(rule.description ?? "");
    setError("");
  }

  return {
    eventType,
    setEventType,
    recipientEmails,
    setRecipientEmails,
    isActive,
    setIsActive,
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
    if (!createForm.eventType) {
      createForm.setError("Event type is required.");
      return;
    }
    const emailError = validateEmails(createForm.recipientEmails);
    if (emailError) {
      createForm.setError(emailError);
      return;
    }
    const payload: CreateNotificationRulePayload = {
      event_type: createForm.eventType,
      recipient_emails: parseEmails(createForm.recipientEmails),
      is_active: createForm.isActive,
      description: createForm.description.trim() || undefined,
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
    if (!editRule || !editForm.eventType) {
      editForm.setError("Event type is required.");
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
        event_type: editForm.eventType,
        recipient_emails: parseEmails(editForm.recipientEmails),
        is_active: editForm.isActive,
        description: editForm.description.trim() || undefined,
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
      key: "event_type",
      header: "Event Type",
      render: (row) => (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium font-mono bg-purple-500/15 text-purple-400 border border-purple-500/30">
          {row.event_type}
        </span>
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
        <span className="text-sm text-muted-foreground">
          {row.description ?? "—"}
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
            aria-label={`Edit rule for ${row.event_type}`}
            onClick={() => openEdit(row)}
            className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
          >
            <Pencil size={14} />
          </button>
          <button
            aria-label={`Delete rule for ${row.event_type}`}
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
          eventType={createForm.eventType}
          recipientEmails={createForm.recipientEmails}
          isActive={createForm.isActive}
          description={createForm.description}
          onEventTypeChange={createForm.setEventType}
          onRecipientEmailsChange={createForm.setRecipientEmails}
          onIsActiveChange={createForm.setIsActive}
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
          eventType={editForm.eventType}
          recipientEmails={editForm.recipientEmails}
          isActive={editForm.isActive}
          description={editForm.description}
          onEventTypeChange={editForm.setEventType}
          onRecipientEmailsChange={editForm.setRecipientEmails}
          onIsActiveChange={editForm.setIsActive}
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
        description={`Are you sure you want to delete the notification rule for "${deleteRule?.event_type}"? This action cannot be undone.`}
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}

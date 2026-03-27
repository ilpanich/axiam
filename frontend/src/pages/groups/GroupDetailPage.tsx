import { useState, useRef } from "react";
import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  groupService,
  userService,
  type User,
  type CreateGroupPayload,
} from "@/services/users";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { DataTable, type Column } from "@/components/DataTable";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Loader2, Plus, Trash2, Search } from "lucide-react";
import { cn } from "@/lib/utils";

const formatDate = (iso: string) =>
  new Intl.DateTimeFormat("en-US", { dateStyle: "medium" }).format(
    new Date(iso)
  );

// ─── Section card ─────────────────────────────────────────────────────────────

function SectionCard({
  title,
  action,
  children,
}: {
  title: string;
  action?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="glass-card mb-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-base font-semibold text-foreground">{title}</h2>
        {action}
      </div>
      {children}
    </div>
  );
}

// ─── Info row ─────────────────────────────────────────────────────────────────

function InfoRow({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-start gap-1 sm:gap-4 py-2 border-b border-white/5 last:border-0">
      <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground sm:w-36 shrink-0 pt-0.5">
        {label}
      </span>
      <span className="text-sm text-foreground/90">{children}</span>
    </div>
  );
}

// ─── Add Member dialog ────────────────────────────────────────────────────────

interface AddMemberDialogProps {
  open: boolean;
  onClose: () => void;
  groupId: string;
  existingMemberIds: Set<string>;
  onAdded: () => void;
}

function AddMemberDialog({
  open,
  onClose,
  groupId,
  existingMemberIds,
  onAdded,
}: AddMemberDialogProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [results, setResults] = useState<User[]>([]);
  const [searching, setSearching] = useState(false);
  const [addingId, setAddingId] = useState<string | null>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  function handleSearchChange(e: React.ChangeEvent<HTMLInputElement>) {
    const term = e.target.value;
    setSearchTerm(term);

    if (debounceRef.current !== null) clearTimeout(debounceRef.current);
    if (!term.trim()) {
      setResults([]);
      return;
    }
    debounceRef.current = setTimeout(async () => {
      setSearching(true);
      try {
        const data = await userService.list(1, 20, term.trim());
        setResults(data.data);
      } catch {
        setResults([]);
      } finally {
        setSearching(false);
      }
    }, 300);
  }

  async function handleAdd(user: User) {
    setAddingId(user.id);
    try {
      await groupService.addMember(groupId, user.id);
      onAdded();
      // Remove added user from results
      setResults((prev) => prev.filter((u) => u.id !== user.id));
    } catch {
      // silently ignore; parent will refetch
    } finally {
      setAddingId(null);
    }
  }

  function handleClose() {
    setSearchTerm("");
    setResults([]);
    onClose();
  }

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      aria-modal="true"
      role="dialog"
      aria-labelledby="add-member-title"
    >
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={handleClose}
        aria-hidden="true"
      />
      <div className="relative z-10 glass-card w-full max-w-md flex flex-col max-h-[80vh]">
        <div className="flex items-center justify-between pb-4 border-b border-primary/10">
          <h2
            id="add-member-title"
            className="text-lg font-semibold text-foreground"
          >
            Add Member
          </h2>
          <button
            onClick={handleClose}
            className="text-muted-foreground hover:text-foreground transition-colors rounded p-1 focus:outline-none focus:ring-2 focus:ring-primary/40"
            aria-label="Close dialog"
          >
            ✕
          </button>
        </div>

        <div className="py-4 flex flex-col gap-3 overflow-hidden">
          {/* Search input */}
          <div className="relative">
            <Search
              size={15}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none"
              aria-hidden="true"
            />
            <input
              type="search"
              value={searchTerm}
              onChange={handleSearchChange}
              placeholder="Search users by name or email…"
              aria-label="Search users"
              className={cn(
                "h-9 w-full rounded-md pl-9 pr-3 text-sm",
                "bg-white/5 border border-primary/20 text-foreground",
                "placeholder:text-muted-foreground",
                "focus:outline-none focus:ring-2 focus:ring-primary/40 focus:border-primary",
                "transition-colors duration-200"
              )}
            />
          </div>

          {/* Results list */}
          <div className="overflow-y-auto flex-1 min-h-[120px] max-h-60 rounded-md border border-white/5">
            {searching ? (
              <div className="flex items-center justify-center py-6">
                <Loader2 size={20} className="animate-spin text-primary/60" />
              </div>
            ) : results.length === 0 && searchTerm ? (
              <p className="text-sm text-muted-foreground text-center py-6">
                No users found.
              </p>
            ) : !searchTerm ? (
              <p className="text-sm text-muted-foreground text-center py-6">
                Type to search for users.
              </p>
            ) : (
              <ul>
                {results.map((user) => {
                  const alreadyMember = existingMemberIds.has(user.id);
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
                      {alreadyMember ? (
                        <span className="text-xs text-muted-foreground">
                          Member
                        </span>
                      ) : (
                        <button
                          onClick={() => handleAdd(user)}
                          disabled={addingId === user.id}
                          className="flex items-center gap-1 text-xs px-2.5 py-1 rounded bg-primary/20 text-primary hover:bg-primary/30 transition-colors disabled:opacity-50"
                        >
                          {addingId === user.id ? (
                            <Loader2 size={12} className="animate-spin" />
                          ) : (
                            <Plus size={12} />
                          )}
                          Add
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

// ─── Edit group form ──────────────────────────────────────────────────────────

interface EditGroupFormProps {
  name: string;
  description: string;
  onNameChange: (v: string) => void;
  onDescriptionChange: (v: string) => void;
  error?: string;
}

function EditGroupForm({
  name,
  description,
  onNameChange,
  onDescriptionChange,
  error,
}: EditGroupFormProps) {
  return (
    <>
      <div className="space-y-1.5">
        <Label htmlFor="group-detail-name">Name *</Label>
        <Input
          id="group-detail-name"
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          required
        />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="group-detail-description">Description</Label>
        <textarea
          id="group-detail-description"
          value={description}
          onChange={(e) => onDescriptionChange(e.target.value)}
          rows={3}
          className={cn(
            "flex w-full rounded-md px-3 py-2 text-sm resize-none",
            "bg-white/5 border border-primary/20 text-foreground",
            "placeholder:text-muted-foreground",
            "focus:outline-none focus:ring-2 focus:ring-primary/40 focus:border-primary",
            "transition-colors duration-200"
          )}
        />
      </div>
      {error && <p className="text-sm text-destructive">{error}</p>}
    </>
  );
}

// ─── Main page ─────────────────────────────────────────────────────────────────

export function GroupDetailPage() {
  const { groupId } = useParams<{ groupId: string }>();
  const queryClient = useQueryClient();

  // ─── Group query ──────────────────────────────────────────────────────────────
  const {
    data: group,
    isLoading: groupLoading,
    error: groupError,
  } = useQuery({
    queryKey: ["group", groupId],
    queryFn: () => groupService.get(groupId!),
    enabled: !!groupId,
  });

  // ─── Members query ────────────────────────────────────────────────────────────
  const { data: members = [], isLoading: membersLoading } = useQuery({
    queryKey: ["group-members", groupId],
    queryFn: () => groupService.listMembers(groupId!),
    enabled: !!groupId,
  });

  const memberIds = new Set(members.map((m) => m.id));

  // ─── Edit state ───────────────────────────────────────────────────────────────
  const [editOpen, setEditOpen] = useState(false);
  const [editName, setEditName] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editError, setEditError] = useState("");

  const editMutation = useMutation({
    mutationFn: ({
      id,
      payload,
    }: {
      id: string;
      payload: CreateGroupPayload;
    }) => groupService.update(id, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["group", groupId] });
      void queryClient.invalidateQueries({ queryKey: ["groups"] });
      setEditOpen(false);
    },
    onError: (err: unknown) => {
      setEditError(
        err instanceof Error ? err.message : "Failed to update group."
      );
    },
  });

  function openEdit() {
    if (!group) return;
    setEditName(group.name);
    setEditDescription(group.description ?? "");
    setEditError("");
    setEditOpen(true);
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setEditError("");
    if (!editName.trim()) {
      setEditError("Name is required.");
      return;
    }
    editMutation.mutate({
      id: groupId!,
      payload: {
        name: editName.trim(),
        description: editDescription.trim() || undefined,
      },
    });
  }

  // ─── Remove member state ──────────────────────────────────────────────────────
  const [removeUser, setRemoveUser] = useState<User | null>(null);

  const removeMemberMutation = useMutation({
    mutationFn: (userId: string) => groupService.removeMember(groupId!, userId),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["group-members", groupId],
      });
      setRemoveUser(null);
    },
  });

  // ─── Add member dialog ────────────────────────────────────────────────────────
  const [addMemberOpen, setAddMemberOpen] = useState(false);

  function handleMemberAdded() {
    void queryClient.invalidateQueries({ queryKey: ["group-members", groupId] });
  }

  // ─── Members table columns ────────────────────────────────────────────────────
  const memberColumns: Column<User>[] = [
    {
      key: "username",
      header: "Username",
      render: (row) => (
        <span className="font-medium text-foreground/90">
          {row.display_name ?? row.username}
        </span>
      ),
    },
    {
      key: "email",
      header: "Email",
      render: (row) => (
        <span className="text-muted-foreground text-sm">{row.email}</span>
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
      key: "actions",
      header: "Actions",
      width: "w-20",
      render: (row) => (
        <button
          aria-label={`Remove ${row.username} from group`}
          onClick={() => setRemoveUser(row)}
          className="p-1.5 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-colors"
        >
          <Trash2 size={14} />
        </button>
      ),
    },
  ];

  // ─── Loading / error states ───────────────────────────────────────────────────
  if (groupLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 size={28} className="animate-spin text-primary/60" />
      </div>
    );
  }

  if (groupError || !group) {
    return (
      <div className="glass-card text-center py-12 text-muted-foreground">
        Group not found or failed to load.
      </div>
    );
  }

  return (
    <div className="max-w-4xl">
      {/* ── Section 1: Group Info ── */}
      <SectionCard
        title="Group Info"
        action={
          <Button size="sm" variant="ghost" onClick={openEdit}>
            Edit
          </Button>
        }
      >
        <InfoRow label="Name">{group.name}</InfoRow>
        <InfoRow label="Description">
          {group.description ?? <span className="opacity-40">—</span>}
        </InfoRow>
        <InfoRow label="Created">{formatDate(group.created_at)}</InfoRow>
      </SectionCard>

      {/* ── Section 2: Members ── */}
      <SectionCard
        title="Members"
        action={
          <Button size="sm" onClick={() => setAddMemberOpen(true)}>
            <Plus size={14} className="mr-1" />
            Add Member
          </Button>
        }
      >
        <DataTable
          columns={memberColumns}
          data={members}
          isLoading={membersLoading}
          emptyMessage="No members in this group yet."
        />
      </SectionCard>

      {/* Edit dialog */}
      <FormDialog
        open={editOpen}
        onClose={() => setEditOpen(false)}
        title="Edit Group"
        onSubmit={handleEditSubmit}
        isLoading={editMutation.isPending}
        submitLabel="Save Changes"
      >
        <EditGroupForm
          name={editName}
          description={editDescription}
          onNameChange={setEditName}
          onDescriptionChange={setEditDescription}
          error={editError}
        />
      </FormDialog>

      {/* Remove member confirm */}
      <ConfirmDialog
        open={removeUser !== null}
        onClose={() => setRemoveUser(null)}
        onConfirm={() =>
          removeUser && removeMemberMutation.mutate(removeUser.id)
        }
        title="Remove Member"
        description={`Remove "${removeUser?.username}" from this group?`}
        isLoading={removeMemberMutation.isPending}
      />

      {/* Add member dialog */}
      <AddMemberDialog
        open={addMemberOpen}
        onClose={() => setAddMemberOpen(false)}
        groupId={groupId!}
        existingMemberIds={memberIds}
        onAdded={handleMemberAdded}
      />
    </div>
  );
}

import { useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  groupService,
  type User,
  type CreateGroupPayload,
} from "@/services/users";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { UserSearchDialog } from "@/components/UserSearchDialog";
import { DataTable, type Column } from "@/components/DataTable";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Loader2, Plus, Trash2, Unlink } from "lucide-react";
import { formatDate } from "@/lib/utils";
import { Textarea } from "@/components/ui/textarea";
import { roleService, type Role } from "@/services/roles";
import { useToast } from "@/hooks/useToast";
import { getApiErrorMessage } from "@/lib/apiError";
import { SectionCard, InfoRow } from "@/components/shared";

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
      <div className="space-y-2">
        <Label htmlFor="group-detail-name">Name *</Label>
        <Input
          id="group-detail-name"
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          required
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="group-detail-description">Description</Label>
        <Textarea
          id="group-detail-description"
          value={description}
          onChange={(e) => onDescriptionChange(e.target.value)}
          rows={3}
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
  const { toast } = useToast();

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
        description: editDescription.trim(),
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

  // ─── Group roles (CQ-F18) ─────────────────────────────────────────────────────
  const { data: groupRoles = [], isLoading: rolesLoading } = useQuery({
    queryKey: ["group-roles", groupId],
    queryFn: () => roleService.listByGroup(groupId!),
    enabled: !!groupId,
  });

  const [unassignRole, setUnassignRole] = useState<Role | null>(null);

  const unassignRoleMutation = useMutation({
    mutationFn: (rId: string) => roleService.unassignFromGroup(rId, groupId!),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["group-roles", groupId] });
      setUnassignRole(null);
    },
    onError: (err: unknown) => {
      toast({ description: getApiErrorMessage(err), variant: "destructive" });
    },
  });

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
      key: "status",
      header: "Status",
      render: (row) => (
        <StatusBadge status={row.status === "Active" ? "active" : "inactive"} />
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

      {/* ── Section 3: Roles ── */}
      <SectionCard title="Assigned Roles">
        {rolesLoading ? (
          <div className="flex items-center justify-center py-6">
            <Loader2 size={20} className="animate-spin text-primary/60" />
          </div>
        ) : groupRoles.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-4">
            No roles assigned to this group.
          </p>
        ) : (
          <ul className="divide-y divide-white/5">
            {groupRoles.map((role) => (
              <li key={role.id} className="flex items-center justify-between py-2.5 px-1">
                <div>
                  <p className="text-sm font-medium text-foreground/90">{role.name}</p>
                  {role.description && (
                    <p className="text-xs text-muted-foreground">{role.description}</p>
                  )}
                </div>
                <button
                  aria-label={`Unassign role ${role.name}`}
                  onClick={() => setUnassignRole(role)}
                  className="p-1.5 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-colors"
                >
                  <Unlink size={14} />
                </button>
              </li>
            ))}
          </ul>
        )}
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
      <UserSearchDialog
        open={addMemberOpen}
        onClose={() => setAddMemberOpen(false)}
        title="Add Member"
        actionLabel="Add"
        existingIds={memberIds}
        existingLabel="Member"
        onAction={async (user) => {
          await groupService.addMember(groupId!, user.id);
          handleMemberAdded();
        }}
      />

      {/* Unassign role confirm */}
      <ConfirmDialog
        open={unassignRole !== null}
        onClose={() => setUnassignRole(null)}
        onConfirm={() => unassignRole && unassignRoleMutation.mutate(unassignRole.id)}
        title="Unassign Role"
        description={`Remove role "${unassignRole?.name}" from this group?`}
        isLoading={unassignRoleMutation.isPending}
      />
    </div>
  );
}

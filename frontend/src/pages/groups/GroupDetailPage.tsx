import { useState } from "react";
import { useParams } from "react-router";
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
import { roleService, type RoleAssignment } from "@/services/roles";
import {
  serviceAccountService,
  type ServiceAccount,
} from "@/services/serviceAccounts";
import { AssignmentScopeBadge } from "@/components/AssignmentScope";
import { useResourceNames } from "@/hooks/useResourceNames";
import { useToast } from "@/hooks/useToast";
import { getApiErrorMessage } from "@/lib/apiError";
import { SectionCard, InfoRow } from "@/components/shared";
import { invalidateEntity } from "@/lib/queryInvalidation";

// ─── Edit group form ──────────────────────────────────────────────────────────

interface EditGroupFormProps {
  name: string;
  description: string;
  onNameChange: (v: string) => void;
  onDescriptionChange: (v: string) => void;
}

function EditGroupForm({
  name,
  description,
  onNameChange,
  onDescriptionChange,
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
      invalidateEntity(queryClient, "groups");
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
      invalidateEntity(queryClient, "group-members");
      setRemoveUser(null);
    },
  });

  // ─── Add member dialog ────────────────────────────────────────────────────────
  const [addMemberOpen, setAddMemberOpen] = useState(false);

  function handleMemberAdded() {
    invalidateEntity(queryClient, "group-members");
  }

  // ─── Service-account members ──────────────────────────────────────────────────
  //
  // A group is a collection of principals whose roles its members inherit, and a
  // machine identity needs that inheritance for the same reason a person does:
  // so a fleet of devices is granted and revoked as one thing rather than one
  // grant per device. Listed separately from the people rather than merged into
  // one table — a page that says "members" has to say which rows are humans.
  const {
    data: serviceAccountMembers = [],
    isLoading: serviceAccountMembersLoading,
  } = useQuery({
    queryKey: ["group-service-accounts", groupId],
    queryFn: () => groupService.listServiceAccountMembers(groupId!),
    enabled: !!groupId,
  });

  const [removeServiceAccount, setRemoveServiceAccount] =
    useState<ServiceAccount | null>(null);
  const [addServiceAccountOpen, setAddServiceAccountOpen] = useState(false);
  const [addServiceAccountId, setAddServiceAccountId] = useState("");
  const [addServiceAccountError, setAddServiceAccountError] = useState("");

  const { data: allServiceAccounts = [] } = useQuery({
    queryKey: ["service-accounts"],
    queryFn: () => serviceAccountService.getAll(),
    enabled: addServiceAccountOpen,
  });

  const removeServiceAccountMutation = useMutation({
    mutationFn: (id: string) =>
      groupService.removeServiceAccountMember(groupId!, id),
    onSuccess: () => {
      invalidateEntity(queryClient, "group-service-accounts");
      setRemoveServiceAccount(null);
    },
  });

  const addServiceAccountMutation = useMutation({
    mutationFn: (id: string) => groupService.addServiceAccountMember(groupId!, id),
    onSuccess: () => {
      invalidateEntity(queryClient, "group-service-accounts");
      setAddServiceAccountOpen(false);
      setAddServiceAccountId("");
    },
    onError: (err: unknown) => {
      // Verbatim: a 409 means it is already a member, which is a different
      // thing from a failure and worth saying so.
      setAddServiceAccountError(getApiErrorMessage(err));
    },
  });

  const serviceAccountColumns: Column<ServiceAccount>[] = [
    {
      key: "name",
      header: "Name",
      render: (row) => (
        <span className="font-medium text-foreground/90">{row.name}</span>
      ),
    },
    {
      key: "client_id",
      header: "Client ID",
      render: (row) => (
        <span className="text-muted-foreground text-sm font-mono">
          {row.client_id}
        </span>
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
          aria-label={`Remove service account ${row.name} from group`}
          onClick={() => setRemoveServiceAccount(row)}
          className="p-1.5 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-colors"
        >
          <Trash2 size={14} />
        </button>
      ),
    },
  ];

  // ─── Group roles (CQ-F18) ─────────────────────────────────────────────────────
  const { data: groupRoles = [], isLoading: rolesLoading } = useQuery({
    queryKey: ["group-roles", groupId],
    queryFn: () => roleService.listByGroup(groupId!),
    enabled: !!groupId,
  });

  // The target is the assignment, not the role: dropping its scope would ask
  // the server to remove a global grant this group may not even hold.
  const [unassignRole, setUnassignRole] = useState<RoleAssignment | null>(null);
  const { nameFor } = useResourceNames();

  const unassignRoleMutation = useMutation({
    mutationFn: (a: RoleAssignment) =>
      roleService.unassignFromGroup(a.role.id, groupId!, a.resource_id),
    onSuccess: () => {
      invalidateEntity(queryClient, "group-roles");
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

      {/* ── Section 2b: Service-account members ── */}
      <SectionCard
        title="Service Accounts"
        action={
          <Button
            size="sm"
            onClick={() => {
              setAddServiceAccountError("");
              setAddServiceAccountOpen(true);
            }}
          >
            <Plus size={14} className="mr-1" />
            Add Service Account
          </Button>
        }
      >
        <DataTable
          columns={serviceAccountColumns}
          data={serviceAccountMembers}
          isLoading={serviceAccountMembersLoading}
          emptyMessage="No service accounts in this group. Adding one gives that machine identity every role assigned to the group."
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
            {groupRoles.map((a) => (
              <li
                key={`${a.role.id}:${a.resource_id ?? "global"}`}
                className="flex items-center justify-between py-2.5 px-1"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-medium text-foreground/90">{a.role.name}</p>
                    <AssignmentScopeBadge
                      resourceId={a.resource_id}
                      nameFor={nameFor}
                    />
                  </div>
                  {a.role.description && (
                    <p className="text-xs text-muted-foreground">{a.role.description}</p>
                  )}
                </div>
                <button
                  aria-label={`Unassign role ${a.role.name}`}
                  onClick={() => setUnassignRole(a)}
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
        error={editError}
        errorId="group-detail-edit-error"
      >
        <EditGroupForm
          name={editName}
          description={editDescription}
          onNameChange={setEditName}
          onDescriptionChange={setEditDescription}
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

      {/* Add service account to group */}
      <FormDialog
        open={addServiceAccountOpen}
        onClose={() => {
          setAddServiceAccountOpen(false);
          setAddServiceAccountId("");
          setAddServiceAccountError("");
        }}
        title="Add Service Account"
        onSubmit={(e) => {
          e.preventDefault();
          setAddServiceAccountError("");
          if (!addServiceAccountId) {
            setAddServiceAccountError("Please select a service account.");
            return;
          }
          addServiceAccountMutation.mutate(addServiceAccountId);
        }}
        isLoading={addServiceAccountMutation.isPending}
        submitLabel="Add"
        error={addServiceAccountError}
        errorId="add-service-account-error"
      >
        <div className="space-y-2">
          <Label htmlFor="add-service-account-select">Service account</Label>
          <select
            id="add-service-account-select"
            value={addServiceAccountId}
            onChange={(e) => setAddServiceAccountId(e.target.value)}
            className="flex h-9 w-full rounded-md px-3 py-1 text-sm bg-white/5 border border-primary/20 text-foreground focus:outline-hidden focus:ring-2 focus:ring-primary/40 focus:border-primary transition-colors duration-200"
          >
            <option value="">Select a service account…</option>
            {allServiceAccounts.map((sa) => (
              <option key={sa.id} value={sa.id}>
                {sa.name}
              </option>
            ))}
          </select>
          <p className="text-xs text-muted-foreground">
            It inherits every role assigned to this group, and loses them again
            when removed.
          </p>
        </div>
      </FormDialog>

      {/* Remove service account confirm */}
      <ConfirmDialog
        open={removeServiceAccount !== null}
        onClose={() => setRemoveServiceAccount(null)}
        onConfirm={() =>
          removeServiceAccount &&
          removeServiceAccountMutation.mutate(removeServiceAccount.id)
        }
        title="Remove Service Account"
        description={`Remove "${removeServiceAccount?.name}" from this group? It loses every role it inherited through the group.`}
        isLoading={removeServiceAccountMutation.isPending}
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
        onConfirm={() => unassignRole && unassignRoleMutation.mutate(unassignRole)}
        title="Unassign Role"
        description={
          unassignRole?.resource_id
            ? `Remove role "${unassignRole.role.name}" from this group under "${nameFor(unassignRole.resource_id)}"?`
            : `Remove role "${unassignRole?.role.name}" from this group?`
        }
        isLoading={unassignRoleMutation.isPending}
      />
    </div>
  );
}

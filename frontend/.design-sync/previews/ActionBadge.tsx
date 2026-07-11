import { ActionBadge } from "frontend";

export const Actions = () => (
  <div className="flex flex-wrap items-center gap-3">
    <ActionBadge action="read" />
    <ActionBadge action="write" />
    <ActionBadge action="delete" />
    <ActionBadge action="admin" />
  </div>
);

export const UnknownAction = () => (
  <div className="flex flex-wrap items-center gap-3">
    <ActionBadge action="issue" />
    <ActionBadge action="revoke" />
    <ActionBadge action="export" />
  </div>
);

export const PermissionMatrix = () => (
  <div className="flex flex-col gap-3">
    {[
      { resource: "tenant:users", actions: ["read", "write", "delete"] },
      { resource: "tenant:certificates", actions: ["read", "issue", "revoke"] },
      { resource: "tenant:audit", actions: ["read", "export"] },
      { resource: "organization", actions: ["admin"] },
    ].map(({ resource, actions }) => (
      <div key={resource} className="flex items-center gap-3">
        <span className="w-48 font-mono text-xs text-muted-foreground">
          {resource}
        </span>
        <div className="flex flex-wrap gap-2">
          {actions.map((a) => (
            <ActionBadge key={a} action={a} />
          ))}
        </div>
      </div>
    ))}
  </div>
);

ActionBadge from frontend. Use via `window.AxiamUI.ActionBadge` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<AxiamSurface>` (full provider chain in README.md — components read theme/i18n from that context).

## Examples

### Actions

```jsx
() => (
  <div className="flex flex-wrap items-center gap-3">
    <ActionBadge action="read" />
    <ActionBadge action="write" />
    <ActionBadge action="delete" />
    <ActionBadge action="admin" />
  </div>
)
```

### UnknownAction

```jsx
() => (
  <div className="flex flex-wrap items-center gap-3">
    <ActionBadge action="issue" />
    <ActionBadge action="revoke" />
    <ActionBadge action="export" />
  </div>
)
```

### PermissionMatrix

```jsx
() => (
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
)
```

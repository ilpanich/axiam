SectionCard from frontend. Use via `window.AxiamUI.SectionCard` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<AxiamSurface>` (full provider chain in README.md — components read theme/i18n from that context).

## Examples

### WithAction

```jsx
() => (
  <SectionCard
    title="OAuth2 clients"
    action={
      <Button size="sm" variant="outline">
        Register client
      </Button>
    }
  >
    <div className="flex flex-col gap-2 text-sm text-foreground/90">
      <div className="flex items-center justify-between">
        <span className="font-mono text-xs">admin-console-spa</span>
        <StatusBadge status="active" />
      </div>
      <div className="flex items-center justify-between">
        <span className="font-mono text-xs">billing-sync-m2m</span>
        <StatusBadge status="active" />
      </div>
      <div className="flex items-center justify-between">
        <span className="font-mono text-xs">legacy-portal</span>
        <StatusBadge status="revoked" />
      </div>
    </div>
  </SectionCard>
)
```

### TitleOnly

```jsx
() => (
  <SectionCard title="Effective permissions">
    <div className="flex flex-wrap gap-2">
      <ActionBadge action="read" />
      <ActionBadge action="write" />
      <ActionBadge action="delete" />
      <ActionBadge action="admin" />
    </div>
  </SectionCard>
)
```

### DetailPanel

```jsx
() => (
  <SectionCard title="Tenant details">
    <div>
      <InfoRow label="Tenant ID">
        <span className="font-mono text-xs">
          9f2c41ad-6b18-4d0e-b7a3-51c8ef0d9a44
        </span>
      </InfoRow>
      <InfoRow label="Organization">Northwind Industrial</InfoRow>
      <InfoRow label="Status">
        <StatusBadge status="active" />
      </InfoRow>
      <InfoRow label="Created">2026-02-14 09:31 UTC</InfoRow>
    </div>
  </SectionCard>
)
```

### EmptyState

```jsx
() => (
  <SectionCard
    title="Webhooks"
    action={
      <Button size="sm" variant="outline">
        Add webhook
      </Button>
    }
  >
    <p className="py-6 text-center text-sm text-muted-foreground">
      No webhook endpoints registered for this tenant yet.
    </p>
  </SectionCard>
)
```

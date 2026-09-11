PageHeader from frontend. Use via `window.AxiamUI.PageHeader` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<AxiamSurface>` (full provider chain in README.md — components read theme/i18n from that context).

## Examples

### WithAction

```jsx
() => (
  <PageHeader
    title="Users"
    description="Manage the users of the acme-prod tenant, their roles and group memberships."
    action={<Button>Invite user</Button>}
  />
)
```

### TitleOnly

```jsx
() => <PageHeader title="Audit log" />
```

### WithBadgeAction

```jsx
() => (
  <PageHeader
    title="Certificates"
    description="X.509 certificates issued by the organization CA."
    action={
      <div className="flex items-center gap-2">
        <Badge variant="accent">3 expiring</Badge>
        <Button variant="outline">Issue certificate</Button>
      </div>
    }
  />
)
```

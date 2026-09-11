Badge from frontend. Use via `window.AxiamUI.Badge` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<AxiamSurface>` (full provider chain in README.md — components read theme/i18n from that context).

## Examples

### Variants

```jsx
() => (
  <div className="flex flex-wrap items-center gap-3">
    <Badge variant="default">Active</Badge>
    <Badge variant="accent">MFA enabled</Badge>
    <Badge variant="secondary">Service account</Badge>
    <Badge variant="outline">OAuth2 client</Badge>
    <Badge variant="destructive">Revoked</Badge>
  </div>
)
```

### UserStatus

```jsx
() => (
  <div className="flex flex-wrap items-center gap-3">
    <Badge variant="default">Enabled</Badge>
    <Badge variant="secondary">Pending invite</Badge>
    <Badge variant="outline">Locked</Badge>
    <Badge variant="destructive">Disabled</Badge>
  </div>
)
```

### RolesAndPermissions

```jsx
() => (
  <div className="flex flex-wrap items-center gap-2">
    <Badge variant="accent">tenant:admin</Badge>
    <Badge variant="outline">users:read</Badge>
    <Badge variant="outline">users:write</Badge>
    <Badge variant="outline">certificates:issue</Badge>
    <Badge variant="outline">audit:export</Badge>
    <Badge variant="secondary">+4 more</Badge>
  </div>
)
```

### CertificateLifecycle

```jsx
() => (
  <div className="flex flex-wrap items-center gap-3">
    <Badge variant="default">Valid — expires 2027-03-14</Badge>
    <Badge variant="accent">Ed25519</Badge>
    <Badge variant="destructive">Expired</Badge>
    <Badge variant="destructive">Revoked — key compromise</Badge>
  </div>
)
```

Button from frontend. Use via `window.AxiamUI.Button` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<AxiamSurface>` (full provider chain in README.md — components read theme/i18n from that context).

## Examples

### Variants

```jsx
() => (
  <div className="flex flex-wrap items-center gap-3">
    <Button variant="default">Create tenant</Button>
    <Button variant="accent">Issue certificate</Button>
    <Button variant="secondary">Duplicate role</Button>
    <Button variant="outline">Export audit log</Button>
    <Button variant="ghost">Cancel</Button>
    <Button variant="destructive">Revoke access</Button>
    <Button variant="link">View documentation</Button>
  </div>
)
```

### Sizes

```jsx
() => (
  <div className="flex flex-wrap items-center gap-3">
    <Button size="sm">Small</Button>
    <Button size="default">Default</Button>
    <Button size="lg">Large</Button>
  </div>
)
```

### Disabled

```jsx
() => (
  <div className="flex flex-wrap items-center gap-3">
    <Button disabled>Create tenant</Button>
    <Button variant="outline" disabled>
      Export audit log
    </Button>
    <Button variant="destructive" disabled>
      Revoke access
    </Button>
  </div>
)
```

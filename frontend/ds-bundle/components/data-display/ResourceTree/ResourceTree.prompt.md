ResourceTree from frontend. Use via `window.AxiamUI.ResourceTree` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<AxiamSurface>` (full provider chain in README.md — components read theme/i18n from that context).

## Examples

### Hierarchy

```jsx
() => (
  <div className="glass-card w-full max-w-xl">
    <ResourceTree resources={resources} />
  </div>
)
```

### Selected

```jsx
() => (
  <div className="glass-card w-full max-w-xl">
    <ResourceTree resources={resources} selectedId="r-api-payments" />
  </div>
)
```

### Empty

```jsx
() => (
  <div className="glass-card w-full max-w-xl">
    <ResourceTree resources={[]} />
  </div>
)
```

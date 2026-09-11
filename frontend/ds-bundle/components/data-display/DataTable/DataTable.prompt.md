DataTable from frontend. Use via `window.AxiamUI.DataTable` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<AxiamSurface>` (full provider chain in README.md — components read theme/i18n from that context).

## Examples

### Users

```jsx
() => (
  <DataTable columns={userColumns} data={users} getRowKey={(r) => r.id} />
)
```

### Certificates

```jsx
() => (
  <DataTable
    columns={certColumns}
    data={certificates}
    getRowKey={(r) => r.id}
  />
)
```

### Loading

```jsx
() => (
  <DataTable columns={userColumns} data={[]} isLoading />
)
```

### Empty

```jsx
() => (
  <DataTable
    columns={certColumns}
    data={[]}
    emptyMessage="No certificates issued for this tenant yet."
  />
)
```

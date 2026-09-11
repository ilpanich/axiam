Topbar from frontend. Use via `window.AxiamUI.Topbar` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<AxiamSurface>` (full provider chain in README.md — components read theme/i18n from that context).

## Examples

### OnUsers

```jsx
() => <TopbarAt crumbs={["Users"]} path="/users" />
```

### NestedCrumb

```jsx
() => (
  <TopbarAt
    crumbs={["Certificates", "Issue certificate"]}
    path="/certificates/issue"
  />
)
```

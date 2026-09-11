Sidebar from frontend. Use via `window.AxiamUI.Sidebar` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<AxiamSurface>` (full provider chain in README.md — components read theme/i18n from that context).

## Examples

### TenantAdmin

```jsx
() => (
  <WithSession permissions={TENANT_ADMIN_PERMISSIONS} route="/users" />
)
```

### AuditorRestricted

```jsx
() => (
  <WithSession permissions={AUDITOR_PERMISSIONS} route="/audit-logs" />
)
```

### MobileDrawer

```jsx
() => {
  useAuthStore.setState({
    user: {
      id: "9f1c2d4e-6a3b-4c88-9f2a-77d0e1b4c210",
      username: "e.panigati",
      email: "e.panigati@acme.example",
      permissions: ["*"],
      tenant_id: "3b7f0a19-2c54-4d6e-8f10-5a2b9c7e4d33",
    },
    tenantSlug: "acme-prod",
    orgSlug: "acme",
    isAuthenticated: true,
    isInitializing: false,
  });
  return (
    <MemoryRouter initialEntries={["/certificates"]}>
      <div className="flex h-[760px] rounded-lg overflow-hidden border border-primary/10">
        <Sidebar mobile onClose={() => {}} />
      </div>
    </MemoryRouter>
  );
}
```

ForbiddenPage from frontend. Use via `window.AxiamUI.ForbiddenPage` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<AxiamSurface>` (full provider chain in README.md — components read theme/i18n from that context).

ForbiddenPage — friendly 403 rendered by ProtectedRoute when the
authenticated user lacks the required permission (CQ-F30 / T-11-05-AUTHZ).

Note: this is a client-side UX guard. The backend RBAC check remains the
authoritative enforcement layer — this page prevents confusing blank views.

## Examples

### AccessDenied

```jsx
() => (
  <MemoryRouter initialEntries={["/certificates"]}>
    <ForbiddenPage />
  </MemoryRouter>
)
```

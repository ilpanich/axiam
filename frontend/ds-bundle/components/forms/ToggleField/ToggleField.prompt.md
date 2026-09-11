ToggleField from frontend. Use via `window.AxiamUI.ToggleField` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<AxiamSurface>` (full provider chain in README.md — components read theme/i18n from that context).

## Examples

### Checked

```jsx
() => {
  const [on, setOn] = useState(true);
  return (
    <ToggleField
      id="mfa-required"
      label="Require MFA for all tenant members"
      checked={on}
      onChange={setOn}
    />
  );
}
```

### Unchecked

```jsx
() => {
  const [on, setOn] = useState(false);
  return (
    <ToggleField
      id="allow-social-login"
      label="Allow social login"
      checked={on}
      onChange={setOn}
    />
  );
}
```

### PermissionGroup

```jsx
() => {
  const [perms, setPerms] = useState({ read: true, write: true, delete: false });
  return (
    <SectionCard title="Permissions on resource:tenant">
      <div className="flex flex-col gap-3">
        {(["read", "write", "delete"] as const).map((action) => (
          <ToggleField
            key={action}
            id={`perm-${action}`}
            label={`tenant:${action}`}
            checked={perms[action]}
            onChange={(v) => setPerms((p) => ({ ...p, [action]: v }))}
          />
        ))}
      </div>
    </SectionCard>
  );
}
```

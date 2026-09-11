Label from frontend. Use via `window.AxiamUI.Label` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<AxiamSurface>` (full provider chain in README.md — components read theme/i18n from that context).

## Examples

### LabeledField

```jsx
() => (
  <div className="space-y-2" style={field}>
    <Label htmlFor="lbl-org">Organization name</Label>
    <Input id="lbl-org" defaultValue="Acme Corporation" />
  </div>
)
```

### RequiredField

```jsx
() => (
  <div className="space-y-2" style={field}>
    <Label htmlFor="lbl-role">
      Role name <span className="text-destructive">*</span>
    </Label>
    <Input id="lbl-role" placeholder="certificate-operator" />
    <p className="text-xs text-muted-foreground">Lowercase, hyphen-separated.</p>
  </div>
)
```

### WithTextarea

```jsx
() => (
  <div className="space-y-2" style={field}>
    <Label htmlFor="lbl-desc">Role description</Label>
    <Textarea
      id="lbl-desc"
      rows={3}
      defaultValue="Grants issue and revoke on X.509 certificates within the tenant."
    />
  </div>
);

// DOM order is input-then-label so Tailwind's `peer-disabled:` sibling selector
// resolves; column-reverse restores the visual label-above-input order.
```

### DisabledPeer

```jsx
() => (
  <div style={{ ...field, display: "flex", flexDirection: "column-reverse", gap: 8 }}>
    <Input id="lbl-issuer" className="peer" disabled defaultValue="Acme Root CA — Ed25519" />
    <Label htmlFor="lbl-issuer">Issuing CA (locked)</Label>
  </div>
)
```

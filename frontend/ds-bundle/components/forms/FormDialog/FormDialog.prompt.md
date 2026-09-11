FormDialog from frontend. Use via `window.AxiamUI.FormDialog` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<AxiamSurface>` (full provider chain in README.md — components read theme/i18n from that context).

## Examples

### CreateServiceAccount

```jsx
() => (
  <Stage>
    <FormDialog
      open
      onClose={noop}
      onSubmit={submit}
      title="New service account"
      submitLabel="Create account"
    >
      <div className="space-y-2">
        <Label htmlFor="sa-name">Name</Label>
        <Input id="sa-name" defaultValue="svc-billing" />
      </div>
      <div className="space-y-2">
        <Label htmlFor="sa-desc">Description</Label>
        <Textarea
          id="sa-desc"
          rows={3}
          defaultValue="Machine-to-machine client for the invoicing pipeline."
        />
      </div>
      <ToggleField
        id="sa-mtls"
        label="Require mTLS client certificate"
        checked
        onChange={noop}
      />
    </FormDialog>
  </Stage>
);

/** A second, denser form: OAuth2 client registration. */
```

### RegisterOAuthClient

```jsx
() => (
  <Stage>
    <FormDialog
      open
      onClose={noop}
      onSubmit={submit}
      title="Register OAuth2 client"
      submitLabel="Register"
    >
      <div className="space-y-2">
        <Label htmlFor="oc-name">Client name</Label>
        <Input id="oc-name" defaultValue="acme-portal" />
      </div>
      <div className="space-y-2">
        <Label htmlFor="oc-redirect">Redirect URI</Label>
        <Input
          id="oc-redirect"
          defaultValue="https://portal.acme.io/oauth2/callback"
        />
      </div>
      <ToggleField
        id="oc-pkce"
        label="Enforce PKCE (Authorization Code)"
        checked
        onChange={noop}
      />
      <ToggleField
        id="oc-refresh"
        label="Issue rotating refresh tokens"
        checked={false}
        onChange={noop}
      />
    </FormDialog>
  </Stage>
);

/** Submitting state — footer button shows the spinner, fields stay readable. */
```

### Submitting

```jsx
() => (
  <Stage>
    <FormDialog
      open
      onClose={noop}
      onSubmit={submit}
      title="Issue X.509 certificate"
      submitLabel="Issue certificate"
      isLoading
    >
      <div className="space-y-2">
        <Label htmlFor="cert-cn">Common name</Label>
        <Input id="cert-cn" defaultValue="gateway.acme-prod" />
      </div>
      <div className="space-y-2">
        <Label htmlFor="cert-alg">Algorithm</Label>
        <Input id="cert-alg" defaultValue="Ed25519" />
      </div>
    </FormDialog>
  </Stage>
)
```

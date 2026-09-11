Textarea from frontend. Use via `window.AxiamUI.Textarea` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<AxiamSurface>` (full provider chain in README.md — components read theme/i18n from that context).

## Examples

### Default

```jsx
() => (
  <div className="space-y-2" style={field}>
    <Label htmlFor="ta-role">Role description</Label>
    <Textarea
      id="ta-role"
      rows={4}
      defaultValue="Grants read access to the audit log and permission to export signed OpenPGP archives for the acme-production tenant."
    />
  </div>
)
```

### Placeholder

```jsx
() => (
  <div className="space-y-2" style={field}>
    <Label htmlFor="ta-reason">Revocation reason</Label>
    <Textarea
      id="ta-reason"
      rows={4}
      placeholder="Explain why this X.509 certificate is being revoked (key compromise, CA compromise, superseded…)"
    />
  </div>
)
```

### Monospace

```jsx
() => (
  <div className="space-y-2" style={field}>
    <Label htmlFor="ta-pem">Certificate signing request (PEM)</Label>
    <Textarea
      id="ta-pem"
      rows={9}
      className="font-mono text-xs"
      defaultValue={`-----BEGIN CERTIFICATE REQUEST-----
MIIBSzCB/gIBADCBjTELMAkGA1UEBhMCSVQxDjAMBgNVBAgMBUxhemlvMQ0wCwYD
VQQHDARSb21lMRUwEwYDVQQKDAxBY21lIENvcnAxFDASBgNVBAsMC0lvVCBHYXRl
d2F5MRcwFQYDVQQDDA5nYXRld2F5LTA0LmlvdA==
-----END CERTIFICATE REQUEST-----`}
    />
  </div>
)
```

### Disabled

```jsx
() => (
  <div className="space-y-2" style={field}>
    <Label htmlFor="ta-locked">Tenant policy (managed by organization)</Label>
    <Textarea
      id="ta-locked"
      rows={3}
      disabled
      defaultValue="Password policy, MFA enforcement and session TTL are inherited from the Acme Corporation organization defaults."
    />
  </div>
)
```

### Invalid

```jsx
() => (
  <div className="space-y-2" style={field}>
    <Label htmlFor="ta-scopes">Consent scopes</Label>
    <Textarea
      id="ta-scopes"
      rows={3}
      aria-invalid
      className="border-destructive"
      defaultValue="openid profile email offline_access urn:acme:billing:*"
    />
    <p className="text-xs text-destructive">
      Wildcard scopes are not permitted for public OAuth2 clients.
    </p>
  </div>
)
```

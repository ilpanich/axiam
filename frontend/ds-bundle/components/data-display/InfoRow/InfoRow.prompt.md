InfoRow from frontend. Use via `window.AxiamUI.InfoRow` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<AxiamSurface>` (full provider chain in README.md — components read theme/i18n from that context).

## Examples

### InDetailPanel

```jsx
() => (
  <SectionCard title="Service account">
    <div>
      <InfoRow label="Client ID">
        <span className="font-mono text-xs">svc-billing-sync</span>
      </InfoRow>
      <InfoRow label="Tenant">Northwind Industrial / production</InfoRow>
      <InfoRow label="Grant type">client_credentials</InfoRow>
      <InfoRow label="Status">
        <StatusBadge status="active" />
      </InfoRow>
      <InfoRow label="Last used">2026-07-10 18:42 UTC</InfoRow>
    </div>
  </SectionCard>
)
```

### RichValues

```jsx
() => (
  <SectionCard title="X.509 certificate">
    <div>
      <InfoRow label="Subject">
        <span className="font-mono text-xs">CN=iot-gateway-04.axiam.dev</span>
      </InfoRow>
      <InfoRow label="Serial">
        <span className="font-mono text-xs">3A:7F:19:C4:0B:E2:56:81</span>
      </InfoRow>
      <InfoRow label="Algorithm">Ed25519</InfoRow>
      <InfoRow label="Permissions">
        <span className="flex flex-wrap gap-2">
          <ActionBadge action="read" />
          <ActionBadge action="write" />
        </span>
      </InfoRow>
      <InfoRow label="Not after">2027-03-14 00:00 UTC</InfoRow>
    </div>
  </SectionCard>
)
```

### LongWrappingValue

```jsx
() => (
  <SectionCard title="Webhook endpoint">
    <div>
      <InfoRow label="Target URL">
        <span className="break-all font-mono text-xs">
          https://hooks.northwind-industrial.example/axiam/v1/events?tenant=production
        </span>
      </InfoRow>
      <InfoRow label="Events">
        user.created, user.deleted, role.assigned, certificate.revoked,
        mfa.enrolled
      </InfoRow>
      <InfoRow label="Signature">HMAC-SHA256</InfoRow>
    </div>
  </SectionCard>
)
```

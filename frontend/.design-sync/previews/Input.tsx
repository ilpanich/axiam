import { Input, Label } from "frontend";

// Widths use inline styles on purpose: the capture stylesheet only contains the
// utilities already used by src/, so preview-only classes like `w-80` are absent.
const field = { maxWidth: 340 };

export const Default = () => (
  <div className="space-y-2" style={field}>
    <Label htmlFor="tenant-slug">Tenant slug</Label>
    <Input id="tenant-slug" defaultValue="acme-production" />
  </div>
);

export const Types = () => (
  <div className="space-y-4" style={field}>
    <div className="space-y-2">
      <Label htmlFor="user-email">Email</Label>
      <Input id="user-email" type="email" defaultValue="dana.okonkwo@acme.io" />
    </div>
    <div className="space-y-2">
      <Label htmlFor="user-password">Password</Label>
      <Input id="user-password" type="password" defaultValue="correct-horse-battery" />
    </div>
    <div className="space-y-2">
      <Label htmlFor="totp-code">TOTP code</Label>
      <Input id="totp-code" inputMode="numeric" defaultValue="418 902" />
    </div>
  </div>
);

export const Placeholder = () => (
  <div className="space-y-2" style={field}>
    <Label htmlFor="redirect-uri">OAuth2 redirect URI</Label>
    <Input id="redirect-uri" placeholder="https://app.acme.io/oauth2/callback" />
  </div>
);

export const Disabled = () => (
  <div className="space-y-2" style={field}>
    <Label htmlFor="client-id">Client ID</Label>
    <Input id="client-id" disabled defaultValue="cl_9f3a7c21-4e0b-4a6d-9b21-7f0c2d8e1a55" />
    <p className="text-xs text-muted-foreground">Generated at creation and immutable.</p>
  </div>
);

export const Invalid = () => (
  <div className="space-y-2" style={field}>
    <Label htmlFor="webhook-url">Webhook endpoint</Label>
    <Input
      id="webhook-url"
      aria-invalid
      className="border-destructive"
      defaultValue="http://hooks.acme.io/axiam"
    />
    <p className="text-xs text-destructive">Endpoint must use TLS (https://).</p>
  </div>
);

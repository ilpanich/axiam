import { Button, Input, Label, PublicLayout } from "frontend";

// PublicLayout is the unauthenticated shell (login, bootstrap, MFA setup,
// password reset). It owns the AXIAM gradient, the spinning neon rings around
// the logo mark, and the glass card that hosts the form — so a preview only
// has to supply a believable card body.

export const SignIn = () => (
  <PublicLayout>
    <form className="space-y-4" onSubmit={(e) => e.preventDefault()}>
      <div className="space-y-2">
        <Label htmlFor="pl-email">Email</Label>
        <Input
          id="pl-email"
          type="email"
          placeholder="e.panigati@acme.example"
          defaultValue="e.panigati@acme.example"
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="pl-password">Password</Label>
        <Input id="pl-password" type="password" defaultValue="hunter-seeker" />
      </div>
      <div className="space-y-2">
        <Label htmlFor="pl-tenant">Tenant</Label>
        <Input id="pl-tenant" placeholder="acme / acme-prod" defaultValue="acme / acme-prod" />
      </div>
      <Button type="submit" className="w-full">
        Sign in
      </Button>
      <p className="text-center text-xs text-muted-foreground">
        Signing in enrolls this session for TOTP step-up.
      </p>
    </form>
  </PublicLayout>
);

export const WideBootstrap = () => (
  <PublicLayout maxWidth="max-w-xl">
    <div className="space-y-5">
      <div>
        <h2 className="text-xl font-bold text-foreground">
          Bootstrap the first administrator
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">
          This organization has no tenant administrator yet. The account created
          here receives the built-in <code className="text-primary">tenant-admin</code>{" "}
          role.
        </p>
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-2">
          <Label htmlFor="pl-org">Organization ID</Label>
          <Input id="pl-org" defaultValue="acme" />
        </div>
        <div className="space-y-2">
          <Label htmlFor="pl-ten">Tenant ID</Label>
          <Input id="pl-ten" defaultValue="acme-prod" />
        </div>
      </div>
      <div className="space-y-2">
        <Label htmlFor="pl-admin">Administrator email</Label>
        <Input id="pl-admin" type="email" defaultValue="admin@acme.example" />
      </div>
      <Button className="w-full">Create administrator</Button>
    </div>
  </PublicLayout>
);

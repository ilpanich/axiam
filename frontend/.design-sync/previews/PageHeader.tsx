import { Badge, Button, PageHeader } from "frontend";

export const WithAction = () => (
  <PageHeader
    title="Users"
    description="Manage the users of the acme-prod tenant, their roles and group memberships."
    action={<Button>Invite user</Button>}
  />
);

export const TitleOnly = () => <PageHeader title="Audit log" />;

export const WithBadgeAction = () => (
  <PageHeader
    title="Certificates"
    description="X.509 certificates issued by the organization CA."
    action={
      <div className="flex items-center gap-2">
        <Badge variant="accent">3 expiring</Badge>
        <Button variant="outline">Issue certificate</Button>
      </div>
    }
  />
);

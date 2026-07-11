import { Button } from "frontend";

export const Variants = () => (
  <div className="flex flex-wrap items-center gap-3">
    <Button variant="default">Create tenant</Button>
    <Button variant="accent">Issue certificate</Button>
    <Button variant="secondary">Duplicate role</Button>
    <Button variant="outline">Export audit log</Button>
    <Button variant="ghost">Cancel</Button>
    <Button variant="destructive">Revoke access</Button>
    <Button variant="link">View documentation</Button>
  </div>
);

export const Sizes = () => (
  <div className="flex flex-wrap items-center gap-3">
    <Button size="sm">Small</Button>
    <Button size="default">Default</Button>
    <Button size="lg">Large</Button>
  </div>
);

export const Disabled = () => (
  <div className="flex flex-wrap items-center gap-3">
    <Button disabled>Create tenant</Button>
    <Button variant="outline" disabled>
      Export audit log
    </Button>
    <Button variant="destructive" disabled>
      Revoke access
    </Button>
  </div>
);

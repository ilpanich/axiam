import { ResourceTree } from "frontend";

interface PreviewResource {
  id: string;
  name: string;
  resource_type: string;
  parent_id?: string;
  metadata?: { description?: string };
  created_at: string;
}

const CREATED = "2026-05-04T09:12:00Z";

const resources: PreviewResource[] = [
  {
    id: "r-platform",
    name: "acme-prod",
    resource_type: "service",
    created_at: CREATED,
    metadata: { description: "Production tenant root" },
  },
  {
    id: "r-api",
    name: "billing-api",
    resource_type: "api",
    parent_id: "r-platform",
    created_at: CREATED,
  },
  {
    id: "r-api-invoices",
    name: "/v1/invoices",
    resource_type: "endpoint",
    parent_id: "r-api",
    created_at: CREATED,
  },
  {
    id: "r-api-payments",
    name: "/v1/payments",
    resource_type: "endpoint",
    parent_id: "r-api",
    created_at: CREATED,
  },
  {
    id: "r-identity",
    name: "identity-service",
    resource_type: "service",
    parent_id: "r-platform",
    created_at: CREATED,
  },
  {
    id: "r-identity-users",
    name: "user-directory",
    resource_type: "dataset",
    parent_id: "r-identity",
    created_at: CREATED,
  },
  {
    id: "r-fleet",
    name: "edge-fleet",
    resource_type: "service",
    created_at: CREATED,
    metadata: { description: "mTLS-authenticated IoT estate" },
  },
  {
    id: "r-fleet-sensor-a",
    name: "iot-sensor-0412",
    resource_type: "iot_device",
    parent_id: "r-fleet",
    created_at: CREATED,
  },
  {
    id: "r-fleet-sensor-b",
    name: "iot-sensor-0177",
    resource_type: "iot_device",
    parent_id: "r-fleet",
    created_at: CREATED,
  },
];

export const Hierarchy = () => (
  <div className="glass-card w-full max-w-xl">
    <ResourceTree resources={resources} />
  </div>
);

export const Selected = () => (
  <div className="glass-card w-full max-w-xl">
    <ResourceTree resources={resources} selectedId="r-api-payments" />
  </div>
);

export const Empty = () => (
  <div className="glass-card w-full max-w-xl">
    <ResourceTree resources={[]} />
  </div>
);

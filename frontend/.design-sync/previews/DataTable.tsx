import { Badge, DataTable, StatusBadge } from "frontend";

interface UserRow {
  id: string;
  email: string;
  roles: string[];
  mfa: boolean;
  status: "active" | "revoked" | "inactive";
  last_login: string;
}

const userColumns = [
  { key: "email", header: "User" },
  {
    key: "roles",
    header: "Roles",
    render: (row: UserRow) => (
      <div className="flex flex-wrap gap-1">
        {row.roles.map((r) => (
          <Badge key={r} variant="outline">
            {r}
          </Badge>
        ))}
      </div>
    ),
  },
  {
    key: "mfa",
    header: "MFA",
    render: (row: UserRow) =>
      row.mfa ? (
        <Badge variant="accent">TOTP</Badge>
      ) : (
        <span className="text-muted-foreground">&mdash;</span>
      ),
  },
  {
    key: "status",
    header: "Status",
    render: (row: UserRow) => <StatusBadge status={row.status} />,
  },
  { key: "last_login", header: "Last login" },
];

const users: UserRow[] = [
  {
    id: "u-1",
    email: "elena.rossi@acme.io",
    roles: ["tenant:admin"],
    mfa: true,
    status: "active",
    last_login: "2026-07-11 08:42 UTC",
  },
  {
    id: "u-2",
    email: "marcus.hale@acme.io",
    roles: ["users:read", "audit:export"],
    mfa: true,
    status: "active",
    last_login: "2026-07-10 21:07 UTC",
  },
  {
    id: "u-3",
    email: "svc-billing@acme.io",
    roles: ["service-account"],
    mfa: false,
    status: "active",
    last_login: "2026-07-11 09:15 UTC",
  },
  {
    id: "u-4",
    email: "priya.nair@acme.io",
    roles: ["certificates:issue"],
    mfa: false,
    status: "inactive",
    last_login: "2026-05-29 13:31 UTC",
  },
  {
    id: "u-5",
    email: "d.okafor@acme.io",
    roles: ["users:write"],
    mfa: true,
    status: "revoked",
    last_login: "2026-06-02 17:58 UTC",
  },
];

interface CertRow {
  id: string;
  subject: string;
  algorithm: string;
  serial: string;
  expires: string;
  status: "active" | "revoked" | "inactive";
}

const certColumns = [
  { key: "subject", header: "Subject" },
  { key: "algorithm", header: "Algorithm" },
  {
    key: "serial",
    header: "Serial",
    render: (row: CertRow) => (
      <span className="font-mono text-xs text-foreground/70">{row.serial}</span>
    ),
  },
  { key: "expires", header: "Expires" },
  {
    key: "status",
    header: "Status",
    render: (row: CertRow) => <StatusBadge status={row.status} />,
  },
];

const certificates: CertRow[] = [
  {
    id: "c-1",
    subject: "CN=gateway.acme-prod, OU=edge",
    algorithm: "Ed25519",
    serial: "3f:a9:1c:04:8b:e2",
    expires: "2027-03-14",
    status: "active",
  },
  {
    id: "c-2",
    subject: "CN=iot-sensor-0412, OU=devices",
    algorithm: "RSA-4096",
    serial: "7b:22:de:90:31:af",
    expires: "2026-11-02",
    status: "active",
  },
  {
    id: "c-3",
    subject: "CN=svc-billing, OU=services",
    algorithm: "Ed25519",
    serial: "aa:14:6c:75:0d:19",
    expires: "2026-08-30",
    status: "active",
  },
  {
    id: "c-4",
    subject: "CN=iot-sensor-0177, OU=devices",
    algorithm: "RSA-4096",
    serial: "c1:8e:33:b0:47:5d",
    expires: "2026-04-11",
    status: "revoked",
  },
];

export const Users = () => (
  <DataTable columns={userColumns} data={users} getRowKey={(r) => r.id} />
);

export const Certificates = () => (
  <DataTable
    columns={certColumns}
    data={certificates}
    getRowKey={(r) => r.id}
  />
);

export const Loading = () => (
  <DataTable columns={userColumns} data={[]} isLoading />
);

export const Empty = () => (
  <DataTable
    columns={certColumns}
    data={[]}
    emptyMessage="No certificates issued for this tenant yet."
  />
);

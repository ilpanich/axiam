import { StatusBadge } from "frontend";

export const Statuses = () => (
  <div className="flex flex-wrap items-center gap-3">
    <StatusBadge status="active" />
    <StatusBadge status="revoked" />
    <StatusBadge status="inactive" />
  </div>
);

export const CertificateRows = () => (
  <div className="flex flex-col gap-3 text-sm">
    <div className="flex items-center gap-3">
      <span className="w-56 font-mono text-xs text-foreground/80">
        CN=iot-gateway-04.axiam.dev
      </span>
      <StatusBadge status="active" />
    </div>
    <div className="flex items-center gap-3">
      <span className="w-56 font-mono text-xs text-foreground/80">
        CN=edge-sensor-117.axiam.dev
      </span>
      <StatusBadge status="revoked" />
    </div>
    <div className="flex items-center gap-3">
      <span className="w-56 font-mono text-xs text-foreground/80">
        CN=legacy-broker.axiam.dev
      </span>
      <StatusBadge status="inactive" />
    </div>
  </div>
);

export const ServiceAccounts = () => (
  <div className="flex flex-wrap items-center gap-2">
    <span className="text-sm text-foreground/90">svc-billing-sync</span>
    <StatusBadge status="active" />
    <span className="ml-4 text-sm text-foreground/90">svc-legacy-import</span>
    <StatusBadge status="inactive" />
  </div>
);

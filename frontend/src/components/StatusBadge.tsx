import { cn } from "@/lib/utils";

type Status = "active" | "revoked" | "inactive";

interface StatusBadgeProps {
  status: Status;
  className?: string;
}

const statusStyles: Record<Status, string> = {
  active:
    "bg-cyan-500/15 text-cyan-400 border border-cyan-500/30",
  revoked:
    "bg-red-500/15 text-red-400 border border-red-500/30",
  inactive:
    "bg-muted/40 text-muted-foreground border border-border",
};

export function StatusBadge({ status, className }: StatusBadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium",
        statusStyles[status],
        className
      )}
    >
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

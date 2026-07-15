import { Ban, Circle, CircleCheck, PauseCircle } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

type Status = "active" | "revoked" | "inactive" | "suspended";

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
  suspended:
    "bg-amber-500/15 text-amber-400 border border-amber-500/30",
};

// A distinct icon shape per state so the badge is scannable without relying on
// color alone. Rendered as an SVG (no text content) and aria-hidden, so the
// text label remains the only accessible/matchable name for the badge.
const statusIcon: Record<Status, LucideIcon> = {
  active: CircleCheck,
  revoked: Ban,
  inactive: Circle,
  suspended: PauseCircle,
};

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const Icon = statusIcon[status];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium",
        statusStyles[status],
        className
      )}
    >
      <Icon size={11} aria-hidden="true" className="shrink-0" />
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

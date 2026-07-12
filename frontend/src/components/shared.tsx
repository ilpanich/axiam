/**
 * shared.tsx — UI primitives reused across multiple pages.
 *
 * Extracted from RoleDetailPage, GroupDetailPage, PermissionsPage, UsersPage
 * to eliminate duplication (CQ-F15).
 */

import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";

// ─── ToggleField ──────────────────────────────────────────────────────────────

export interface ToggleFieldProps {
  id: string;
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}

export function ToggleField({ id, label, checked, onChange }: ToggleFieldProps) {
  return (
    <div className="flex items-center gap-3">
      <input
        type="checkbox"
        id={id}
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="w-4 h-4 accent-cyan-400 cursor-pointer"
      />
      <Label htmlFor={id} className="cursor-pointer">
        {label}
      </Label>
    </div>
  );
}

// ─── SectionCard ──────────────────────────────────────────────────────────────

export interface SectionCardProps {
  title: string;
  action?: React.ReactNode;
  children: React.ReactNode;
}

export function SectionCard({ title, action, children }: SectionCardProps) {
  return (
    <div className="glass-card mb-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-base font-semibold text-foreground">{title}</h2>
        {action}
      </div>
      {children}
    </div>
  );
}

// ─── InfoRow ──────────────────────────────────────────────────────────────────

export interface InfoRowProps {
  label: string;
  children: React.ReactNode;
}

export function InfoRow({ label, children }: InfoRowProps) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-start gap-1 sm:gap-4 py-2 border-b border-white/5 last:border-0">
      <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground sm:w-36 shrink-0 pt-0.5">
        {label}
      </span>
      <span className="text-sm text-foreground/90">{children}</span>
    </div>
  );
}

// ─── ActionBadge ──────────────────────────────────────────────────────────────

const ACTION_COLOR_MAP: Record<string, string> = {
  read: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  write: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  delete: "bg-rose-500/15 text-rose-400 border-rose-500/30",
  admin: "bg-purple-500/15 text-purple-400 border-purple-500/30",
};

export interface ActionBadgeProps {
  action: string;
}

export function ActionBadge({ action }: ActionBadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border",
        ACTION_COLOR_MAP[action.toLowerCase()] ??
          "bg-white/10 text-foreground/70 border-white/20",
      )}
    >
      {action}
    </span>
  );
}

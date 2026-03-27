import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

interface PublicLayoutProps {
  children: ReactNode;
  /** Tailwind max-width class applied to the card. Defaults to "max-w-md". */
  maxWidth?: string;
}

export function PublicLayout({ children, maxWidth = "max-w-md" }: PublicLayoutProps) {
  return (
    <div className="min-h-screen flex items-center justify-center bg-axiam-gradient px-4">
      {/* Background ambient glow */}
      <div
        className="fixed inset-0 overflow-hidden pointer-events-none"
        aria-hidden="true"
      >
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[600px] rounded-full bg-primary/5 blur-[120px]" />
        <div className="absolute bottom-1/4 left-1/3 w-[400px] h-[400px] rounded-full bg-accent/5 blur-[100px]" />
      </div>

      <div className={cn("relative w-full", maxWidth)}>
        {/* Logo area with neon ring effect */}
        <div className="flex flex-col items-center mb-8">
          <div className="relative mb-4">
            {/* Animated neon rings */}
            <div
              className="absolute inset-0 rounded-full border-2 border-primary/30 animate-ring-spin"
              style={{ margin: "-16px" }}
              aria-hidden="true"
            />
            <div
              className="absolute inset-0 rounded-full border border-accent/20 animate-ring-spin-reverse"
              style={{ margin: "-24px" }}
              aria-hidden="true"
            />
            <div className="relative h-16 w-16 rounded-full bg-primary/10 border border-primary/30 flex items-center justify-center shadow-glow-cyan">
              <img
                src="/axiam_logo.png"
                alt="AXIAM"
                className="h-10 w-10 object-contain"
              />
            </div>
          </div>
          <h1 className="text-3xl font-bold text-foreground tracking-tight">
            AXIAM
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Identity &amp; Access Management
          </p>
        </div>

        {/* Glass card */}
        <div className="glass-card p-8">{children}</div>

        <p className="text-center text-xs text-muted-foreground/50 mt-6">
          Secured by AXIAM IAM · GDPR &amp; ISO27001 compliant
        </p>
      </div>
    </div>
  );
}

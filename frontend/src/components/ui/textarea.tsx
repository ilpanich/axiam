import * as React from "react";
import { cn } from "@/lib/utils";

export interface TextareaProps
  extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  /** Marks the field invalid without necessarily rendering a message. */
  invalid?: boolean;
  /**
   * Error message text. When set, the field is styled as invalid, gets
   * `aria-invalid="true"`, and is wired to the message via `aria-describedby`.
   */
  error?: string;
  /** Explicit id for the rendered error node. Defaults to `${id}-error`. */
  errorId?: string;
}

const Textarea = React.forwardRef<HTMLTextAreaElement, TextareaProps>(
  (
    { className, invalid, error, errorId, id, "aria-describedby": describedBy, ...props },
    ref
  ) => {
    const isInvalid = invalid ?? Boolean(error);
    const resolvedErrorId = errorId ?? (id ? `${id}-error` : undefined);
    const describedByIds =
      [describedBy, isInvalid && error ? resolvedErrorId : undefined]
        .filter(Boolean)
        .join(" ") || undefined;

    return (
      <>
        <textarea
          ref={ref}
          id={id}
          aria-invalid={isInvalid || undefined}
          aria-describedby={describedByIds}
          className={cn(
            "focus-ring flex w-full rounded-md px-3 py-2 text-sm resize-none",
            "bg-white/5 border text-foreground",
            "placeholder:text-muted-foreground",
            "focus:border-primary",
            "disabled:cursor-not-allowed disabled:opacity-50",
            "transition-colors duration-200",
            isInvalid
              ? "border-destructive focus:border-destructive"
              : "border-primary/20",
            className
          )}
          {...props}
        />
        {error ? (
          <p id={resolvedErrorId} className="mt-1.5 text-xs text-destructive">
            {error}
          </p>
        ) : null}
      </>
    );
  }
);

Textarea.displayName = "Textarea";

export { Textarea };

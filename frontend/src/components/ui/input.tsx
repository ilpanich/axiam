import * as React from "react";
import { cn } from "@/lib/utils";

export interface InputProps
  extends React.InputHTMLAttributes<HTMLInputElement> {
  /** Marks the field invalid without necessarily rendering a message. */
  invalid?: boolean;
  /**
   * Error message text. When set, the field is styled as invalid, gets
   * `aria-invalid="true"`, and is wired to the message via `aria-describedby`.
   */
  error?: string;
  /**
   * Explicit id for the rendered error node. Defaults to `${id}-error` when an
   * `id` is provided. Callers that render their own error node can pass the id
   * and omit `error` to keep the wiring.
   */
  errorId?: string;
}

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  (
    { className, type, invalid, error, errorId, id, "aria-describedby": describedBy, ...props },
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
        <input
          ref={ref}
          id={id}
          type={type}
          aria-invalid={isInvalid || undefined}
          aria-describedby={describedByIds}
          className={cn(
            "focus-ring flex h-10 w-full rounded-md px-3 py-2 text-sm",
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
          <p
            id={resolvedErrorId}
            className="mt-1.5 text-xs text-destructive"
          >
            {error}
          </p>
        ) : null}
      </>
    );
  }
);

Input.displayName = "Input";

export { Input };

import { Check, X } from "lucide-react";
import { cn } from "@/lib/utils";

export interface PasswordPolicyCheckerProps {
  password: string;
}

interface PolicyRule {
  label: string;
  test: (pw: string) => boolean;
}

const POLICY_RULES: PolicyRule[] = [
  { label: "At least 12 characters", test: (pw) => pw.length >= 12 },
  { label: "At least one uppercase letter", test: (pw) => /[A-Z]/.test(pw) },
  { label: "At least one lowercase letter", test: (pw) => /[a-z]/.test(pw) },
  { label: "At least one digit", test: (pw) => /[0-9]/.test(pw) },
  {
    label: "At least one special character",
    test: (pw) => /[^A-Za-z0-9]/.test(pw),
  },
];

/**
 * Returns true when every password policy rule is satisfied.
 */
export function checkPasswordPolicy(password: string): boolean {
  return POLICY_RULES.every((rule) => rule.test(password));
}

/**
 * Pure display component — all state comes from the `password` prop.
 * Renders 5 policy requirement rows with animated green/red icons.
 */
export function PasswordPolicyChecker({ password }: PasswordPolicyCheckerProps) {
  return (
    <ul className="space-y-1.5" aria-label="Password requirements">
      {POLICY_RULES.map((rule) => {
        const met = rule.test(password);
        return (
          <li
            key={rule.label}
            className={cn(
              "flex items-center gap-2 text-sm transition-colors duration-200",
              met ? "text-emerald-400" : "text-destructive/80"
            )}
          >
            <span
              className={cn(
                "flex h-4 w-4 items-center justify-center rounded-full transition-all duration-200",
                met
                  ? "bg-emerald-400/20 text-emerald-400"
                  : "bg-destructive/10 text-destructive/80"
              )}
              aria-hidden="true"
            >
              {met ? <Check size={10} strokeWidth={3} /> : <X size={10} strokeWidth={3} />}
            </span>
            <span>{rule.label}</span>
          </li>
        );
      })}
    </ul>
  );
}

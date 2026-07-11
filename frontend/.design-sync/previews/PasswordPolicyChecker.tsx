import { useState } from "react";
import {
  Input,
  Label,
  PasswordPolicyChecker,
  SectionCard,
  checkPasswordPolicy,
} from "frontend";

export const AllRulesFailing = () => (
  <div className="w-80">
    <PasswordPolicyChecker password="" />
  </div>
);

export const PartiallyMet = () => (
  <div className="w-80">
    <PasswordPolicyChecker password="northwind" />
  </div>
);

export const AllRulesMet = () => (
  <div className="w-80">
    <PasswordPolicyChecker password="Kx9!vTernary#Ledger" />
  </div>
);

export const RelaxedPolicy = () => (
  <div className="w-80">
    <PasswordPolicyChecker
      password="opensesame"
      minLength={8}
      requireComplexity={false}
    />
  </div>
);

export const InSetPasswordForm = () => {
  const [password, setPassword] = useState("Argon2id!Rotate2026");
  const valid = checkPasswordPolicy(password);
  return (
    <SectionCard title="Set password">
      <div className="flex w-96 flex-col gap-4">
        <div className="flex flex-col gap-2">
          <Label htmlFor="new-password">New password</Label>
          <Input
            id="new-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <PasswordPolicyChecker password={password} />
        <p className="text-xs text-muted-foreground">
          {valid
            ? "Password satisfies the tenant password policy."
            : "Password does not satisfy the tenant password policy."}
        </p>
      </div>
    </SectionCard>
  );
};

import { useState } from "react";
import { SectionCard, ToggleField } from "frontend";

export const Checked = () => {
  const [on, setOn] = useState(true);
  return (
    <ToggleField
      id="mfa-required"
      label="Require MFA for all tenant members"
      checked={on}
      onChange={setOn}
    />
  );
};

export const Unchecked = () => {
  const [on, setOn] = useState(false);
  return (
    <ToggleField
      id="allow-social-login"
      label="Allow social login"
      checked={on}
      onChange={setOn}
    />
  );
};

export const PermissionGroup = () => {
  const [perms, setPerms] = useState({ read: true, write: true, delete: false });
  return (
    <SectionCard title="Permissions on resource:tenant">
      <div className="flex flex-col gap-3">
        {(["read", "write", "delete"] as const).map((action) => (
          <ToggleField
            key={action}
            id={`perm-${action}`}
            label={`tenant:${action}`}
            checked={perms[action]}
            onChange={(v) => setPerms((p) => ({ ...p, [action]: v }))}
          />
        ))}
      </div>
    </SectionCard>
  );
};

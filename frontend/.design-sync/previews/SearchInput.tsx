import { useState } from "react";
import { SearchInput, SectionCard, StatusBadge } from "frontend";

export const Empty = () => {
  const [query, setQuery] = useState("");
  return (
    <div className="w-80">
      <SearchInput
        value={query}
        onChange={setQuery}
        placeholder="Search users by email or username…"
      />
    </div>
  );
};

export const WithQuery = () => {
  const [query, setQuery] = useState("svc-billing");
  return (
    <div className="w-80">
      <SearchInput
        value={query}
        onChange={setQuery}
        placeholder="Search service accounts…"
      />
    </div>
  );
};

export const FilteringUsers = () => {
  const [query, setQuery] = useState("north");
  const users = [
    { email: "ada.byron@northwind-industrial.example", status: "active" },
    { email: "grace.hopper@northwind-industrial.example", status: "active" },
    { email: "alan.turing@northwind-industrial.example", status: "inactive" },
  ] as const;
  return (
    <SectionCard title="Users">
      <div className="flex flex-col gap-4">
        <SearchInput
          value={query}
          onChange={setQuery}
          placeholder="Search users by email or username…"
        />
        <div className="flex flex-col gap-2">
          {users.map((u) => (
            <div key={u.email} className="flex items-center justify-between">
              <span className="text-sm text-foreground/90">{u.email}</span>
              <StatusBadge status={u.status} />
            </div>
          ))}
        </div>
      </div>
    </SectionCard>
  );
};

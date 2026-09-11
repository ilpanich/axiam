SearchInput from frontend. Use via `window.AxiamUI.SearchInput` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<AxiamSurface>` (full provider chain in README.md — components read theme/i18n from that context).

Debounced search input — calls onChange 300ms after the user stops typing.
Manages its own internal state so the input feels instant.

## Examples

### Empty

```jsx
() => {
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
}
```

### WithQuery

```jsx
() => {
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
}
```

### FilteringUsers

```jsx
() => {
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
}
```

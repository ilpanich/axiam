TotpSetupPanel from frontend. Use via `window.AxiamUI.TotpSetupPanel` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<AxiamSurface>` (full provider chain in README.md — components read theme/i18n from that context).

## Examples

### Enrolling

```jsx
() => {
  const [code, setCode] = useState("");
  return (
    <div className="glass-card p-6 max-w-sm">
      <TotpSetupPanel
        setupData={SETUP}
        code={code}
        onCodeChange={setCode}
        onConfirm={() => {}}
        error={null}
        isPending={false}
        confirmLabel="Enable MFA"
        onCancel={() => {}}
      />
    </div>
  );
}
```

### CodeEntered

```jsx
() => {
  const [code, setCode] = useState("482915");
  return (
    <div className="glass-card p-6 max-w-sm">
      <TotpSetupPanel
        setupData={SETUP}
        code={code}
        onCodeChange={setCode}
        onConfirm={() => {}}
        error={null}
        isPending={false}
        confirmLabel="Enable MFA"
        onCancel={() => {}}
      />
    </div>
  );
}
```

### RejectedCode

```jsx
() => {
  const [code, setCode] = useState("300174");
  return (
    <div className="glass-card p-6 max-w-sm">
      <TotpSetupPanel
        setupData={SETUP}
        code={code}
        onCodeChange={setCode}
        onConfirm={() => {}}
        error="Invalid MFA code — the code did not match the enrolled secret. Check your device clock and try the next code."
        isPending={false}
        confirmLabel="Enable MFA"
        onCancel={() => {}}
      />
    </div>
  );
}
```

### Confirming

```jsx
() => {
  const [code, setCode] = useState("729300");
  return (
    <div className="glass-card p-6 max-w-sm">
      <TotpSetupPanel
        setupData={SETUP}
        code={code}
        onCodeChange={setCode}
        onConfirm={() => {}}
        error={null}
        isPending
        confirmLabel="Enable MFA"
        confirmPendingLabel="Verifying…"
      />
    </div>
  );
}
```

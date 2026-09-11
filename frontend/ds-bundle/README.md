## AXIAM — how to build with this design system

AXIAM is the admin UI for an Identity & Access Management platform (organizations, tenants,
users, groups, roles, permissions, service accounts, X.509 certificates, OAuth2 clients,
webhooks, audit logs). It is a **dark-only, neon-on-deep-indigo** system: a deep indigo
gradient surface, translucent "glass" panels, cyan as the primary action colour and violet
as the accent.

### 1. Dark surface: wrap the tree in `<AxiamSurface>`

Every AXIAM screen is designed against a fixed dark gradient that normally lives on `body`.
Wrap your tree in `AxiamSurface` — it paints that surface. **Without it the page renders on
white, glass panels wash out, and muted/ghost text becomes unreadable.**

```jsx
const { AxiamSurface, Card, CardTitle, Button } = window.AxiamUI;

<AxiamSurface>
  <Card>…</Card>
</AxiamSurface>
```

There is no theme provider and no light mode. Do not build a light variant.

### 2. Styling idiom: Tailwind utilities over a custom token theme

Style with **Tailwind utility classes**, using AXIAM's own token names — never raw hex, and
never invented colour names. The full vocabulary below is compiled into the shipped
stylesheet, so all of it is safe to use.

| Family | Use | Real class names |
|---|---|---|
| Surface | page + panels | `bg-background`, `bg-card`, `bg-popover`, `bg-muted`, `bg-secondary`, `bg-axiam-gradient` |
| Text | copy | `text-foreground`, `text-muted-foreground`, `text-primary`, `text-accent`, `text-destructive` |
| Primary (cyan `#00d4ff`) | main actions, active state, focus | `bg-primary`, `text-primary`, `border-primary`, `ring-primary` |
| Accent (violet `#a855f7`) | secondary emphasis, "special" state | `bg-accent`, `text-accent`, `border-accent` |
| Destructive | danger/revoke | `bg-destructive`, `text-destructive`, `border-destructive` |
| Borders | hairlines | `border-border` (a translucent cyan), `border-primary/30` |
| Translucency | the glass idiom | `bg-white/5`, `bg-primary/10`, `border-primary/20` (opacity steps 5–80) |
| Glow (the brand signature) | hover/emphasis | `shadow-glow-cyan`, `shadow-glow-cyan-lg`, `shadow-glow-purple`, `shadow-glass` |
| Radius | `--radius: 0.75rem` | `rounded-lg` (12px), `rounded-md`, `rounded-sm`, `rounded-full` |
| Motion | ambient | `animate-neon-pulse`, `animate-ring-spin` |

Plus these **project CSS classes** (defined by AXIAM itself, not Tailwind):

- **`glass-card`** — the signature panel: translucent white fill, 12px blur, cyan hairline
  border, deep drop shadow. This is the default container for anything on a page.
- `glow-cyan` / `glow-cyan-lg` / `glow-purple` — standalone glow shadows.
- `sidebar-item-active` — the lit nav item (cyan left border + glow).
- `btn-primary` — the cyan gradient button fill (`Button` already applies its own styling; use
  this only for a non-`Button` element that must read as the primary action).
- `input-axiam` — the translucent input treatment.

Standard layout/spacing/typography utilities (`flex`, `grid grid-cols-3`, `gap-4`, `p-6`,
`max-w-2xl`, `text-2xl`, `font-semibold`, `uppercase tracking-wider`, …) are available and are
the right way to lay out your own composition.

### 3. Where the truth lives

- **`_ds/<folder>/styles.css`** and its `@import` closure (`_ds_bundle.css`) — the actual
  compiled stylesheet: every token (`--primary`, `--background`, `--radius`, …) and every class
  above. Read it before inventing anything.
- **`components/<group>/<Name>/<Name>.prompt.md`** — per-component usage; **`<Name>.d.ts`** — the
  exact props. Read the component's own docs before guessing an API.

### 4. Composition rules that matter here

- **`Card` is a compound**: `Card` + `CardHeader` / `CardTitle` / `CardDescription` /
  `CardContent` / `CardFooter`. `Card` already carries `glass-card`.
- **`Button`** variants: `default` (cyan, the primary action), `accent` (violet), `secondary`,
  `outline`, `ghost`, `link`, `destructive`. Sizes: `sm`, `default`, `lg`, `icon`.
- **`Badge`** variants: `default`, `secondary`, `destructive`, `outline`, `accent`. For entity
  state prefer the purpose-built **`StatusBadge`** (`active | revoked | inactive`) and
  **`ActionBadge`** (a permission verb — `read`/`write`/`delete`/`admin` are colour-coded).
- **Detail screens** use `SectionCard` + `InfoRow` (label/value rows), list screens use
  `PageHeader` + `SearchInput` + `DataTable`.
- **Dialogs** (`ConfirmDialog`, `FormDialog`, `SecretRevealModal`, `UserSearchDialog`) are
  controlled — they render nothing until `open` is true.
- **Toasts**: render `<Toaster />` once, then fire with the `useToast()` hook from the same
  bundle: `const { toast } = window.AxiamUI.useToast()`.
- `Sidebar`, `Topbar` and `AppLayout` are the real app shell and depend on react-router and the
  auth store; for most designs compose a page *inside* a layout rather than rebuilding the shell.

### 5. An idiomatic screen

```jsx
const {
  AxiamSurface, PageHeader, Button, Card, CardHeader, CardTitle, CardDescription,
  CardContent, StatusBadge, Badge,
} = window.AxiamUI;

<AxiamSurface>
  <div className="p-8">
    <PageHeader
      title="Service accounts"
      description="Machine-to-machine principals with client credentials or mTLS."
      action={<Button>Create service account</Button>}
    />

    <div className="grid grid-cols-3 gap-4">
      <Card>
        <CardHeader>
          <CardTitle>billing-sync</CardTitle>
          <CardDescription>Northwind Industrial / production</CardDescription>
        </CardHeader>
        <CardContent className="flex items-center gap-2">
          <StatusBadge status="active" />
          <Badge variant="accent">mTLS</Badge>
        </CardContent>
      </Card>
    </div>
  </div>
</AxiamSurface>
```

Note the split: **library components** for the controls, **AXIAM's own utility classes** for the
layout glue around them.

# AxiamUI (frontend@0.0.0)

This design system is the published frontend React library, bundled as a single
browser global. All 27 components are the real upstream code.

## Where things are

- `_ds_bundle.js` — the whole-DS bundle at the project root; loads every component to `window.AxiamUI`. First line is a `/* @ds-bundle: … */` metadata header.
- `styles.css` — the single stylesheet entry: it `@import`s the tokens, fonts, and component styles (`_ds_bundle.css`). Link this one file.
- `components/<group>/<Name>/<Name>.prompt.md` (example JSX + variants), `<Name>.d.ts` (types), `<Name>.html` (variant grid).
- `tokens/*.css` — CSS custom properties, names verbatim from upstream.
- `fonts/` — `@font-face` files + `fonts.css` (when the package ships fonts).

For a specific component, `read_file("components/<group>/<Name>/<Name>.prompt.md")`.

## Loading

Add these two lines to your page once (React must be on the page first):

```html
<link rel="stylesheet" href="styles.css">
<script src="_ds_bundle.js"></script>
```

Components are then available at `window.AxiamUI.*`. Mount into a dedicated child node (e.g. `<div id="ds-root">`), not the host page's own React root, so the two trees don't collide:

```jsx
const { ActionBadge } = window.AxiamUI;
ReactDOM.createRoot(document.getElementById('ds-root')).render(<ActionBadge />);
```

Wrap the tree in the provider — most components read theme/i18n from context:

```jsx
<AxiamSurface>{children}</AxiamSurface>
```

## Tokens

83 CSS custom properties from frontend. Names are
preserved verbatim from upstream. They are declared inside `_ds_bundle.css` (this DS ships one compiled stylesheet rather than separate token files).

- **color** (9): `--tw-border-spacing-x`, `--tw-border-spacing-y`, `--tw-ring-offset-color`, …
- **spacing** (3): `--tw-ring-inset`, `--tw-space-x-reverse`, `--tw-space-y-reverse`
- **radius** (1): `--radius`
- **shadow** (4): `--tw-ring-offset-shadow`, `--tw-ring-shadow`, `--tw-shadow`, …
- **other** (66): `--tw-translate-x`, `--tw-translate-y`, `--tw-rotate`, …

## Components

### data-display
- `ActionBadge`
- `DataTable`
- `InfoRow`
- `PageHeader`
- `ResourceTree`
- `SectionCard`
- `StatusBadge`

### layout
- `AppLayout`
- `PublicLayout`
- `Sidebar`
- `Topbar`

### primitives
- `Badge`
- `Button`
- `Card`
- `Input`
- `Label`
- `Textarea`

### overlays
- `ConfirmDialog`
- `SecretRevealModal`
- `Toaster`
- `UserSearchDialog`

### auth
- `ForbiddenPage`
- `TotpSetupPanel`

### forms
- `FormDialog`
- `PasswordPolicyChecker`
- `SearchInput`
- `ToggleField`

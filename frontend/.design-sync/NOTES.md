# design-sync notes — AXIAM admin frontend

Repo-specific gotchas for future syncs. Read this before re-running the converter.

## Shape

- This repo is an **app, not a published component library**: no Storybook, no library
  `dist/`, `package.json` is `private` with no `exports`. So the converter runs the
  **package shape** against an explicit barrel entry, `.design-sync/entry.ts`, which
  re-exports the real components out of `src/components/`. Nothing is reimplemented —
  the barrel is the only "dist" that exists.
- `node_modules/frontend` does not exist (npm never self-installs), so the converter's
  default package resolution crashes with `ENOENT .../node_modules/frontend/package.json`.
  **`cfg.entry` is mandatory here** — it makes the build walk up to the repo's own
  `package.json` instead.
- Component discovery is driven entirely by `cfg.componentSrcMap` (27 entries). With a
  barrel entry and no shipped `.d.ts`, auto-discovery finds nothing, so the map is the
  component list. **Add a component here when one is added to `src/components/`** —
  otherwise it silently won't sync.

## tsconfig `@/*` aliases — do NOT point cfg.tsconfig at tsconfig.app.json

The converter strips `/* … */` comments before `JSON.parse`ing the tsconfig. The alias
key `"@/*"` itself contains the characters `/*`, so on a tsconfig that ALSO has block
comments (which `tsconfig.app.json` does), the stripper eats everything from `"@/` to the
next `*/` and the JSON fails to parse. The paths plugin then silently returns null and
every `@/lib/utils` import fails to resolve (`[UNRESOLVED_IMPORT]`, 32 esbuild errors).

Fix in place: `cfg.tsconfig` → **`.design-sync/tsconfig.paths.json`**, a comment-free file
that holds only `baseUrl` + the `@/*` alias. Don't "simplify" this back to the app tsconfig.

## Dark-only DS — the AxiamSurface provider is load-bearing

AXIAM is dark-only: the gradient every component is designed against lives on `body` in
`src/index.css`. The generated preview cards hardcode `body{background:#fff}`, so without
intervention every card renders on white — glass cards wash out and low-contrast variants
(ghost Button, muted text) are effectively invisible.

`cfg.provider` → **`AxiamSurface`** (`.design-sync/preview-frame.tsx`, wired in via
`cfg.extraEntries`) reproduces that `body` rule as a component. It is not preview
scaffolding to be dropped later: it is also what tells the design agent to build AXIAM
screens on the AXIAM surface. Keep it.

## Tailwind: the stylesheet is compiled, not shipped

The app has no static stylesheet — styling is Tailwind utilities compiled at app build
time. `cfg.cssEntry` therefore points at **`.design-sync/compiled.css`**, a generated file
(gitignored), produced by `cfg.buildCmd`:

    npx tailwindcss -c .design-sync/tailwind.preview.config.js -i src/index.css -o .design-sync/compiled.css

`tailwind.preview.config.js` re-uses the app's real theme and widens `content` to include
`.design-sync/previews/**`. **Re-run this after authoring or editing any preview** — a
utility class used only in a preview does not exist in the CSS until Tailwind sees it, and
the card renders unstyled with no error.

### The safelist is load-bearing — do not delete it

Tailwind only emits classes it can *see*, and `src/` uses a fraction of the AXIAM theme. But this
stylesheet is what **every design the claude.ai/design agent builds** renders against, and that agent
writes its own layout glue (`flex`, `gap-4`, `grid-cols-3`, `p-6`, …) plus brand tokens the app happens
not to use yet (`bg-card`, `bg-muted`, `bg-popover`, `shadow-glow-purple`, `animate-neon-pulse`, and the
`glow-*` / `btn-primary` / `input-axiam` component classes — all of which were purged before the
safelist existed). Without the safelist those classes are absent from the shipped CSS and the agent's
designs render **silently unstyled**.

`tailwind.preview.config.js` therefore safelists the full AXIAM colour/shadow/motion vocabulary plus a
bounded set of layout/typography utilities. This is deliberately a *superset* of what the app itself
uses. Cost: `compiled.css` goes from ~47 KB to ~272 KB. Keep it bounded — an early attempt with more
variants and every colour-bearing property produced a **1.9 MB** stylesheet, which is too heavy to ship
to every design. If you widen it, re-check the size.

## The bundle inlines react-router / zustand / react-query — previews MUST NOT import them directly

This is the subtlest trap in this repo, and it silently produced blank cards.

`_ds_bundle.js` **inlines** `react-router`, `zustand` and `@tanstack/react-query` (only react/react-dom
are externalized). A preview that imports `react-router-dom` from `node_modules` therefore gets a
**second copy of the library with its own React context objects** — so a `<MemoryRouter>` rendered by
the preview populates contexts the *bundled* `Sidebar`/`Topbar`/`AppLayout` never read. Symptoms:
blank cell with no error, or `useNavigate() may be used only in the context of a <Router>`. The same
argument applies to `useAuthStore` (a second zustand store, so `setState` seeds a store nobody reads)
and to `QueryClientProvider`.

Two config-level pieces fix it, and both must stay:

1. **`.design-sync/preview-frame.tsx`** is compiled INTO the bundle (via `cfg.extraEntries`), so what it
   re-exports ARE the bundle's own instances: the react-router API, the react-query API
   (`QueryClient`, `QueryClientProvider`, `useQuery`, `useMutation`, `useQueryClient`), `useAuthStore`,
   and `useToast`/`setToastDispatch`.
2. **`cfg.storyImports.shim`** rewrites `/node_modules/react-router`, `/node_modules/@tanstack/react-query`
   and `/src/stores/auth` onto those bundle instances.

Consequences for anyone editing previews:

- **Keep the natural import specifiers.** `import { MemoryRouter } from "react-router-dom"` and
  `import { useAuthStore } from "@/stores/auth"` are correct — the shim resolves them to the bundle copy.
  Never hand-roll a fake router context or a local store.
- **The shim redirects the WHOLE module**, so `preview-frame.tsx` must re-export every part of an API
  that `src/` uses. When a bundled component started calling `useQuery` and the frame only exported
  `QueryClient`/`QueryClientProvider`, the card died with `ds_exports.useQuery is not a function`.
  Adding a new react-query/react-router API call in `src/` may require adding it to the frame.
- **`Toaster` must be driven by the bundle's `useToast`.** The bundled `Toaster` registers its dispatch
  singleton in the *bundle's* `useToast` module; a source-imported `useToast` is a different instance
  whose dispatch stays null, and the card renders empty with no error.

## Seeding the auth store — the "empty sidebar" trap

`Sidebar` dims every nav target the principal lacks permission for, so an *unseeded* store renders a wall
of grey links that looks like a broken component. Seed at module scope (zustand stores are module-level):

```ts
useAuthStore.setState({
  user: { id, username, email, permissions: ["*"], tenant_id },
  tenantSlug: "acme-prod", orgSlug: "acme",
  isAuthenticated: true, isInitializing: false,
});
```

`permissions: ["*"]` = full tenant-admin nav. A narrow list is the *intended* way to show the
disabled-item styling (the `AuditorRestricted` cell does this on purpose — a partially dimmed sidebar
there is correct). `AppLayout` hard-gates on `isAuthenticated` and renders `<Navigate to="/login">`
otherwise, and it needs a `createMemoryRouter` with a real nested route for both the lit
`sidebar-item-active` item and the `useMatches()` breadcrumb.

## Fixed-position overlays need a transform Stage in the preview

Every dialog/modal/toast here is `position: fixed`. Left alone it escapes its card and the card collapses
to zero height. `cardMode: "single"` fixes the *product card* but NOT the review sheet (which captures
each cell against the viewport). The durable fix lives in the preview: an ancestor with a `transform`
becomes the containing block for fixed descendants (CSS Transforms spec), trapping the dialog — backdrop
and blur included — inside the cell:

```tsx
<div style={{ position: "relative", transform: "translateZ(0)", height: 480, width: "100%",
              overflow: "hidden", borderRadius: 12,
              background: "linear-gradient(135deg,#0d0d2b 0%,#1a0a3d 100%)" }}>
```

**Any future overlay/dialog/drawer/popover preview must use this Stage.** Give it enough height to clear
the tallest story (400 for ConfirmDialog, 480 for FormDialog); the components' own `max-h-[90vh]` stays
viewport-relative, not stage-relative. Note toasts default to a 5s auto-dismiss — fire them with
`duration: 600_000` or the screenshot can land on an empty card.

## Groups

`src/components/` is flat, so every component would land in one `general` group. Groups come
from frontmatter-only stubs in `.design-sync/docs/<Name>.md` (`---\ncategory: X\n---`), wired
via `cfg.docsMap`. A frontmatter-only stub sets the group **without** suppressing the
converter's synthesized `.prompt.md` (props + examples) — verified. Add a stub when you add
a component.

## A preview-only Tailwind class NEVER reaches the card

The single most expensive lesson of the first sync. The rendered card loads **`ds-bundle/_ds_bundle.css`**,
which is regenerated **only by `package-build.mjs`** — `preview-rebuild.mjs` and `package-capture.mjs` do
not fold `.design-sync/compiled.css` into it. So running the Tailwind compile alone is NOT enough: a
utility class used only in a preview silently does nothing (`flex-col-reverse` renders as a row, `w-80`
renders full-bleed), with **no error and no warning**.

Practical rules:
- The orchestrator must run a full `package-build.mjs` after previews change, before the final capture
  and grading — otherwise cards are graded against a stylesheet that is missing their classes.
- An agent that may not run `package-build.mjs` must restrict itself to classes already present in
  `ds-bundle/_ds_bundle.css` (grep it) or use inline `style={{…}}`.

## Component-specific facts worth keeping

- **DataTable** is `DataTable<T extends object>` + `Column<T>[]`. Don't annotate column arrays with a
  `Column<Row>` imported from `'frontend'` — that specifier is a runtime shim and carries no types.
  Statically-renderable states: rows, `isLoading` (skeletons), empty + `emptyMessage`.
- **ResourceTree** takes a **flat** `Resource[]` and builds the tree itself from `parent_id` — do not
  nest the fixture data. Nodes default to expanded. Its `actions` are hover-only
  (`opacity-0 group-hover:opacity-100`), so an actions story is invisible in a static shot — don't author one.
- **StatusBadge** — closed union `active | revoked | inactive`; it renders its own label, so badge text
  isn't authorable. **ActionBadge** — `action` is a free string; only `read|write|delete|admin` are
  color-mapped, everything else falls back to a neutral chip (a real state, worth previewing).
- **PasswordPolicyChecker** — driven purely by the `password` prop, no internal state. A cell that varies
  a *config* prop (`minLength`, `requireComplexity`) must hold the password at "passing", or the config
  axis is indistinguishable from the failing-password cell.
- **Input/Textarea** have no `variant`/`error` prop — an error state is composed
  (`className="border-destructive"` + a `text-destructive` hint). Textarea is `resize-none`; it only grows
  via `rows`.
- **PublicLayout** owns its own gradient, neon rings and glass card; it deliberately overdraws the
  `AxiamSurface` provider. That is correct, not a bug.
- **TotpSetupPanel** is purely props-driven and renders a real `QRCodeSVG` from an `otpauth://` URI.
- Empty-state icons in DataTable/ResourceTree render as a small muted square rather than a lucide glyph
  at card scale. Cosmetic; if real glyphs are wanted, the icon set must be reachable from the preview bundle.

## Known render warns

None. `package-validate.mjs` exits clean with zero warnings as of the first sync (2026-07-11). **Any warn
on a future run is new** — investigate it rather than assuming it is baseline.

## Excluded

- `ProtectedRoute` — a route guard that renders `<Outlet/>`; nothing visual to preview.
- Card sub-parts (`CardHeader`/`CardTitle`/`CardContent`/…) are not separate cards; they are
  still exported from the bundle and are documented inside `Card`'s preview and prompt.

## Re-sync risks

- **`componentSrcMap` / `docs/` stubs are hand-maintained.** A component added to
  `src/components/` after this sync will NOT appear until it is added to both. There is no
  discovery to catch it.
- **`.design-sync/entry.ts` is hand-maintained** for the same reason.
- **Preview content is invented composition, not ported examples.** The repo has no
  `examples/`, no docs site and no stories, so preview props were composed from each
  component's source + AXIAM domain vocabulary (tenants, roles, certificates, audit).
  They are realistic but not authoritative — if the team writes real usage docs, prefer those.
- **`compiled.css` is gitignored and regenerated.** A fresh clone must run `cfg.buildCmd`
  before the converter, or `cssEntry` is missing and every card ships unstyled.
- **`preview-frame.tsx` must track `src/`'s use of react-router / react-query / zustand.** The shim
  redirects those whole modules to the frame's re-exports, so if a component starts calling a
  react-query or react-router API the frame doesn't re-export, its card dies with
  `ds_exports.<api> is not a function`. Adding an API call in `src/` can require a frame edit.
- **The Tailwind safelist is a curated superset** (see above). New brand utilities added to
  `tailwind.config.js` are NOT automatically in it — add them, or designs using them render unstyled.
- **Preview content is invented composition.** It is realistic but not authoritative; if the team ever
  writes real usage docs or a Storybook, prefer those and re-shape the previews around them.
- Adding a Storybook to this repo would flip `cfg.shape` to `storybook` and change the whole pipeline
  (previews would come from stories, verified against a real storybook render). That is an improvement,
  not a regression — but it is a re-plan, not a re-run.

# AXIAM Design System — UI/UX & Accessibility Audit

Review of the AXIAM component library as shipped in `_ds_bundle.js` / `_ds_bundle.css`.
Findings are grouped by area and prioritized (**P1** = fix first, **P2** = should fix, **P3** = polish).
Each item names the affected component, the source location, the problem, and a concrete fix.

> **Context / what's already good.** This library is well built for accessibility: dialogs
> (`ConfirmDialog`, `FormDialog`, `SecretRevealModal`, `UserSearchDialog`) implement `role="dialog"`/
> `aria-modal`, `aria-labelledby`/`describedby`, Escape-to-close, Tab focus trapping and initial
> focus; `ResourceTree` implements the full ARIA `tree` pattern with arrow-key navigation; `Sidebar`
> uses `aria-current`; `Topbar` menus use `aria-expanded`/`aria-haspopup` with arrow-key roving;
> `Toaster` uses `aria-live`; badges (`StatusBadge`, `ActionBadge`) always render a text label, so
> meaning is never conveyed by color alone. The items below are the gaps that remain.

---

## P1 — Accessibility

### 1. No `prefers-reduced-motion` support anywhere
**Where:** `_ds_bundle.css` (base layer, `.btn-primary`, glow/`animate-*` utilities); `buttonVariants` uses `hover:-translate-y-0.5` and `hover:shadow-glow-cyan` (`Button`, `bundle.js` ~L13725); spinners use `animate-spin`; `animate-neon-pulse` / `animate-ring-spin` are ambient.
**Problem:** Every transition, hover lift, glow pulse, ring spin and loading spinner runs unconditionally. Users who set "reduce motion" (WCAG 2.3.3, and a comfort/vestibular concern) get no relief.
**Fix:** Add a global guard in the base CSS:
```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
}
```
Keep essential loading spinners perceivable (e.g. swap the spin for an opacity pulse or a static "Loading…" label under reduced motion).

### 2. Inputs/Textarea have no accessible error/invalid state
**Where:** `Input` (`bundle.js` ~L13851), `Textarea` (~L13961), `FormDialog` (~L14620).
**Problem:** There is no `aria-invalid`, no `aria-describedby` wiring to an error message, and no visible error style token. Validation feedback is left entirely to each caller, so forms will inconsistently (or never) announce errors to screen readers.
**Fix:** Add an `error?: string` / `invalid?: boolean` prop to `Input` and `Textarea` that:
- sets `aria-invalid="true"`,
- applies a destructive border/ring (`border-destructive focus:ring-destructive/50`),
- renders (or accepts) an error node with a stable `id`, and sets `aria-describedby` to it.
Expose a matching error slot in `FormDialog`'s field layout so it's the default path.

### 3. Dialogs don't restore focus or lock background scroll
**Where:** `ConfirmDialog` (~L14470), `FormDialog` (~L14620), `SecretRevealModal` (~L14890), `UserSearchDialog` (~L19950).
**Problem:** All four set initial focus and trap Tab correctly, but on close focus is **not returned to the triggering element** (WCAG 2.4.3), and the `<body>` is **not scroll-locked** while the modal is open, so the page behind scrolls.
**Fix:** In each dialog's open effect, capture `document.activeElement`, and on close call `previousActive?.focus()`. Add `document.body.style.overflow = 'hidden'` on open and restore it on close (or a shared `useModalA11y` hook so all four behave identically).

---

## P2 — Accessibility

### 4. Focus indicators are inconsistent and weaker on form controls
**Where:** `Button` uses `focus-visible:ring-2 ring-primary ring-offset-2 ring-offset-background` (correct). But `Input`/`Textarea` and the dialog Cancel/Close buttons use `focus:ring-2 focus:ring-primary/40`.
**Problem:** Two divergent patterns: `focus:` (fires on mouse click, not just keyboard) vs `focus-visible:`, and a 40%-opacity ring vs a full-opacity ring with offset. The faint ring is harder to see and the behavior is unpredictable across the app.
**Fix:** Standardize one focus token used everywhere: `focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 focus-visible:ring-offset-background`. Apply it to `Input`, `Textarea`, `SearchInput`, and all hand-rolled dialog buttons.

### 5. `backdrop-filter` glass has no fallback
**Where:** `.glass-card` in `_ds_bundle.css` (`background: rgba(255,255,255,0.05); backdrop-filter: blur(12px)`).
**Problem:** Where `backdrop-filter` is unsupported/disabled, panels collapse to a near-transparent 5% white over the gradient — card text and hairlines lose most of their contrast.
**Fix:** Add a more opaque solid fallback so panels never depend on blur:
```css
@supports not ((backdrop-filter: blur(12px)) or (-webkit-backdrop-filter: blur(12px))) {
  .glass-card { background: rgba(20, 20, 54, 0.92); }
}
```

### 6. Structural borders are near-invisible (component contrast)
**Where:** `--border: 191 100% 50% / 0.15`, the global `* { border-color: rgba(0,212,255,0.15) }`, `DataTable` row dividers `divide-white/5`, `InfoRow` `border-white/5`.
**Problem:** Panel edges, table headers, and row separators sit well below the 3:1 non-text contrast guideline (WCAG 1.4.11). Card boundaries and table rows are hard to distinguish, especially on the lighter glass fill.
**Fix:** Raise *structural* boundaries to roughly `border-primary/25`–`/30` (and dividers to `white/10`) while leaving decorative hairlines subtle. Consider distinct tokens: `--border` (decorative) vs a stronger `--border-strong` for panels/tables.

### 7. `ToggleField` target size is too small
**Where:** `ToggleField` (`bundle.js` ~L13984), checkbox `className: "w-4 h-4 …"`.
**Problem:** A 16×16px hit target is below the 24px minimum (WCAG 2.5.8) and well below a comfortable 44px touch target.
**Fix:** Enlarge the control (e.g. `w-5 h-5` minimum) and/or make the whole label row the click target with adequate padding — the `<label htmlFor>` association is already correct, so extend the clickable/pointer area.

---

## P3 — Accessibility polish

### 8. `DataTable` header cells lack `scope`, empty-state glyph not hidden
**Where:** `DataTable` (`bundle.js` ~L14566).
**Fix:** Add `scope="col"` to each `<th>`. The empty-state decorative "■" glyph should be `aria-hidden="true"` so it isn't announced as "black square".

### 9. `SearchInput` uses the placeholder as its only label
**Where:** `SearchInput` (`bundle.js` ~L14810), `aria-label={placeholder}`.
**Problem:** Placeholder-as-label disappears once the user types, and there's no accessible name if `placeholder` is ever empty.
**Fix:** Accept an explicit `label` (visually-hidden is fine) and associate it, keeping the placeholder as a hint only.

### 10. Icon-only buttons at 40px
**Where:** `Button` `size: "icon"` → `h-10 w-10` (40px).
**Note:** Fine for a desktop admin console (above the 24px minimum), but below the 44px comfortable touch target if this UI is ever used on tablets/touch. Consider a 44px variant for touch contexts.

---

## UI/UX & consistency

### 11. `DataTable` is display-only — a real gap for IAM lists
**Where:** `DataTable` (`bundle.js` ~L14566).
**Problem:** No column sorting, no pagination/virtualization, no row selection, and rows aren't focusable/clickable. For users, groups, audit logs and certificates — inherently long lists in an IAM tool — this forces every screen to reinvent these behaviors or ship none.
**Fix (product decision):** Add opt-in sortable headers (with `aria-sort`), pagination or infinite scroll, and an optional selectable-row mode. If rows become clickable, make the row (or a cell action) a real focusable control with a visible focus ring.

### 12. Row hover feedback is too subtle
**Where:** `DataTable` row `hover:bg-white/[0.03]`.
**Fix:** Strengthen to ~`hover:bg-white/[0.06]` (or a faint `bg-primary/5`) so the hovered row is scannable at a glance.

### 13. Global `*` border-color rule is too broad
**Where:** `_ds_bundle.css`: `* { border-color: rgba(0,212,255,0.15) }`.
**Problem:** Every element inherits a cyan border color; any element that later receives a `border` width from a utility picks up an unintended cyan hairline, making borders unpredictable to reason about.
**Fix:** Rely on the Tailwind `border-border` token instead of forcing the color onto every element; scope the default to elements that actually draw borders, or drop the universal rule.

### 14. No error state for async data surfaces
**Where:** `DataTable` has `isLoading` (skeleton) and `emptyMessage`, but no error path.
**Fix:** Add an `error` slot/prop with a retry affordance so failed fetches render consistently instead of falling back to the empty state.

### 15. `StatusBadge` distinguishes only by color + text
**Where:** `StatusBadge` (`bundle.js` ~L14974).
**Note:** Text is always present (good), but adding a small leading dot/icon per state (active ●, revoked ⨯, inactive ○) would speed scanning in dense tables and add a non-color cue. Optional enhancement.

---

## Cross-browser compatibility & mobile / responsive

**Baseline requirement:** must be fully correct in **Firefox and Chrome**, and also work in **Safari
and Edge** (Edge shares Chrome's Blink engine, so Chrome-correct ≈ Edge-correct; Safari/WebKit is the
real risk surface). The findings below are ordered by how likely they are to actually break something.

### 16. `background-attachment: fixed` breaks / janks on iOS Safari — P1
**Where:** `_ds_bundle.css` `body { background: linear-gradient(...); background-attachment: fixed; }`.
**Problem:** iOS Safari (and some Android browsers) handle `background-attachment: fixed` poorly — it's
often ignored, and where honored it forces expensive full-page repaints on every scroll frame,
producing visible jank. This is the single most likely mobile defect in the system.
**Fix:** Drop `background-attachment: fixed`. Paint the gradient on a `position: fixed; inset: 0;
z-index: -1` layer (or a `::before` on a fixed wrapper) instead, so it stays put without the
scroll-repaint cost and renders identically across engines.

### 17. `100vh` cuts off content behind the mobile browser chrome — P1
**Where:** `body`/`#root` `min-height: 100vh` (`_ds_bundle.css`); `.h-screen`/`.min-h-screen`/
`.max-h-screen` utilities; **`AppLayout`** root `flex h-screen overflow-hidden` (`bundle.js` ~L20734);
dialog panels `max-h-[90vh]` / `max-h-[80vh]` (`ConfirmDialog`, `FormDialog`, `SecretRevealModal`,
`UserSearchDialog`).
**Problem:** On mobile Safari and Chrome, `100vh` is the viewport height *with the address bar
retracted*, so it's taller than the visible area. Combined with `AppLayout`'s `h-screen
overflow-hidden`, the bottom of the app (and the last row of a scrolled panel) is hidden under the
browser UI, and modals can extend past the visible bottom edge.
**Fix:** Use dynamic-viewport units with a fallback everywhere a full-height measure matters:
```css
.min-h-screen { min-height: 100vh; min-height: 100dvh; }
.h-screen     { height: 100vh; height: 100dvh; }
```
`dvh`/`svh`/`lvh` are supported in all current Firefox/Chrome/Safari/Edge. Apply the same to the
dialog `max-h-[90vh]` → `max-h-[90dvh]`.

### 18. Hover-only feedback is invisible on touch devices — P2
**Where:** `DataTable` `hover:bg-white/[0.03]`; `Button` `hover:-translate-y-0.5` + `hover:shadow-glow-*`;
`.btn-primary:hover`; sidebar/menu hover states.
**Problem:** On touch devices there is no hover, so the row-highlight, button lift and glow — in
several cases the *only* affordance — never appear; taps also leave a "stuck hover" state on some
mobile browsers.
**Fix:** Guard hover effects with `@media (hover: hover) and (pointer: fine) { … }` and provide
`active:`/`:active` (tap) equivalents so touch users get press feedback. (This also resolves the
sticky-hover artifact.)

### 19. Layered `backdrop-filter` blur is a performance risk on Firefox & low-end mobile — P2
**Where:** `.glass-card` `blur(12px)`; `Sidebar` `backdrop-blur-xl`; four dialogs `backdrop-blur-sm`;
mobile drawer overlay `backdrop-blur-sm`.
**Problem:** `backdrop-filter` is supported in all target browsers now, but stacking many blurred
surfaces (a blurred sidebar + blurred overlay + blurred dialog at once) is GPU-heavy and janks scroll/
animation on Firefox and mid/low-end phones. (Correctness fallback for *unsupported* engines is covered
in #5.)
**Fix:** Reduce simultaneous blur layers — e.g. don't blur the full-screen overlay *and* the panel;
lower blur radius on mobile via a media query; and consider `will-change`/promoting only the panel.
Test scroll on a real Android device and in Firefox.

### 20. Canonical multi-column layouts aren't responsive — P2
**Where:** The documented page pattern (README §5 and the `Card` grid examples) uses
`grid grid-cols-3 gap-4` with **no responsive prefix**. `InfoRow` (`flex-col sm:flex-row`) and the app
shell (`Sidebar`/`Topbar` `lg:hidden` drawer, `hidden sm:inline` labels) *are* responsive — the gap is
in the content-composition guidance.
**Problem:** A fixed `grid-cols-3` keeps three columns at 375px, crushing cards to unreadable widths.
Because this is the copy-pasted example, every screen built from it inherits the bug.
**Fix:** Change the canonical examples/snippets to `grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3`
and document "always start single-column, add columns at breakpoints" as the rule.

### 21. `DataTable` only offers horizontal scroll on small screens — P2
**Where:** `DataTable` wrapper `overflow-x-auto` (`bundle.js` ~L14566).
**Problem:** Horizontal scroll keeps it *functional* on mobile (good baseline), but for data-dense IAM
tables (users, audit logs, certificates) it means off-screen columns, no sticky identifying column, and
easy-to-miss content.
**Fix:** Add a responsive mode: below ~`sm`, render each row as a stacked label/value card (reusing the
`InfoRow` pattern), or at minimum make the first column `sticky left-0` so the row identity stays
visible while scrolling.

### 22. Requires the host app to set the viewport meta — P3 (checklist)
**Problem:** None of the responsive behavior works if the embedding page omits
`<meta name="viewport" content="width=device-width, initial-scale=1">`; the page renders zoomed-out at
desktop width on phones.
**Fix:** Document it as a hard requirement in the DS README / app shell template.

### 23. Modern-CSS floor to state explicitly — P3
`:focus-visible`, `accent-color` (`ToggleField` checkbox), dynamic-viewport units and `rgb(… / α)`
slash-alpha are all fine in **current** Firefox/Chrome/Safari 15.4+/Edge, but degrade on older Safari
(no focus ring, default-styled checkbox). If a specific minimum Safari/older-browser version must be
supported, pin it and add fallbacks (`:focus` alongside `:focus-visible`); otherwise document the
supported-browser floor so it's a decision, not an accident.

> **How to verify (suggested test matrix):** Chrome + Firefox on desktop (primary); Safari on macOS;
> Edge (spot-check, Blink); then **iOS Safari and Android Chrome on real devices** for #16–#21 (the
> `background-attachment`, `100vh`, hover, blur-perf and grid issues only reproduce there). Test at
> 320 / 375 / 768 / 1280 / 1440 widths and with "reduce motion" enabled (#1).

---

## Suggested order of work
1. Reduced-motion guard (#1) — one CSS block, protects the whole system.
2. **Mobile-correctness pass: `background-attachment` (#16) + `100vh`→`dvh` (#17) — highest risk of a
   visible break on phones.**
3. Shared modal a11y hook: focus restore + scroll lock (#3).
4. Input/Textarea error state + `aria-invalid`/`describedby` (#2), then standardize focus rings (#4).
5. Touch/hover guards (#18) and responsive layout guidance (#20, #21).
6. Border/contrast pass: glass fallback (#5), structural border tokens (#6), scope the global border rule (#13); blur-perf (#19).
7. Target sizes (#7), DataTable a11y (#8) and UX features (#11, #12, #14).
8. Remaining polish (#9, #10, #15, #22, #23).

# AXIAM website

The public marketing & documentation website for AXIAM, served at
**https://ilpanich.github.io/axiam/**.

It is a self-contained static single-page app (React + TypeScript + Vite) with
no backend dependency. It is intentionally separate from [`frontend/`](../frontend),
which is the authenticated admin SPA.

## Sections

- **Home** — hero, feature grid, architecture, the vibe-coding story, SDK
  overview and compliance.
- **SDKs** — the eleven official client SDKs, each with a detail page linking to
  its package-registry entry, package documentation (docs.rs, tsdocs.dev,
  Read the Docs, javadoc.io, fuget.org, pkg.go.dev, DocC, Doxygen), repository,
  examples and Coveralls coverage report.
- **Docs** — a small documentation site: quickstart plus platform and operate
  guides, with a functional sidebar and per-page table of contents.
- **Security** — the public threat-modeling and security write-up, including an
  interactive browser for all nine OWASP Threat Dragon diagrams and the 149
  STRIDE threats behind them.
- **Benchmarks** — the measured head-to-head against Keycloak and Zitadel,
  transcribed from [`benchmarks/PUBLIC_BENCH_ANALYSIS.md`](../benchmarks/PUBLIC_BENCH_ANALYSIS.md)
  (currently run 5): throughput, efficiency and resource charts, the TLS/mTLS
  cost table, the eleven-SDK client benchmarks, the labelled investigation
  passes, the honest caveats and the report's §10 "why build AXIAM at all?"
  excerpt.
- **Roadmap** — the 19-phase, 64-task delivery plan.
- **News** — project milestones and engineering notes.

## Develop

```bash
npm install
npm run dev        # start the dev server
npm run build      # type-check + production build to dist/
npm run preview    # serve the production build
npm run lint       # oxlint
```

## Content

Page content lives in plain TypeScript data modules so it is easy to edit:

- `src/data.ts` — SDKs, news posts, roadmap phases, benchmark rows.
- `src/docs.ts` — the documentation pages (sidebar groups + page blocks).
- `src/security.ts` — the Security section, transcribed from
  [`claude_dev/threat-modeling-and-security.md`](../claude_dev/threat-modeling-and-security.md).

`src/threatModel.ts` and `src/threatModelSummary.ts` are **generated** — never
edit them by hand. They are built from the OWASP Threat Dragon model at
`ThreatDragonModels/Axiam/Axiam.json`, which is the source of truth for the
diagrams, the threats and the counts quoted on the page:

```bash
npm run gen:threat-model   # re-emit both modules after editing the model
```

The generator resolves the model's geometry into SVG coordinates and routes each
data flow into a path string, so `ThreatModelExplorer.tsx` stays a pure renderer.
The generated modules are committed; CI does not regenerate them.

## Deployment

`.github/workflows/website-publish.yml` builds this app and publishes it to the
**root** of the `gh-pages` branch on every push to `main` that touches
`website/**` (and on manual dispatch). It deploys with `keep_files: true`, so it
never clobbers the `/server` (rustdoc) and `/docs` (landing page) subtrees that
`docs-publish.yml` owns on the same branch.

The Vite `base` is set to `/axiam/` to match the GitHub Pages project path.

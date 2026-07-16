# AXIAM website

The public marketing & documentation website for AXIAM, served at
**https://ilpanich.github.io/axiam/**.

It is a self-contained static single-page app (React + TypeScript + Vite) with
no backend dependency. It is intentionally separate from [`frontend/`](../frontend),
which is the authenticated admin SPA.

## Sections

- **Home** — hero, feature grid, architecture, the vibe-coding story, SDK
  overview and compliance.
- **SDKs** — the seven official client SDKs, each with a detail page linking to
  its package-registry entry and package documentation (docs.rs, tsdocs.dev,
  Read the Docs, javadoc.io, fuget.org, pkg.go.dev).
- **Docs** — a small documentation site: quickstart plus platform and operate
  guides, with a functional sidebar and per-page table of contents.
- **Benchmarks** — currently a **draft** with placeholder figures; real,
  measured results will be published here after the benchmark runs.
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

## Deployment

`.github/workflows/website-publish.yml` builds this app and publishes it to the
**root** of the `gh-pages` branch on every push to `main` that touches
`website/**` (and on manual dispatch). It deploys with `keep_files: true`, so it
never clobbers the `/server` (rustdoc) and `/docs` (landing page) subtrees that
`docs-publish.yml` owns on the same branch.

The Vite `base` is set to `/axiam/` to match the GitHub Pages project path.

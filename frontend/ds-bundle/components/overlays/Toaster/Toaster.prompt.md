Toaster from frontend. Use via `window.AxiamUI.Toaster` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<AxiamSurface>` (full provider chain in README.md — components read theme/i18n from that context).

Toaster — mount once in App.tsx.
Registers the global dispatch function so useToast() works anywhere
in the component tree without a React context.

// Global test setup: registers @testing-library/jest-dom matchers and ensures
// React Testing Library unmounts rendered trees between tests. Loaded via
// `setupFiles` in vitest.config.ts. Test-only — never imported by app code.
import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

afterEach(() => {
  cleanup();
});

// jsdom does not implement the Pointer Capture API or scrollIntoView, which
// Radix primitives (toast, etc.) call during pointer interactions. Provide
// no-op polyfills so those components can be exercised in tests.
if (!Element.prototype.hasPointerCapture) {
  Element.prototype.hasPointerCapture = () => false;
}
if (!Element.prototype.setPointerCapture) {
  Element.prototype.setPointerCapture = () => {};
}
if (!Element.prototype.releasePointerCapture) {
  Element.prototype.releasePointerCapture = () => {};
}
if (!Element.prototype.scrollIntoView) {
  Element.prototype.scrollIntoView = () => {};
}

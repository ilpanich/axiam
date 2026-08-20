import { Suspense, lazy, useEffect, useState } from "react";
import type { Page } from "./types";
import { SDKS, POSTS } from "./data";
import Header from "./components/Header";
import Footer from "./components/Footer";
import Home from "./pages/Home";
import SdksOverview from "./pages/SdksOverview";
import SdkDetail from "./pages/SdkDetail";
import NewsIndex from "./pages/NewsIndex";
import NewsPost from "./pages/NewsPost";
import Benchmarks from "./pages/Benchmarks";
import Roadmap from "./pages/Roadmap";
import Security from "./pages/Security";

/**
 * The documentation section is code-split.
 *
 * Its content model is by some distance the largest module on the site — every
 * doc page, every table and every code sample — and a visitor landing on the
 * home page should not download all of it to read a hero section. The threat
 * model explorer is split for the same reason.
 */
const Docs = lazy(() => import("./pages/Docs"));

const scrollTop = () => {
  if (typeof window !== "undefined") window.scrollTo(0, 0);
};

/** True when the URL hash is a deep link into the documentation section. */
const hashIsDocLink = () =>
  typeof window !== "undefined" && /^#\/docs\/[a-z0-9-]+$/.test(window.location.hash);

export default function App() {
  const [page, setPage] = useState<Page>(() => (hashIsDocLink() ? "docs" : "home"));
  const [sdkId, setSdkId] = useState("typescript");
  const [postSlug, setPostSlug] = useState("feature-complete");

  // A shared `#/docs/<slug>` link must open that page on a cold load, and the
  // browser's back button must return to it. `Docs` owns which page is shown;
  // this only decides whether the docs section is the one on screen.
  useEffect(() => {
    const onHashChange = () => {
      if (hashIsDocLink()) setPage("docs");
    };
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  const go = (next: Page) => {
    // Leaving the docs section: drop the stale doc slug so a refresh does not
    // bounce the reader back into documentation they had navigated away from.
    if (next !== "docs" && hashIsDocLink()) {
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
    }
    setPage(next);
    scrollTop();
  };
  const openSdk = (id: string) => {
    setSdkId(id);
    setPage("sdk");
    scrollTop();
  };
  const openPost = (slug: string) => {
    setPostSlug(slug);
    setPage("post");
    scrollTop();
  };

  const sdk = SDKS.find((s) => s.id === sdkId) ?? SDKS[1];
  const post = POSTS.find((p) => p.slug === postSlug) ?? POSTS[0];

  return (
    <div className="ax-shell">
      <Header page={page} go={go} />
      <main className="ax-main">
        {page === "home" && <Home go={go} openSdk={openSdk} />}
        {page === "sdks" && <SdksOverview openSdk={openSdk} />}
        {page === "sdk" && <SdkDetail sdk={sdk} go={go} />}
        {page === "docs" && (
          <Suspense
            fallback={
              <p style={{ color: "#64748b", fontSize: 14, padding: "40px 0" }}>
                Loading the documentation…
              </p>
            }
          >
            <Docs go={go} />
          </Suspense>
        )}
        {page === "news" && <NewsIndex openPost={openPost} />}
        {page === "post" && <NewsPost post={post} go={go} />}
        {page === "bench" && <Benchmarks />}
        {page === "roadmap" && <Roadmap />}
        {page === "security" && <Security go={go} />}
      </main>
      <Footer go={go} />
    </div>
  );
}

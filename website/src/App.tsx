import { useState } from "react";
import type { Page } from "./types";
import { SDKS, POSTS } from "./data";
import Header from "./components/Header";
import Footer from "./components/Footer";
import Home from "./pages/Home";
import SdksOverview from "./pages/SdksOverview";
import SdkDetail from "./pages/SdkDetail";
import Docs from "./pages/Docs";
import NewsIndex from "./pages/NewsIndex";
import NewsPost from "./pages/NewsPost";
import Benchmarks from "./pages/Benchmarks";
import Roadmap from "./pages/Roadmap";

const scrollTop = () => {
  if (typeof window !== "undefined") window.scrollTo(0, 0);
};

export default function App() {
  const [page, setPage] = useState<Page>("home");
  const [sdkId, setSdkId] = useState("typescript");
  const [postSlug, setPostSlug] = useState("feature-complete");

  const go = (next: Page) => {
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
        {page === "docs" && <Docs go={go} />}
        {page === "news" && <NewsIndex openPost={openPost} />}
        {page === "post" && <NewsPost post={post} go={go} />}
        {page === "bench" && <Benchmarks />}
        {page === "roadmap" && <Roadmap />}
      </main>
      <Footer go={go} />
    </div>
  );
}

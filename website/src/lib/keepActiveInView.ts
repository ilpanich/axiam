import { useEffect, type RefObject } from "react";

/**
 * Keep a scrollable side column's active entry visible.
 *
 * The docs and security side columns scroll on their own once they are taller
 * than the viewport, so an entry near the bottom — opened by a deep link, or
 * made active by scrolling the article — can sit out of sight. This scrolls the
 * column itself, never the window, and only as far as needed. It does nothing
 * where the column does not overflow (the stacked layout on small screens).
 */
export function useKeepActiveInView(ref: RefObject<HTMLElement | null>, activeKey: string) {
  useEffect(() => {
    const box = ref.current;
    if (!box || box.scrollHeight <= box.clientHeight) return;
    const item = box.querySelector<HTMLElement>(".ax-side-active");
    if (!item) return;
    const outer = box.getBoundingClientRect();
    const inner = item.getBoundingClientRect();
    const margin = 12;
    if (inner.top < outer.top) {
      box.scrollTop -= outer.top - inner.top + margin;
    } else if (inner.bottom > outer.bottom) {
      box.scrollTop += inner.bottom - outer.bottom + margin;
    }
  }, [ref, activeKey]);
}

import { useEffect, useRef, useState, type RefObject } from "react";

/**
 * Tracks the width of an element, so a chart can be drawn in real pixels instead of being
 * stretched. Until the first measurement (and where ResizeObserver does not exist, such as in
 * unit tests) the fallback width is used.
 */
export function useChartWidth<T extends HTMLElement>(fallback = 640): [RefObject<T | null>, number] {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(fallback);

  useEffect(() => {
    const element = ref.current;
    if (element === null || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver((entries) => {
      const measured = entries[0]?.contentRect.width ?? 0;
      if (measured > 0) setWidth(Math.round(measured));
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  return [ref, width];
}

import { useEffect, useRef } from "react";

import { formatIstTime } from "../../features/time/ist";

/**
 * A clock in Indian Standard Time. It writes to the DOM directly, so ticking every second
 * re-renders nothing and the rest of the page is never disturbed.
 */
export default function IstClock() {
  const node = useRef<HTMLTimeElement>(null);

  useEffect(() => {
    const tick = () => {
      const element = node.current;
      if (element === null) return;
      const now = new Date();
      element.dateTime = now.toISOString();
      element.textContent = formatIstTime(now);
    };
    tick();
    const timer = window.setInterval(tick, 1000);
    return () => window.clearInterval(timer);
  }, []);

  return <time ref={node} className="font-mono text-xs tabular-nums text-ink-200" />;
}

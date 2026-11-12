import { useEffect, useRef } from "react";

function pad(value: number): string {
  return String(value).padStart(2, "0");
}

/** `HH:MM:SS` in UTC, the time zone every timestamp in the console uses. */
export function formatClock(date: Date): string {
  return `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`;
}

/**
 * A UTC clock. It writes to the DOM directly, so ticking every second re-renders nothing and the
 * rest of the page is never disturbed.
 */
export default function UtcClock() {
  const node = useRef<HTMLTimeElement>(null);

  useEffect(() => {
    const tick = () => {
      const element = node.current;
      if (element === null) return;
      const now = new Date();
      element.dateTime = now.toISOString();
      element.textContent = `${formatClock(now)} UTC`;
    };
    tick();
    const timer = window.setInterval(tick, 1000);
    return () => window.clearInterval(timer);
  }, []);

  return <time ref={node} className="font-mono text-xs tabular-nums text-ink-200" />;
}

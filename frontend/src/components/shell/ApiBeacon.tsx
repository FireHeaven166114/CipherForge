import { Link } from "react-router";

import type { OverallStatus } from "../../features/status/overallStatus";
import { useServiceStatus } from "../../hooks/useServiceStatus";
import StatusLed, { type LedTone } from "../hud/StatusLed";

const BEACON: Record<OverallStatus, { label: string; tone: LedTone; text: string }> = {
  checking: { label: "CHECKING", tone: "idle", text: "text-ink-300" },
  operational: { label: "API ONLINE", tone: "ok", text: "text-ok" },
  degraded: { label: "API DEGRADED", tone: "warn", text: "text-warn" },
  down: { label: "API OFFLINE", tone: "bad", text: "text-bad" },
};

/**
 * The API's health at a glance, always on screen. The state is spelled out in words as well as
 * shown by the light, and the whole thing links to the full status page.
 */
export default function ApiBeacon() {
  const { overall } = useServiceStatus();
  const { label, tone, text } = BEACON[overall];
  return (
    <Link
      to="/status"
      title="Open system status"
      className={`flex shrink-0 items-center gap-2 whitespace-nowrap rounded-[3px] border border-ink-600 bg-ink-900/70 px-2.5 py-1.5 text-[0.7rem] font-semibold tracking-[0.14em] transition hover:border-cipher/60 ${text}`}
    >
      <StatusLed tone={tone} pulsing={overall === "operational"} />
      {label}
    </Link>
  );
}

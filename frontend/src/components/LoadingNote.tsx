import type { ReactNode } from "react";

import StatusLed from "./hud/StatusLed";

/** A "still working" message that assistive technology announces politely. */
export default function LoadingNote({ children }: { children: ReactNode }) {
  return (
    <p role="status" className="flex items-center gap-2 text-sm text-ink-200">
      <StatusLed tone="cipher" pulsing />
      {children}
    </p>
  );
}

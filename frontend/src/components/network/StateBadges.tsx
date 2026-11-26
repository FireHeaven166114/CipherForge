import { CAPTURE_STATE_META, SESSION_STATUS_META } from "../../features/network/labels";
import type { CaptureState, SessionStatus } from "../../types/network";
import StatusLed from "../hud/StatusLed";
import StatusBadge from "../StatusBadge";

/** The state of live capture: a lamp, a symbol and a word. */
export function CaptureStateBadge({ state }: { state: CaptureState }) {
  const meta = CAPTURE_STATE_META[state];
  return (
    <span className="inline-flex items-center gap-2">
      <StatusLed tone={meta.led} pulsing={meta.pulsing} />
      <StatusBadge tone={meta.tone}>{meta.label}</StatusBadge>
    </span>
  );
}

export function SessionStatusBadge({ status }: { status: SessionStatus }) {
  return <StatusBadge tone={SESSION_STATUS_META[status].tone}>{SESSION_STATUS_META[status].label}</StatusBadge>;
}

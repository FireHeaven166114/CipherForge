import { useId, useState } from "react";

import {
  activeInterfaceId,
  captureNotices,
  interfaceLabel,
  startAvailability,
  stopAvailability,
} from "../../features/network/capture";
import { isCaptureActive } from "../../features/network/labels";
import { networkErrorMessage } from "../../features/network/messages";
import { useNetworkCapture } from "../../hooks/useNetworkCapture";
import { useNetworkInterfaces } from "../../hooks/useNetworkInterfaces";
import type { NetworkInterface, NetworkStatus } from "../../types/network";
import { PlayIcon, RefreshIcon, StopIcon } from "../hud/Icons";
import Panel from "../hud/Panel";
import LoadingNote from "../LoadingNote";
import StatusBadge from "../StatusBadge";
import { BUTTON, FIELD, LABEL, PRIMARY_BUTTON } from "../styles";
import NetworkErrorNotice from "./NetworkErrorNotice";
import Notice from "./Notice";
import { CaptureStateBadge } from "./StateBadges";

/** What a Start or Stop led to, so the page can ask for the new status and follow the new session. */
export type CaptureOutcome = "started" | "stopped" | "failed";

interface CaptureControlProps {
  status: NetworkStatus;
  onSettled: (outcome: CaptureOutcome) => void;
  className?: string;
}

// The option for a running capture whose interface is not in the list (it was unplugged since).
const UNLISTED = "__unlisted__";
const MAX_ADDRESSES = 4;

function statusSentence(status: NetworkStatus): string {
  const where = status.interface === null ? "" : ` on ${status.interface}`;
  switch (status.state) {
    case "running":
      return `Capturing${where}. The figures below update as packets arrive.`;
    case "starting":
      return `Starting the capture${where}…`;
    case "stopping":
      return `Stopping the capture${where}…`;
    case "ready":
      return "Ready. Choose an interface and press Start.";
    case "stopped":
      return "The capture is stopped.";
    case "failed":
      return "The last capture failed.";
    case "permission_denied":
      return "Packet capture was refused by the operating system.";
    case "not_configured":
      return "Live capture is not available on this server.";
  }
}

function Addresses({ entry }: { entry: NetworkInterface | undefined }) {
  if (entry === undefined || entry.addresses.length === 0) return null;
  const shown = entry.addresses.slice(0, MAX_ADDRESSES).join(", ");
  const hidden = entry.addresses.length - MAX_ADDRESSES;
  return (
    <p className="mt-1.5 break-words font-mono text-xs text-ink-300">
      Addresses: {shown}
      {hidden > 0 ? ` and ${hidden} more` : ""}
    </p>
  );
}

export default function CaptureControl({ status, onSettled, className }: CaptureControlProps) {
  const selectId = useId();
  const hintId = useId();
  const stopHintId = useId();
  const interfaces = useNetworkInterfaces();
  const controls = useNetworkCapture();
  const [choice, setChoice] = useState<string | null>(null);
  // The answer to the last Start or Stop holds until the next poll replaces the status it followed.
  const [command, setCommand] = useState<{ result: NetworkStatus; basedOn: NetworkStatus } | null>(
    null,
  );
  const view = command !== null && command.basedOn === status ? command.result : status;

  const list = interfaces.state.status === "ready" ? interfaces.state.data.interfaces : [];
  const locked = isCaptureActive(view.state);
  const activeId = activeInterfaceId(view, list);
  const unlisted = locked && view.interface !== null && activeId === null;
  const picked = choice !== null && list.some((entry) => entry.id === choice) ? choice : null;
  const selectedId = locked ? (activeId ?? (unlisted ? UNLISTED : null)) : (picked ?? list[0]?.id ?? null);
  const selected = list.find((entry) => entry.id === selectedId);

  const start = startAvailability(view, locked ? null : selectedId, list.length);
  const stop = stopAvailability(view);
  const working = controls.busy !== null;
  const notices = captureNotices(view);
  const extraMessage =
    view.message !== null && !notices.some((notice) => notice.body === view.message) ? view.message : null;

  async function run(kind: "start" | "stop") {
    if (working) return;
    if (kind === "start" && (!start.allowed || selectedId === null)) return;
    if (kind === "stop" && !stop.allowed) return;
    const result = kind === "start" && selectedId !== null ? await controls.start(selectedId) : await controls.stop();
    if (result !== null) setCommand({ result, basedOn: status });
    onSettled(result === null ? "failed" : kind === "start" ? "started" : "stopped");
  }

  const refreshing = interfaces.state.status === "ready" && interfaces.state.refreshing;
  const refreshError = interfaces.state.status === "ready" ? interfaces.state.refreshError : null;

  return (
    <Panel
      title="Live capture"
      code="CAP-01"
      className={className}
      actions={<CaptureStateBadge state={view.state} />}
    >
      <div className="space-y-4">
        <div>
          <label htmlFor={selectId} className={LABEL}>
            Interface
          </label>
          {interfaces.state.status === "loading" ? (
            <LoadingNote>Looking for capture interfaces…</LoadingNote>
          ) : null}
          {interfaces.state.status === "error" ? (
            <div className="mt-1.5">
              <NetworkErrorNotice error={interfaces.state.error} onRetry={interfaces.refresh} />
            </div>
          ) : null}
          {interfaces.state.status === "ready" ? (
            <>
              <div className="mt-1.5 flex flex-wrap items-center gap-2">
                <select
                  id={selectId}
                  value={selectedId ?? ""}
                  disabled={locked || list.length === 0}
                  onChange={(event) => setChoice(event.target.value)}
                  className={`${FIELD} min-w-0 flex-1 basis-56`}
                >
                  {list.length === 0 ? <option value="">None available</option> : null}
                  {unlisted ? <option value={UNLISTED}>{view.interface}</option> : null}
                  {list.map((entry) => (
                    <option key={entry.id} value={entry.id}>
                      {interfaceLabel(entry)}
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  onClick={refreshing ? undefined : interfaces.refresh}
                  aria-disabled={refreshing || undefined}
                  className={BUTTON}
                >
                  <RefreshIcon className={`size-4 ${refreshing ? "animate-spin" : ""}`} />
                  {refreshing ? "Refreshing…" : "Refresh interfaces"}
                </button>
              </div>
              {list.length === 0 ? (
                <p className="mt-1.5 text-sm text-ink-200">
                  No capture interfaces found. Refresh the list after connecting or enabling one.
                </p>
              ) : null}
              <Addresses entry={selected} />
              {refreshError !== null ? (
                <p role="alert" className="mt-1.5 text-sm text-warn">
                  <span aria-hidden="true">▲ </span>
                  {networkErrorMessage(refreshError)}
                </p>
              ) : null}
            </>
          ) : null}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => void run("start")}
            aria-disabled={!start.allowed || working || undefined}
            aria-describedby={!start.allowed ? hintId : undefined}
            className={PRIMARY_BUTTON}
          >
            <PlayIcon className="size-4" />
            {controls.busy === "start" ? "Starting…" : "Start capture"}
          </button>
          <button
            type="button"
            onClick={() => void run("stop")}
            aria-disabled={!stop.allowed || working || undefined}
            aria-describedby={!stop.allowed ? stopHintId : undefined}
            className={BUTTON}
          >
            <StopIcon className="size-4" />
            {controls.busy === "stop" ? "Stopping…" : "Stop capture"}
          </button>
        </div>
        {!start.allowed ? (
          <p id={hintId} className="-mt-2 text-xs text-ink-300">
            {start.reason}
          </p>
        ) : null}
        {!stop.allowed ? (
          <span id={stopHintId} className="sr-only">
            {stop.reason}
          </span>
        ) : null}

        {controls.error !== null ? <NetworkErrorNotice error={controls.error} /> : null}

        <div role="status" aria-live="polite" className="space-y-1 text-sm text-ink-100">
          <p>{statusSentence(view)}</p>
          {extraMessage !== null ? <p className="text-ink-200">{extraMessage}</p> : null}
        </div>

        {notices.map((notice) => (
          <Notice key={notice.title} tone={notice.tone} title={notice.title}>
            <p>{notice.body}</p>
          </Notice>
        ))}

        <dl className="grid grid-cols-[minmax(7rem,max-content)_minmax(0,1fr)] gap-x-4 gap-y-1.5">
          <dt className="text-ink-300">Capture backend</dt>
          <dd className="flex flex-wrap items-center gap-2">
            <span className="font-mono">{view.backend.name}</span>
            <StatusBadge tone={view.backend.available ? "ok" : "warn"}>
              {view.backend.available ? "Available" : "Not available"}
            </StatusBadge>
          </dd>
          {view.interface !== null ? (
            <>
              <dt className="text-ink-300">Capture interface</dt>
              <dd className="break-words font-mono">{view.interface}</dd>
            </>
          ) : null}
        </dl>

        <p className="text-xs text-ink-300">
          Live capture is not promiscuous: it sees the traffic of the machine that runs the API.
          Packet payloads are never stored.
        </p>
      </div>
    </Panel>
  );
}

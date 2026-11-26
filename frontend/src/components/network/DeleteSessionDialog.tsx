import { useRef } from "react";

import { countOf, describeSource } from "../../features/network/labels";
import { formatIst } from "../../features/time/ist";
import type { ApiError } from "../../services/apiClient";
import type { CaptureSession } from "../../types/network";
import { TrashIcon } from "../hud/Icons";
import Overlay from "../hud/Overlay";
import { BUTTON, DANGER_BUTTON } from "../styles";
import NetworkErrorNotice from "./NetworkErrorNotice";

interface DeleteSessionDialogProps {
  /** The session about to be deleted. `null` keeps the dialog closed. */
  target: CaptureSession | null;
  /** True while the API is working. Nothing can be dismissed or pressed again then. */
  busy: boolean;
  /** Why the last attempt failed. The dialog stays open so the analyst can try again. */
  error: ApiError | null;
  onConfirm: () => void;
  onCancel: () => void;
}

const TITLE = "Delete this session?";

export default function DeleteSessionDialog({
  target,
  busy,
  error,
  onConfirm,
  onCancel,
}: DeleteSessionDialogProps) {
  const cancel = useRef<HTMLButtonElement>(null);
  const source = target === null ? null : describeSource(target);

  return (
    <Overlay open={target !== null} onClose={busy ? () => undefined : onCancel} label={TITLE} initialFocus={cancel}>
      <div className="hud-panel rounded-ui shadow-glow-crit">
        <div className="max-h-[calc(100dvh-2rem)] overflow-y-auto rounded-ui">
          <div className="px-5 pt-5">
            <h2 className="text-lg font-semibold text-ink-50">{TITLE}</h2>

            {target !== null && source !== null ? (
              <dl className="mt-3 space-y-1 rounded-control border border-white/10 bg-ink-950/60 p-3 text-xs text-ink-100">
                <div>
                  <dt className="inline text-ink-300">{source.kind}: </dt>
                  <dd className="inline break-all font-mono">{source.name}</dd>
                </div>
                <div>
                  <dt className="inline text-ink-300">Started: </dt>
                  <dd className="inline">{formatIst(target.started_at)}</dd>
                </div>
                <div>
                  <dt className="inline text-ink-300">Contains: </dt>
                  <dd className="inline">
                    {countOf(target.packets_total, "packet")}, {countOf(target.flows_total, "flow")},{" "}
                    {countOf(target.alerts_total, "alert")}
                  </dd>
                </div>
              </dl>
            ) : null}

            <p className="mt-4 text-sm text-ink-100">
              This permanently removes the session with its stored flows, its alerts and the address lookup
              results kept with it. It cannot be undone.
            </p>
            <p className="mt-2 text-xs text-ink-300">
              The audit log is kept as it is, and gains a record that this session was deleted.
            </p>

            {error !== null ? (
              <div className="mt-4">
                <NetworkErrorNotice error={error} />
              </div>
            ) : null}
          </div>

          <div className="sticky bottom-0 flex flex-wrap justify-end gap-2 bg-ink-950 px-5 pb-5 pt-5">
            <button
              ref={cancel}
              type="button"
              aria-disabled={busy || undefined}
              onClick={busy ? undefined : onCancel}
              className={BUTTON}
            >
              Cancel
            </button>
            <button
              type="button"
              aria-disabled={busy || undefined}
              onClick={busy ? undefined : onConfirm}
              className={DANGER_BUTTON}
            >
              <TrashIcon className="size-4" />
              {busy ? "Deleting…" : "Delete session"}
            </button>
          </div>
        </div>
      </div>
    </Overlay>
  );
}

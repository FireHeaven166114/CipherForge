import { useRef } from "react";

import type { ApiError } from "../../services/apiClient";
import ErrorNotice from "../ErrorNotice";
import { TrashIcon } from "../hud/Icons";
import Overlay from "../hud/Overlay";
import { BUTTON, DANGER_BUTTON } from "../styles";

/** An indicator waiting to be deleted: what the dialog names, and what is sent to the API. */
export interface DeleteTarget {
  id: string;
  value: string;
}

/** A long selection is summarised so the dialog stays small. */
const MAX_LISTED = 5;

interface DeleteIndicatorsDialogProps {
  /** What is about to be deleted. `null` keeps the dialog closed. */
  targets: readonly DeleteTarget[] | null;
  /** True while the API is working. Nothing can be dismissed or pressed again then. */
  busy: boolean;
  /** Why the last attempt failed. The dialog stays open so the analyst can try again. */
  error: ApiError | null;
  onConfirm: () => void;
  onCancel: () => void;
}

export default function DeleteIndicatorsDialog({
  targets,
  busy,
  error,
  onConfirm,
  onCancel,
}: DeleteIndicatorsDialogProps) {
  const cancel = useRef<HTMLButtonElement>(null);
  const count = targets?.length ?? 0;
  const one = count === 1;
  const title = one ? "Delete this indicator?" : `Delete ${count} indicators?`;
  const listed = targets?.slice(0, MAX_LISTED) ?? [];
  const unlisted = count - listed.length;

  return (
    <Overlay
      open={targets !== null}
      onClose={busy ? () => undefined : onCancel}
      label={title}
      initialFocus={cancel}
    >
      <div className="hud-panel rounded-ui shadow-glow-crit">
        {/*
          The panel itself cannot scroll: that would clip its glow and carry its border ring away
          with the text. This box inside it scrolls instead, so a tall dialog (very long values, an
          error, a short or enlarged screen) never runs off the screen. The buttons are part of it
          and stay in view at the bottom, which also makes the box reachable by keyboard.
        */}
        <div className="max-h-[calc(100dvh-2rem)] overflow-y-auto rounded-ui">
          <div className="px-5 pt-5">
            <h2 className="text-lg font-semibold text-ink-50">{title}</h2>

            <ul className="mt-3 space-y-1 rounded-control border border-white/10 bg-ink-950/60 p-3 font-mono text-xs text-ink-100">
              {listed.map((target) => (
                <li key={target.id} className="break-all">
                  {target.value}
                </li>
              ))}
              {unlisted > 0 ? <li className="font-sans text-ink-300">and {unlisted} more</li> : null}
            </ul>

            <p className="mt-4 text-sm text-ink-100">
              This permanently removes {one ? "it" : "them"}, and every provider answer stored for{" "}
              {one ? "it" : "them"}, from the database. It cannot be undone.
            </p>
            <p className="mt-2 text-xs text-ink-300">
              The audit log is kept as it is: it still records the past lookups and gains a record of
              this deletion.
            </p>

            {error ? (
              <div className="mt-4">
                <ErrorNotice error={error} />
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
              {busy ? "Deleting…" : one ? "Delete indicator" : `Delete ${count} indicators`}
            </button>
          </div>
        </div>
      </div>
    </Overlay>
  );
}

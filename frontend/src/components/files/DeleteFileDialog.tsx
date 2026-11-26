import { useRef } from "react";

import { plural } from "../../features/intel/format";
import type { ApiError } from "../../services/apiClient";
import type { StoredFile } from "../../types/files";
import { TrashIcon } from "../hud/Icons";
import Overlay from "../hud/Overlay";
import { BUTTON, DANGER_BUTTON } from "../styles";
import FileErrorNotice from "./FileErrorNotice";

interface DeleteFileDialogProps {
  /** The file about to be deleted. `null` keeps the dialog closed. */
  file: Pick<StoredFile, "name" | "active_share_count"> | null;
  /** True while the API is working. Nothing can be dismissed or pressed again then. */
  busy: boolean;
  /** Why the last attempt failed. The dialog stays open so it can be tried again. */
  error: ApiError | null;
  onConfirm: () => void;
  onCancel: () => void;
}

export default function DeleteFileDialog({ file, busy, error, onConfirm, onCancel }: DeleteFileDialogProps) {
  const cancel = useRef<HTMLButtonElement>(null);
  const active = file?.active_share_count ?? 0;

  return (
    <Overlay
      open={file !== null}
      onClose={busy ? () => undefined : onCancel}
      label="Delete this file?"
      initialFocus={cancel}
    >
      <div className="hud-panel rounded-ui shadow-glow-crit">
        <div className="max-h-[calc(100dvh-2rem)] overflow-y-auto rounded-ui">
          <div className="px-5 pt-5">
            <h2 className="text-lg font-semibold text-ink-50">Delete this file?</h2>

            <p className="mt-3 break-all rounded-control border border-white/10 bg-ink-950/60 p-3 font-mono text-xs text-ink-100">
              {file?.name}
            </p>

            <p className="mt-4 text-sm text-ink-100">
              This permanently deletes the encrypted file and its key. Every share link made for it stops
              working immediately
              {active > 0 ? `, including ${plural(active, "active link")}` : ""}. It cannot be undone.
            </p>
            <p className="mt-2 text-xs text-ink-300">
              The audit log keeps a record that the file existed and was deleted.
            </p>

            {error ? (
              <div className="mt-4">
                <FileErrorNotice title="The file could not be deleted" error={error} />
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
              {busy ? "Deleting…" : "Delete file"}
            </button>
          </div>
        </div>
      </div>
    </Overlay>
  );
}

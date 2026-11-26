import { useRef } from "react";

import { shortId } from "../../features/files/labels";
import type { ApiError } from "../../services/apiClient";
import type { Share } from "../../types/files";
import { StopIcon } from "../hud/Icons";
import Overlay from "../hud/Overlay";
import { BUTTON, DANGER_BUTTON } from "../styles";
import FileErrorNotice from "./FileErrorNotice";

interface RevokeShareDialogProps {
  /** The link about to be revoked. `null` keeps the dialog closed. */
  share: Pick<Share, "id" | "download_count" | "max_downloads" | "password_protected"> | null;
  /** True while the API is working. Nothing can be dismissed or pressed again then. */
  busy: boolean;
  /** Why the last attempt failed. The dialog stays open so it can be tried again. */
  error: ApiError | null;
  onConfirm: () => void;
  onCancel: () => void;
}

export default function RevokeShareDialog({ share, busy, error, onConfirm, onCancel }: RevokeShareDialogProps) {
  const cancel = useRef<HTMLButtonElement>(null);

  return (
    <Overlay
      open={share !== null}
      onClose={busy ? () => undefined : onCancel}
      label="Revoke this link?"
      initialFocus={cancel}
    >
      <div className="hud-panel rounded-ui shadow-glow-crit">
        <div className="max-h-[calc(100dvh-2rem)] overflow-y-auto rounded-ui">
          <div className="px-5 pt-5">
            <h2 className="text-lg font-semibold text-ink-50">Revoke this link?</h2>

            {share ? (
              <p className="mt-3 rounded-control border border-white/10 bg-ink-950/60 p-3 text-xs text-ink-100">
                Link <span className="font-mono">{shortId(share.id)}</span>
                {share.password_protected ? ", protected by a password" : ""}:{" "}
                {share.download_count} of {share.max_downloads} downloads used.
              </p>
            ) : null}

            <p className="mt-4 text-sm text-ink-100">
              Anyone who opens this link afterwards, including someone who has already copied it, is told
              that it was revoked and receives nothing. The file stays stored, and you can make another
              link. This cannot be undone.
            </p>

            {error ? (
              <div className="mt-4">
                <FileErrorNotice title="The link could not be revoked" error={error} />
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
              <StopIcon className="size-4" />
              {busy ? "Revoking…" : "Revoke link"}
            </button>
          </div>
        </div>
      </div>
    </Overlay>
  );
}

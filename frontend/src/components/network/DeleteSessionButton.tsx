import { useId } from "react";

import { isSessionActive } from "../../features/network/labels";
import type { CaptureSession } from "../../types/network";
import { TrashIcon } from "../hud/Icons";
import { BUTTON, DANGER_BUTTON } from "../styles";

interface DeleteSessionButtonProps {
  session: Pick<CaptureSession, "status">;
  /** Shown to assistive technology when the button is just an icon, so each row says which session it removes. */
  name?: string;
  /** An icon button for a table row. */
  compact?: boolean;
  onDelete: () => void;
}

/** Opens the confirmation to delete a session. A session still being filled cannot be deleted. */
export default function DeleteSessionButton({ session, name, compact = false, onDelete }: DeleteSessionButtonProps) {
  const reasonId = useId();
  const active = isSessionActive(session.status);
  return (
    <>
      <button
        type="button"
        aria-disabled={active || undefined}
        aria-describedby={active ? reasonId : undefined}
        onClick={active ? undefined : onDelete}
        className={compact ? `${BUTTON} px-2 py-1 text-xs` : DANGER_BUTTON}
      >
        <TrashIcon className="size-4" />
        <span className={compact ? "sr-only" : undefined}>
          Delete session{compact && name !== undefined ? ` ${name}` : ""}
        </span>
      </button>
      {active ? (
        <span id={reasonId} className="sr-only">
          A session cannot be deleted while it is running.
        </span>
      ) : null}
    </>
  );
}
